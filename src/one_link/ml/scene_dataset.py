"""Production scene-graph dataset builder for the video predictor.

Generates deterministic sequences of SCENE SNAPSHOTS. Each snapshot
is a fixed-size feature vector:

  [n_objects, mean_conf, lighting, camera_motion, object_activity,
   avg_obj_x, avg_obj_y, avg_obj_size,
   obj0_x, obj0_y, obj0_size, obj0_vx, obj0_vy,
   obj1_x, obj1_y, obj1_size, obj1_vx, obj1_vy,
   ...
   obj5_x, obj5_y, obj5_size, obj5_vx, obj5_vy]

= 8 global features + 6 slots x 5 object features = 38-dim per frame

Sequences traverse the same realistic regimes as synth_scene_sequence
in tools/video_e2e_sim.py: static talking head, object translation,
camera pan, object appearance, scene cut, stable post-cut.

Regime labels per frame (5 classes):
  0: static
  1: object_translate
  2: camera_pan
  3: object_appear_disappear
  4: scene_cut

Output layout on disk:
    data/scene_corpus_v1/
        meta.json
        train/seq_*.npz
        val/seq_*.npz
        test/seq_*.npz
"""

from __future__ import annotations

import argparse
import json
import math
import random
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np


REGIME_NAMES = ["static", "object_translate", "camera_pan",
                "object_appear_disappear", "scene_cut"]
REGIME_ID = {n: i for i, n in enumerate(REGIME_NAMES)}
MAX_OBJECTS = 6
PER_OBJECT_FEATURES = 5                 # x, y, size, vx, vy
GLOBAL_FEATURES = 8
FEATURE_DIM = GLOBAL_FEATURES + MAX_OBJECTS * PER_OBJECT_FEATURES


@dataclass
class Object:
    x: float
    y: float
    size: float
    vx: float
    vy: float

    def step(self, dt: float = 1.0 / 30.0) -> None:
        self.x += self.vx * dt
        self.y += self.vy * dt


@dataclass
class SceneGen:
    rng: random.Random
    camera_motion: float = 0.0
    lighting: float = 0.5
    objects: list[Object] = field(default_factory=list)

    def static_phase(self, n_frames: int) -> list[np.ndarray]:
        out = []
        for _ in range(n_frames):
            self.camera_motion = 0.01 * self.rng.random()
            self.lighting += 0.001 * (self.rng.random() - 0.5)
            for o in self.objects:
                o.vx *= 0.9
                o.vy *= 0.9
                o.step()
            out.append(self._snapshot(regime_id=0))
        return out

    def translate_phase(self, n_frames: int) -> list[np.ndarray]:
        # Pick one object to move
        if not self.objects:
            self._spawn_object()
        target = self.rng.choice(self.objects)
        target.vx = self.rng.uniform(-0.3, 0.3)
        target.vy = self.rng.uniform(-0.3, 0.3)
        out = []
        for _ in range(n_frames):
            for o in self.objects:
                o.step()
            self.camera_motion = 0.05 + 0.02 * self.rng.random()
            out.append(self._snapshot(regime_id=1))
        return out

    def pan_phase(self, n_frames: int) -> list[np.ndarray]:
        pan_dir = self.rng.uniform(0, 2 * math.pi)
        pan_speed = self.rng.uniform(0.5, 1.0)
        dx = pan_speed * math.cos(pan_dir)
        dy = pan_speed * math.sin(pan_dir)
        out = []
        for _ in range(n_frames):
            for o in self.objects:
                o.x -= dx * (1.0 / 30.0)
                o.y -= dy * (1.0 / 30.0)
            self.camera_motion = 0.7 + 0.1 * self.rng.random()
            out.append(self._snapshot(regime_id=2))
        return out

    def appear_phase(self, n_frames: int) -> list[np.ndarray]:
        if len(self.objects) < MAX_OBJECTS:
            self._spawn_object()
        out = []
        for _ in range(n_frames):
            for o in self.objects:
                o.step()
            out.append(self._snapshot(regime_id=3))
        return out

    def scene_cut(self) -> None:
        # Replace all objects + change lighting
        self.objects = [self._random_object() for _ in range(self.rng.randint(2, MAX_OBJECTS))]
        self.lighting = self.rng.uniform(0.2, 0.9)

    def _spawn_object(self) -> None:
        if len(self.objects) < MAX_OBJECTS:
            self.objects.append(self._random_object())

    def _random_object(self) -> Object:
        return Object(
            x=self.rng.uniform(0.1, 0.9),
            y=self.rng.uniform(0.1, 0.9),
            size=self.rng.uniform(0.05, 0.3),
            vx=self.rng.uniform(-0.1, 0.1),
            vy=self.rng.uniform(-0.1, 0.1),
        )

    def _snapshot(self, regime_id: int) -> tuple[np.ndarray, int]:
        feat = np.zeros(FEATURE_DIM, dtype=np.float32)
        n_obj = len(self.objects)
        feat[0] = n_obj
        feat[1] = 0.95 if self.camera_motion < 0.2 else 0.75
        feat[2] = self.lighting
        feat[3] = self.camera_motion
        act = float(np.mean([abs(o.vx) + abs(o.vy) for o in self.objects])) if self.objects else 0.0
        feat[4] = min(1.0, act)
        if self.objects:
            feat[5] = float(np.mean([o.x for o in self.objects]))
            feat[6] = float(np.mean([o.y for o in self.objects]))
            feat[7] = float(np.mean([o.size for o in self.objects]))
        for i, o in enumerate(self.objects[:MAX_OBJECTS]):
            base = GLOBAL_FEATURES + i * PER_OBJECT_FEATURES
            feat[base + 0] = o.x
            feat[base + 1] = o.y
            feat[base + 2] = o.size
            feat[base + 3] = o.vx
            feat[base + 4] = o.vy
        return (feat, regime_id)


def build_scene_sequence(n_frames: int, seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    rng = random.Random(seed)
    gen = SceneGen(rng=rng)
    # Seed with 1-3 objects
    for _ in range(rng.randint(1, 3)):
        gen._spawn_object()
    out_frames: list[np.ndarray] = []
    out_labels: list[int] = []
    remaining = n_frames
    while remaining > 0:
        segment_type = rng.choice(["static", "translate", "pan", "appear", "cut"])
        seg_len = rng.randint(15, 45)
        seg_len = min(seg_len, remaining)
        if segment_type == "static":
            rows = gen.static_phase(seg_len)
        elif segment_type == "translate":
            rows = gen.translate_phase(seg_len)
        elif segment_type == "pan":
            rows = gen.pan_phase(seg_len)
        elif segment_type == "appear":
            rows = gen.appear_phase(seg_len)
        elif segment_type == "cut":
            # One scene cut frame + stable post-cut
            gen.scene_cut()
            rows = [gen._snapshot(regime_id=4)]
            post = gen.static_phase(max(1, seg_len - 1))
            rows += post
        for feat, rid in rows:
            out_frames.append(feat)
            out_labels.append(rid)
        remaining -= len(rows)
    feats = np.stack(out_frames[:n_frames]).astype(np.float32)
    labels = np.array(out_labels[:n_frames], dtype=np.int16)
    return feats, labels


# =============================================================================
# CORPUS
# =============================================================================

@dataclass
class SceneStats:
    n_sequences: int
    n_train: int
    n_val: int
    n_test: int
    total_frames: int
    feature_dim: int
    regime_counts: dict[str, int]
    wall_seconds: float = 0.0


def build_scene_corpus(out_dir: Path, n_sequences: int = 2000,
                       seq_len: int = 120, seed: int = 314,
                       train_frac: float = 0.8, val_frac: float = 0.1,
                       progress_every: int = 200) -> SceneStats:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for s in ("train", "val", "test"):
        (out_dir / s).mkdir(exist_ok=True)
    n_train = int(n_sequences * train_frac)
    n_val = int(n_sequences * val_frac)
    n_test = n_sequences - n_train - n_val
    splits = (["train"] * n_train) + (["val"] * n_val) + (["test"] * n_test)
    random.Random(seed + 1).shuffle(splits)
    regime_counts = {r: 0 for r in REGIME_NAMES}
    total_frames = 0
    t0 = time.time()
    for i in range(n_sequences):
        feats, labels = build_scene_sequence(seq_len, seed=seed * 13 + i)
        np.savez_compressed(
            out_dir / splits[i] / f"seq_{i:06d}.npz",
            features=feats.astype(np.float16),
            labels=labels,
        )
        total_frames += feats.shape[0]
        for rid in labels:
            regime_counts[REGIME_NAMES[int(rid)]] += 1
        if progress_every and (i + 1) % progress_every == 0:
            rate = (i + 1) / max(time.time() - t0, 1e-6)
            print(f"[scene_corpus] {i+1}/{n_sequences}  {rate:.1f}/s", file=sys.stderr)
    stats = SceneStats(
        n_sequences=n_sequences, n_train=n_train, n_val=n_val, n_test=n_test,
        total_frames=total_frames, feature_dim=FEATURE_DIM,
        regime_counts=regime_counts, wall_seconds=time.time() - t0,
    )
    (out_dir / "meta.json").write_text(json.dumps({
        "stats": asdict(stats),
        "config": {"n_sequences": n_sequences, "seq_len": seq_len,
                   "train_frac": train_frac, "val_frac": val_frac,
                   "feature_dim": FEATURE_DIM,
                   "max_objects": MAX_OBJECTS,
                   "per_object_features": PER_OBJECT_FEATURES},
        "seed": seed,
        "regime_names": REGIME_NAMES,
    }, indent=2, default=str))
    return stats


def load_scene_split(corpus_dir: Path, split: str):
    for p in sorted((Path(corpus_dir) / split).glob("seq_*.npz")):
        with np.load(p) as d:
            yield d["features"].astype(np.float32), d["labels"].astype(np.int16)


# =============================================================================
# CLI / SELFTEST
# =============================================================================

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out-dir", type=str, default="data/scene_corpus_v1")
    ap.add_argument("--n-sequences", type=int, default=2000)
    ap.add_argument("--seq-len", type=int, default=120)
    ap.add_argument("--seed", type=int, default=314)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        import tempfile
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            stats = build_scene_corpus(Path(td), n_sequences=40, seq_len=60,
                                       seed=1, progress_every=0)
            assert stats.n_train >= 1 and stats.n_test >= 1
            for feats, labels in load_scene_split(Path(td), "train"):
                assert feats.shape == (60, FEATURE_DIM)
                assert labels.shape == (60,)
                break
            # All regimes covered in 40 sequences
            observed = sum(1 for v in stats.regime_counts.values() if v > 0)
            assert observed >= 3, f"too few regimes: {observed}"
        print(f"scene_dataset selftest: OK "
              f"({stats.total_frames} frames, {observed}/{len(REGIME_NAMES)} regimes)")
        return 0

    out = Path(__file__).resolve().parent.parent.parent / args.out_dir
    stats = build_scene_corpus(out, n_sequences=args.n_sequences,
                               seq_len=args.seq_len, seed=args.seed)
    print(f"[scene_dataset] built {stats.n_sequences} sequences in "
          f"{stats.wall_seconds:.1f}s -> {out}")
    print(f"  train/val/test:  {stats.n_train}/{stats.n_val}/{stats.n_test}")
    print(f"  total frames:    {stats.total_frames}")
    print(f"  feature dim:     {stats.feature_dim}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
