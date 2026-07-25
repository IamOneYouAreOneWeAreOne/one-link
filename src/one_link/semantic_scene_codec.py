"""Research-only semantic scene codec — Tier θ design substrate.

The stable daemon does not capture, transport, or render this representation.
The design targets ~3-5 kbps of *scene-level* video features:

  38-dim scene snapshot per frame
    [n_objects, mean_conf, lighting, camera_motion, object_activity,
     avg_obj_x, avg_obj_y, avg_obj_size,
     {6 × (obj_x, obj_y, obj_size, obj_vx, obj_vy)}]

  + regime tag per frame (5 classes:
    static / object_translate / camera_pan / object_appear / scene_cut)

The scene predictor (38→38 dim GRU) runs at both sender and receiver.
Each frame the sender emits only the residual between actual scene
features and the predictor's expectation, sparsified to the K
largest-magnitude dimensions. At 10 fps with K=8 residuals + regime
+ a small global header, total bitrate stays around 3 kbps.

This is NOT photorealistic video reconstruction — Tier θ ships
*intelligent scene representation* that the UI can render as moving
boxes / icons / face stand-ins. The doctrine of invisibility (§4.c)
keeps the rendering plain-language: "Mom · in motion · camera panning"
rather than a synthetic-face uncanny-valley.

Intended capability gate: ``SEMANTIC_SCENE_V1`` plus a signed matching
``model_pack_hash``. The stable capability registry intentionally does not
advertise this gate before the browser media-wire and physical quality gates
are complete.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md §4.8 (Semantic Engine)
"""

from __future__ import annotations

import hashlib
import struct
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import numpy as np


WIRE_MAGIC = b"OLSSC1\x00\x00"   # 8 bytes
WIRE_VERSION = 1


# ---------------------------------------------------------------------------
# Wire format
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SceneFrame:
    """One semantic scene frame on the wire."""

    regime_id: int                      # 0..4 (5 regimes — fits in 3 bits)
    n_objects: int                      # 0..6
    residual_indices: tuple[int, ...]   # MAX_OBJECTS*5 + 8 = 38 dims
    residual_values_q: tuple[int, ...]  # quantized int8 signed -128..127

    def to_bytes(self) -> bytes:
        # Encoding:
        # byte 0: (regime_id << 5) | (n_objects << 2) | (n_residual_hi)
        # byte 1: n_residual_lo (so total residual count up to 256)
        # then n_residual × (1 byte index + 1 byte signed value)
        b = bytearray()
        n = len(self.residual_indices)
        assert n == len(self.residual_values_q)
        assert 0 <= self.regime_id <= 7
        assert 0 <= self.n_objects <= 6
        assert 0 <= n <= 38
        b.append(((self.regime_id & 0x07) << 5) | ((self.n_objects & 0x07) << 2) | ((n >> 4) & 0x03))
        b.append(n & 0xff)
        for idx, val in zip(self.residual_indices, self.residual_values_q):
            b.append(idx & 0xff)
            b.append((val + 128) & 0xff)  # bias to unsigned for byte serialization
        return bytes(b)

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> tuple["SceneFrame", int]:
        if len(data) < offset + 2:
            raise ValueError("scene frame truncated at header")
        h = data[offset]
        regime_id = (h >> 5) & 0x07
        n_objects = (h >> 2) & 0x07
        n_hi = h & 0x03
        n_lo = data[offset + 1]
        n = (n_hi << 4) | (n_lo & 0xff)
        body_len = n * 2
        if len(data) < offset + 2 + body_len:
            raise ValueError("scene frame truncated at body")
        indices = []
        values = []
        for i in range(n):
            indices.append(data[offset + 2 + i * 2])
            values.append(data[offset + 2 + i * 2 + 1] - 128)
        return (
            cls(
                regime_id=regime_id,
                n_objects=n_objects,
                residual_indices=tuple(indices),
                residual_values_q=tuple(values),
            ),
            2 + body_len,
        )


# ---------------------------------------------------------------------------
# Quantization — int8 with fixed scale for normalised scene features
# ---------------------------------------------------------------------------

# Scene features are in roughly [-1, 1] (positions / velocities are
# unit-normalized at the dataset builder). int8 with scale 100 covers
# ±1.27 with 0.01 resolution — plenty for box positions / sizes.
_SCENE_SCALE = 100.0


def _quantize_scene(v: float) -> int:
    q = int(round(v * _SCENE_SCALE))
    return max(-128, min(127, q))


def _dequantize_scene(q: int) -> float:
    return q / _SCENE_SCALE


def _top_k_scene_residual(
    actual: np.ndarray, predicted: np.ndarray, k: int = 8,
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Return (indices, quantized) for the K largest-magnitude
    residual dims."""
    n_dims = min(len(actual), len(predicted), 38)
    residual = actual[:n_dims] - predicted[:n_dims]
    abs_res = np.abs(residual)
    k_eff = min(k, n_dims)
    idx = np.argpartition(abs_res, -k_eff)[-k_eff:]
    idx = np.sort(idx)
    indices = tuple(int(i) for i in idx)
    values = tuple(_quantize_scene(float(residual[i])) for i in idx)
    return indices, values


# ---------------------------------------------------------------------------
# Encoder
# ---------------------------------------------------------------------------

class SemanticSceneEncoder:
    """Encode a stream of 38-dim scene features into sparse residuals.

    The caller supplies scene features per video frame; the encoder
    runs the scene predictor in lockstep with the receiver and emits
    only the residual + regime tag.

    Stateful — predictor hidden state carries across calls.
    Thread-safe.
    """

    FRAME_RATE_HZ = 10
    RESIDUAL_K = 8
    FEATURE_DIM = 38

    def __init__(self, ckpt_path: Path, device: str = "cpu") -> None:
        from one_link.ml.onnx_oracles import load_scene_oracle
        self._lock = threading.Lock()
        ckpt_path = Path(ckpt_path)
        if ckpt_path.is_dir():
            self._oracle = load_scene_oracle(ckpt_path)
        elif ckpt_path.suffix == ".onnx":
            self._oracle = load_scene_oracle(ckpt_path.parent)
        else:
            from one_link.ml.trained_scene_oracle import TrainedSceneOracle
            self._oracle = TrainedSceneOracle(ckpt_path, device=device)
        self._is_torch_backed = type(self._oracle).__name__ == "TrainedSceneOracle"
        self._prev_features: Optional[np.ndarray] = None

    def reset(self) -> None:
        with self._lock:
            self._oracle._hidden = None
            self._prev_features = None

    def _call_oracle(self, x_np: np.ndarray):
        """Invoke the predictor against either backend with the right
        input shape. Returns (pred, regime, hn) as numpy arrays."""
        if self._is_torch_backed:
            import torch
            x = torch.from_numpy(x_np.astype(np.float32))
            with torch.no_grad():
                pred, regime, hn = self._oracle.model(
                    x, h0=self._oracle._hidden,
                )
                self._oracle._hidden = hn.detach()
            return (
                pred.cpu().numpy(),
                regime.cpu().numpy(),
                hn.detach(),
            )
        # ONNX backend
        pred, regime, hn = self._oracle.model(
            x_np, h0=self._oracle._hidden,
        )
        self._oracle._hidden = hn.numpy() if hasattr(hn, "numpy") else hn
        return (
            pred.numpy() if hasattr(pred, "numpy") else pred,
            regime.numpy() if hasattr(regime, "numpy") else regime,
            self._oracle._hidden,
        )

    def encode_features(self, features: np.ndarray) -> list[SceneFrame]:
        """Encode an (n_frames, 38) scene feature array."""
        with self._lock:
            features = features.astype(np.float32)
            if features.ndim == 1:
                features = features.reshape(1, -1)
            assert features.shape[1] == self.FEATURE_DIM
            frames: list[SceneFrame] = []
            for t in range(features.shape[0]):
                actual = features[t]
                x_np = actual.astype(np.float32).reshape(1, 1, -1)
                pred_np, regime_np, _ = self._call_oracle(x_np)
                if self._prev_features is None:
                    # First frame — no prior prediction; send everything
                    # as residual against zero.
                    predicted = np.zeros_like(actual)
                else:
                    predicted = pred_np[0, 0]
                regime_id = int(np.argmax(regime_np, axis=-1).item())
                indices, values = _top_k_scene_residual(
                    actual, predicted, k=self.RESIDUAL_K,
                )
                n_objects = int(round(actual[0]))
                n_objects = max(0, min(6, n_objects))
                frames.append(SceneFrame(
                    regime_id=regime_id,
                    n_objects=n_objects,
                    residual_indices=indices,
                    residual_values_q=values,
                ))
                self._prev_features = actual
            return frames


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------

class SemanticSceneDecoder:
    """Reconstructs the scene feature stream + regime tags from wire
    frames. Runs the SAME scene predictor on the receiver so the
    residual decoding produces (predicted + residual) ≈ actual."""

    FEATURE_DIM = 38

    def __init__(self, ckpt_path: Path, device: str = "cpu") -> None:
        from one_link.ml.onnx_oracles import load_scene_oracle
        self._lock = threading.Lock()
        ckpt_path = Path(ckpt_path)
        if ckpt_path.is_dir():
            self._oracle = load_scene_oracle(ckpt_path)
        elif ckpt_path.suffix == ".onnx":
            self._oracle = load_scene_oracle(ckpt_path.parent)
        else:
            from one_link.ml.trained_scene_oracle import TrainedSceneOracle
            self._oracle = TrainedSceneOracle(ckpt_path, device=device)
        self._is_torch_backed = type(self._oracle).__name__ == "TrainedSceneOracle"
        self._reconstructed: Optional[np.ndarray] = None

    def reset(self) -> None:
        with self._lock:
            self._oracle._hidden = None
            self._reconstructed = None

    def _call_oracle(self, x_np: np.ndarray):
        """Run the predictor against either backend; return pred_np."""
        if self._is_torch_backed:
            import torch
            x = torch.from_numpy(x_np.astype(np.float32))
            with torch.no_grad():
                pred, _, hn = self._oracle.model(
                    x, h0=self._oracle._hidden,
                )
                self._oracle._hidden = hn.detach()
            return pred.cpu().numpy()
        pred, _, hn = self._oracle.model(x_np, h0=self._oracle._hidden)
        self._oracle._hidden = hn.numpy() if hasattr(hn, "numpy") else hn
        return pred.numpy() if hasattr(pred, "numpy") else pred

    def decode_frames(self, frames: list[SceneFrame]) -> tuple[np.ndarray, list[int]]:
        """Decode wire frames into (features, regime_ids). features is
        (T, 38) float32."""
        with self._lock:
            out_features = np.zeros((len(frames), self.FEATURE_DIM), dtype=np.float32)
            regime_ids: list[int] = []
            for t, f in enumerate(frames):
                if self._reconstructed is None:
                    predicted = np.zeros(self.FEATURE_DIM, dtype=np.float32)
                else:
                    x_np = self._reconstructed.astype(np.float32).reshape(1, 1, -1)
                    predicted = self._call_oracle(x_np)[0, 0]
                # Apply residual to the prediction.
                reconstructed = predicted.copy()
                for idx, val_q in zip(f.residual_indices, f.residual_values_q):
                    if 0 <= idx < self.FEATURE_DIM:
                        reconstructed[idx] = predicted[idx] + _dequantize_scene(val_q)
                out_features[t] = reconstructed
                regime_ids.append(f.regime_id)
                self._reconstructed = reconstructed
            return out_features, regime_ids


# ---------------------------------------------------------------------------
# Wire packet envelope
# ---------------------------------------------------------------------------

def pack_packet(frames: list[SceneFrame]) -> bytes:
    body = b"".join(f.to_bytes() for f in frames)
    return WIRE_MAGIC + struct.pack("!BH", WIRE_VERSION, len(frames)) + body


def unpack_packet(data: bytes) -> list[SceneFrame]:
    if len(data) < len(WIRE_MAGIC) + 3:
        raise ValueError("scene packet too short")
    if data[:len(WIRE_MAGIC)] != WIRE_MAGIC:
        raise ValueError("bad magic")
    version, count = struct.unpack(
        "!BH", data[len(WIRE_MAGIC):len(WIRE_MAGIC) + 3],
    )
    if version != WIRE_VERSION:
        raise ValueError(f"unsupported scene version {version}")
    pos = len(WIRE_MAGIC) + 3
    frames: list[SceneFrame] = []
    for _ in range(count):
        if pos >= len(data):
            raise ValueError("scene packet truncated mid-frame")
        f, consumed = SceneFrame.from_bytes(data, offset=pos)
        frames.append(f)
        pos += consumed
    if pos != len(data):
        raise ValueError(
            f"scene packet has {len(data) - pos} trailing bytes",
        )
    return frames


def model_pack_hash(ckpt_path: Path) -> str:
    h = hashlib.sha256()
    with Path(ckpt_path).open("rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def estimate_bitrate_bps(
    frames: list[SceneFrame], frame_rate_hz: float = 10.0,
) -> float:
    if not frames:
        return 0.0
    total_bytes = sum(len(f.to_bytes()) for f in frames)
    duration_s = len(frames) / frame_rate_hz
    return (total_bytes * 8) / duration_s


# ---------------------------------------------------------------------------
# Plain-language scene labels — doctrine §3.6.c
# ---------------------------------------------------------------------------

REGIME_LABELS_UI = {
    0: "still",
    1: "moving",
    2: "camera moving",
    3: "scene changing",
    4: "scene changed",
}


def regime_to_user_label(regime_id: int) -> str:
    return REGIME_LABELS_UI.get(regime_id, "still")
