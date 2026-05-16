"""Adapter: use the trained scene predictor as the video accuracy oracle.

Loads models/scene_predictor_v1 and exposes per-frame accuracy plus
next-regime prediction to video_e2e_sim.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import numpy as np
import torch

from one_link.ml.scene_dataset import FEATURE_DIM, REGIME_NAMES  # noqa: E402
from one_link.ml.scene_predictor import (  # noqa: E402
    ScenePredictor, ScenePredictorConfig, compute_scene_accuracy,
)


class TrainedSceneOracle:
    def __init__(self, ckpt_path: Path, device: str = "auto",
                 sigma: float = 1.0):
        ckpt_path = Path(ckpt_path)
        if not ckpt_path.exists():
            raise FileNotFoundError(
                f"scene-predictor checkpoint not found at {ckpt_path}; "
                f"train with `python tools/ml/train_scene_model.py` first"
            )
        requested_device = device
        if device == "auto":
            device = "cuda" if torch.cuda.is_available() else "cpu"
        elif device == "cuda" and not torch.cuda.is_available():
            import warnings as _warnings
            _warnings.warn(
                "CUDA requested for scene oracle but torch.cuda.is_available() "
                "is False; falling back to CPU. Inference will be slower.",
                RuntimeWarning, stacklevel=2,
            )
            device = "cpu"
        self.device = device
        self.requested_device = requested_device
        try:
            ckpt = torch.load(ckpt_path, map_location=device, weights_only=True)
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(
                f"scene checkpoint {ckpt_path} is corrupted or incompatible "
                f"({type(e).__name__}: {e}); retrain or restore from git"
            ) from e
        if "config" not in ckpt or "state_dict" not in ckpt:
            raise RuntimeError(
                f"scene checkpoint {ckpt_path} missing required keys"
            )
        cfg = ScenePredictorConfig(**ckpt["config"])
        self.model = ScenePredictor(cfg).to(device).eval()
        try:
            self.model.load_state_dict(ckpt["state_dict"])
        except RuntimeError as e:
            raise RuntimeError(
                f"scene checkpoint {ckpt_path} architecture mismatch: {e}"
            ) from e
        self.cfg = cfg
        self.sigma = sigma
        self._hidden: Optional[torch.Tensor] = None

        # Forward-pass smoke test at load time.
        try:
            dummy = torch.zeros((1, 1, cfg.feature_dim),
                                dtype=torch.float32, device=device)
            with torch.no_grad():
                self.model(dummy)
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(
                f"scene checkpoint forward-pass smoke test failed: {e}"
            ) from e

    def reset(self) -> None:
        self._hidden = None

    def predict_per_frame_accuracy(self, features: np.ndarray) -> np.ndarray:
        """features: (T, FEATURE_DIM). Returns (T-1,) of accuracies."""
        self.reset()
        T = features.shape[0]
        if T < 2:
            return np.zeros(0, dtype=np.float32)
        x = torch.from_numpy(features[:-1].astype(np.float32)).to(self.device)
        x = x.view(1, T - 1, -1)
        with torch.no_grad():
            pred, _, _ = self.model(x)
        pred_np = pred.cpu().numpy()[0]
        targets = features[1:]
        err = (targets - pred_np) ** 2
        per_frame_err = np.mean(err, axis=-1)
        p = np.exp(-per_frame_err / (2.0 * self.sigma * self.sigma))
        return p.astype(np.float32)

    def predict_regimes(self, features: np.ndarray) -> np.ndarray:
        """features: (T, FEATURE_DIM). Returns (T,) argmax regime labels."""
        if features.shape[0] == 0:
            return np.zeros(0, dtype=np.int16)
        x = torch.from_numpy(features.astype(np.float32)).to(self.device)
        x = x.view(1, features.shape[0], -1)
        with torch.no_grad():
            _, logits, _ = self.model(x)
        return logits.argmax(dim=-1).cpu().numpy()[0].astype(np.int16)


def _selftest() -> int:
    ckpt = REPO_ROOT / "models" / "scene_predictor_v1" / "checkpoint.pt"
    if not ckpt.exists():
        print(f"trained_scene_oracle selftest: SKIP ({ckpt} missing)"); return 0
    oracle = TrainedSceneOracle(ckpt)
    from ml.scene_dataset import build_scene_sequence
    feats, labels = build_scene_sequence(120, seed=999)
    p = oracle.predict_per_frame_accuracy(feats)
    assert p.shape == (119,)
    mean_p = float(p.mean())
    assert mean_p > 0.85, f"oracle p too low: {mean_p}"

    regimes = oracle.predict_regimes(feats)
    assert regimes.shape == (120,)
    print(f"trained_scene_oracle selftest: OK (mean_p={mean_p:.4f})")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    print(__doc__)
