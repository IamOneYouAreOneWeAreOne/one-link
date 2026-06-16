"""Adapter: use the trained voice predictor as the accuracy oracle.

Replaces tools/world_model_standin.py's audio regime classification
with real per-frame MFCC predictions from a trained VoicePredictor
checkpoint. The 'predictive accuracy' returned is the measured
1 - normalized-MSE value, not a hand-coded regime base.

Public:
    TrainedVoiceOracle(ckpt_path, device="auto")
      .predict_frame_accuracy(mfcc_history, mfcc_current) -> float
      .extract_mfcc(audio) -> np.ndarray

The oracle is stateful: it maintains a hidden GRU state across calls
so that predictions reflect the REAL online inference the voice.cl
decoder would do, not one-shot per-frame.

Deterministic: same checkpoint + same audio -> bit-identical accuracy.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import numpy as np
import torch

from one_link.ml.mfcc import MfccConfig, compute_mfcc  # noqa: E402
from one_link.ml.voice_predictor import (  # noqa: E402
    VoicePredictor, VoicePredictorConfig, compute_predictive_accuracy,
)


class TrainedVoiceOracle:
    """Wraps a trained VoicePredictor checkpoint for inference."""

    def __init__(self, ckpt_path: Path, device: str = "auto",
                 sigma: float = 1.0):
        ckpt_path = Path(ckpt_path)
        if not ckpt_path.exists():
            raise FileNotFoundError(
                f"voice-predictor checkpoint not found at {ckpt_path}; "
                f"train with `python tools/ml/train_voice_model.py` first"
            )
        requested_device = device
        if device == "auto":
            device = "cuda" if torch.cuda.is_available() else "cpu"
        elif device == "cuda" and not torch.cuda.is_available():
            import warnings as _warnings
            _warnings.warn(
                "CUDA requested for voice oracle but torch.cuda.is_available() "
                "is False; falling back to CPU. Inference will be ~10-20x slower. "
                "Install CUDA + matching PyTorch or pass device='cpu' to silence.",
                RuntimeWarning, stacklevel=2,
            )
            device = "cpu"
        self.device = device
        self.requested_device = requested_device
        try:
            ckpt = torch.load(ckpt_path, map_location=device, weights_only=True)
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(
                f"voice checkpoint {ckpt_path} is corrupted or incompatible "
                f"({type(e).__name__}: {e}); retrain or restore from git"
            ) from e
        if "config" not in ckpt or "state_dict" not in ckpt:
            raise RuntimeError(
                f"voice checkpoint {ckpt_path} missing required keys "
                f"(got {list(ckpt)!r}); expected 'config' + 'state_dict'"
            )
        cfg = VoicePredictorConfig(**ckpt["config"])
        self.model = VoicePredictor(cfg).to(device).eval()
        try:
            self.model.load_state_dict(ckpt["state_dict"])
        except RuntimeError as e:
            raise RuntimeError(
                f"voice checkpoint {ckpt_path} architecture mismatch: {e}"
            ) from e
        self.cfg = cfg
        self.sigma = sigma

        # MFCC config must match the training corpus exactly.
        model_dir = ckpt_path.parent
        mcfg_path = model_dir / "config.json"
        if mcfg_path.exists():
            meta = json.loads(mcfg_path.read_text())
            self.feature_dim = meta.get("feature_dim", cfg.feature_dim)
        else:
            self.feature_dim = cfg.feature_dim
        self.mfcc_cfg = MfccConfig()

        # Shape smoke-test: one fake frame must round-trip without a
        # RuntimeError. Catches feature-dim drift at LOAD time rather
        # than 1000 frames into a sim.
        try:
            import numpy as _np
            dummy = torch.from_numpy(
                _np.zeros((1, 1, cfg.feature_dim), dtype=_np.float32)
            ).to(device)
            with torch.no_grad():
                self.model(dummy)
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(
                f"voice checkpoint {ckpt_path} forward-pass sanity check "
                f"failed: {e}"
            ) from e

        # GRU hidden state for online inference
        self._hidden: Optional[torch.Tensor] = None
        self._prev_mfcc: Optional[np.ndarray] = None

    def reset(self) -> None:
        self._hidden = None
        self._prev_mfcc = None

    def extract_mfcc(self, audio: np.ndarray) -> np.ndarray:
        return compute_mfcc(audio.astype(np.float32), self.mfcc_cfg)

    def predict_next(self, mfcc_frame: np.ndarray) -> np.ndarray:
        """Feed one frame in, return the predicted NEXT frame."""
        x = torch.from_numpy(mfcc_frame.astype(np.float32)).to(self.device)
        x = x.view(1, 1, -1)  # (B=1, T=1, F)
        with torch.no_grad():
            pred, _, h = self.model(x, h0=self._hidden)
            self._hidden = h.detach()
        return pred.cpu().numpy()[0, 0]

    def predict_frame_accuracy(self, mfcc_frames: np.ndarray) -> float:
        """Given T MFCC frames, run the model online and return the
        mean predictive accuracy across the sequence. Matches what the
        coherence-prior decoder sees in a real deployment."""
        self.reset()
        T = mfcc_frames.shape[0]
        if T < 2:
            return 0.5
        preds = []
        for t in range(T - 1):
            preds.append(self.predict_next(mfcc_frames[t]))
        preds = np.stack(preds)
        targets = mfcc_frames[1:]
        return compute_predictive_accuracy(targets, preds, sigma=self.sigma)

    def predict_per_frame_accuracy(self, mfcc_frames: np.ndarray) -> np.ndarray:
        """Return per-frame accuracy (T-1 values). Used by the e2e sim to
        drive the coherence-prior feasibility check per frame."""
        self.reset()
        T = mfcc_frames.shape[0]
        if T < 2:
            return np.zeros(0, dtype=np.float32)
        # Run the whole sequence as a single batched forward pass for speed.
        x = torch.from_numpy(mfcc_frames[:-1].astype(np.float32)).to(self.device)
        x = x.view(1, T - 1, -1)
        with torch.no_grad():
            pred, _, _ = self.model(x)
        pred_np = pred.cpu().numpy()[0]
        targets = mfcc_frames[1:]
        err = (targets - pred_np) ** 2
        per_frame_err = np.mean(err, axis=-1)
        p = np.exp(-per_frame_err / (2.0 * self.sigma * self.sigma))
        return p.astype(np.float32)


# =============================================================================
# SELFTEST
# =============================================================================

def _selftest() -> int:
    import time
    from pathlib import Path
    # REPO_ROOT was used here but never defined (undefined-name bug
    # caught by the external audit / mypy — _selftest() would NameError).
    # This file is src/one_link/ml/trained_voice_oracle.py, so the repo
    # root is parents[3].
    REPO_ROOT = Path(__file__).resolve().parents[3]
    ckpt = REPO_ROOT / "models" / "voice_predictor_v1" / "checkpoint.pt"
    if not ckpt.exists():
        print(f"voice oracle selftest: SKIP (no checkpoint at {ckpt})")
        return 0
    oracle = TrainedVoiceOracle(ckpt)

    # Render a test utterance.
    from ml.speech_synth import synth_sentence
    audio, _ = synth_sentence(
        [("sil", 0.05), ("m", 0.05), ("a", 0.12), ("l", 0.06),
         ("o", 0.12), ("sil", 0.05)],
        sr=16000.0, seed=7,
    )
    mfcc = oracle.extract_mfcc(audio)
    assert mfcc.shape[0] >= 10

    t0 = time.time()
    p = oracle.predict_frame_accuracy(mfcc)
    t_ms = (time.time() - t0) * 1e3
    assert 0.0 < p <= 1.0
    # Real audio from the same distribution as training should hit
    # at least 0.80 given 96% test accuracy.
    assert p > 0.80, f"predictive accuracy surprisingly low: {p}"

    # Per-frame mode
    per_frame = oracle.predict_per_frame_accuracy(mfcc)
    assert per_frame.shape == (mfcc.shape[0] - 1,)
    assert (per_frame > 0.0).all()
    assert (per_frame <= 1.0).all()

    print(f"trained_voice_oracle selftest: OK  (mean_p={p:.4f}  frame time {t_ms:.1f}ms)")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    print(__doc__)
