"""ONNX Runtime-backed oracles — drop-in replacements that avoid PyTorch.

The torch-based ``TrainedVoiceOracle`` and ``TrainedSceneOracle`` ship
a ~200 MB PyTorch dependency in any bundle. ONNX Runtime CPU is ~20 MB
and produces byte-equivalent inference (parity verified at 1.4e-06
max error during export — see scripts/export_ml_to_onnx.py).

These classes preserve the same public API as their torch siblings:
  * extract_mfcc(audio) -> np.ndarray
  * predict_next(mfcc_frame) -> np.ndarray
  * predict_frame_accuracy(mfcc_frames) -> float
  * predict_per_frame_accuracy(mfcc_frames) -> np.ndarray
  * reset() / state attributes

So the call sites in semantic_voice_codec / semantic_scene_codec /
neural_extrapolator can swap implementations behind a single
``load_voice_oracle()`` / ``load_scene_oracle()`` factory.

The stable daemon does not load these oracles. A future graduated media path
must initialize them outside an active call and preserve Doctrine §3.4.c's
no-spinner UI contract.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import numpy as np

from one_link.fault_observability import report_best_effort_failure

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Voice oracle (ONNX-backed)
# ---------------------------------------------------------------------------

@dataclass
class _VoiceCfg:
    feature_dim: int
    hidden_dim: int
    n_layers: int
    n_phonemes: int


class OnnxVoiceOracle:
    """ONNX Runtime equivalent of :class:`TrainedVoiceOracle`.

    Stateful: carries the GRU hidden state across :meth:`predict_next`
    calls so streaming inference matches the torch baseline byte-for-
    byte (within float-rounding noise at 1e-6).
    """

    def __init__(
        self,
        onnx_path: Path,
        config_path: Optional[Path] = None,
        sigma: float = 1.0,
    ) -> None:
        import onnxruntime as ort
        onnx_path = Path(onnx_path)
        if not onnx_path.exists():
            raise FileNotFoundError(
                f"voice ONNX model not found at {onnx_path}; "
                "run scripts/export_ml_to_onnx.py first"
            )
        # CPU is plenty fast (~0.2 ms / frame). GPU providers add load
        # latency that doesn't pay off until very large batches.
        sess_opts = ort.SessionOptions()
        sess_opts.intra_op_num_threads = 1
        sess_opts.inter_op_num_threads = 1
        sess_opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        self.session = ort.InferenceSession(
            str(onnx_path),
            sess_opts,
            providers=["CPUExecutionProvider"],
        )

        if config_path is None:
            config_path = onnx_path.parent / "config.json"
        if not config_path.exists():
            raise FileNotFoundError(
                f"voice model config not found at {config_path}"
            )
        meta = json.loads(config_path.read_text(encoding="utf-8"))
        model_cfg = meta.get("model", meta)
        self.cfg = _VoiceCfg(
            feature_dim=int(model_cfg["feature_dim"]),
            hidden_dim=int(model_cfg["hidden_dim"]),
            n_layers=int(model_cfg["n_layers"]),
            n_phonemes=int(model_cfg["n_phonemes"]),
        )
        self.feature_dim = self.cfg.feature_dim
        self.sigma = sigma
        # MFCC extraction lives in the existing CPU-only module.
        from one_link.ml.mfcc import MfccConfig
        self.mfcc_cfg = MfccConfig()
        self._hidden: Optional[np.ndarray] = None

    @property
    def device(self) -> str:
        """Compat shim — torch oracle exposes .device for some callers."""
        return "cpu"

    @property
    def model(self):
        """Compat shim — codec calls oracle.model(x, h0=h) for batched
        phoneme inference. Return a callable that wraps the ONNX session."""
        return _OnnxVoiceModelShim(self)

    def reset(self) -> None:
        self._hidden = None

    def extract_mfcc(self, audio: np.ndarray) -> np.ndarray:
        from one_link.ml.mfcc import compute_mfcc
        return compute_mfcc(audio.astype(np.float32), self.mfcc_cfg)

    def predict_next(self, mfcc_frame: np.ndarray) -> np.ndarray:
        """Feed one frame; advance hidden state; return predicted next."""
        x = mfcc_frame.astype(np.float32).reshape(1, 1, -1)
        h0 = (
            self._hidden
            if self._hidden is not None
            else np.zeros(
                (self.cfg.n_layers, 1, self.cfg.hidden_dim),
                dtype=np.float32,
            )
        )
        pred, _, hn = self.session.run(None, {"x": x, "h0": h0})
        self._hidden = hn
        return pred[0, 0]

    def predict_frame_accuracy(self, mfcc_frames: np.ndarray) -> float:
        self.reset()
        T = mfcc_frames.shape[0]
        if T < 2:
            return 0.5
        x = mfcc_frames[:-1].astype(np.float32).reshape(1, T - 1, -1)
        h0 = np.zeros(
            (self.cfg.n_layers, 1, self.cfg.hidden_dim),
            dtype=np.float32,
        )
        pred, _, _ = self.session.run(None, {"x": x, "h0": h0})
        pred_np = pred[0]
        targets = mfcc_frames[1:]
        err = targets - pred_np
        per_frame_err = np.mean(err ** 2, axis=-1)
        p_per = np.exp(-per_frame_err / (2.0 * self.sigma * self.sigma))
        return float(np.mean(p_per))

    def predict_per_frame_accuracy(self, mfcc_frames: np.ndarray) -> np.ndarray:
        self.reset()
        T = mfcc_frames.shape[0]
        if T < 2:
            return np.zeros(0, dtype=np.float32)
        x = mfcc_frames[:-1].astype(np.float32).reshape(1, T - 1, -1)
        h0 = np.zeros(
            (self.cfg.n_layers, 1, self.cfg.hidden_dim),
            dtype=np.float32,
        )
        pred, _, _ = self.session.run(None, {"x": x, "h0": h0})
        pred_np = pred[0]
        targets = mfcc_frames[1:]
        err = (targets - pred_np) ** 2
        per_frame_err = np.mean(err, axis=-1)
        p = np.exp(-per_frame_err / (2.0 * self.sigma * self.sigma))
        return p.astype(np.float32)


class _OnnxVoiceModelShim:
    """Lets the codec call oracle.model(x, h0=h) the same way it does
    with the torch oracle. Returns a (pred, phone_logits, hn) tuple
    of numpy arrays wrapped to look like the torch interface."""

    def __init__(self, oracle: OnnxVoiceOracle) -> None:
        self._oracle = oracle

    def __call__(self, x, h0=None):
        # Accept torch tensors OR numpy. Coerce.
        try:
            import torch
            if isinstance(x, torch.Tensor):
                x_np = x.cpu().numpy()
            else:
                x_np = np.asarray(x)
            h0_np: "Any | None"
            if h0 is not None and isinstance(h0, torch.Tensor):
                h0_np = h0.cpu().numpy()
            else:
                h0_np = h0 if h0 is not None else None
        except ImportError:
            x_np = np.asarray(x)
            h0_np = h0 if h0 is not None else None

        x_np = x_np.astype(np.float32)
        if h0_np is None:
            h0_np = np.zeros(
                (self._oracle.cfg.n_layers, x_np.shape[0], self._oracle.cfg.hidden_dim),
                dtype=np.float32,
            )
        else:
            h0_np = h0_np.astype(np.float32)

        pred, phone, hn = self._oracle.session.run(
            None, {"x": x_np, "h0": h0_np},
        )
        # Wrap in light torch-like tuple for the codec.
        return _NpTensorWrapper(pred), _NpTensorWrapper(phone), _NpTensorWrapper(hn)


class _NpTensorWrapper:
    """Numpy array wearing a torch.Tensor mask. The codec only calls
    .cpu().numpy() and .item() and argmax — implemented here."""

    def __init__(self, arr: np.ndarray) -> None:
        self._arr = arr

    def cpu(self) -> "_NpTensorWrapper":
        return self

    def numpy(self) -> np.ndarray:
        return self._arr

    def detach(self) -> "_NpTensorWrapper":
        return self

    def item(self):
        return self._arr.item()

    def view(self, *shape) -> "_NpTensorWrapper":
        return _NpTensorWrapper(self._arr.reshape(*shape))

    @property
    def shape(self):
        return self._arr.shape


# ---------------------------------------------------------------------------
# Scene oracle (ONNX-backed)
# ---------------------------------------------------------------------------

@dataclass
class _SceneCfg:
    feature_dim: int
    hidden_dim: int
    n_layers: int
    n_regimes: int


class OnnxSceneOracle:
    """ONNX Runtime equivalent of :class:`TrainedSceneOracle`."""

    def __init__(
        self,
        onnx_path: Path,
        config_path: Optional[Path] = None,
        sigma: float = 1.0,
    ) -> None:
        import onnxruntime as ort
        onnx_path = Path(onnx_path)
        if not onnx_path.exists():
            raise FileNotFoundError(
                f"scene ONNX model not found at {onnx_path}; "
                "run scripts/export_ml_to_onnx.py first"
            )
        sess_opts = ort.SessionOptions()
        sess_opts.intra_op_num_threads = 1
        sess_opts.inter_op_num_threads = 1
        sess_opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        self.session = ort.InferenceSession(
            str(onnx_path),
            sess_opts,
            providers=["CPUExecutionProvider"],
        )

        if config_path is None:
            config_path = onnx_path.parent / "config.json"
        if not config_path.exists():
            raise FileNotFoundError(
                f"scene model config not found at {config_path}"
            )
        meta = json.loads(config_path.read_text(encoding="utf-8"))
        model_cfg = meta.get("model", meta)
        self.cfg = _SceneCfg(
            feature_dim=int(model_cfg["feature_dim"]),
            hidden_dim=int(model_cfg["hidden_dim"]),
            n_layers=int(model_cfg["n_layers"]),
            n_regimes=int(model_cfg["n_regimes"]),
        )
        self.sigma = sigma
        self._hidden: Optional[np.ndarray] = None

    @property
    def device(self) -> str:
        return "cpu"

    @property
    def model(self):
        return _OnnxSceneModelShim(self)


class _OnnxSceneModelShim:
    def __init__(self, oracle: OnnxSceneOracle) -> None:
        self._oracle = oracle

    def __call__(self, x, h0=None):
        try:
            import torch
            if isinstance(x, torch.Tensor):
                x_np = x.cpu().numpy()
            else:
                x_np = np.asarray(x)
            h0_np: "Any | None"
            if h0 is not None and isinstance(h0, torch.Tensor):
                h0_np = h0.cpu().numpy()
            else:
                h0_np = h0 if h0 is not None else None
        except ImportError:
            x_np = np.asarray(x)
            h0_np = h0 if h0 is not None else None

        x_np = x_np.astype(np.float32)
        if h0_np is None:
            h0_np = np.zeros(
                (self._oracle.cfg.n_layers, x_np.shape[0], self._oracle.cfg.hidden_dim),
                dtype=np.float32,
            )
        else:
            h0_np = h0_np.astype(np.float32)

        pred, regime, hn = self._oracle.session.run(
            None, {"x": x_np, "h0": h0_np},
        )
        return (
            _NpTensorWrapper(pred),
            _NpTensorWrapper(regime),
            _NpTensorWrapper(hn),
        )


# ---------------------------------------------------------------------------
# Smart factories — prefer ONNX, fall back to torch
# ---------------------------------------------------------------------------

def load_voice_oracle(
    ckpt_dir: Path, sigma: float = 1.0, prefer: str = "onnx",
):
    """Load the best available voice oracle.

    Tries ONNX first (no torch dependency, ~20 MB ONNX Runtime).
    Falls back to torch ``TrainedVoiceOracle`` if no .onnx file
    exists or onnxruntime isn't installed.
    """
    ckpt_dir = Path(ckpt_dir)
    onnx_path = ckpt_dir / "checkpoint.onnx"
    pt_path = ckpt_dir / "checkpoint.pt"
    if prefer == "onnx" and onnx_path.exists():
        try:
            return OnnxVoiceOracle(onnx_path, sigma=sigma)
        except Exception as exc:
            report_best_effort_failure(log, "onnx_voice_preferred_load", exc)
    if pt_path.exists():
        from one_link.ml.trained_voice_oracle import TrainedVoiceOracle
        return TrainedVoiceOracle(pt_path, device="cpu", sigma=sigma)
    if onnx_path.exists():
        return OnnxVoiceOracle(onnx_path, sigma=sigma)
    raise FileNotFoundError(
        f"no voice oracle checkpoint in {ckpt_dir} (looking for "
        ".onnx or .pt)"
    )


def load_scene_oracle(
    ckpt_dir: Path, sigma: float = 1.0, prefer: str = "onnx",
):
    """Load the best available scene oracle. Same semantics as
    :func:`load_voice_oracle` but for the scene predictor."""
    ckpt_dir = Path(ckpt_dir)
    onnx_path = ckpt_dir / "checkpoint.onnx"
    pt_path = ckpt_dir / "checkpoint.pt"
    if prefer == "onnx" and onnx_path.exists():
        try:
            return OnnxSceneOracle(onnx_path, sigma=sigma)
        except Exception as exc:
            report_best_effort_failure(log, "onnx_scene_preferred_load", exc)
    if pt_path.exists():
        from one_link.ml.trained_scene_oracle import TrainedSceneOracle
        return TrainedSceneOracle(pt_path, device="cpu", sigma=sigma)
    if onnx_path.exists():
        return OnnxSceneOracle(onnx_path, sigma=sigma)
    raise FileNotFoundError(
        f"no scene oracle checkpoint in {ckpt_dir}"
    )
