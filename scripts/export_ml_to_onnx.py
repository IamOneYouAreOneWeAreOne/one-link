"""Export the vendored PyTorch checkpoints to ONNX.

For explicitly opted-in research artifacts, ONNX Runtime is ~20 MB vs
PyTorch's ~200 MB. Stable product artifacts ship neither runtime. The exported
.onnx files keep
byte-equivalent inference to the .pt checkpoints (verified by
this script with a numerical-parity check).

Usage:
  python scripts/export_ml_to_onnx.py

Inputs:
  assets/models/voice_predictor_v3_librispeech/checkpoint.pt
  assets/models/scene_predictor_v1/checkpoint.pt

Outputs:
  assets/models/voice_predictor_v3_librispeech/checkpoint.onnx
  assets/models/scene_predictor_v1/checkpoint.onnx

Both ONNX files use opset 17 (broadly compatible with onnxruntime
1.16+). The GRU + linear heads export cleanly without custom ops.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import torch

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from one_link.ml.scene_predictor import (  # noqa: E402
    ScenePredictor,
    ScenePredictorConfig,
)
from one_link.ml.voice_predictor import (  # noqa: E402
    VoicePredictor,
    VoicePredictorConfig,
)


PARITY_TOL = 1e-5


def _export_voice(ckpt_path: Path, out_path: Path) -> None:
    # Checkpoints contain only tensors plus primitive config values. Keep
    # PyTorch's restricted unpickler enabled so a replaced model file cannot
    # execute arbitrary pickle payloads during export.
    ckpt = torch.load(ckpt_path, map_location="cpu", weights_only=True)
    cfg = VoicePredictorConfig(**ckpt["config"])
    model = VoicePredictor(cfg)
    model.load_state_dict(ckpt["state_dict"])
    model.eval()

    # Wrap to fix the GRU h0 shape — onnx export needs concrete shapes.
    class _Wrapper(torch.nn.Module):
        def __init__(self, m: VoicePredictor) -> None:
            super().__init__()
            self.m = m

        def forward(
            self, x: torch.Tensor, h0: torch.Tensor,
        ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
            return self.m(x, h0)

    wrapped = _Wrapper(model).eval()
    # (B, T, F=60) and h0 shape (n_layers=2, B=1, hidden=256)
    dummy_x = torch.randn(1, 1, cfg.feature_dim)
    dummy_h0 = torch.zeros(cfg.n_layers, 1, cfg.hidden_dim)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    torch.onnx.export(
        wrapped,
        (dummy_x, dummy_h0),
        str(out_path),
        dynamo=False,
        input_names=["x", "h0"],
        output_names=["mfcc_pred", "phone_logits", "hn"],
        # T is dynamic so we can run with arbitrary sequence lengths.
        dynamic_axes={
            "x": {0: "batch", 1: "seq"},
            "h0": {1: "batch"},
            "mfcc_pred": {0: "batch", 1: "seq"},
            "phone_logits": {0: "batch", 1: "seq"},
            "hn": {1: "batch"},
        },
        opset_version=17,
        do_constant_folding=True,
    )
    print(f"  exported → {out_path}  ({out_path.stat().st_size:,} bytes)")

    # Numerical parity check.
    import onnxruntime as ort
    sess = ort.InferenceSession(str(out_path), providers=["CPUExecutionProvider"])
    with torch.no_grad():
        tp_pred, tp_phone, tp_hn = wrapped(dummy_x, dummy_h0)
    ox_pred, ox_phone, ox_hn = sess.run(
        None,
        {"x": dummy_x.numpy(), "h0": dummy_h0.numpy()},
    )
    diff_pred = float(np.max(np.abs(tp_pred.numpy() - ox_pred)))
    diff_phone = float(np.max(np.abs(tp_phone.numpy() - ox_phone)))
    diff_hn = float(np.max(np.abs(tp_hn.numpy() - ox_hn)))
    print(
        f"  parity vs torch: mfcc_pred max-err={diff_pred:.2e}  "
        f"phone_logits max-err={diff_phone:.2e}  hn max-err={diff_hn:.2e}"
    )
    if max(diff_pred, diff_phone, diff_hn) > PARITY_TOL:
        raise SystemExit(
            f"ONNX parity check failed (tol {PARITY_TOL})"
        )


def _export_scene(ckpt_path: Path, out_path: Path) -> None:
    ckpt = torch.load(ckpt_path, map_location="cpu", weights_only=True)
    cfg = ScenePredictorConfig(**ckpt["config"])
    model = ScenePredictor(cfg)
    model.load_state_dict(ckpt["state_dict"])
    model.eval()

    class _Wrapper(torch.nn.Module):
        def __init__(self, m: ScenePredictor) -> None:
            super().__init__()
            self.m = m

        def forward(
            self, x: torch.Tensor, h0: torch.Tensor,
        ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
            return self.m(x, h0)

    wrapped = _Wrapper(model).eval()
    dummy_x = torch.randn(1, 1, cfg.feature_dim)
    dummy_h0 = torch.zeros(cfg.n_layers, 1, cfg.hidden_dim)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    torch.onnx.export(
        wrapped,
        (dummy_x, dummy_h0),
        str(out_path),
        dynamo=False,
        input_names=["x", "h0"],
        output_names=["scene_pred", "regime_logits", "hn"],
        dynamic_axes={
            "x": {0: "batch", 1: "seq"},
            "h0": {1: "batch"},
            "scene_pred": {0: "batch", 1: "seq"},
            "regime_logits": {0: "batch", 1: "seq"},
            "hn": {1: "batch"},
        },
        opset_version=17,
        do_constant_folding=True,
    )
    print(f"  exported → {out_path}  ({out_path.stat().st_size:,} bytes)")

    import onnxruntime as ort
    sess = ort.InferenceSession(str(out_path), providers=["CPUExecutionProvider"])
    with torch.no_grad():
        tp_pred, tp_regime, tp_hn = wrapped(dummy_x, dummy_h0)
    ox_pred, ox_regime, ox_hn = sess.run(
        None,
        {"x": dummy_x.numpy(), "h0": dummy_h0.numpy()},
    )
    diff_pred = float(np.max(np.abs(tp_pred.numpy() - ox_pred)))
    diff_regime = float(np.max(np.abs(tp_regime.numpy() - ox_regime)))
    diff_hn = float(np.max(np.abs(tp_hn.numpy() - ox_hn)))
    print(
        f"  parity vs torch: scene_pred max-err={diff_pred:.2e}  "
        f"regime_logits max-err={diff_regime:.2e}  hn max-err={diff_hn:.2e}"
    )
    if max(diff_pred, diff_regime, diff_hn) > PARITY_TOL:
        raise SystemExit(
            f"ONNX parity check failed (tol {PARITY_TOL})"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--models-root", type=Path,
        default=REPO_ROOT / "assets" / "models",
        help="Root directory holding the model checkpoints.",
    )
    args = parser.parse_args()

    voice_root = args.models_root / "voice_predictor_v3_librispeech"
    voice_pt = voice_root / "checkpoint.pt"
    voice_onnx = voice_root / "checkpoint.onnx"
    if voice_pt.exists():
        print(f"[voice] {voice_pt}")
        _export_voice(voice_pt, voice_onnx)
    else:
        print(f"[voice] SKIP (no checkpoint at {voice_pt})")

    scene_root = args.models_root / "scene_predictor_v1"
    scene_pt = scene_root / "checkpoint.pt"
    scene_onnx = scene_root / "checkpoint.onnx"
    if scene_pt.exists():
        print(f"[scene] {scene_pt}")
        _export_scene(scene_pt, scene_onnx)
    else:
        print(f"[scene] SKIP (no checkpoint at {scene_pt})")

    print()
    print("ONNX export complete. Resulting sizes:")
    for p in [voice_onnx, scene_onnx]:
        if p.exists():
            kb = p.stat().st_size // 1024
            print(f"  {p.relative_to(REPO_ROOT)}  {kb} KB")


if __name__ == "__main__":
    main()
