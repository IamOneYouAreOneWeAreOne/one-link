"""Research-only ML substrate for preview semantic codecs.

Sources: harvested from `OneField Mesh/tools/ml/` (Apr 2026), where
the models were trained on LibriSpeech. The voice predictor here is
the v3_librispeech checkpoint — 88% predictive accuracy on
validation, 97% on simple Klatt-synth utterances.

Modules:
  - mfcc: production MFCC extractor (scipy + numpy, no torchaudio)
  - voice_predictor: 60-dim MFCC + 19-phoneme GRU predictor
  - trained_voice_oracle: stateful online inference wrapper
  - speech_synth: Klatt-style formant synthesizer for the receiver
    reconstruction path

This package is not imported or advertised by the stable daemon. Stable
artifacts omit it; engineering builds must opt in with
``scripts/build_binary.py --include-preview-ml``. The opt-in bundle contains
the ONNX checkpoints only, not the torch training stack.
"""

from __future__ import annotations

import sys
from pathlib import Path


_KNOWN_PREVIEW_MODELS = frozenset({
    "voice_predictor_v3_librispeech",
    "scene_predictor_v1",
})


def preview_model_dir(model_name: str) -> Path:
    """Resolve a validated preview model directory in source/frozen layouts.

    This is an engineering API, not capability activation. It avoids depending
    on the process working directory, which made previously bundled assets
    unreachable in PyInstaller's ``_MEIPASS`` data tree.
    """
    if model_name not in _KNOWN_PREVIEW_MODELS:
        raise ValueError(f"unknown preview model: {model_name!r}")

    roots: list[Path] = []
    bundle_root = getattr(sys, "_MEIPASS", None)
    if bundle_root:
        roots.append(Path(bundle_root) / "assets" / "models")
    roots.append(Path(__file__).resolve().parents[3] / "assets" / "models")

    required = ("checkpoint.onnx", "config.json")
    for root in roots:
        candidate = root / model_name
        if all((candidate / name).is_file() for name in required):
            return candidate
    checked = ", ".join(str(root / model_name) for root in roots)
    raise FileNotFoundError(
        f"preview model {model_name!r} is unavailable; checked {checked}"
    )


__all__ = ["preview_model_dir"]
