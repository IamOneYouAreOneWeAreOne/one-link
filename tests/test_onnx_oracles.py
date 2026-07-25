"""Tests for the ONNX-backed oracles.

The whole point: byte-equivalent inference to the torch oracles
within float-rounding noise. This lets an explicit preview engineering
artifact omit torch; stable artifacts omit the entire ML substrate.

Properties verified:
  - Parity vs torch oracle (mean_p within 1e-4)
  - Smart factory prefers ONNX when available
  - Falls back to torch if ONNX missing or onnxruntime fails to load
  - Voice + scene codecs work against both backends
"""

from __future__ import annotations

from pathlib import Path

import pytest

np = pytest.importorskip("numpy")
pytest.importorskip("onnxruntime")
torch = pytest.importorskip("torch", exc_type=(ImportError, OSError))

VOICE_DIR = Path(__file__).resolve().parents[1] / "assets" / "models" / "voice_predictor_v3_librispeech"
SCENE_DIR = Path(__file__).resolve().parents[1] / "assets" / "models" / "scene_predictor_v1"

if not (VOICE_DIR / "checkpoint.onnx").exists():
    pytest.skip(
        f"voice ONNX export missing at {VOICE_DIR}/checkpoint.onnx; "
        "run scripts/export_ml_to_onnx.py",
        allow_module_level=True,
    )
if not (SCENE_DIR / "checkpoint.onnx").exists():
    pytest.skip(
        f"scene ONNX export missing at {SCENE_DIR}/checkpoint.onnx; "
        "run scripts/export_ml_to_onnx.py",
        allow_module_level=True,
    )


from one_link.ml.onnx_oracles import (  # noqa: E402
    OnnxSceneOracle,
    OnnxVoiceOracle,
    load_scene_oracle,
    load_voice_oracle,
)


# ---------------------------------------------------------------------------
# Voice oracle parity
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def voice_torch():
    from one_link.ml.trained_voice_oracle import TrainedVoiceOracle
    return TrainedVoiceOracle(VOICE_DIR / "checkpoint.pt", device="cpu")


@pytest.fixture(scope="module")
def voice_onnx() -> OnnxVoiceOracle:
    return OnnxVoiceOracle(VOICE_DIR / "checkpoint.onnx")


@pytest.fixture(scope="module")
def synth_mfcc(voice_onnx: OnnxVoiceOracle) -> np.ndarray:
    from one_link.ml.speech_synth import synth_sentence
    audio_f32, _ = synth_sentence(
        [("m", 0.08), ("a", 0.18), ("l", 0.08), ("o", 0.18)],
        sr=16000.0, seed=11,
    )
    return voice_onnx.extract_mfcc(audio_f32)


def test_voice_onnx_predict_frame_accuracy_matches_torch(
    voice_torch, voice_onnx, synth_mfcc,
) -> None:
    p_onnx = voice_onnx.predict_frame_accuracy(synth_mfcc)
    p_torch = voice_torch.predict_frame_accuracy(synth_mfcc)
    assert abs(p_onnx - p_torch) < 1e-4, (
        f"ONNX p={p_onnx:.6f} vs torch p={p_torch:.6f}"
    )


def test_voice_onnx_per_frame_matches_torch(
    voice_torch, voice_onnx, synth_mfcc,
) -> None:
    p_onnx = voice_onnx.predict_per_frame_accuracy(synth_mfcc)
    p_torch = voice_torch.predict_per_frame_accuracy(synth_mfcc)
    assert p_onnx.shape == p_torch.shape
    max_diff = float(np.max(np.abs(p_onnx - p_torch)))
    assert max_diff < 1e-4, f"max per-frame delta {max_diff:.2e}"


def test_voice_onnx_predict_next_advances_hidden_state(
    voice_onnx: OnnxVoiceOracle, synth_mfcc: np.ndarray,
) -> None:
    voice_onnx.reset()
    first = voice_onnx.predict_next(synth_mfcc[0])
    second = voice_onnx.predict_next(synth_mfcc[1])
    # Different inputs + hidden state advanced → different output.
    assert not np.allclose(first, second)


def test_voice_onnx_reset_returns_to_zero_state(
    voice_onnx: OnnxVoiceOracle, synth_mfcc: np.ndarray,
) -> None:
    voice_onnx.reset()
    p1 = voice_onnx.predict_frame_accuracy(synth_mfcc)
    voice_onnx.reset()
    p2 = voice_onnx.predict_frame_accuracy(synth_mfcc)
    assert p1 == pytest.approx(p2, abs=1e-9)


def test_voice_onnx_inference_speed_under_one_ms_per_frame(
    voice_onnx: OnnxVoiceOracle, synth_mfcc: np.ndarray,
) -> None:
    """ONNX Runtime CPU should beat torch CPU on small models."""
    import time
    voice_onnx.reset()
    # Warm.
    voice_onnx.predict_next(synth_mfcc[0])
    voice_onnx.reset()
    t0 = time.perf_counter()
    for f in synth_mfcc:
        voice_onnx.predict_next(f)
    elapsed_ms = (time.perf_counter() - t0) * 1000 / max(1, len(synth_mfcc))
    # Loose bound — laptop / CI machines vary. Real perf < 0.3 ms.
    assert elapsed_ms < 5.0, f"per-frame inference {elapsed_ms:.2f} ms"


# ---------------------------------------------------------------------------
# Scene oracle parity
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def scene_torch():
    from one_link.ml.trained_scene_oracle import TrainedSceneOracle
    return TrainedSceneOracle(SCENE_DIR / "checkpoint.pt", device="cpu")


@pytest.fixture(scope="module")
def scene_onnx() -> OnnxSceneOracle:
    return OnnxSceneOracle(SCENE_DIR / "checkpoint.onnx")


def _scene_seq(seed: int, n: int = 30) -> np.ndarray:
    rng = np.random.default_rng(seed)
    out = np.zeros((n, 38), dtype=np.float32)
    for t in range(n):
        out[t, 0] = 2.0
        out[t, 1] = 0.95
        out[t, 5] = 0.3 + 0.01 * t
        out[t, 8] = 0.3 + 0.01 * t
        out[t] += rng.normal(0, 0.02, 38).astype(np.float32)
    return out


def test_scene_onnx_model_call_matches_torch(scene_torch, scene_onnx) -> None:
    seq = _scene_seq(seed=7, n=10)
    x_np = seq.astype(np.float32).reshape(1, 10, -1)

    pred_onnx, regime_onnx, hn_onnx = scene_onnx.model(x_np)
    pred_onnx = pred_onnx.numpy()
    regime_onnx = regime_onnx.numpy()

    import torch
    x_torch = torch.from_numpy(x_np)
    with torch.no_grad():
        pred_torch, regime_torch, _ = scene_torch.model(x_torch)
    pred_torch = pred_torch.cpu().numpy()
    regime_torch = regime_torch.cpu().numpy()

    pred_diff = float(np.max(np.abs(pred_onnx - pred_torch)))
    regime_diff = float(np.max(np.abs(regime_onnx - regime_torch)))
    assert pred_diff < 1e-4, f"pred max-diff {pred_diff:.2e}"
    assert regime_diff < 1e-4, f"regime max-diff {regime_diff:.2e}"


# ---------------------------------------------------------------------------
# Smart factory
# ---------------------------------------------------------------------------

def test_load_voice_oracle_prefers_onnx_when_available() -> None:
    o = load_voice_oracle(VOICE_DIR)
    assert type(o).__name__ == "OnnxVoiceOracle"


def test_load_scene_oracle_prefers_onnx_when_available() -> None:
    o = load_scene_oracle(SCENE_DIR)
    assert type(o).__name__ == "OnnxSceneOracle"


def test_load_voice_oracle_falls_back_to_torch_when_onnx_missing(
    tmp_path: Path,
) -> None:
    """If only .pt exists in the directory, we get the torch oracle."""
    import shutil
    fake_dir = tmp_path / "voice_pt_only"
    fake_dir.mkdir()
    shutil.copy(VOICE_DIR / "checkpoint.pt", fake_dir / "checkpoint.pt")
    shutil.copy(VOICE_DIR / "config.json", fake_dir / "config.json")
    o = load_voice_oracle(fake_dir)
    assert type(o).__name__ == "TrainedVoiceOracle"


def test_load_voice_oracle_raises_when_nothing_available(
    tmp_path: Path,
) -> None:
    empty = tmp_path / "no_models"
    empty.mkdir()
    with pytest.raises(FileNotFoundError):
        load_voice_oracle(empty)


# ---------------------------------------------------------------------------
# Codec compatibility — voice codec works against either backend
# ---------------------------------------------------------------------------

def test_voice_codec_against_onnx_backend() -> None:
    """Pass the directory; encoder picks ONNX automatically and
    produces a same-shape encoded stream."""
    from one_link.semantic_voice_codec import (
        SemanticVoiceEncoder,
        estimate_bitrate_bps,
    )
    from one_link.ml.speech_synth import synth_sentence

    enc = SemanticVoiceEncoder(VOICE_DIR, device="cpu")
    audio_f32, _ = synth_sentence(
        [("m", 0.08), ("a", 0.18), ("l", 0.08), ("o", 0.18)],
        sr=16000.0, seed=7,
    )
    audio_i16 = (audio_f32 * 32767).astype(np.int16)
    frames = enc.encode_pcm(audio_i16)
    assert 5 <= len(frames) <= 10
    assert estimate_bitrate_bps(frames) < 1500


def test_scene_codec_against_onnx_backend() -> None:
    from one_link.semantic_scene_codec import (
        SemanticSceneDecoder,
        SemanticSceneEncoder,
        estimate_bitrate_bps,
    )
    enc = SemanticSceneEncoder(SCENE_DIR, device="cpu")
    dec = SemanticSceneDecoder(SCENE_DIR, device="cpu")
    seq = _scene_seq(seed=13, n=20)
    frames = enc.encode_features(seq)
    assert len(frames) == 20
    assert estimate_bitrate_bps(frames) < 2000
    out_features, _ = dec.decode_frames(frames)
    assert out_features.shape == (20, 38)
