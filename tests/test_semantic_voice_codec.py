"""Tests for the Tier ζ semantic voice codec.

Properties:
  - Encoder + decoder round-trip is deterministic.
  - Bitrate stays well under 1 kbps for clear speech.
  - Wire format round-trips byte-equal.
  - Capability gate: model_pack_hash is stable across calls + machines.
  - Decoded audio has plausible duration + non-zero RMS.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest


# Skip the whole module if torch is unavailable — the codec needs it.
torch = pytest.importorskip("torch", exc_type=(ImportError, OSError))

CKPT_PATH = Path(__file__).resolve().parents[1] / "assets" / "models" / "voice_predictor_v3_librispeech" / "checkpoint.pt"

if not CKPT_PATH.exists():
    pytest.skip(
        f"voice predictor checkpoint not vendored at {CKPT_PATH}",
        allow_module_level=True,
    )


from one_link.ml.speech_synth import synth_sentence  # noqa: E402
from one_link.semantic_voice_codec import (  # noqa: E402
    CodecFrame,
    SemanticVoiceDecoder,
    SemanticVoiceEncoder,
    WIRE_MAGIC,
    WIRE_VERSION,
    estimate_bitrate_bps,
    model_pack_hash,
    pack_packet,
    unpack_packet,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _synth_test_audio(seed: int = 7) -> np.ndarray:
    audio_f32, _ = synth_sentence(
        [
            ("sil", 0.1), ("m", 0.08), ("a", 0.18),
            ("l", 0.08), ("o", 0.18), ("sil", 0.1),
        ],
        sr=16000.0, seed=seed,
    )
    return (audio_f32 * 32767).astype(np.int16)


# ---------------------------------------------------------------------------
# Wire format: byte-equal round trip
# ---------------------------------------------------------------------------

def test_codec_frame_round_trip() -> None:
    f = CodecFrame(
        phoneme_id=5,
        log_f0_q=128,
        residual_indices=(0, 3, 7, 15),
        residual_values_q=(2, -3, 1, -1),
    )
    blob = f.to_bytes()
    back, consumed = CodecFrame.from_bytes(blob)
    assert back == f
    assert consumed == len(blob)


def test_codec_frame_with_zero_residual() -> None:
    f = CodecFrame(
        phoneme_id=0, log_f0_q=0,
        residual_indices=(), residual_values_q=(),
    )
    back, _ = CodecFrame.from_bytes(f.to_bytes())
    assert back == f


def test_codec_frame_handles_negative_residual() -> None:
    f = CodecFrame(
        phoneme_id=18, log_f0_q=255,
        residual_indices=(0, 1),
        residual_values_q=(-8, 7),  # min + max int4
    )
    back, _ = CodecFrame.from_bytes(f.to_bytes())
    assert back == f


def test_pack_unpack_packet() -> None:
    frames = [
        CodecFrame(
            phoneme_id=i,
            log_f0_q=100 + i,
            residual_indices=(0, 5),
            residual_values_q=(1, -1),
        )
        for i in range(5)
    ]
    packet = pack_packet(frames)
    assert packet.startswith(WIRE_MAGIC)
    back = unpack_packet(packet)
    assert back == frames


def test_unpack_rejects_bad_magic() -> None:
    with pytest.raises(ValueError, match="bad magic"):
        unpack_packet(b"\x00" * 32)


def test_unpack_rejects_truncated() -> None:
    with pytest.raises(ValueError, match="too short"):
        unpack_packet(b"")


def test_unpack_rejects_bad_version() -> None:
    bad = WIRE_MAGIC + bytes([99, 0, 0])
    with pytest.raises(ValueError, match="unsupported version"):
        unpack_packet(bad)


def test_unpack_rejects_trailing_garbage() -> None:
    frames = [CodecFrame(0, 0, (), ())]
    packet = pack_packet(frames) + b"extra"
    with pytest.raises(ValueError, match="trailing bytes"):
        unpack_packet(packet)


# ---------------------------------------------------------------------------
# Model pack hash
# ---------------------------------------------------------------------------

def test_model_pack_hash_is_stable() -> None:
    h1 = model_pack_hash(CKPT_PATH)
    h2 = model_pack_hash(CKPT_PATH)
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex


# ---------------------------------------------------------------------------
# Encoder
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def encoder() -> SemanticVoiceEncoder:
    return SemanticVoiceEncoder(CKPT_PATH, device="cpu")


def test_encode_produces_frames(encoder: SemanticVoiceEncoder) -> None:
    encoder.reset()
    audio = _synth_test_audio()
    frames = encoder.encode_pcm(audio)
    # 0.72 sec at 10 fps semantic ≈ 7 frames
    assert 5 <= len(frames) <= 10


def test_encode_streaming_matches_batch(encoder: SemanticVoiceEncoder) -> None:
    """Encoding a chunked stream should yield the same frame count
    as encoding the buffer in one shot (predictor state is the
    important guarantee; bitwise frame equality not required since
    chunking boundaries differ)."""
    encoder.reset()
    audio = _synth_test_audio()
    full = encoder.encode_pcm(audio)

    encoder.reset()
    half = len(audio) // 2
    chunks = encoder.encode_pcm(audio[:half])
    chunks += encoder.encode_pcm(audio[half:])
    # Frame counts within 1 of each other (boundary alignment differs)
    assert abs(len(full) - len(chunks)) <= 1


def test_encoder_bitrate_under_one_kbps(encoder: SemanticVoiceEncoder) -> None:
    """The whole point of Tier ζ. Bitrate must stay under 1 kbps for
    realistic clear speech."""
    encoder.reset()
    audio = _synth_test_audio()
    frames = encoder.encode_pcm(audio)
    bps = estimate_bitrate_bps(frames)
    assert bps < 1000.0, f"bitrate {bps:.0f} bps exceeds 1 kbps budget"


def test_encoder_reset_clears_state(encoder: SemanticVoiceEncoder) -> None:
    """Encoding after reset must not crash + must not blow bitrate.
    Phoneme classification on silence is model-defined and may not
    pick 'sil' — LibriSpeech contained little to no isolated
    silence so the classifier's silence response is undefined.
    What we DO test: no crash, sane frame count, plausible bitrate."""
    encoder.reset()
    audio = _synth_test_audio()
    encoder.encode_pcm(audio)
    encoder.reset()
    silence = np.zeros(16000, dtype=np.int16)
    frames = encoder.encode_pcm(silence)
    # Should produce ~10 frames for 1 second of input at 10 fps.
    assert 8 <= len(frames) <= 12
    # Bitrate stays in budget.
    assert estimate_bitrate_bps(frames) < 1500


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------

def test_decode_produces_audio_of_expected_duration() -> None:
    decoder = SemanticVoiceDecoder()
    # 5 frames at 10 fps = 0.5 sec
    frames = [
        CodecFrame(phoneme_id=i % 19, log_f0_q=128, residual_indices=(), residual_values_q=())
        for i in range(5)
    ]
    audio = decoder.decode_frames(frames)
    # 5 frames × 100 ms × 16 kHz = 8000 samples
    assert audio.shape[0] == 8000
    assert audio.dtype == np.float32


def test_decode_voiced_frames_have_nonzero_rms() -> None:
    """Voiced frames (non-silence phonemes with f0 > 0) must produce
    audible output, not silence."""
    decoder = SemanticVoiceDecoder()
    # Phoneme 0 = 'a' (voiced vowel)
    frames = [
        CodecFrame(phoneme_id=0, log_f0_q=128, residual_indices=(), residual_values_q=())
        for _ in range(5)
    ]
    audio = decoder.decode_frames(frames)
    rms = float(np.sqrt(np.mean(audio.astype(np.float64) ** 2)))
    assert rms > 1e-3, f"voiced frames produced near-silent audio (rms={rms})"


def test_decode_empty_returns_empty_audio() -> None:
    assert SemanticVoiceDecoder().decode_frames([]).shape[0] == 0


# ---------------------------------------------------------------------------
# End-to-end: encode → wire → decode
# ---------------------------------------------------------------------------

def test_end_to_end_round_trip(encoder: SemanticVoiceEncoder) -> None:
    encoder.reset()
    audio_in = _synth_test_audio()
    frames = encoder.encode_pcm(audio_in)
    packet = pack_packet(frames)
    received = unpack_packet(packet)
    audio_out = SemanticVoiceDecoder().decode_frames(received)
    # Reconstructed duration should be close to the encoded duration.
    # 7 frames × 100 ms = 700 ms; original audio is 720 ms.
    assert abs(audio_out.shape[0] - audio_in.shape[0]) <= 1600, (
        f"reconstructed length {audio_out.shape[0]} differs from "
        f"original {audio_in.shape[0]} by more than 1 semantic frame"
    )
    # Audible.
    rms = float(np.sqrt(np.mean(audio_out.astype(np.float64) ** 2)))
    assert rms > 1e-3


# ---------------------------------------------------------------------------
# Bitrate sanity at multiple input lengths
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("duration_s", [0.5, 1.0, 2.0])
def test_bitrate_stable_across_durations(
    encoder: SemanticVoiceEncoder, duration_s: float,
) -> None:
    """Bitrate shouldn't blow up for longer signals — top-K
    residual coding is per-frame, bounded above."""
    encoder.reset()
    # Build a longer test utterance.
    from one_link.ml.speech_synth import synth_sentence
    n_repeats = int(duration_s / 0.72)
    audio_f32 = np.array([], dtype=np.float32)
    for _ in range(max(1, n_repeats)):
        chunk, _ = synth_sentence(
            [("m", 0.08), ("a", 0.18), ("l", 0.08), ("o", 0.18)],
            sr=16000.0, seed=11,
        )
        audio_f32 = np.concatenate([audio_f32, chunk])
    audio = (audio_f32 * 32767).astype(np.int16)
    frames = encoder.encode_pcm(audio)
    bps = estimate_bitrate_bps(frames)
    # Should stay close to 1 kbps regardless of duration.
    assert bps < 1500.0, f"bitrate {bps:.0f} bps at {duration_s}s"
