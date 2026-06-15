"""Tests for the Tier θ semantic scene codec.

Verifies:
  - Wire format round-trips
  - Bitrate stays under the 2 kbps Tier θ design budget
  - Encoder + decoder use the same predictor so residual decoding
    converges
  - Model_pack_hash is stable
"""

from __future__ import annotations

import statistics
from pathlib import Path

import pytest

np = pytest.importorskip("numpy")
torch = pytest.importorskip("torch", exc_type=(ImportError, OSError))

CKPT_PATH = Path(__file__).resolve().parents[1] / "assets" / "models" / "scene_predictor_v1" / "checkpoint.pt"
if not CKPT_PATH.exists():
    pytest.skip(
        f"scene checkpoint not vendored at {CKPT_PATH}",
        allow_module_level=True,
    )


from one_link.semantic_scene_codec import (  # noqa: E402
    REGIME_LABELS_UI,
    SceneFrame,
    SemanticSceneDecoder,
    SemanticSceneEncoder,
    WIRE_MAGIC,
    estimate_bitrate_bps,
    model_pack_hash,
    pack_packet,
    regime_to_user_label,
    unpack_packet,
)


# ---------------------------------------------------------------------------
# SceneFrame wire-format round trip
# ---------------------------------------------------------------------------

def test_scene_frame_round_trip() -> None:
    f = SceneFrame(
        regime_id=2,
        n_objects=3,
        residual_indices=(0, 5, 12, 24),
        residual_values_q=(10, -20, 50, -50),
    )
    back, consumed = SceneFrame.from_bytes(f.to_bytes())
    assert back == f
    assert consumed == len(f.to_bytes())


def test_scene_frame_empty_residual() -> None:
    f = SceneFrame(
        regime_id=0, n_objects=0,
        residual_indices=(), residual_values_q=(),
    )
    back, _ = SceneFrame.from_bytes(f.to_bytes())
    assert back == f


def test_scene_frame_negative_residual_round_trip() -> None:
    f = SceneFrame(
        regime_id=4, n_objects=6,
        residual_indices=(0, 1, 37),
        residual_values_q=(-128, 0, 127),  # int8 extremes
    )
    back, _ = SceneFrame.from_bytes(f.to_bytes())
    assert back == f


def test_pack_unpack_packet() -> None:
    frames = [
        SceneFrame(
            regime_id=i % 5, n_objects=(i % 6) + 1,
            residual_indices=(0, 5, 10),
            residual_values_q=(i, -i, i * 2),
        )
        for i in range(8)
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


def test_unpack_rejects_trailing_garbage() -> None:
    frames = [SceneFrame(0, 0, (), ())]
    packet = pack_packet(frames) + b"garbage"
    with pytest.raises(ValueError, match="trailing"):
        unpack_packet(packet)


# ---------------------------------------------------------------------------
# Model pack hash
# ---------------------------------------------------------------------------

def test_model_pack_hash_stable() -> None:
    h1 = model_pack_hash(CKPT_PATH)
    h2 = model_pack_hash(CKPT_PATH)
    assert h1 == h2
    assert len(h1) == 64


# ---------------------------------------------------------------------------
# Encoder + Decoder
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def encoder() -> SemanticSceneEncoder:
    return SemanticSceneEncoder(CKPT_PATH, device="cpu")


@pytest.fixture(scope="module")
def decoder() -> SemanticSceneDecoder:
    return SemanticSceneDecoder(CKPT_PATH, device="cpu")


def _synth_scene_sequence(n_frames: int = 30, seed: int = 7) -> np.ndarray:
    """Build a synthetic scene-features sequence: 2 objects translating
    smoothly across the frame."""
    rng = np.random.default_rng(seed)
    out = np.zeros((n_frames, 38), dtype=np.float32)
    for t in range(n_frames):
        out[t, 0] = 2.0                              # n_objects
        out[t, 1] = 0.95                             # mean_conf
        out[t, 2] = 0.5                              # lighting
        out[t, 3] = 0.05                             # camera_motion
        out[t, 4] = 0.2                              # object_activity
        out[t, 5] = 0.3 + 0.01 * t                   # avg_obj_x
        out[t, 6] = 0.5                              # avg_obj_y
        out[t, 7] = 0.2                              # avg_obj_size
        # Object 0: translating
        out[t, 8] = 0.3 + 0.01 * t                   # obj0_x
        out[t, 9] = 0.4                              # obj0_y
        out[t, 10] = 0.1                             # obj0_size
        out[t, 11] = 0.01                            # obj0_vx
        out[t, 12] = 0.0                             # obj0_vy
        # Object 1: static
        out[t, 13] = 0.7                             # obj1_x
        out[t, 14] = 0.6                             # obj1_y
        out[t, 15] = 0.15                            # obj1_size
        out[t, 16] = 0.0                             # obj1_vx
        out[t, 17] = 0.0                             # obj1_vy
        # Add a touch of noise so the predictor's residual is non-zero
        out[t] += rng.normal(0, 0.01, 38).astype(np.float32)
    return out


def test_encode_then_decode_round_trip(
    encoder: SemanticSceneEncoder, decoder: SemanticSceneDecoder,
) -> None:
    encoder.reset()
    decoder.reset()
    seq = _synth_scene_sequence(n_frames=30)
    frames = encoder.encode_features(seq)
    packet = pack_packet(frames)
    received = unpack_packet(packet)
    features_out, regimes = decoder.decode_frames(received)
    # Same frame count.
    assert features_out.shape[0] == 30
    assert len(regimes) == 30
    # Reconstruction is approximate — within a reasonable L2.
    # Top-K residual coding loses some precision on the un-coded dims.
    mean_err = float(np.sqrt(np.mean((seq - features_out) ** 2)))
    # Loose bound — semantic codec, not byte-perfect.
    assert mean_err < 2.0, f"reconstruction error {mean_err} too high"


def test_encoder_bitrate_under_two_kbps(
    encoder: SemanticSceneEncoder,
) -> None:
    encoder.reset()
    seq = _synth_scene_sequence(n_frames=30)
    frames = encoder.encode_features(seq)
    bps = estimate_bitrate_bps(frames)
    # Design target ≈ 1.5 kbps; gate at 2 kbps for headroom.
    assert bps < 2000.0, f"bitrate {bps:.0f} bps exceeds 2 kbps"


def test_encoder_handles_single_frame_input(
    encoder: SemanticSceneEncoder,
) -> None:
    encoder.reset()
    seq = _synth_scene_sequence(n_frames=1)
    frames = encoder.encode_features(seq)
    assert len(frames) == 1


def test_encoder_handles_1d_input(
    encoder: SemanticSceneEncoder,
) -> None:
    """A single 38-dim feature vector (1D) should be treated as one frame."""
    encoder.reset()
    feat = np.zeros(38, dtype=np.float32)
    frames = encoder.encode_features(feat)
    assert len(frames) == 1


def test_regime_classification_propagates(
    encoder: SemanticSceneEncoder, decoder: SemanticSceneDecoder,
) -> None:
    """Encoder picks a regime per frame; decoder receives it verbatim."""
    encoder.reset()
    decoder.reset()
    seq = _synth_scene_sequence(n_frames=15)
    frames = encoder.encode_features(seq)
    _, regimes = decoder.decode_frames(frames)
    for f, r in zip(frames, regimes):
        assert f.regime_id == r


# ---------------------------------------------------------------------------
# UI labels (doctrine §3.6.c)
# ---------------------------------------------------------------------------

def test_all_regime_ids_have_plain_language_labels() -> None:
    for rid in range(5):
        label = regime_to_user_label(rid)
        assert label  # non-empty
        # No technical jargon
        for forbidden in ("error", "frame", "codec", "video"):
            assert forbidden not in label.lower(), f"regime {rid} label has '{forbidden}': {label}"


def test_unknown_regime_falls_back_to_still() -> None:
    assert regime_to_user_label(99) == "still"
