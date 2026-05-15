"""A/B comparison: semantic voice codec vs Opus baseline.

The Living Presence doc §4.8 calls for an A/B measurement before
promising any quality publicly. This test produces the empirical
numbers — bitrate, latency, intelligibility-proxy — so the claim
"voice survives at 1 kbps" is grounded in actual measurement.

Methodology:
  - Generate 8 test utterances (different phoneme sequences, seeds).
  - For each utterance:
      * Encode via the semantic voice codec → measure bitrate
      * Decode → measure intelligibility-proxy (MFCC distance + voice
        predictor accuracy on reconstructed audio)
      * Compare against the Opus reference bitrate of 16 kbps
        (Compiler's AUDIO_ONLY rung floor).
  - Aggregate + assert against acceptance gates:
      * mean bitrate ≤ 1.5 kbps (target 1 kbps with budget for residual)
      * intelligibility-proxy ≥ 0.4 (rough threshold — 0.5+ is the
        SOTA for low-bitrate codecs on the same proxy)
      * encode + decode latency total < 250 ms per second of audio

Doctrine: this is engineer-facing. The user never sees these
numbers. We do not promise quality in the UI until a real MOS test
runs (Tier ζ AUTOPILOT graduation gate).
"""

from __future__ import annotations

import statistics
from pathlib import Path

import numpy as np
import pytest


torch = pytest.importorskip("torch")

CKPT_PATH = Path(__file__).resolve().parents[1] / "assets" / "models" / "voice_predictor_v3_librispeech" / "checkpoint.pt"
if not CKPT_PATH.exists():
    pytest.skip(
        f"voice predictor checkpoint not vendored at {CKPT_PATH}",
        allow_module_level=True,
    )


from one_link.ml.speech_synth import synth_sentence  # noqa: E402
from one_link.ml.trained_voice_oracle import TrainedVoiceOracle  # noqa: E402
from one_link.semantic_voice_codec import (  # noqa: E402
    SemanticVoiceDecoder,
    SemanticVoiceEncoder,
    estimate_bitrate_bps,
    pack_packet,
    unpack_packet,
)


# Reference Opus AUDIO_ONLY bitrate the Compiler hands to a healthy
# call (per LIVING_PRESENCE_ARCHITECTURE.md §4.2 rung table).
OPUS_AUDIO_ONLY_KBPS = 16.0


# ---------------------------------------------------------------------------
# Test utterances
# ---------------------------------------------------------------------------

_TEST_UTTERANCES = [
    [("m", 0.08), ("a", 0.18), ("l", 0.08), ("o", 0.18)],
    [("s", 0.08), ("i", 0.18), ("l", 0.08), ("e", 0.18), ("n", 0.10)],
    [("p", 0.06), ("a", 0.15), ("p", 0.06), ("a", 0.15)],
    [("f", 0.08), ("a", 0.18), ("st", 0.05) if False else ("s", 0.08), ("t", 0.05)],
    [("r", 0.08), ("e", 0.18), ("d", 0.06) if False else ("z", 0.10)],
    [("k", 0.06), ("o", 0.18), ("k", 0.06), ("o", 0.18)],
    [("sh", 0.08), ("i", 0.18), ("p", 0.06)],
    [("u", 0.18), ("n", 0.10), ("i", 0.15), ("k", 0.06)],
]


def _synth(utterance, seed: int) -> np.ndarray:
    audio_f32, _ = synth_sentence(utterance, sr=16000.0, seed=seed)
    return (audio_f32 * 32767).astype(np.int16)


# ---------------------------------------------------------------------------
# Intelligibility proxy — MFCC distance + predictor confirm-ratio
# ---------------------------------------------------------------------------

def _intelligibility_proxy(
    audio_in_i16: np.ndarray, audio_out_f32: np.ndarray,
    oracle: TrainedVoiceOracle,
) -> dict[str, float]:
    """Return a dict of quality scores comparing reconstructed audio
    against the original.

      - ``mfcc_distance``: mean per-frame L2 distance between MFCCs.
        Lower = more similar. 0 = identical.
      - ``predictor_confirm``: the trained predictor's mean confirm-
        ratio on the reconstructed audio. Higher = sound more like
        natural speech the predictor was trained on.
      - ``rms_ratio``: RMS(reconstructed) / RMS(original). Should be
        in [0.3, 3.0] — within an order of magnitude.
    """
    audio_in_f32 = audio_in_i16.astype(np.float32) / 32768.0
    mfcc_in = oracle.extract_mfcc(audio_in_f32)
    mfcc_out = oracle.extract_mfcc(audio_out_f32)
    n = min(mfcc_in.shape[0], mfcc_out.shape[0])
    if n == 0:
        return {
            "mfcc_distance": float("inf"),
            "predictor_confirm": 0.0,
            "rms_ratio": 0.0,
        }
    err = mfcc_in[:n] - mfcc_out[:n]
    mfcc_distance = float(np.mean(np.sqrt(np.mean(err ** 2, axis=-1))))
    predictor_confirm = float(oracle.predict_frame_accuracy(mfcc_out))
    rms_in = float(np.sqrt(np.mean(audio_in_f32 ** 2)))
    rms_out = float(np.sqrt(np.mean(audio_out_f32 ** 2)))
    rms_ratio = rms_out / max(rms_in, 1e-9)
    return {
        "mfcc_distance": mfcc_distance,
        "predictor_confirm": predictor_confirm,
        "rms_ratio": rms_ratio,
    }


# ---------------------------------------------------------------------------
# The A/B harness
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def shared_oracle() -> TrainedVoiceOracle:
    return TrainedVoiceOracle(CKPT_PATH, device="cpu")


@pytest.fixture(scope="module")
def shared_encoder() -> SemanticVoiceEncoder:
    return SemanticVoiceEncoder(CKPT_PATH, device="cpu")


def _run_ab(
    encoder: SemanticVoiceEncoder, oracle: TrainedVoiceOracle,
    utterance, seed: int,
) -> dict:
    import time
    encoder.reset()
    audio_in = _synth(utterance, seed=seed)

    t0 = time.perf_counter()
    frames = encoder.encode_pcm(audio_in)
    encode_ms = (time.perf_counter() - t0) * 1000

    packet = pack_packet(frames)
    received = unpack_packet(packet)

    t0 = time.perf_counter()
    audio_out = SemanticVoiceDecoder().decode_frames(received)
    decode_ms = (time.perf_counter() - t0) * 1000

    bitrate_bps = estimate_bitrate_bps(frames)
    duration_s = audio_in.shape[0] / 16000

    proxy = _intelligibility_proxy(audio_in, audio_out, oracle)
    return {
        "seed": seed,
        "duration_s": duration_s,
        "n_frames": len(frames),
        "packet_bytes": len(packet),
        "bitrate_bps": bitrate_bps,
        "bitrate_ratio_vs_opus": bitrate_bps / (OPUS_AUDIO_ONLY_KBPS * 1000),
        "encode_ms": encode_ms,
        "decode_ms": decode_ms,
        "total_latency_per_sec": (encode_ms + decode_ms) / duration_s,
        **proxy,
    }


def test_ab_aggregate_bitrate_under_target(
    shared_encoder: SemanticVoiceEncoder, shared_oracle: TrainedVoiceOracle,
) -> None:
    results = []
    for i, utt in enumerate(_TEST_UTTERANCES):
        try:
            r = _run_ab(shared_encoder, shared_oracle, utt, seed=i + 1)
            results.append(r)
        except Exception as e:
            pytest.fail(f"A/B utterance {i} crashed: {e}")
    bitrates = [r["bitrate_bps"] for r in results]
    mean_bps = statistics.mean(bitrates)
    median_bps = statistics.median(bitrates)
    p95_bps = sorted(bitrates)[int(len(bitrates) * 0.95)]
    print(
        f"\nSemantic voice codec A/B (vs Opus AUDIO_ONLY @ "
        f"{OPUS_AUDIO_ONLY_KBPS * 1000:.0f} bps):"
        f"\n  mean   bitrate: {mean_bps:.0f} bps "
        f"({mean_bps / (OPUS_AUDIO_ONLY_KBPS * 10):.1f}x smaller)"
        f"\n  median bitrate: {median_bps:.0f} bps"
        f"\n  p95    bitrate: {p95_bps:.0f} bps"
    )
    # Acceptance gate: mean ≤ 1.5 kbps.
    assert mean_bps < 1500, f"mean bitrate {mean_bps:.0f} bps exceeds 1500 bps gate"


def test_ab_aggregate_latency_real_time_capable(
    shared_encoder: SemanticVoiceEncoder, shared_oracle: TrainedVoiceOracle,
) -> None:
    results = []
    for i, utt in enumerate(_TEST_UTTERANCES):
        results.append(
            _run_ab(shared_encoder, shared_oracle, utt, seed=i + 1),
        )
    latencies = [r["total_latency_per_sec"] for r in results]
    mean_lat = statistics.mean(latencies)
    p95_lat = sorted(latencies)[int(len(latencies) * 0.95)]
    print(
        f"\nLatency: mean {mean_lat:.0f} ms/sec, p95 {p95_lat:.0f} ms/sec"
    )
    # Per-second-of-audio latency under 250 ms = 4× real-time
    # headroom. Critical for live calls.
    assert mean_lat < 250, (
        f"mean encode+decode latency {mean_lat:.0f} ms/sec exceeds budget"
    )


def test_ab_intelligibility_proxy_meets_floor(
    shared_encoder: SemanticVoiceEncoder, shared_oracle: TrainedVoiceOracle,
) -> None:
    """The reconstructed audio must still be classifiable by the
    same voice predictor (i.e., it still 'sounds like speech' to
    the model). predictor_confirm threshold is permissive — the
    formant synth is not designed to be byte-equal to the input,
    only intelligible at the phoneme level."""
    results = []
    for i, utt in enumerate(_TEST_UTTERANCES):
        results.append(
            _run_ab(shared_encoder, shared_oracle, utt, seed=i + 1),
        )
    confirms = [r["predictor_confirm"] for r in results]
    mean_conf = statistics.mean(confirms)
    print(f"\nPredictor confirm ratio (reconstructed): mean {mean_conf:.3f}")
    # Floor: reconstructed audio classifies as natural-speech-like
    # to the predictor at ≥ 0.4. The Klatt synth produces
    # phonetically-correct vowels + consonants; the predictor was
    # trained on LibriSpeech with similar formant structures, so
    # a reconstructed pure /a/ should rank well.
    assert mean_conf >= 0.4, (
        f"reconstructed audio scored {mean_conf:.3f} on predictor "
        f"confirm-ratio (need ≥ 0.4)"
    )


def test_ab_rms_within_order_of_magnitude(
    shared_encoder: SemanticVoiceEncoder, shared_oracle: TrainedVoiceOracle,
) -> None:
    """Reconstructed audio must be audible — its RMS amplitude must
    be within an order of magnitude of the original. Tier ζ-voice
    explicitly does NOT preserve waveform; it preserves phoneme
    sequences + pitch. But the perceived loudness should match."""
    results = []
    for i, utt in enumerate(_TEST_UTTERANCES):
        results.append(
            _run_ab(shared_encoder, shared_oracle, utt, seed=i + 1),
        )
    rms_ratios = [r["rms_ratio"] for r in results]
    print(f"\nRMS ratios: {[f'{r:.2f}' for r in rms_ratios]}")
    # Each utterance reconstructs to within 0.1× — 10× of original.
    for r in rms_ratios:
        assert 0.1 < r < 10.0, f"RMS ratio {r:.2f} out of range"


def test_ab_bitrate_savings_vs_opus_at_least_8x(
    shared_encoder: SemanticVoiceEncoder, shared_oracle: TrainedVoiceOracle,
) -> None:
    """The Tier ζ headline claim: at least 8× smaller than Opus
    AUDIO_ONLY. Opus at 16 kbps → 2 kbps would be the bar; we
    target ~1 kbps so 16× savings is the design point."""
    results = []
    for i, utt in enumerate(_TEST_UTTERANCES):
        results.append(
            _run_ab(shared_encoder, shared_oracle, utt, seed=i + 1),
        )
    mean_bps = statistics.mean(r["bitrate_bps"] for r in results)
    savings = (OPUS_AUDIO_ONLY_KBPS * 1000) / mean_bps
    print(f"\nBitrate savings vs Opus: {savings:.1f}x")
    assert savings >= 8.0, (
        f"only {savings:.1f}x smaller than Opus; need ≥ 8×"
    )


def test_ab_no_packet_blows_up(
    shared_encoder: SemanticVoiceEncoder, shared_oracle: TrainedVoiceOracle,
) -> None:
    """No utterance produces a packet larger than 1 KiB for the
    typical 0.5–1 sec test clips."""
    for i, utt in enumerate(_TEST_UTTERANCES):
        r = _run_ab(shared_encoder, shared_oracle, utt, seed=i + 1)
        assert r["packet_bytes"] < 1024, (
            f"utterance {i} produced packet of {r['packet_bytes']} bytes"
        )
