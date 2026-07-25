"""Tests for the rolling-window FrameProvenance engine.

The producer + receiver sides need to converge on identical
window hashes when no loss happens, AND diverge gracefully when
the receiver's local stream differs from the sender's (loss, PLC,
reorder). The Reality dot UI keys off this divergence.
"""

from __future__ import annotations

import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from one_link.frame_provenance import (
    DEVICE_ID_LEN,
    FrameKind,
    PathClass,
    RecordingState,
)
from one_link.live_frame_provenance import (
    LIVE_SCHEMA_V2,
    WindowAttestor,
    WindowVerifier,
    sha256_segment_hash,
    sign_browser_window,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mk_signing_key() -> tuple[Ed25519PrivateKey, bytes]:
    sk = Ed25519PrivateKey.generate()
    pub_bytes = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return sk, pub_bytes


def _hex_device(name: str) -> str:
    return hashlib.sha256(name.encode()).hexdigest()[:DEVICE_ID_LEN]


# ---------------------------------------------------------------------------
# Producer: window mechanics
# ---------------------------------------------------------------------------

def test_observe_packet_starts_first_window() -> None:
    sk, _ = _mk_signing_key()
    attestor = WindowAttestor(
        signing_key=sk,
        device_id=_hex_device("a"),
        path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
    )
    result = attestor.observe_packet(b"frame-0", timestamp_us=0)
    assert result is None  # window not yet closed
    assert attestor.closed_count == 0


def test_window_closes_at_boundary() -> None:
    sk, _ = _mk_signing_key()
    attestor = WindowAttestor(
        signing_key=sk,
        device_id=_hex_device("a"),
        path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
    )
    attestor.observe_packet(b"frame-0", timestamp_us=0)
    attestor.observe_packet(b"frame-1", timestamp_us=500_000)
    # Window default is 1000 ms = 1_000_000 us. This packet crosses it.
    result = attestor.observe_packet(b"frame-2", timestamp_us=1_100_000)
    assert result is not None
    assert result.schema_version == LIVE_SCHEMA_V2
    assert len(result.signature) == 64
    assert attestor.closed_count == 1


def test_force_close_signs_partial_window() -> None:
    sk, _ = _mk_signing_key()
    attestor = WindowAttestor(
        signing_key=sk,
        device_id=_hex_device("a"),
        path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
    )
    attestor.observe_packet(b"frame-0", timestamp_us=0)
    attestor.observe_packet(b"frame-1", timestamp_us=400_000)
    signed = attestor.force_close(timestamp_us=500_000)
    assert signed is not None
    assert signed.timestamp_us == 500_000


def test_force_close_with_no_packets_returns_none() -> None:
    sk, _ = _mk_signing_key()
    attestor = WindowAttestor(
        signing_key=sk,
        device_id=_hex_device("a"),
        path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
    )
    assert attestor.force_close(timestamp_us=1) is None


def test_callback_fires_on_window_close() -> None:
    sk, _ = _mk_signing_key()
    seen = []
    attestor = WindowAttestor(
        signing_key=sk,
        device_id=_hex_device("a"),
        path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
        on_window_signed=lambda w, p: seen.append(p),
    )
    attestor.observe_packet(b"a", timestamp_us=0)
    attestor.observe_packet(b"b", timestamp_us=1_100_000)
    attestor.observe_packet(b"c", timestamp_us=2_200_000)
    assert len(seen) == 2


@pytest.mark.parametrize("force_close", [False, True])
def test_callback_failure_is_observable_without_breaking_capture(
    caplog: pytest.LogCaptureFixture,
    *,
    force_close: bool,
) -> None:
    sk, _ = _mk_signing_key()

    def fail_callback(_window: object, _provenance: object) -> None:
        raise RuntimeError("transport unavailable")

    attestor = WindowAttestor(
        signing_key=sk,
        device_id=_hex_device("a"),
        path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
        on_window_signed=fail_callback,
    )
    attestor.observe_packet(b"a", timestamp_us=0)

    with caplog.at_level("ERROR"):
        if force_close:
            signed = attestor.force_close(timestamp_us=500_000)
        else:
            signed = attestor.observe_packet(b"b", timestamp_us=1_100_000)

    assert signed is not None
    assert "live frame provenance callback failed" in caplog.text


def test_set_recording_state_takes_on_next_window() -> None:
    sk, _ = _mk_signing_key()
    attestor = WindowAttestor(
        signing_key=sk,
        device_id=_hex_device("a"),
        path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
    )
    attestor.observe_packet(b"a", timestamp_us=0)
    first = attestor.observe_packet(b"b", timestamp_us=1_100_000)
    attestor.set_recording_state(RecordingState.RECORDING_MUTUAL)
    second = attestor.observe_packet(b"c", timestamp_us=2_200_000)
    assert first is not None and first.recording_state == RecordingState.NOT_RECORDING
    assert second is not None
    assert second.recording_state == RecordingState.RECORDING_MUTUAL


# ---------------------------------------------------------------------------
# Receiver: hash convergence
# ---------------------------------------------------------------------------

def test_receiver_converges_on_identical_stream() -> None:
    sk, pub = _mk_signing_key()
    device_id = _hex_device("a")
    attestor = WindowAttestor(
        signing_key=sk, device_id=device_id,
        path_class=PathClass.LAN, recording_state=RecordingState.NOT_RECORDING,
    )
    verifier = WindowVerifier(sender_public_bytes=pub)

    packets = [(f"frame-{i}".encode(), i * 100_000) for i in range(15)]
    signed = None
    for pkt, t in packets:
        s = attestor.observe_packet(pkt, timestamp_us=t)
        verifier.observe_packet(pkt, timestamp_us=t)
        if s is not None:
            signed = s
    assert signed is not None
    verdict = verifier.verify_attestation(signed)
    assert verdict == FrameKind.REAL


def test_receiver_marks_repaired_when_packet_lost() -> None:
    sk, pub = _mk_signing_key()
    device_id = _hex_device("a")
    attestor = WindowAttestor(
        signing_key=sk, device_id=device_id,
        path_class=PathClass.LAN, recording_state=RecordingState.NOT_RECORDING,
    )
    verifier = WindowVerifier(sender_public_bytes=pub)

    packets = [(f"frame-{i}".encode(), i * 100_000) for i in range(15)]
    signed = None
    for i, (pkt, t) in enumerate(packets):
        s = attestor.observe_packet(pkt, timestamp_us=t)
        # Drop packet 5 on receive — simulates a missing RTP packet
        # that PLC fills with silence on the receiver side.
        if i != 5:
            verifier.observe_packet(pkt, timestamp_us=t)
        if s is not None:
            signed = s
    assert signed is not None
    # Hash divergence → REPAIRED.
    assert verifier.verify_attestation(signed) == FrameKind.REPAIRED


def test_receiver_rejects_forged_signature() -> None:
    sk, _ = _mk_signing_key()
    sk_attacker, attacker_pub = _mk_signing_key()
    attestor = WindowAttestor(
        signing_key=sk_attacker, device_id=_hex_device("a"),
        path_class=PathClass.LAN, recording_state=RecordingState.NOT_RECORDING,
    )
    # Verifier expects sk's pubkey, not the attacker's.
    pub_real = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    verifier = WindowVerifier(sender_public_bytes=pub_real)
    for i in range(15):
        pkt = f"frame-{i}".encode()
        s = attestor.observe_packet(pkt, timestamp_us=i * 100_000)
        verifier.observe_packet(pkt, timestamp_us=i * 100_000)
        if s is not None:
            # BLANK = unverified
            assert verifier.verify_attestation(s) == FrameKind.BLANK
            return
    pytest.fail("attestor never produced a closed window")


def test_receiver_history_evicts_oldest_windows() -> None:
    sk, pub = _mk_signing_key()
    verifier = WindowVerifier(sender_public_bytes=pub)
    # Drive 50 windows through the verifier; only the last ~32 are kept.
    for w in range(50):
        for i in range(10):
            verifier.observe_packet(
                f"w{w}-f{i}".encode(),
                timestamp_us=w * 1_000_000 + i * 100_000,
            )
    # The verifier internal map should have at most max_history entries
    # (32 by default, plus the one currently open).
    assert len(verifier._closed_hashes) <= 32


def test_receiver_force_close_retains_final_window() -> None:
    sk, pub = _mk_signing_key()
    verifier = WindowVerifier(sender_public_bytes=pub)
    verifier.observe_packet(b"a", timestamp_us=0)
    verifier.observe_packet(b"b", timestamp_us=400_000)
    assert len(verifier._closed_hashes) == 0
    verifier.force_close()
    assert len(verifier._closed_hashes) == 1


# ---------------------------------------------------------------------------
# Browser-bridge helpers
# ---------------------------------------------------------------------------

def test_sha256_segment_hash_matches_stdlib() -> None:
    assert sha256_segment_hash(b"hello") == hashlib.sha256(b"hello").digest()


def test_sign_browser_window_round_trip_verifies() -> None:
    sk, pub = _mk_signing_key()
    seg = sha256_segment_hash(b"some recorded audio chunk")
    signed = sign_browser_window(
        signing_key=sk,
        device_id=_hex_device("a"),
        path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
        segment_hash=seg,
        timestamp_us=1_700_000_000_000_000,
    )
    # Hand it to a verifier that has been fed the same chunk —
    # verdict should be REAL.
    verifier = WindowVerifier(sender_public_bytes=pub)
    verifier.observe_packet(b"some recorded audio chunk", timestamp_us=0)
    verifier.force_close()
    assert verifier.verify_attestation(signed) == FrameKind.REAL


def test_sign_browser_window_rejects_wrong_hash_length() -> None:
    sk, _ = _mk_signing_key()
    with pytest.raises(ValueError):
        sign_browser_window(
            signing_key=sk,
            device_id=_hex_device("a"),
            path_class=PathClass.LAN,
            recording_state=RecordingState.NOT_RECORDING,
            segment_hash=b"too-short",
            timestamp_us=0,
        )


def test_path_class_updates_take_effect_on_next_window() -> None:
    sk, pub = _mk_signing_key()
    attestor = WindowAttestor(
        signing_key=sk, device_id=_hex_device("a"),
        path_class=PathClass.LAN, recording_state=RecordingState.NOT_RECORDING,
    )
    attestor.observe_packet(b"a", timestamp_us=0)
    first = attestor.observe_packet(b"b", timestamp_us=1_100_000)
    attestor.set_path_class(PathClass.RELAY)
    second = attestor.observe_packet(b"c", timestamp_us=2_200_000)
    assert first.path_class == PathClass.LAN
    assert second.path_class == PathClass.RELAY


def test_attestor_rejects_bad_device_id() -> None:
    sk, _ = _mk_signing_key()
    with pytest.raises(ValueError):
        WindowAttestor(
            signing_key=sk,
            device_id="too-long-device-id",
            path_class=PathClass.LAN,
            recording_state=RecordingState.NOT_RECORDING,
        )


def test_attestor_rejects_nonpositive_window() -> None:
    sk, _ = _mk_signing_key()
    with pytest.raises(ValueError):
        WindowAttestor(
            signing_key=sk,
            device_id=_hex_device("a"),
            path_class=PathClass.LAN,
            recording_state=RecordingState.NOT_RECORDING,
            window_ms=0,
        )
