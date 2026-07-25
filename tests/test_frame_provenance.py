"""Tests for FrameProvenance — Cryptographic Reality Engine.

Covers:
    - Round-trip mint and verify
    - Tamper detection on every signed field
    - Non-forgery without the signing key
    - Canonical encoding stability (byte-identity across calls)
    - Wire-format round-trip
    - Schema version refusal for unknown versions
    - Field-validation errors (segment hash length, device_id format, etc.)
    - Plain-language UI labels never leak hex / network jargon (doctrine)
"""

from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.frame_provenance import (
    ED25519_SIG_LEN,
    SCHEMA_V1,
    SEGMENT_HASH_LEN,
    FrameKind,
    FrameProvenance,
    PathClass,
    RecordingState,
    _canonical_bytes,
    from_wire_dict,
    frame_kind_label,
    make_segment_hash,
    now_us,
    path_class_label,
    recording_state_label,
    sign_provenance,
    to_ui_dict,
    to_wire_dict,
    verify_provenance,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def keypair() -> tuple[Ed25519PrivateKey, bytes]:
    """Fresh signing keypair per test. Returns (priv, raw_public_bytes)."""
    priv = Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub_bytes


@pytest.fixture
def other_keypair() -> tuple[Ed25519PrivateKey, bytes]:
    """Independent keypair (the attacker / wrong-signer scenario)."""
    priv = Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub_bytes


@pytest.fixture
def sample_segment() -> bytes:
    return b"<opaque opus blob bytes that constitute a voice message>"


@pytest.fixture
def sample_provenance(
    keypair: tuple[Ed25519PrivateKey, bytes],
    sample_segment: bytes,
) -> FrameProvenance:
    priv, _ = keypair
    return sign_provenance(
        segment_hash=make_segment_hash(sample_segment),
        device_id="a3f9e2c1",
        frame_kind=FrameKind.REAL,
        path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
        timestamp_us=int(time.time() * 1_000_000),
        produce_confidence=1.0,
        signing_key=priv,
    )


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------

def test_round_trip_sign_verify(
    keypair: tuple[Ed25519PrivateKey, bytes],
    sample_provenance: FrameProvenance,
) -> None:
    _, pub_bytes = keypair
    assert verify_provenance(sample_provenance, pub_bytes) is True


def test_verify_with_wrong_key_returns_false(
    sample_provenance: FrameProvenance,
    other_keypair: tuple[Ed25519PrivateKey, bytes],
) -> None:
    _, attacker_pub = other_keypair
    assert verify_provenance(sample_provenance, attacker_pub) is False


def test_verify_with_garbage_key_returns_false(
    sample_provenance: FrameProvenance,
) -> None:
    # Non-32-byte key — Ed25519PublicKey.from_public_bytes raises;
    # verify_provenance must swallow it and return False, not raise.
    assert verify_provenance(sample_provenance, b"too-short") is False
    assert verify_provenance(sample_provenance, b"\x00" * 64) is False


# ---------------------------------------------------------------------------
# Tamper detection — every signed field
# ---------------------------------------------------------------------------

def _replace(p: FrameProvenance, **kwargs: object) -> FrameProvenance:
    """Helper: replace one field of a frozen dataclass."""
    from dataclasses import replace
    return replace(p, **kwargs)


def test_tampered_segment_hash_fails_verify(
    keypair: tuple[Ed25519PrivateKey, bytes],
    sample_provenance: FrameProvenance,
) -> None:
    _, pub_bytes = keypair
    forged = _replace(sample_provenance, segment_hash=b"\xff" * 32)
    assert verify_provenance(forged, pub_bytes) is False


def test_tampered_device_id_fails_verify(
    keypair: tuple[Ed25519PrivateKey, bytes],
    sample_provenance: FrameProvenance,
) -> None:
    _, pub_bytes = keypair
    forged = _replace(sample_provenance, device_id="deadbeef")
    assert verify_provenance(forged, pub_bytes) is False


def test_tampered_frame_kind_fails_verify(
    keypair: tuple[Ed25519PrivateKey, bytes],
    sample_provenance: FrameProvenance,
) -> None:
    _, pub_bytes = keypair
    # REAL -> PREDICTED would let an attacker deny that a frame was
    # captured live. The signature must protect this field.
    forged = _replace(sample_provenance, frame_kind=FrameKind.PREDICTED)
    assert verify_provenance(forged, pub_bytes) is False


def test_tampered_path_class_fails_verify(
    keypair: tuple[Ed25519PrivateKey, bytes],
    sample_provenance: FrameProvenance,
) -> None:
    _, pub_bytes = keypair
    # LAN -> RELAY would let an attacker hide a relay hop.
    forged = _replace(sample_provenance, path_class=PathClass.RELAY)
    assert verify_provenance(forged, pub_bytes) is False


def test_tampered_recording_state_fails_verify(
    keypair: tuple[Ed25519PrivateKey, bytes],
    sample_provenance: FrameProvenance,
) -> None:
    _, pub_bytes = keypair
    # NOT_RECORDING -> RECORDING_LOCAL would let an attacker make
    # the receiver think they consented to recording when they
    # didn't. Critical signature target.
    forged = _replace(
        sample_provenance, recording_state=RecordingState.RECORDING_LOCAL
    )
    assert verify_provenance(forged, pub_bytes) is False


def test_tampered_timestamp_fails_verify(
    keypair: tuple[Ed25519PrivateKey, bytes],
    sample_provenance: FrameProvenance,
) -> None:
    _, pub_bytes = keypair
    forged = _replace(
        sample_provenance, timestamp_us=sample_provenance.timestamp_us + 1
    )
    assert verify_provenance(forged, pub_bytes) is False


def test_tampered_confidence_fails_verify(
    keypair: tuple[Ed25519PrivateKey, bytes],
    sample_provenance: FrameProvenance,
) -> None:
    _, pub_bytes = keypair
    # Even confidence is signed, so the Body Engine's crossfade
    # selection cannot be manipulated by the network.
    forged = _replace(sample_provenance, produce_confidence=0.0)
    assert verify_provenance(forged, pub_bytes) is False


def test_tampered_signature_fails_verify(
    keypair: tuple[Ed25519PrivateKey, bytes],
    sample_provenance: FrameProvenance,
) -> None:
    _, pub_bytes = keypair
    bad_sig = b"\x00" * ED25519_SIG_LEN
    forged = _replace(sample_provenance, signature=bad_sig)
    assert verify_provenance(forged, pub_bytes) is False


def test_signature_wrong_length_fails_verify(
    keypair: tuple[Ed25519PrivateKey, bytes],
    sample_provenance: FrameProvenance,
) -> None:
    _, pub_bytes = keypair
    forged = _replace(sample_provenance, signature=b"\x00" * 32)
    assert verify_provenance(forged, pub_bytes) is False


# ---------------------------------------------------------------------------
# Non-forgery
# ---------------------------------------------------------------------------

def test_attacker_cannot_forge_without_signing_key(
    keypair: tuple[Ed25519PrivateKey, bytes],
    other_keypair: tuple[Ed25519PrivateKey, bytes],
    sample_segment: bytes,
) -> None:
    """An attacker who tries to mint a frame signed by Mom's key
    using only their own key produces a frame that fails Mom-key
    verification."""
    mom_priv, mom_pub = keypair
    attacker_priv, _ = other_keypair

    # Attacker signs a fake "real frame from Mom's device."
    fake = sign_provenance(
        segment_hash=make_segment_hash(sample_segment),
        device_id="a3f9e2c1",  # claim Mom's device_id
        frame_kind=FrameKind.REAL,
        path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
        timestamp_us=int(time.time() * 1_000_000),
        produce_confidence=1.0,
        signing_key=attacker_priv,  # ← only the attacker's key
    )
    # Receiver verifies against Mom's public key — must fail.
    assert verify_provenance(fake, mom_pub) is False


# ---------------------------------------------------------------------------
# Canonical encoding stability
# ---------------------------------------------------------------------------

def test_canonical_bytes_is_deterministic(
    sample_provenance: FrameProvenance,
) -> None:
    """Same provenance, called twice — byte-identical output. This
    is load-bearing for soak-replay determinism."""
    a = _canonical_bytes(sample_provenance)
    b = _canonical_bytes(sample_provenance)
    assert a == b


def test_canonical_bytes_length(sample_provenance: FrameProvenance) -> None:
    """The canonical layout is exactly 54 bytes (per the docstring
    layout). Changing this is a schema bump."""
    assert len(_canonical_bytes(sample_provenance)) == 54


def test_canonical_bytes_changes_when_any_field_changes(
    sample_provenance: FrameProvenance,
) -> None:
    base = _canonical_bytes(sample_provenance)
    for kw in (
        {"frame_kind": FrameKind.PREDICTED},
        {"path_class": PathClass.RELAY},
        {"recording_state": RecordingState.RECORDING_LOCAL},
        {"timestamp_us": sample_provenance.timestamp_us + 1},
        {"produce_confidence": 0.5},
        {"device_id": "deadbeef"},
    ):
        mutated = _canonical_bytes(_replace(sample_provenance, **kw))
        assert mutated != base, f"canonical bytes unchanged for {kw}"


# ---------------------------------------------------------------------------
# Wire format
# ---------------------------------------------------------------------------

def test_wire_round_trip(
    sample_provenance: FrameProvenance,
    keypair: tuple[Ed25519PrivateKey, bytes],
) -> None:
    _, pub_bytes = keypair
    wire = to_wire_dict(sample_provenance)
    decoded = from_wire_dict(wire)
    assert decoded == sample_provenance
    # The decoded copy must still verify.
    assert verify_provenance(decoded, pub_bytes) is True


def test_wire_missing_field_raises() -> None:
    wire = {
        "v": SCHEMA_V1,
        "seg": "00" * 32,
        "did": "a3f9e2c1",
        "fk": 0,
        "pc": 1,
        "rs": 0,
        "ts": 1234567890,
        "pcf": 1.0,
        # "sig" missing
    }
    with pytest.raises(ValueError, match="missing field"):
        from_wire_dict(wire)


def test_wire_malformed_field_raises() -> None:
    wire = {
        "v": SCHEMA_V1,
        "seg": "GG" * 32,  # not hex
        "did": "a3f9e2c1",
        "fk": 0,
        "pc": 1,
        "rs": 0,
        "ts": 1234567890,
        "pcf": 1.0,
        "sig": "00" * 64,
    }
    with pytest.raises(ValueError, match="malformed"):
        from_wire_dict(wire)


def test_wire_rejects_unknown_fields(
    sample_provenance: FrameProvenance,
) -> None:
    wire = to_wire_dict(sample_provenance)
    wire["shadow"] = "unsigned parser confusion"
    with pytest.raises(ValueError, match="unknown field"):
        from_wire_dict(wire)


@pytest.mark.parametrize("field", ["v", "fk", "pc", "rs", "ts"])
def test_wire_rejects_bool_integer_aliases(
    sample_provenance: FrameProvenance, field: str,
) -> None:
    wire = to_wire_dict(sample_provenance)
    wire[field] = True
    with pytest.raises(ValueError, match="malformed"):
        from_wire_dict(wire)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -0.01, 1.01, True, "1"])
def test_wire_rejects_noncanonical_confidence(
    sample_provenance: FrameProvenance, bad,
) -> None:
    wire = to_wire_dict(sample_provenance)
    wire["pcf"] = bad
    with pytest.raises(ValueError, match="malformed"):
        from_wire_dict(wire)


@pytest.mark.parametrize("field,size", [("seg", 64), ("sig", 128)])
def test_wire_rejects_noncanonical_or_oversized_hex_before_decode(
    sample_provenance: FrameProvenance, field: str, size: int,
) -> None:
    wire = to_wire_dict(sample_provenance)
    wire[field] = "A" * size
    with pytest.raises(ValueError, match="malformed"):
        from_wire_dict(wire)
    wire[field] = "0" * (size + 2)
    with pytest.raises(ValueError, match="malformed"):
        from_wire_dict(wire)


def test_wire_rejects_unsupported_schema_at_parse_boundary(
    sample_provenance: FrameProvenance,
) -> None:
    wire = to_wire_dict(sample_provenance)
    wire["v"] = 99
    with pytest.raises(ValueError, match="malformed"):
        from_wire_dict(wire)


def test_wire_contains_only_compact_keys(
    sample_provenance: FrameProvenance,
) -> None:
    wire = to_wire_dict(sample_provenance)
    assert set(wire.keys()) == {"v", "seg", "did", "fk", "pc", "rs", "ts", "pcf", "sig"}


# ---------------------------------------------------------------------------
# Schema versioning
# ---------------------------------------------------------------------------

def test_unknown_schema_version_refused(
    sample_provenance: FrameProvenance,
    keypair: tuple[Ed25519PrivateKey, bytes],
) -> None:
    """Receivers must refuse provenance from a schema they don't
    understand, even if the signature happens to verify (it
    shouldn't, but defence in depth)."""
    _, pub_bytes = keypair
    # We can't easily produce a "valid signature over future-schema"
    # since canonical_bytes refuses anything outside SCHEMA_V1's
    # layout. But verifier must refuse unknown schema regardless.
    forged = _replace(sample_provenance, schema_version=99)
    assert verify_provenance(forged, pub_bytes) is False


# ---------------------------------------------------------------------------
# Field validation at mint time
# ---------------------------------------------------------------------------

def test_segment_hash_wrong_length_raises_on_canonical(
    keypair: tuple[Ed25519PrivateKey, bytes],
) -> None:
    priv, _ = keypair
    with pytest.raises(ValueError, match="segment_hash"):
        sign_provenance(
            segment_hash=b"\x00" * 16,  # not 32
            device_id="a3f9e2c1",
            frame_kind=FrameKind.REAL,
            path_class=PathClass.LAN,
            recording_state=RecordingState.NOT_RECORDING,
            timestamp_us=now_us(),
            produce_confidence=1.0,
            signing_key=priv,
        )


def test_device_id_wrong_length_raises(
    keypair: tuple[Ed25519PrivateKey, bytes],
) -> None:
    priv, _ = keypair
    with pytest.raises(ValueError, match="device_id"):
        sign_provenance(
            segment_hash=b"\x00" * SEGMENT_HASH_LEN,
            device_id="a3f9",  # too short
            frame_kind=FrameKind.REAL,
            path_class=PathClass.LAN,
            recording_state=RecordingState.NOT_RECORDING,
            timestamp_us=now_us(),
            produce_confidence=1.0,
            signing_key=priv,
        )


def test_device_id_uppercase_raises(
    keypair: tuple[Ed25519PrivateKey, bytes],
) -> None:
    """Device IDs must be lowercase hex so canonical encoding is
    unambiguous. The Identity.short_id is always lowercase, but if a
    caller hand-rolls an upper-case id, fail loud rather than silently
    producing a different canonical hash."""
    priv, _ = keypair
    with pytest.raises(ValueError, match="hex"):
        sign_provenance(
            segment_hash=b"\x00" * SEGMENT_HASH_LEN,
            device_id="A3F9E2C1",
            frame_kind=FrameKind.REAL,
            path_class=PathClass.LAN,
            recording_state=RecordingState.NOT_RECORDING,
            timestamp_us=now_us(),
            produce_confidence=1.0,
            signing_key=priv,
        )


def test_produce_confidence_out_of_range_raises(
    keypair: tuple[Ed25519PrivateKey, bytes],
) -> None:
    priv, _ = keypair
    with pytest.raises(ValueError, match="produce_confidence"):
        sign_provenance(
            segment_hash=b"\x00" * SEGMENT_HASH_LEN,
            device_id="a3f9e2c1",
            frame_kind=FrameKind.REAL,
            path_class=PathClass.LAN,
            recording_state=RecordingState.NOT_RECORDING,
            timestamp_us=now_us(),
            produce_confidence=1.5,  # out of range
            signing_key=priv,
        )


def test_produce_confidence_negative_raises(
    keypair: tuple[Ed25519PrivateKey, bytes],
) -> None:
    priv, _ = keypair
    with pytest.raises(ValueError, match="produce_confidence"):
        sign_provenance(
            segment_hash=b"\x00" * SEGMENT_HASH_LEN,
            device_id="a3f9e2c1",
            frame_kind=FrameKind.REAL,
            path_class=PathClass.LAN,
            recording_state=RecordingState.NOT_RECORDING,
            timestamp_us=now_us(),
            produce_confidence=-0.1,
            signing_key=priv,
        )


def test_confidence_rounds_correctly() -> None:
    """The 0.0..1.0 float must round-trip through the u16 scaling
    cleanly enough that the canonical signature still verifies after
    a from_wire decode."""
    priv = Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    for conf in (0.0, 0.5, 0.9999, 1.0):
        p = sign_provenance(
            segment_hash=b"\x00" * SEGMENT_HASH_LEN,
            device_id="a3f9e2c1",
            frame_kind=FrameKind.REAL,
            path_class=PathClass.LAN,
            recording_state=RecordingState.NOT_RECORDING,
            timestamp_us=now_us(),
            produce_confidence=conf,
            signing_key=priv,
        )
        assert verify_provenance(p, pub_bytes), f"failed at conf={conf}"


# ---------------------------------------------------------------------------
# UI doctrine: plain-language labels never expose hex / network jargon
# ---------------------------------------------------------------------------

_FORBIDDEN_UI_TOKENS = (
    "wi-fi", "wifi", "cellular", "5g", "4g", "lte", "ed25519",
    "blake3", "hmac", "hex", "blob", "ratchet", "sha",
)


def test_frame_kind_labels_are_plain_language() -> None:
    for k in FrameKind:
        label = frame_kind_label(k).lower()
        for tok in _FORBIDDEN_UI_TOKENS:
            assert tok not in label, (
                f"frame_kind_label({k.name}) leaks doctrine-forbidden "
                f"token {tok!r}: {label!r}"
            )


def test_path_class_labels_are_plain_language() -> None:
    """Doctrine §3.6.c forbids 'on Wi-Fi', 'on 5G' etc. The path-class
    labels must never include network-technology language."""
    for pc in PathClass:
        label = path_class_label(pc).lower()
        for tok in _FORBIDDEN_UI_TOKENS:
            assert tok not in label, (
                f"path_class_label({pc.name}) leaks doctrine-forbidden "
                f"token {tok!r}: {label!r}"
            )


def test_recording_state_labels_are_plain_language() -> None:
    for rs in RecordingState:
        label = recording_state_label(rs).lower()
        for tok in _FORBIDDEN_UI_TOKENS:
            assert tok not in label, (
                f"recording_state_label({rs.name}) leaks doctrine-forbidden "
                f"token {tok!r}: {label!r}"
            )


def test_ui_dict_omits_hex_fields(
    sample_provenance: FrameProvenance,
) -> None:
    """Doctrine §3.9.a forbids raw fingerprint hex on the user
    surface. The Reality dot detail pane uses ``to_ui_dict``, which
    must never expose segment_hash, signature, or device_id."""
    ui = to_ui_dict(sample_provenance, verified=True)
    # The doctrine-forbidden fields:
    assert "seg" not in ui
    assert "sig" not in ui
    assert "segment_hash" not in ui
    assert "signature" not in ui
    assert "device_id" not in ui


def test_ui_dict_contains_required_user_facing_fields(
    sample_provenance: FrameProvenance,
) -> None:
    ui = to_ui_dict(sample_provenance, verified=True)
    assert ui["kind"] == "Original"
    assert ui["path"] == "Local network"
    assert ui["recording"] == "Not recording"
    assert ui["verified"] is True
    assert ui["verification"] == "Sender signature confirmed"
    assert "not the truth of a physical scene" in ui["scope"]
    assert ui["produced_at_us"] == sample_provenance.timestamp_us


# ---------------------------------------------------------------------------
# Segment hashing
# ---------------------------------------------------------------------------

def test_segment_hash_length() -> None:
    h = make_segment_hash(b"hello")
    assert len(h) == SEGMENT_HASH_LEN


def test_segment_hash_deterministic() -> None:
    a = make_segment_hash(b"voice frame payload")
    b = make_segment_hash(b"voice frame payload")
    assert a == b


def test_segment_hash_distinguishes_content() -> None:
    a = make_segment_hash(b"voice frame payload a")
    b = make_segment_hash(b"voice frame payload b")
    assert a != b


# ---------------------------------------------------------------------------
# Doctrine compliance: hex is never emitted to user surface, signature
# is never accidentally serialised in human-facing logs.
# ---------------------------------------------------------------------------

def test_provenance_repr_is_safe_for_debug_log() -> None:
    """Dataclass repr emits the signature in raw bytes form. This is
    fine for debug logs (which never reach the user UI) but the
    repr should not be carelessly forwarded to the user. We don't
    test that here — that's the doctrine lint's job — but we DO
    confirm to_ui_dict never returns the raw signature."""
    priv = Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    p = sign_provenance(
        segment_hash=b"\x00" * SEGMENT_HASH_LEN,
        device_id="a3f9e2c1",
        frame_kind=FrameKind.REAL,
        path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
        timestamp_us=now_us(),
        produce_confidence=1.0,
        signing_key=priv,
    )
    assert verify_provenance(p, pub_bytes) is True
    ui = to_ui_dict(p, verified=True)
    assert p.signature.hex() not in str(ui)
