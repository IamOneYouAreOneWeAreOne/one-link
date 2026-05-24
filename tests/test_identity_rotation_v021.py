"""v0.21.x identity key rotation - cryptographic primitive tests.

The flawless gate on rotation is that a cert signed by the OLD key
verifies under the OLD pinned pubkey AND fails under anything else.
If that property breaks, the entire rotation flow becomes either
spoofable (attacker rotates your identity) or unusable (legitimate
rotations are rejected). This file pins every detail.
"""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.identity_rotation import (
    CERT_VERSION,
    CertVerifyError,
    RotationCertificate,
    RotationReason,
    VALID_REASONS,
    apply_certificate_to_peer,
    fingerprint_for_pubkey,
    mint_certificate,
    verify_certificate,
)


# ── mint ────────────────────────────────────────────────────────────


def test_mint_signs_with_old_key_over_canonical_body():
    """A freshly-minted cert verifies under the old pubkey, and the
    canonical bytes parse into the expected schema."""
    old = Ed25519PrivateKey.generate()
    new = Ed25519PrivateKey.generate()
    new_pub = new.public_key().public_bytes_raw()
    cert = mint_certificate(old_priv=old, new_pub=new_pub, ts_ms=1_700_000_000_000)
    assert cert.version == CERT_VERSION
    assert cert.new_pub_hex == new_pub.hex()
    assert cert.new_fp == fingerprint_for_pubkey(new_pub)
    assert cert.old_fp == fingerprint_for_pubkey(old.public_key().public_bytes_raw())
    assert cert.ts_ms == 1_700_000_000_000
    assert cert.reason == RotationReason.SCHEDULED.value
    assert len(cert.signature) == 64

    body = json.loads(cert.canonical_bytes.decode("ascii"))
    assert sorted(body.keys()) == sorted([
        "v", "old_fp", "new_fp", "new_pub_hex", "ts_ms", "reason",
    ])
    # Canonical form is sorted-keys + tight separators.
    assert cert.canonical_bytes == json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")


def test_mint_rejects_bad_new_pub_length():
    old = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError, match="32 bytes"):
        mint_certificate(old_priv=old, new_pub=b"\x00" * 31)
    with pytest.raises(ValueError, match="32 bytes"):
        mint_certificate(old_priv=old, new_pub=b"\x00" * 33)


def test_mint_rejects_unknown_reason():
    old = Ed25519PrivateKey.generate()
    new = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    with pytest.raises(ValueError, match="reason must be"):
        mint_certificate(old_priv=old, new_pub=new, reason="just because")


def test_mint_supports_every_documented_reason():
    """Every enum value mints + verifies. Catches a stale string in
    VALID_REASONS or the enum."""
    old = Ed25519PrivateKey.generate()
    new = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    for reason in VALID_REASONS:
        cert = mint_certificate(old_priv=old, new_pub=new, reason=reason)
        verify_certificate(
            cert=cert, expected_old_pubkey=old.public_key().public_bytes_raw(),
        )


def test_mint_is_deterministic_for_fixed_ts_ms():
    """Mint twice with the same ts_ms and same inputs - canonical
    bytes match. (Signature won't match: Ed25519 is deterministic
    against the message, so actually it WILL match. We assert both.)
    """
    old = Ed25519PrivateKey.generate()
    new = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    a = mint_certificate(old_priv=old, new_pub=new, ts_ms=42)
    b = mint_certificate(old_priv=old, new_pub=new, ts_ms=42)
    assert a.canonical_bytes == b.canonical_bytes
    # Ed25519 (per RFC 8032) is deterministic given (key, message).
    assert a.signature == b.signature


# ── verify ──────────────────────────────────────────────────────────


def _good_cert():
    old = Ed25519PrivateKey.generate()
    new = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    cert = mint_certificate(old_priv=old, new_pub=new)
    return old, new, cert


def test_verify_accepts_freshly_minted_cert():
    old, _, cert = _good_cert()
    verify_certificate(
        cert=cert,
        expected_old_pubkey=old.public_key().public_bytes_raw(),
    )


def test_verify_rejects_wrong_pubkey():
    _, _, cert = _good_cert()
    impostor = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    with pytest.raises(CertVerifyError, match="different identity"):
        verify_certificate(cert=cert, expected_old_pubkey=impostor)


def test_verify_rejects_flipped_signature_byte():
    """One bit-flip in the signature breaks Ed25519 verification."""
    old, _, cert = _good_cert()
    bad_sig = bytearray(cert.signature)
    bad_sig[0] ^= 0x01
    tampered = RotationCertificate(
        version=cert.version,
        old_fp=cert.old_fp,
        new_fp=cert.new_fp,
        new_pub_hex=cert.new_pub_hex,
        ts_ms=cert.ts_ms,
        reason=cert.reason,
        canonical_bytes=cert.canonical_bytes,
        signature=bytes(bad_sig),
    )
    with pytest.raises(CertVerifyError, match="signature does not verify"):
        verify_certificate(
            cert=tampered,
            expected_old_pubkey=old.public_key().public_bytes_raw(),
        )


def test_verify_rejects_flipped_canonical_byte():
    """One bit-flip in the canonical body breaks Ed25519 verification.
    The body is what got signed; changing it without re-signing means
    the signature targets the wrong message."""
    old, _, cert = _good_cert()
    bad_body = bytearray(cert.canonical_bytes)
    bad_body[-2] ^= 0x01
    # Schema parser may also reject the corruption (depends on which
    # byte got hit) - either failure mode is correct rejection.
    tampered = RotationCertificate(
        version=cert.version,
        old_fp=cert.old_fp,
        new_fp=cert.new_fp,
        new_pub_hex=cert.new_pub_hex,
        ts_ms=cert.ts_ms,
        reason=cert.reason,
        canonical_bytes=bytes(bad_body),
        signature=cert.signature,
    )
    with pytest.raises(CertVerifyError):
        verify_certificate(
            cert=tampered,
            expected_old_pubkey=old.public_key().public_bytes_raw(),
        )


def test_verify_rejects_inconsistent_new_fp():
    """The cert.new_fp must equal SHA-256(new_pub_hex). If not, an
    attacker could craft a cert that names one fingerprint in old_fp
    but exposes a totally different pubkey."""
    old = Ed25519PrivateKey.generate()
    real_new = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    impostor_new = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    # Build canonical body with INCONSISTENT new_fp / new_pub_hex.
    body = {
        "v": CERT_VERSION,
        "old_fp": fingerprint_for_pubkey(old.public_key().public_bytes_raw()),
        "new_fp": fingerprint_for_pubkey(impostor_new),
        "new_pub_hex": real_new.hex(),
        "ts_ms": 1,
        "reason": "scheduled",
    }
    canonical = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")
    sig = old.sign(canonical)
    bad_cert = RotationCertificate(
        version=CERT_VERSION,
        old_fp=body["old_fp"],
        new_fp=body["new_fp"],
        new_pub_hex=body["new_pub_hex"],
        ts_ms=body["ts_ms"],
        reason=body["reason"],
        canonical_bytes=canonical,
        signature=sig,
    )
    with pytest.raises(CertVerifyError, match="internally inconsistent"):
        verify_certificate(
            cert=bad_cert,
            expected_old_pubkey=old.public_key().public_bytes_raw(),
        )


# ── wire round-trip ─────────────────────────────────────────────────


def test_to_wire_dict_and_back_round_trips_byte_equal():
    """to_wire_dict + from_wire_dict must preserve canonical bytes
    exactly so the signature still verifies after a serialize/
    deserialize hop. If we ever break the canonical_bytes field by
    re-serializing from the parsed dict, this test fails loudly."""
    old, _, cert = _good_cert()
    wire = cert.to_wire_dict()
    assert sorted(wire.keys()) == ["cert_json", "sig_hex"]
    restored = RotationCertificate.from_wire_dict(wire)
    assert restored.canonical_bytes == cert.canonical_bytes
    assert restored.signature == cert.signature
    verify_certificate(
        cert=restored,
        expected_old_pubkey=old.public_key().public_bytes_raw(),
    )


def test_from_wire_dict_rejects_short_signature():
    _, _, cert = _good_cert()
    wire = cert.to_wire_dict()
    wire["sig_hex"] = wire["sig_hex"][:-2]  # drop a byte
    with pytest.raises(ValueError, match="64 bytes"):
        RotationCertificate.from_wire_dict(wire)


def test_from_wire_dict_rejects_extra_schema_keys():
    """Extra unexpected keys in the canonical body are rejected -
    otherwise an attacker could add fields the verifier ignores
    but the application layer trusts."""
    old, _, cert = _good_cert()
    body = json.loads(cert.canonical_bytes.decode("ascii"))
    body["sneaky"] = "extra"
    canonical = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")
    # The signature won't verify against the new bytes, but the
    # schema check should fail FIRST so the rejection is clearly
    # about the schema, not the signature.
    sig = old.sign(canonical)
    wire = {"cert_json": canonical.decode("ascii"), "sig_hex": sig.hex()}
    with pytest.raises(ValueError, match="unexpected keys"):
        RotationCertificate.from_wire_dict(wire)


def test_from_wire_dict_rejects_missing_required_key():
    _, _, cert = _good_cert()
    body = json.loads(cert.canonical_bytes.decode("ascii"))
    del body["ts_ms"]
    canonical = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")
    wire = {"cert_json": canonical.decode("ascii"), "sig_hex": "00" * 64}
    with pytest.raises(ValueError, match="missing keys"):
        RotationCertificate.from_wire_dict(wire)


# ── apply ───────────────────────────────────────────────────────────


def test_apply_returns_transition_data():
    """The happy path: cert verifies + current pinned matches old_fp;
    apply returns the new pubkey + new_fp the daemon should pin."""
    old = Ed25519PrivateKey.generate()
    new = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    cert = mint_certificate(old_priv=old, new_pub=new)
    result = apply_certificate_to_peer(
        cert=cert,
        expected_old_pubkey=old.public_key().public_bytes_raw(),
        current_pinned_fp=cert.old_fp,
    )
    assert result.old_fp == cert.old_fp
    assert result.new_fp == cert.new_fp
    assert result.new_pubkey == new
    assert result.reason == cert.reason


def test_apply_detects_replay_when_pinned_already_at_new_fp():
    """If our pinned fp is already the cert's new_fp, the cert was
    already applied. Treat as replay, refuse."""
    old = Ed25519PrivateKey.generate()
    new = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    cert = mint_certificate(old_priv=old, new_pub=new)
    with pytest.raises(CertVerifyError, match="already applied"):
        apply_certificate_to_peer(
            cert=cert,
            expected_old_pubkey=old.public_key().public_bytes_raw(),
            current_pinned_fp=cert.new_fp,
        )


def test_apply_refuses_rollback_attempt():
    """An attacker replays an OLD cert (e.g. from a previous
    rotation) to roll the peer back to a no-longer-current key.
    Refuse: cert.old_fp doesn't match current pinned fp."""
    # Set up a 3-key chain: K1 -> K2 -> K3. The cert under attack
    # is the K1 -> K2 cert. Current pinned is K3 (post-second
    # rotation). The cert is technically valid, but applying it
    # would roll back to K2.
    k1 = Ed25519PrivateKey.generate()
    k2_pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    k3_pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    k1_to_k2 = mint_certificate(old_priv=k1, new_pub=k2_pub)
    current_pinned_fp = fingerprint_for_pubkey(k3_pub)
    with pytest.raises(CertVerifyError, match="refusing rollback"):
        apply_certificate_to_peer(
            cert=k1_to_k2,
            expected_old_pubkey=k1.public_key().public_bytes_raw(),
            current_pinned_fp=current_pinned_fp,
        )


def test_apply_allows_first_application_without_pinned_hint():
    """When the caller passes current_pinned_fp=None (e.g. a brand-
    new peer that has never been pinned), we accept the cert as long
    as the signature verifies. The application-layer caller is
    responsible for deciding whether to pin a peer it has never
    seen before."""
    old, _, cert = _good_cert()
    result = apply_certificate_to_peer(
        cert=cert,
        expected_old_pubkey=old.public_key().public_bytes_raw(),
        current_pinned_fp=None,
    )
    assert result.old_fp == cert.old_fp


# ── fingerprint helper ─────────────────────────────────────────────


def test_fingerprint_matches_sha256_of_pubkey():
    pub = b"\x00" * 32
    expected = hashlib.sha256(pub).hexdigest()
    assert fingerprint_for_pubkey(pub) == expected


def test_fingerprint_rejects_non_32_byte_input():
    with pytest.raises(ValueError):
        fingerprint_for_pubkey(b"\x00" * 31)


# ── state helpers (Commit B) ────────────────────────────────────────


def _open_state(tmp_path):
    """Open a temp State DB for the state-helper tests. Uses the same
    sqlite store the daemon uses; full schema migrations run."""
    from one_link.state import State
    return State(tmp_path / "state.db")


def test_queue_rotation_announcement_is_idempotent_on_peer_new_fp(tmp_path):
    """Queueing the same (peer_fp, new_fp) twice returns the same
    row id - we don't duplicate. A retry of the queue path (e.g. UI
    re-submission, daemon restart in mid-rotation) is a no-op."""
    state = _open_state(tmp_path)
    a = state.queue_rotation_announcement(
        peer_fp="aa" * 32, old_fp="bb" * 32, new_fp="cc" * 32,
        cert_json='{"v":1}', sig_hex="00" * 64,
    )
    b = state.queue_rotation_announcement(
        peer_fp="aa" * 32, old_fp="bb" * 32, new_fp="cc" * 32,
        cert_json='{"v":1}', sig_hex="00" * 64,
    )
    assert a == b
    rows = state.list_pending_rotation_announcements()
    assert len(rows) == 1


def test_list_pending_rotation_announcements_filters_acked(tmp_path):
    state = _open_state(tmp_path)
    state.queue_rotation_announcement(
        peer_fp="aa" * 32, old_fp="bb" * 32, new_fp="cc" * 32,
        cert_json='{"v":1}', sig_hex="00" * 64,
    )
    state.queue_rotation_announcement(
        peer_fp="dd" * 32, old_fp="bb" * 32, new_fp="cc" * 32,
        cert_json='{"v":1}', sig_hex="00" * 64,
    )
    state.ack_rotation_announcement(peer_fp="aa" * 32, new_fp="cc" * 32)
    assert len(state.list_pending_rotation_announcements()) == 1  # unacked only
    assert len(state.list_pending_rotation_announcements(unacked_only=False)) == 2


def test_mark_rotation_attempt_increments_counter(tmp_path):
    state = _open_state(tmp_path)
    row_id = state.queue_rotation_announcement(
        peer_fp="aa" * 32, old_fp="bb" * 32, new_fp="cc" * 32,
        cert_json='{"v":1}', sig_hex="00" * 64,
    )
    state.mark_rotation_attempt(row_id)
    state.mark_rotation_attempt(row_id)
    state.mark_rotation_attempt(row_id)
    rows = state.list_pending_rotation_announcements()
    assert rows[0]["attempt_count"] == 3
    assert rows[0]["last_attempt_ms"] is not None


def test_ack_rotation_announcement_is_idempotent(tmp_path):
    state = _open_state(tmp_path)
    state.queue_rotation_announcement(
        peer_fp="aa" * 32, old_fp="bb" * 32, new_fp="cc" * 32,
        cert_json='{"v":1}', sig_hex="00" * 64,
    )
    n1 = state.ack_rotation_announcement(peer_fp="aa" * 32, new_fp="cc" * 32)
    n2 = state.ack_rotation_announcement(peer_fp="aa" * 32, new_fp="cc" * 32)
    assert n1 == 1
    assert n2 == 0  # already acked, no-op


def test_rotation_announcement_summary_counts(tmp_path):
    state = _open_state(tmp_path)
    state.queue_rotation_announcement(
        peer_fp="aa" * 32, old_fp="bb" * 32, new_fp="cc" * 32,
        cert_json='{}', sig_hex="00" * 64,
    )
    state.queue_rotation_announcement(
        peer_fp="dd" * 32, old_fp="bb" * 32, new_fp="cc" * 32,
        cert_json='{}', sig_hex="00" * 64,
    )
    state.queue_rotation_announcement(
        peer_fp="ee" * 32, old_fp="bb" * 32, new_fp="cc" * 32,
        cert_json='{}', sig_hex="00" * 64,
    )
    state.ack_rotation_announcement(peer_fp="aa" * 32, new_fp="cc" * 32)
    summary = state.rotation_announcement_summary()
    assert summary == {"total": 3, "pending": 2, "acked": 1}


# ── perform_local_rotation orchestration ────────────────────────────


def test_perform_local_rotation_persists_new_seed_and_clears_identity(tmp_path, monkeypatch):
    """End-to-end of the orchestration: new seed written, identity.key
    + DRK cleared, new phrase returned, cert minted under the OLD key."""
    from one_link import identity_rotation, master_seed, paths
    # Layout the daemon expects: seed lives in data_dir; identity.key
    # lives in config_dir (which paths.key_path() resolves to).
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    monkeypatch.setattr(paths, "key_path", lambda: config_dir / "identity.key")
    # Plant an "old" identity + seed.
    old_seed = master_seed.load_or_create_seed(data_dir)[0]
    old_priv = master_seed.derive_identity_priv(old_seed)
    (config_dir / "identity.key").write_bytes(b"sentinel-identity")
    (data_dir / "data-root-key.bin").write_bytes(b"sentinel-drk")

    result = identity_rotation.perform_local_rotation(
        data_dir=data_dir,
        old_priv=old_priv,
        pinned_peer_fingerprints=[],
        reason=identity_rotation.RotationReason.COMPROMISE.value,
    )

    # New phrase round-trips.
    assert len(result.new_phrase.split()) == 24
    # Seed file replaced.
    seed_on_disk = master_seed.load_seed(data_dir)
    assert seed_on_disk is not None
    assert seed_on_disk != old_seed
    # Identity.key + DRK gone.
    assert not (config_dir / "identity.key").exists()
    assert not (data_dir / "data-root-key.bin").exists()
    # Cert verifies under the OLD pubkey (proving the cert was signed
    # with the old private key, NOT the new one).
    identity_rotation.verify_certificate(
        cert=result.cert,
        expected_old_pubkey=old_priv.public_key().public_bytes_raw(),
    )
    # And the cert names the NEW pubkey derived from the new seed.
    new_priv = master_seed.derive_identity_priv(seed_on_disk)
    expected_new_pub = new_priv.public_key().public_bytes_raw()
    assert result.cert.new_pub_hex == expected_new_pub.hex()


def test_perform_local_rotation_queues_per_peer_announcements(tmp_path, monkeypatch):
    """When state is passed, one row per pinned peer is queued, and
    the cert blob in each row reconstructs to the SAME cert
    perform_local_rotation returned."""
    from one_link import identity_rotation, master_seed, paths
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    monkeypatch.setattr(paths, "key_path", lambda: config_dir / "identity.key")
    old_seed = master_seed.load_or_create_seed(data_dir)[0]
    old_priv = master_seed.derive_identity_priv(old_seed)

    state = _open_state(tmp_path)
    peers = ["aa" * 32, "bb" * 32, "cc" * 32]
    result = identity_rotation.perform_local_rotation(
        data_dir=data_dir,
        old_priv=old_priv,
        pinned_peer_fingerprints=peers,
        state=state,
    )
    assert result.queued_peer_count == 3
    rows = state.list_pending_rotation_announcements()
    assert {r["peer_fp"] for r in rows} == set(peers)
    # Reconstruct cert from a row and verify it under the old pubkey.
    sample = rows[0]
    rebuilt = identity_rotation.RotationCertificate.from_wire_dict({
        "cert_json": sample["cert_json"],
        "sig_hex": sample["sig_hex"],
    })
    identity_rotation.verify_certificate(
        cert=rebuilt,
        expected_old_pubkey=old_priv.public_key().public_bytes_raw(),
    )


def test_perform_local_rotation_rejects_unknown_reason(tmp_path, monkeypatch):
    from one_link import identity_rotation, master_seed, paths
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    monkeypatch.setattr(paths, "key_path", lambda: config_dir / "identity.key")
    seed = master_seed.load_or_create_seed(data_dir)[0]
    priv = master_seed.derive_identity_priv(seed)
    with pytest.raises(ValueError, match="reason must be"):
        identity_rotation.perform_local_rotation(
            data_dir=data_dir, old_priv=priv,
            pinned_peer_fingerprints=[], reason="trust_me",
        )


# ── HTTP endpoint wiring ────────────────────────────────────────────


def test_rotate_endpoint_registered_guarded_rate_limited():
    """Routes /api/v1/recovery/rotate{,/status} exist, both _guarded,
    rotate has a low rate limit (security-sensitive)."""
    from types import SimpleNamespace
    from one_link.server import UIServer
    daemon = SimpleNamespace(state=None, peer_rtc=None)
    server = UIServer(daemon)
    methods: dict[str, set[str]] = {}
    for resource in server.app.router.resources():
        info = resource.get_info()
        path = info.get("path") or info.get("formatter") or ""
        if path in ("/api/v1/recovery/rotate", "/api/v1/recovery/rotate/status"):
            for route in resource:
                methods.setdefault(path, set()).add(route.method)
    assert "POST" in methods.get("/api/v1/recovery/rotate", set())
    assert "GET" in methods.get("/api/v1/recovery/rotate/status", set())

    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "src" / "one_link" / "server.py").read_text(encoding="utf-8")
    for path in ("/api/v1/recovery/rotate", "/api/v1/recovery/rotate/status"):
        idx = src.find(f'"{path}"')
        assert idx > 0
        line_start = src.rfind("\n", 0, idx) + 1
        line_end = src.find("\n", idx)
        line = src[line_start:line_end]
        assert "self._guarded(" in line, f"{path} not guarded: {line!r}"
    handler_idx = src.find("async def api_recovery_rotate(")
    assert handler_idx > 0
    body = src[handler_idx:handler_idx + 5000]
    assert "_rate_limited(" in body
    assert '"recovery_rotate"' in body
    assert "confirmed_rotate" in body
    assert "_recovery_no_store_headers" in body
