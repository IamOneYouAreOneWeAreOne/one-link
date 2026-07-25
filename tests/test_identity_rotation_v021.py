"""v0.21.x identity key rotation - cryptographic primitive tests.

The flawless gate on rotation is that a cert signed by the OLD key
verifies under the OLD pinned pubkey AND fails under anything else.
If that property breaks, the entire rotation flow becomes either
spoofable (attacker rotates your identity) or unusable (legitimate
rotations are rejected). This file pins every detail.
"""
from __future__ import annotations

import json

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


def test_fingerprint_matches_blake3_of_pubkey():
    """Rotation fingerprints must use BLAKE3 - same hash function the
    rest of the daemon (identity._fingerprint / fingerprint_of /
    state.peers.fingerprint) uses. The two-daemon integration test
    catches the bug if this drifts back to SHA-256."""
    import blake3
    pub = b"\x00" * 32
    expected = blake3.blake3(pub).hexdigest()
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


def test_perform_local_rotation_stages_then_replays_atomically(tmp_path, monkeypatch):
    """Live authority is unchanged until boot replay commits the journal."""
    from one_link import (
        identity_rotation,
        master_seed,
        mnemonic,
        paths,
        recovery_api,
    )
    # Layout the daemon expects: seed lives in data_dir; identity.key
    # lives in config_dir (which paths.key_path() resolves to).
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    monkeypatch.setattr(paths, "key_path", lambda: config_dir / "identity.key")
    # Establish fully converged old authority, as daemon boot does.
    old_seed = master_seed.load_or_create_seed(data_dir)[0]
    old_priv = master_seed.derive_identity_priv(old_seed)
    master_seed.install_seed_derived_authority(
        data_dir,
        identity_path=config_dir / "identity.key",
        seed=old_seed,
        previous_seed=old_seed,
    )
    old_identity_blob = (config_dir / "identity.key").read_bytes()
    old_drk_blob = (data_dir / "data-root-key.bin").read_bytes()

    result = identity_rotation.perform_local_rotation(
        data_dir=data_dir,
        old_priv=old_priv,
        pinned_peer_fingerprints=[],
        reason=identity_rotation.RotationReason.COMPROMISE.value,
    )

    # New phrase round-trips.
    assert len(result.new_phrase.split()) == 24
    # Staging never mutates or pre-deletes current authority.
    assert master_seed.load_seed(data_dir) == old_seed
    assert (config_dir / "identity.key").read_bytes() == old_identity_blob
    assert (data_dir / "data-root-key.bin").read_bytes() == old_drk_blob
    assert result.staged_peer_count == 0
    assert result.queued_peer_count == 0
    assert recovery_api.pending_recovery_summary(data_dir)["kind"] == "rotation"
    # Cert verifies under the OLD pubkey (proving the cert was signed
    # with the old private key, NOT the new one).
    identity_rotation.verify_certificate(
        cert=result.cert,
        expected_old_pubkey=old_priv.public_key().public_bytes_raw(),
    )
    # And the cert names the NEW pubkey from the phrase/journal.
    new_seed = mnemonic.decode(result.new_phrase)
    new_priv = master_seed.derive_identity_priv(new_seed)
    expected_new_pub = new_priv.public_key().public_bytes_raw()
    assert result.cert.new_pub_hex == expected_new_pub.hex()

    applied = recovery_api.complete_pending_recovery(
        data_dir=data_dir,
        identity_path=config_dir / "identity.key",
    )
    assert applied["pending_finalization"] is True
    assert master_seed.load_seed(data_dir) == new_seed
    assert recovery_api.has_pending_recovery(data_dir) is True
    state = _open_state(data_dir)
    finalized = recovery_api.finalize_pending_rotation(
        data_dir=data_dir,
        state=state,
        identity_path=config_dir / "identity.key",
    )
    assert finalized == {"completed": True, "queued_peer_count": 0}
    assert recovery_api.has_pending_recovery(data_dir) is False


def test_perform_local_rotation_queues_peer_snapshot_only_at_boot(tmp_path, monkeypatch):
    """The complete peer snapshot lands atomically after authority replay."""
    from one_link import identity_rotation, master_seed, paths, recovery_api
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    monkeypatch.setattr(paths, "key_path", lambda: config_dir / "identity.key")
    old_seed = master_seed.load_or_create_seed(data_dir)[0]
    old_priv = master_seed.derive_identity_priv(old_seed)
    master_seed.install_seed_derived_authority(
        data_dir,
        identity_path=config_dir / "identity.key",
        seed=old_seed,
        previous_seed=old_seed,
    )

    state = _open_state(tmp_path)
    peers = ["aa" * 32, "bb" * 32, "cc" * 32]
    result = identity_rotation.perform_local_rotation(
        data_dir=data_dir,
        old_priv=old_priv,
        pinned_peer_fingerprints=peers,
        state=state,
    )
    assert result.staged_peer_count == 3
    assert result.queued_peer_count == 0
    # Passing live State cannot mutate it; the compatibility argument is inert.
    assert state.list_pending_rotation_announcements() == []
    recovery_api.complete_pending_recovery(
        data_dir=data_dir,
        identity_path=config_dir / "identity.key",
    )
    finalized = recovery_api.finalize_pending_rotation(
        data_dir=data_dir,
        state=state,
        identity_path=config_dir / "identity.key",
    )
    assert finalized == {"completed": True, "queued_peer_count": 3}
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


def test_transition_peer_fingerprint_renames_in_place_when_new_fp_unknown(tmp_path):
    """Happy path: rotation cert arrives, new_fp hasn't been seen
    on this daemon yet, so the peers row is renamed in place + all
    other tables cascade."""
    state = _open_state(tmp_path)
    old_fp = "11" * 32
    new_fp = "22" * 32
    new_pub = b"\x02" * 32
    state.upsert_peer(
        fingerprint=old_fp, short_id="oldshort",
        pubkey=b"\x01" * 32, hostname="alice.lan",
    )
    state.set_peer_trust(old_fp, "pinned")
    # Plant some downstream per-peer state.
    state.queue_rotation_announcement(
        peer_fp=old_fp, old_fp="ee" * 32, new_fp="ff" * 32,
        cert_json='{"v":1}', sig_hex="00" * 64,
    )

    transitioned = state.transition_peer_fingerprint(
        old_fp=old_fp, new_fp=new_fp, new_pubkey=new_pub,
    )
    assert transitioned is True

    # peers row now has new_fp + new_pubkey.
    old_peer = state.get_peer(old_fp)
    new_peer = state.get_peer(new_fp)
    assert old_peer is None
    assert new_peer is not None
    assert new_peer.pubkey == new_pub
    assert new_peer.trust == "pinned"  # preserved
    assert new_peer.hostname == "alice.lan"  # preserved

    # Cascaded: pending_rotation_announcements moved with the peer.
    rows = state.list_pending_rotation_announcements(peer_fp=new_fp)
    assert len(rows) == 1


def test_transition_peer_fingerprint_preserves_alias_mute_dm_ttl_verified(tmp_path):
    """Every per-peer field the user has set must survive the
    transition. A user who renamed their friend, muted them, and
    verified them in person should still see all of that after the
    rotation."""
    state = _open_state(tmp_path)
    old_fp = "33" * 32
    new_fp = "44" * 32
    state.upsert_peer(
        fingerprint=old_fp, short_id="bob",
        pubkey=b"\x03" * 32, hostname="bob.lan",
    )
    state.set_peer_trust(old_fp, "pinned")
    import time as _time
    now_ms = int(_time.time() * 1000)
    state.set_peer_profile(old_fp, local_alias="Bob from work")
    state.set_peer_muted_until(old_fp, now_ms + 86400000)
    state.set_peer_verified(
        old_fp, method="sas-digits", note="met at lunch",
    )
    state.set_peer_dm_ttl(old_fp, 60_000)

    state.transition_peer_fingerprint(
        old_fp=old_fp, new_fp=new_fp, new_pubkey=b"\x04" * 32,
    )

    new_peer = state.get_peer(new_fp)
    assert new_peer is not None
    assert new_peer.local_alias == "Bob from work"
    assert new_peer.verified_method == "sas-digits"
    assert new_peer.verified_note == "met at lunch"
    assert new_peer.verified_at_ms is not None
    assert new_peer.dm_ttl_ms == 60_000
    assert new_peer.muted_until_ms is not None
    assert new_peer.muted_until_ms > int(_time.time() * 1000)


def test_transition_peer_fingerprint_returns_false_on_unknown_peer(tmp_path):
    state = _open_state(tmp_path)
    transitioned = state.transition_peer_fingerprint(
        old_fp="aa" * 32, new_fp="bb" * 32, new_pubkey=b"\x00" * 32,
    )
    assert transitioned is False


def test_transition_peer_fingerprint_merges_when_new_fp_already_exists(tmp_path):
    """If a daemon hand-shook with the new identity BEFORE the cert
    arrived, it has a peers row at new_fp already. Transition must
    promote the OLD per-peer state onto the new row + delete the
    old row."""
    state = _open_state(tmp_path)
    old_fp = "55" * 32
    new_fp = "66" * 32
    state.upsert_peer(
        fingerprint=old_fp, short_id="x", pubkey=b"\x05" * 32, hostname="x.lan",
    )
    state.set_peer_trust(old_fp, "pinned")
    state.set_peer_profile(old_fp, local_alias="X my friend")
    state.upsert_peer(
        fingerprint=new_fp, short_id="x2", pubkey=b"\x06" * 32, hostname="x.lan",
    )
    # new_fp is "pending" by default - rotation should bring the
    # OLD pinned trust forward.

    state.transition_peer_fingerprint(
        old_fp=old_fp, new_fp=new_fp, new_pubkey=b"\x06" * 32,
    )

    # OLD row gone; NEW row inherited the alias + pinned trust.
    assert state.get_peer(old_fp) is None
    new_peer = state.get_peer(new_fp)
    assert new_peer is not None
    assert new_peer.trust == "pinned"
    assert new_peer.local_alias == "X my friend"


def test_transition_peer_fingerprint_rejects_same_fp_or_bad_input(tmp_path):
    state = _open_state(tmp_path)
    with pytest.raises(ValueError, match="must differ"):
        state.transition_peer_fingerprint(
            old_fp="aa" * 32, new_fp="aa" * 32, new_pubkey=b"\x00" * 32,
        )
    with pytest.raises(ValueError, match="32 bytes"):
        state.transition_peer_fingerprint(
            old_fp="aa" * 32, new_fp="bb" * 32, new_pubkey=b"\x00" * 31,
        )


# ── UI symbols (Commit D) ───────────────────────────────────────────


def test_index_html_exposes_rotate_api_methods():
    """The UI's api wrapper has both endpoints the rotation flow
    needs: trigger rotation + read live status counters."""
    from pathlib import Path
    html = (Path(__file__).resolve().parents[1] / "src" / "one_link" / "web" / "index.html").read_text(encoding="utf-8")
    assert "recoveryRotate(reason)" in html
    assert '"/api/v1/recovery/rotate"' in html
    assert 'recoveryRotateStatus() { return this.get("/api/v1/recovery/rotate/status"); }' in html


def test_rotate_status_endpoint_attaches_peer_display_labels():
    """The status endpoint must include a peer_label for every row so
    the UI can render 'Alice acked' instead of '11ab...'. The label
    falls back through alias > hostname > short_id > short fp."""
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "src" / "one_link" / "server.py").read_text(encoding="utf-8")
    idx = src.find("async def api_recovery_rotate_status(")
    assert idx > 0
    body = src[idx:idx + 3000]
    assert '"peer_label"' in body
    # The fallback chain attribute lookups must all be present so
    # peers without an alias still get a sensible label.
    assert "local_alias" in body
    assert "hostname" in body
    assert "short_id" in body


def test_index_html_rotate_card_in_wizard():
    """The wizard's modal must include the rotation card and route
    clicks on its 'Rotate identity' button through the same modal-
    opener function the tests reference."""
    from pathlib import Path
    html = (Path(__file__).resolve().parents[1] / "src" / "one_link" / "web" / "index.html").read_text(encoding="utf-8")
    assert 'id="recwiz-track-rotate"' in html
    assert 'data-track="rotate"' in html
    # Wizard's click dispatcher routes open-rotate to openRotationModal.
    assert 'action === "open-rotate"' in html
    assert "openRotationModal()" in html
    # Card renderer is called from the refresh.
    assert "_recwizRenderRotateCard" in html


def test_rotate_card_shows_current_identity_fingerprint():
    """A user looking at the rotation card should see their CURRENT
    identity fingerprint so they can: (a) verify which install
    they're running as before clicking Rotate, and (b) visually
    confirm post-rotation that the identity actually changed. The
    card reads from state.me.fingerprint (already populated from
    the existing /api/me response - no new endpoint needed)."""
    from pathlib import Path
    html = (Path(__file__).resolve().parents[1] / "src" / "one_link" / "web" / "index.html").read_text(encoding="utf-8")
    idx = html.find("async function _recwizRenderRotateCard()")
    assert idx > 0
    body = html[idx:idx + 7000]
    assert "state.me?.fingerprint" in body
    assert "Current identity" in body
    # Truncated for readability so the row fits.
    assert ".slice(0, 16)" in body


def test_home_screen_rotation_banner_exists_and_polls_status():
    """The home-screen rotation banner must be wired so users who
    rotated and closed the wizard still see 'X of Y peers acked'
    without having to dig back into Settings. The banner element
    + the poll function + the dismiss/open click handlers + the
    WS-event refresh must all be present."""
    from pathlib import Path
    html = (Path(__file__).resolve().parents[1] / "src" / "one_link" / "web" / "index.html").read_text(encoding="utf-8")
    # CSS class.
    assert ".rotation-banner" in html
    # Banner element.
    assert 'id="rotation-banner"' in html
    assert 'id="rotation-banner-text"' in html
    assert 'id="rotation-banner-dismiss"' in html
    assert 'id="rotation-banner-open"' in html
    # Poll function exists + reads rotation status.
    assert "async function refreshRotationBanner()" in html
    assert "api.recoveryRotateStatus()" in html
    # Dismiss persists for the session (not localStorage - rotation
    # IS incomplete until acks land, so re-show on restart is right).
    assert 'sessionStorage.setItem("ol_rotation_banner_dismissed"' in html
    # Open button hops into the recovery wizard so the user can see
    # per-peer detail.
    assert "_showRecoveryWizard()" in html
    # WS dispatcher calls refreshRotationBanner on rotation events.
    idx = html.find('m.type === "peer_rotated"')
    assert idx > 0
    body = html[idx:idx + 1500]
    assert "refreshRotationBanner()" in body


def test_ws_dispatcher_toasts_peer_rotated_with_display_label():
    """When a peer rotates, the user should see a calm informational
    toast resolving the display label so they notice the change even
    if they're looking at a different conversation. Source-text gate
    pins the toast call + the alias > hostname > short_id fallback
    chain + the safe-text fallback for unknown peers."""
    from pathlib import Path
    html = (Path(__file__).resolve().parents[1] / "src" / "one_link" / "web" / "index.html").read_text(encoding="utf-8")
    idx = html.find('m.type === "peer_rotated"')
    assert idx > 0
    body = html[idx:idx + 2500]
    assert "rotated their identity key" in body
    assert "local_alias" in body
    assert "hostname" in body
    assert "short_id" in body
    # Tries both new and old fp to ride the race between the WS
    # event and the peers refresh.
    assert "new_fingerprint" in body
    assert "old_fingerprint" in body


def test_ws_dispatcher_handles_peer_rotated_and_ack_events():
    """The daemon broadcasts peer_rotated when an inbound cert
    applies and rotation_announcement_acked when one of our certs
    gets acknowledged. The UI's WS dispatcher must handle both so
    the rotation card refreshes live without the user clicking
    'Refresh status'."""
    from pathlib import Path
    html = (Path(__file__).resolve().parents[1] / "src" / "one_link" / "web" / "index.html").read_text(encoding="utf-8")
    # Both event types branched in the dispatcher.
    assert 'm.type === "peer_rotated"' in html
    assert 'm.type === "rotation_announcement_acked"' in html
    # The handler re-renders the rotation card when the wizard is open.
    assert '_recwizRenderRotateCard()' in html
    # And refreshes peers so the sidebar reflects the new identity.
    # (refreshPeers is also called from many other branches; the
    # check above + the rotation-card render together are the
    # rotation-specific assertion.)


def test_index_html_rotate_card_renders_per_peer_ack_list():
    """When rotations are in flight, the rotation card must show a
    per-peer status row using peer_label so the user can see exactly
    who is up to date. Otherwise an 'X of Y acked' counter alone
    doesn't tell the user which peers need attention."""
    from pathlib import Path
    html = (Path(__file__).resolve().parents[1] / "src" / "one_link" / "web" / "index.html").read_text(encoding="utf-8")
    idx = html.find("async function _recwizRenderRotateCard()")
    assert idx > 0
    body = html[idx:idx + 7000]
    # Renders peer rows from status.rows.
    assert "status.rows" in body
    assert "peer_label" in body
    # Sorts pending before acked so action items rise to the top.
    assert "pending first" in body
    # Has a Refresh button when in flight (live polling without WS).
    assert "data-recwiz-rotate-refresh" in body


def test_index_html_rotate_modal_demands_confirm_checkbox_and_reason():
    """The rotation modal must require explicit confirmation + offer
    every documented reason value. Source-text gate so a refactor
    that loses the checkbox surfaces immediately."""
    from pathlib import Path
    html = (Path(__file__).resolve().parents[1] / "src" / "one_link" / "web" / "index.html").read_text(encoding="utf-8")
    # Builder + symbols.
    assert "function _ensureRotationModal()" in html
    assert "async function openRotationModal()" in html
    assert "function _renderRotationModalIntro()" in html
    assert "async function _recwizRotateSubmit()" in html
    # Reason picker covers every backend-validated value.
    for reason in ("scheduled", "compromise", "device_lost", "other"):
        assert f'value="{reason}"' in html
    # Confirm checkbox + submit-disabled gating.
    assert 'id="recwiz-rotate-confirm"' in html
    assert 'submit.disabled = !confirmBox.checked' in html


def test_index_html_rotate_success_shows_new_phrase_and_restart_prompt():
    """A staged rotation reports the live/boot boundary truthfully."""
    from pathlib import Path
    html = (Path(__file__).resolve().parents[1] / "src" / "one_link" / "web" / "index.html").read_text(encoding="utf-8")
    submit_idx = html.find("async function _recwizRotateSubmit(")
    assert submit_idx > 0
    submit_body = html[submit_idx:submit_idx + 1800]
    assert "api.recoveryRotate" in submit_body
    assert "_recwizRenderRotationPhrase" in submit_body
    idx = html.find("function _recwizRenderRotationPhrase(")
    assert idx > 0
    body = html[idx:idx + 5000]
    # Renders the new 24 words.
    assert "new_words" in body
    assert "recwiz-words" in body
    # Restart prompt.
    assert "Restart One Link" in body
    assert "Identity rotation staged" in body
    assert "No live key or queue changed yet" in body
    assert "staged_peer_count" in body
    assert "Identity rotated." not in body
    # Print path reuses the existing phrase-print helper from the
    # setup wizard so we don't duplicate the print HTML.
    assert "_recwizPhrasePrint" in body


# ── wire protocol round-trip (Commit C-wire) ────────────────────────


def test_end_to_end_cert_round_trip_through_state(tmp_path):
    """Full simulated round-trip: sender mints cert under OLD key,
    receiver looks up its pinned OLD pubkey, verifies cert, applies
    transition via state.transition_peer_fingerprint. After the
    round-trip the receiver's peer state has migrated from old_fp
    to new_fp with all per-peer fields preserved."""
    from one_link import identity_rotation
    from one_link.state import State
    # Sender's keys.
    sender_old = Ed25519PrivateKey.generate()
    sender_new_pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    sender_old_pub = sender_old.public_key().public_bytes_raw()
    old_fp = identity_rotation.fingerprint_for_pubkey(sender_old_pub)
    new_fp = identity_rotation.fingerprint_for_pubkey(sender_new_pub)

    # Receiver state: pin the sender's OLD identity with rich per-peer state.
    receiver = State(tmp_path / "receiver.db")
    receiver.upsert_peer(
        fingerprint=old_fp, short_id="snd", pubkey=sender_old_pub, hostname="sender.lan",
    )
    receiver.set_peer_trust(old_fp, "pinned")
    receiver.set_peer_profile(old_fp, local_alias="My friend")
    receiver.set_peer_verified(old_fp, method="sas-digits", note="met IRL")

    # Sender mints + ships the cert as a wire dict.
    cert = identity_rotation.mint_certificate(
        old_priv=sender_old, new_pub=sender_new_pub,
        reason=identity_rotation.RotationReason.SCHEDULED.value,
    )
    wire = cert.to_wire_dict()

    # Receiver side: parse + verify + apply.
    rebuilt = identity_rotation.RotationCertificate.from_wire_dict(wire)
    pinned = receiver.get_peer(rebuilt.old_fp)
    assert pinned is not None
    applied = identity_rotation.apply_certificate_to_peer(
        cert=rebuilt,
        expected_old_pubkey=bytes(pinned.pubkey),
        current_pinned_fp=pinned.fingerprint,
    )
    transitioned = receiver.transition_peer_fingerprint(
        old_fp=applied.old_fp,
        new_fp=applied.new_fp,
        new_pubkey=applied.new_pubkey,
    )
    assert transitioned is True

    # After round-trip: receiver knows the sender as new_fp,
    # all per-peer state preserved.
    migrated = receiver.get_peer(new_fp)
    assert migrated is not None
    assert migrated.pubkey == sender_new_pub
    assert migrated.trust == "pinned"
    assert migrated.local_alias == "My friend"
    assert migrated.verified_method == "sas-digits"
    assert receiver.get_peer(old_fp) is None


def test_wire_dispatcher_registers_rotation_cert_branches():
    """The dispatcher in daemon._on_peer_message must route both
    ROTATION_CERT and ROTATION_CERT_ACK. Source-text gate so a
    refactor that drops either branch surfaces as a test failure."""
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "src" / "one_link" / "daemon.py").read_text(encoding="utf-8")
    # Both wire-type branches present.
    assert 'elif t == "ROTATION_CERT":' in src
    assert 'elif t == "ROTATION_CERT_ACK":' in src
    assert "_handle_rotation_cert" in src
    assert "_handle_rotation_cert_ack" in src
    # Opportunistic-delivery hook fires at the end of CAPS.
    assert "_drain_pending_rotation_certs_to" in src
    # ROTATION_CERT_ACK carries the new_fp so the sender can find
    # the right pending row to mark.
    assert '"ROTATION_CERT_ACK"' in src


def test_handle_rotation_cert_silent_drops_unknown_old_fp(tmp_path):
    """If the receiver has no pinned record for cert.old_fp, the cert
    isn't ours to apply - silent drop. The receiver state is not
    modified; no exception leaks."""
    import asyncio
    from types import SimpleNamespace
    from one_link import identity_rotation
    from one_link.state import State

    sender_old = Ed25519PrivateKey.generate()
    sender_new = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    cert = identity_rotation.mint_certificate(old_priv=sender_old, new_pub=sender_new)

    receiver = State(tmp_path / "r.db")
    # No upsert_peer for cert.old_fp - the receiver doesn't know
    # this sender's old identity.

    # Build a minimal Daemon stub that has just the methods
    # _handle_rotation_cert touches.
    from one_link.daemon import Daemon
    sent: list[bytes] = []

    class _Chan:
        async def send(self, frame): sent.append(frame)
    daemon = Daemon.__new__(Daemon)
    daemon.state = receiver
    daemon.ui_server = None
    daemon.me = SimpleNamespace(short_id="me")

    asyncio.run(daemon._handle_rotation_cert(
        _Chan(),
        {"cert": cert.to_wire_dict(), "id": "x"},
        peer_fp="ff" * 32,
    ))
    # No state mutation; no ack sent (silent drop on unknown old_fp).
    assert receiver.get_peer(cert.old_fp) is None
    assert receiver.get_peer(cert.new_fp) is None
    assert sent == []


def test_record_authorized_rotation_inserts_auto_acked_row(tmp_path):
    """The state helper writes a key_change_events row with
    severity='low' and acked_ms preset so existing surfaces
    (activity feed, device drawer) show the rotation as a
    historical event without the manual-confirm warning UI."""
    state = _open_state(tmp_path)
    row_id = state.record_authorized_rotation(
        old_fingerprint="aa" * 32, new_fingerprint="bb" * 32,
        old_pub_hex="00" * 32, new_pub_hex="01" * 32,
        hostname="alice.lan", ts_ms=1_700_000_000_000,
    )
    assert row_id is not None and row_id > 0
    rows = state.list_key_change_events()
    assert len(rows) == 1
    r = rows[0]
    assert r["old_fingerprint"] == "aa" * 32
    assert r["new_fingerprint"] == "bb" * 32
    assert r["hostname"] == "alice.lan"
    assert r["severity"] == "low"
    # Pre-acked so the manual-confirm warning UI does not fire.
    assert r["acked_ms"] == 1_700_000_000_000


def test_record_authorized_rotation_is_idempotent(tmp_path):
    """Repeated cert delivery for the same (old_fp, new_fp) must
    not duplicate the audit row."""
    state = _open_state(tmp_path)
    state.record_authorized_rotation(
        old_fingerprint="aa" * 32, new_fingerprint="bb" * 32,
        old_pub_hex="00" * 32, new_pub_hex="01" * 32,
    )
    duplicate = state.record_authorized_rotation(
        old_fingerprint="aa" * 32, new_fingerprint="bb" * 32,
        old_pub_hex="00" * 32, new_pub_hex="01" * 32,
    )
    assert duplicate is None
    rows = state.list_key_change_events()
    assert len(rows) == 1


def test_handle_rotation_cert_writes_authorized_rotation_audit():
    """After applying a rotation cert the daemon handler writes a
    key_change_events audit row so the activity feed picks it up."""
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "src" / "one_link" / "daemon.py").read_text(encoding="utf-8")
    idx = src.find("async def _handle_rotation_cert(")
    assert idx > 0
    body = src[idx:idx + 5000]
    assert "record_authorized_rotation" in body


def test_handle_rotation_cert_applies_and_acks_when_old_fp_pinned(tmp_path):
    """Happy path through the inbound handler: cert verifies, state
    transitions, ack is sent back to the sender."""
    import asyncio
    from types import SimpleNamespace
    from one_link import identity_rotation
    from one_link.state import State

    sender_old = Ed25519PrivateKey.generate()
    sender_new_pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    old_fp = identity_rotation.fingerprint_for_pubkey(
        sender_old.public_key().public_bytes_raw(),
    )
    new_fp = identity_rotation.fingerprint_for_pubkey(sender_new_pub)
    cert = identity_rotation.mint_certificate(
        old_priv=sender_old, new_pub=sender_new_pub,
    )

    receiver = State(tmp_path / "r.db")
    receiver.upsert_peer(
        fingerprint=old_fp, short_id="snd",
        pubkey=sender_old.public_key().public_bytes_raw(),
        hostname="snd.lan",
    )
    receiver.set_peer_trust(old_fp, "pinned")

    from one_link.daemon import Daemon
    sent: list[dict] = []

    class _Chan:
        async def send(self, frame):
            # Parse the encoded frame so the test can inspect it.
            from one_link.wire import decode_msg
            sent.append(decode_msg(frame))

    daemon = Daemon.__new__(Daemon)
    daemon.state = receiver
    daemon.ui_server = None
    daemon.me = SimpleNamespace(short_id="me")

    asyncio.run(daemon._handle_rotation_cert(
        _Chan(),
        {"cert": cert.to_wire_dict(), "id": "x"},
        peer_fp=new_fp,  # channel handshake gave us new identity
    ))
    # Transition applied.
    assert receiver.get_peer(old_fp) is None
    assert receiver.get_peer(new_fp) is not None
    assert receiver.get_peer(new_fp).trust == "pinned"
    # Ack frame emitted with the new_fp the receiver just pinned.
    assert len(sent) == 1
    ack = sent[0]
    assert ack.get("t") == "ROTATION_CERT_ACK"
    assert ack.get("new_fp") == new_fp
    assert ack.get("of") == "x"


def test_handle_rotation_cert_ack_marks_queue_row_acked(tmp_path):
    """Sender-side ACK handler: receiving ROTATION_CERT_ACK from a
    peer must mark the matching pending_rotation_announcements row
    acknowledged so the drain doesn't re-send."""
    import asyncio
    from one_link.state import State

    sender_state = State(tmp_path / "s.db")
    peer_fp = "aa" * 32
    sender_state.queue_rotation_announcement(
        peer_fp=peer_fp, old_fp="bb" * 32, new_fp="cc" * 32,
        cert_json='{}', sig_hex="00" * 64,
    )

    from one_link.daemon import Daemon

    class _Chan:
        async def send(self, frame): pass

    daemon = Daemon.__new__(Daemon)
    daemon.state = sender_state
    daemon.ui_server = None

    asyncio.run(daemon._handle_rotation_cert_ack(
        _Chan(),
        {"new_fp": "cc" * 32, "of": "x"},
        peer_fp=peer_fp,
    ))
    # Row is acked - no longer in the unacked list.
    assert sender_state.list_pending_rotation_announcements(peer_fp=peer_fp) == []
    # But still in the all-rows list, with acked_ms set.
    all_rows = sender_state.list_pending_rotation_announcements(
        peer_fp=peer_fp, unacked_only=False,
    )
    assert len(all_rows) == 1
    assert all_rows[0]["acked_ms"] is not None


def test_drain_sends_one_cert_per_pending_row(tmp_path):
    """The opportunistic-delivery helper sends one ROTATION_CERT
    frame per unacked queue row + bumps attempt_count on each."""
    import asyncio
    from types import SimpleNamespace
    from one_link.state import State

    state = State(tmp_path / "s.db")
    peer_fp = "aa" * 32
    state.queue_rotation_announcement(
        peer_fp=peer_fp, old_fp="bb" * 32, new_fp="cc" * 32,
        cert_json='{"v":1}', sig_hex="00" * 64,
    )

    from one_link.daemon import Daemon
    from one_link.wire import decode_msg
    sent: list[dict] = []

    class _Chan:
        async def send(self, frame): sent.append(decode_msg(frame))

    daemon = Daemon.__new__(Daemon)
    daemon.state = state
    daemon.ui_server = None
    daemon.me = SimpleNamespace(short_id="me")

    asyncio.run(daemon._drain_pending_rotation_certs_to(_Chan(), peer_fp))
    assert len(sent) == 1
    assert sent[0].get("t") == "ROTATION_CERT"
    assert sent[0].get("new_fp") == "cc" * 32
    # Attempt counter bumped.
    rows = state.list_pending_rotation_announcements(peer_fp=peer_fp)
    assert rows[0]["attempt_count"] == 1


def test_rotate_endpoint_refuses_double_rotate_without_restart():
    """A pending journal or legacy signer/seed mismatch blocks rotation.

    The journal guard is primary; the signer-vs-disk comparison retains
    defense in depth for pre-journal partial state or manual replacement.
    """
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "src" / "one_link" / "server.py").read_text(encoding="utf-8")
    idx = src.find("async def api_recovery_rotate(")
    assert idx > 0
    body = src[idx:idx + 6000]
    assert "restart_required_before_rotate" in body
    assert "pending_recovery_summary" in body
    assert "on_disk_seed" in body
    assert "master_seed.load_seed" in body
    assert "derive_identity_priv" in body
    # 409 (conflict) is the right code - the request is valid but the
    # current state forbids it; the same code we use for the
    # destructive-restore-requires-confirmation guard.
    assert "status=409" in body


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
    # Bound the source contract by the next handler declaration instead of a
    # brittle character count. Security comments and defensive branches are
    # expected to grow without silently moving the final no-store header out
    # of the assertion window.
    next_handler_idx = src.find(
        "async def api_recovery_rotate_status(", handler_idx,
    )
    assert next_handler_idx > handler_idx
    body = src[handler_idx:next_handler_idx]
    assert "_rate_limited(" in body
    assert '"recovery_rotate"' in body
    assert "confirmed_rotate" in body
    assert "_recovery_no_store_headers" in body


# ── inbound cert handler auto-acks v0.7.8 key-change banner ─────────


def test_inbound_rotation_cert_handler_acks_pending_key_change_row(tmp_path):
    """Behavioral test: plant a key_change_events row for new_fp
    (simulating v0.7.8 detection firing first), drive a valid
    rotation cert through the handler, then assert the row is
    acked AND the UI server received a key_change_acked_all
    broadcast so any open tab refreshes live.
    """
    import asyncio
    from types import SimpleNamespace

    from one_link.daemon import Daemon
    from one_link.state import State
    from one_link.identity_rotation import (
        fingerprint_for_pubkey,
        mint_certificate,
    )

    old = Ed25519PrivateKey.generate()
    new = Ed25519PrivateKey.generate()
    old_pub = old.public_key().public_bytes_raw()
    new_pub = new.public_key().public_bytes_raw()
    old_fp = fingerprint_for_pubkey(old_pub)
    new_fp = fingerprint_for_pubkey(new_pub)

    state = State(tmp_path / "ack.db")
    state.upsert_peer(
        fingerprint=old_fp, short_id="bench",
        pubkey=old_pub, hostname="bench.lan",
    )
    state.set_peer_trust(old_fp, "pinned")

    # Plant the v0.7.8 detection-layer row by hand: the handler
    # doesn't care HOW it got there, only that ack_all... clears
    # any unacked row keyed by new_fp.
    with state._write_lock:  # noqa: SLF001 - test reaches into internals
        state._conn.execute(  # noqa: SLF001
            """
            INSERT INTO key_change_events(
                ts_ms, hostname,
                old_fingerprint, new_fingerprint,
                old_pub_hex, new_pub_hex,
                severity, acked_ms
            ) VALUES(?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                1_700_000_000_000, "bench.lan",
                old_fp, new_fp,
                old_pub.hex(), new_pub.hex(),
                "high",
            ),
        )
        state._conn.commit()  # noqa: SLF001

    # Confirm the row is initially unacked.
    pending_before = state.list_key_change_events(
        unacked_only=True, new_fingerprint=new_fp, limit=10,
    )
    assert len(pending_before) == 1

    cert = mint_certificate(
        old_priv=old, new_pub=new_pub, ts_ms=1_700_000_001_000,
    )

    broadcasts: list[dict] = []

    class _UI:
        def broadcast(self, payload):
            broadcasts.append(payload)

    sent: list[bytes] = []

    class _Chan:
        async def send(self, frame):
            sent.append(frame)

    daemon = Daemon.__new__(Daemon)
    daemon.state = state
    daemon.ui_server = _UI()
    daemon.me = SimpleNamespace(short_id="me")

    asyncio.run(daemon._handle_rotation_cert(
        _Chan(),
        {"cert": cert.to_wire_dict(), "id": "frame-1"},
        peer_fp=old_fp,
    ))

    # Row is now acked.
    pending_after = state.list_key_change_events(
        unacked_only=True, new_fingerprint=new_fp, limit=10,
    )
    assert pending_after == [], (
        f"v0.7.8 key_change_events row for new_fp was not auto-acked "
        f"after the rotation cert applied: {pending_after}"
    )

    # WS broadcast was emitted in the right shape.
    types = [b.get("type") for b in broadcasts]
    assert "key_change_acked_all" in types, (
        f"handler did not broadcast key_change_acked_all; "
        f"saw broadcasts: {types}"
    )
    ack_msg = next(b for b in broadcasts if b.get("type") == "key_change_acked_all")
    assert ack_msg.get("fingerprint") == new_fp
    assert ack_msg.get("count") == 1

    state.close()


def test_inbound_rotation_cert_handler_skips_broadcast_when_no_row(tmp_path):
    """Symmetric: if no v0.7.8 row was pending (common case: the
    cert arrived BEFORE detection fired, or detection ran on a
    different fingerprint), the handler must NOT emit a no-op
    key_change_acked_all WS broadcast. Pin so future refactors
    don't spam every WS client on every cert."""
    import asyncio
    from types import SimpleNamespace

    from one_link.daemon import Daemon
    from one_link.state import State
    from one_link.identity_rotation import (
        fingerprint_for_pubkey,
        mint_certificate,
    )

    old = Ed25519PrivateKey.generate()
    new = Ed25519PrivateKey.generate()
    old_pub = old.public_key().public_bytes_raw()
    new_pub = new.public_key().public_bytes_raw()
    old_fp = fingerprint_for_pubkey(old_pub)

    state = State(tmp_path / "noack.db")
    state.upsert_peer(
        fingerprint=old_fp, short_id="bench",
        pubkey=old_pub, hostname="bench.lan",
    )
    state.set_peer_trust(old_fp, "pinned")
    cert = mint_certificate(
        old_priv=old, new_pub=new_pub, ts_ms=1_700_000_001_000,
    )

    broadcasts: list[dict] = []

    class _UI:
        def broadcast(self, payload):
            broadcasts.append(payload)

    class _Chan:
        async def send(self, frame): pass

    daemon = Daemon.__new__(Daemon)
    daemon.state = state
    daemon.ui_server = _UI()
    daemon.me = SimpleNamespace(short_id="me")

    asyncio.run(daemon._handle_rotation_cert(
        _Chan(),
        {"cert": cert.to_wire_dict(), "id": "frame-1"},
        peer_fp=old_fp,
    ))

    types = [b.get("type") for b in broadcasts]
    assert "key_change_acked_all" not in types, (
        f"handler emitted no-op key_change_acked_all when no v0.7.8 "
        f"row was pending; broadcasts: {types}"
    )
    # peer_rotated + peers_changed should still fire (those are
    # always-on signals, not conditional on prior detection).
    assert "peer_rotated" in types
    assert "peers_changed" in types

    state.close()


def test_inbound_rotation_cert_handler_auto_acks_v078_key_change():
    """When a peer rotates legitimately the v0.7.8 hostname/key-change
    detection layer fires FIRST (red 'Did this peer really change
    keys?' banner) before our ROTATION_CERT verifies. Once the cert
    applies cleanly that banner is stale - the rotation was
    cryptographically authorized.

    The handler MUST bulk-ack any unacked key_change_events row
    targeting the new fingerprint AND broadcast key_change_acked_all
    so every open tab's banner self-clears live. Source-text gate so
    a future refactor that drops either half surfaces in CI.
    """
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "src" / "one_link" / "daemon.py").read_text(encoding="utf-8")
    idx = src.find("async def _handle_rotation_cert(")
    assert idx > 0, "_handle_rotation_cert not found"
    # Bound the search to this handler only; the next handler is
    # _handle_rotation_cert_ack which begins right after.
    end = src.find("async def _handle_rotation_cert_ack(", idx)
    assert end > idx
    body = src[idx:end]
    assert "ack_all_key_change_events_for(applied.new_fp)" in body, (
        "inbound rotation cert handler must bulk-ack v0.7.8 "
        "key_change_events rows for the new fingerprint so the "
        "stale red 'key change!' banner self-clears once the cert "
        "verifies"
    )
    assert '"type": "key_change_acked_all"' in body, (
        "handler must broadcast key_change_acked_all so the UI "
        "banner refreshes across all open tabs live"
    )
    # The broadcast must be gated on acked_count > 0 to avoid
    # firing a no-op WS event on every cert application.
    assert "acked_count > 0" in body, (
        "broadcast should be gated on acked_count > 0 to avoid "
        "no-op WS traffic when no v0.7.8 row was pending"
    )
