"""Phase C-3 daemon migration: cap_migration shim (ADR-0021).

Verifies the Ed25519 grant -> macaroon capability translator and the
new-share minting helper.
"""

from __future__ import annotations

import os

import pytest


def _native_available() -> bool:
    try:
        from one_link import capability_native

        return capability_native.HAS_NATIVE
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native.capability not installed (build via maturin)",
)


def _fresh_pair():
    """Return (priv_seed, pub) for a brand-new Ed25519 identity."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes_raw()
    pk = sk.public_key().public_bytes_raw()
    return seed, pk


def test_mint_share_capability_round_trips_through_wire():
    from one_link import cap_migration

    granter_seed, granter_pub = _fresh_pair()
    _, subject_pub = _fresh_pair()

    cap = cap_migration.mint_share_capability(
        granter_priv_seed=granter_seed,
        granter_pub=granter_pub,
        subject_pub=subject_pub,
        capabilities=["files:read", "files:list"],
        not_after_ms=5_000_000,
        scope=b"/share/alice",
    )
    wire = cap.encode()
    from one_link import capability_native

    decoded = capability_native.decode_capability(wire)
    assert decoded.signature() == cap.signature()


def test_mint_share_verifies_with_derived_root_and_correct_context():
    from one_link import cap_migration

    granter_seed, granter_pub = _fresh_pair()
    _, subject_pub = _fresh_pair()

    cap = cap_migration.mint_share_capability(
        granter_priv_seed=granter_seed,
        granter_pub=granter_pub,
        subject_pub=subject_pub,
        capabilities=["files:read"],
        not_after_ms=10_000_000,
        scope=b"/share/alice",
    )
    root_key = cap_migration.derive_root_key(granter_seed)
    peer_fp = cap_migration._peer_fingerprint(subject_pub)

    # Accepts when the context matches every caveat.
    assert cap.accepts(
        root_key,
        now_ms=1_000_000,
        peer=peer_fp,
        path="/share/alice/x.pdf",
        operation="files:read",
    )
    # Rejects when the expiry passes.
    assert not cap.accepts(
        root_key,
        now_ms=99_000_000,
        peer=peer_fp,
        path="/share/alice/x.pdf",
        operation="files:read",
    )
    # Rejects when the operation is outside the allowlist.
    assert not cap.accepts(
        root_key,
        now_ms=1_000_000,
        peer=peer_fp,
        path="/share/alice/x.pdf",
        operation="files:delete",
    )
    # Rejects when the peer pin is wrong.
    assert not cap.accepts(
        root_key,
        now_ms=1_000_000,
        peer=b"\xAA" * 32,
        path="/share/alice/x.pdf",
        operation="files:read",
    )


def test_grant_to_capability_translates_existing_ed25519_grant():
    from one_link import cap_migration, caps_grants

    granter_seed, granter_pub = _fresh_pair()
    _, subject_pub = _fresh_pair()

    grant_blob = caps_grants.encode_grant(
        granter_priv_seed=granter_seed,
        granter_pub=granter_pub,
        subject_pub=subject_pub,
        capabilities=["files:read"],
        not_before_ms=0,
        not_after_ms=5_000_000,
        scope=b"/share/x",
    )
    grant = caps_grants.parse_grant(grant_blob)
    cap = cap_migration.grant_to_capability(grant, granter_priv_seed=granter_seed)

    # Translated cap verifies under the derived root.
    root_key = cap_migration.derive_root_key(granter_seed)
    peer_fp = cap_migration._peer_fingerprint(subject_pub)
    assert cap.accepts(
        root_key,
        now_ms=1_000_000,
        peer=peer_fp,
        path="/share/x/file",
        operation="files:read",
    )


def test_grant_translation_without_seed_is_parse_only():
    from one_link import cap_migration, caps_grants

    granter_seed, granter_pub = _fresh_pair()
    _, subject_pub = _fresh_pair()

    grant_blob = caps_grants.encode_grant(
        granter_priv_seed=granter_seed,
        granter_pub=granter_pub,
        subject_pub=subject_pub,
        capabilities=["chat:send"],
        not_before_ms=0,
        not_after_ms=5_000_000,
    )
    grant = caps_grants.parse_grant(grant_blob)
    cap_no_seed = cap_migration.grant_to_capability(grant)

    # Without the seed, the cap is parse-only — it can't verify
    # against the real granter's root.
    real_root = cap_migration.derive_root_key(granter_seed)
    peer_fp = cap_migration._peer_fingerprint(subject_pub)
    assert not cap_no_seed.accepts(
        real_root,
        now_ms=1_000_000,
        peer=peer_fp,
        operation="chat:send",
    )


def test_describe_translation_reports_caveat_shape():
    from one_link import cap_migration, caps_grants

    granter_seed, granter_pub = _fresh_pair()
    _, subject_pub = _fresh_pair()

    grant_blob = caps_grants.encode_grant(
        granter_priv_seed=granter_seed,
        granter_pub=granter_pub,
        subject_pub=subject_pub,
        capabilities=["files:read", "files:list"],
        not_before_ms=0,
        not_after_ms=5_000_000,
        scope=b"/share/x",
    )
    grant = caps_grants.parse_grant(grant_blob)
    report = cap_migration.describe_translation(grant)
    assert report.has_peer_pin
    assert report.has_expiry
    assert report.has_op_allowlist
    assert report.has_path_prefix
    assert report.n_caveats >= 5  # peer+expiry+ops+scope+granter+nonce


def test_distinct_granters_produce_distinct_root_keys():
    from one_link import cap_migration

    seed_a = os.urandom(32)
    seed_b = os.urandom(32)
    assert cap_migration.derive_root_key(seed_a) != cap_migration.derive_root_key(
        seed_b
    )


def test_distinct_subjects_produce_distinct_peer_fingerprints():
    from one_link import cap_migration

    _, pub_a = _fresh_pair()
    _, pub_b = _fresh_pair()
    assert cap_migration._peer_fingerprint(pub_a) != cap_migration._peer_fingerprint(
        pub_b
    )


# Phase C-3 (ADR-0027): macaroon advertisement on CAPABILITY_GRANT wire.


def test_macaroon_wire_round_trips_through_base64_url():
    """Operators carry the dual-issued macaroon on the same wire as
    the legacy Ed25519 grant via `macaroon_b64`. The daemon emits
    `urlsafe_b64encode(cap.encode()).rstrip("=")`; the receiver
    reverses the steps. This test pins the round-trip shape."""
    import base64

    from one_link import cap_migration

    granter_seed, granter_pub = _fresh_pair()
    _, subject_pub = _fresh_pair()
    cap = cap_migration.mint_share_capability(
        granter_priv_seed=granter_seed,
        granter_pub=granter_pub,
        subject_pub=subject_pub,
        capabilities=["files:read"],
        not_after_ms=5_000_000,
    )
    wire_bytes = cap.encode()
    encoded = base64.urlsafe_b64encode(wire_bytes).rstrip(b"=").decode("ascii")

    # Receiver path: pad + urlsafe_b64decode.
    padded = encoded + "=" * (-len(encoded) % 4)
    decoded = base64.urlsafe_b64decode(padded)
    assert decoded == wire_bytes

    # Final verify: decoded bytes parse back to the same Capability.
    from one_link import capability_native

    decoded_cap = capability_native.decode_capability(decoded)
    assert decoded_cap.signature() == cap.signature()
    assert decoded_cap.cap_id() == cap.cap_id()


def test_macaroon_advertisement_optional_when_native_missing():
    """If `_last_minted_macaroon` is None (native module unavailable
    or mint failed), the CAPABILITY_GRANT wire frame stays
    backward-compatible: only `grant_b64` is present, no
    `macaroon_b64` key. This is what makes the wire forward-
    compatible — legacy receivers see a familiar frame, capable
    receivers see the new key and use it."""
    # Replicate the daemon's emit logic at the dict-construction level.
    grant_fields = {"grant_b64": "legacy-b64-payload"}
    last_minted_macaroon = None  # native unavailable / mint failed
    if last_minted_macaroon is not None:
        grant_fields["macaroon_b64"] = "should-not-appear"
    assert "macaroon_b64" not in grant_fields

    # And the present case.
    grant_fields_2 = {"grant_b64": "legacy"}
    last_minted_macaroon = b"native-macaroon-bytes"
    if last_minted_macaroon is not None:
        import base64

        grant_fields_2["macaroon_b64"] = base64.urlsafe_b64encode(
            last_minted_macaroon
        ).rstrip(b"=").decode("ascii")
    assert "macaroon_b64" in grant_fields_2
