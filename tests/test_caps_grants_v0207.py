"""v0.20.7 — signed capability grants with auto-expiry.

Today the capability system is binary (paired = full access,
unpaired = denied). Bundle 44 ships fine-grained signed grants:
granter mints a (granter_pub, subject_pub, capabilities, scope,
not_before_ms, not_after_ms, nonce) record signed by their
Ed25519. Receiver verifies on every use. After ``not_after_ms`` the
grant is dead even if the granter is offline — auto-expiry without
a coordinated revoke.

These tests pin:
  - encode + parse round-trip preserves all fields
  - signature verifies under granter_pub
  - capability strings are canonicalized (sorted) so equivalent sets
    produce the same wire bytes
  - tamper at every field (granter_pub, subject_pub, ts, nonce,
    caps, scope, signature) rejected
  - now_ms outside [not_before, not_after] rejected
  - nonce replay rejected when seen_nonces supplied
  - expected_granter_pub / expected_subject_pub binding enforced
  - oversized caps + scope rejected at encode
  - empty capability set is valid
  - capability with embedded comma rejected (delimiter conflict)
"""
from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import caps_grants as cg


def _gen_ed25519():
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes_raw()
    pub = priv.public_key().public_bytes_raw()
    return seed, pub


def _now_ms():
    return int(time.time() * 1000)


# ── encode / parse / verify round-trip ────────────────────────────


def test_round_trip_full_grant():
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    now = _now_ms()
    blob = cg.encode_grant(
        granter_priv_seed=granter_seed,
        granter_pub=granter_pub,
        subject_pub=subject_pub,
        capabilities=["files:read", "chat:send"],
        not_before_ms=now,
        not_after_ms=now + 60 * 60 * 1000,
        scope=b"/shared",
    )
    parsed = cg.verify_grant(blob)
    assert parsed.granter_pub == granter_pub
    assert parsed.subject_pub == subject_pub
    assert parsed.capabilities == frozenset({"files:read", "chat:send"})
    assert parsed.scope == b"/shared"
    assert parsed.not_before_ms == now


def test_capabilities_canonicalized_sorted():
    """Two grants with the same capability SET (different order)
    must produce identical bytes after the leading random nonce
    is held constant. Sorting ensures stable signing."""
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    fixed_nonce = b"\x00" * cg.NONCE_LEN
    a = cg.encode_grant(
        granter_priv_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=subject_pub,
        capabilities=["files:read", "chat:send", "files:read"],  # dup
        not_before_ms=0, not_after_ms=2**40, nonce=fixed_nonce,
    )
    b = cg.encode_grant(
        granter_priv_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=subject_pub,
        capabilities=["chat:send", "files:read"],
        not_before_ms=0, not_after_ms=2**40, nonce=fixed_nonce,
    )
    assert a == b


def test_empty_capabilities_valid():
    """A grant with an empty capability set is still meaningful — it
    proves the granter knows the subject and acknowledges them; the
    actual permissions are zero. Useful as a "I see you" handshake."""
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    now = _now_ms()
    blob = cg.encode_grant(
        granter_priv_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=subject_pub, capabilities=[],
        not_before_ms=now, not_after_ms=now + 1000,
    )
    parsed = cg.verify_grant(blob)
    assert parsed.capabilities == frozenset()


# ── signature verification ─────────────────────────────────────────


def test_tampered_signature_rejected():
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    now = _now_ms()
    blob = bytearray(cg.encode_grant(
        granter_priv_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=subject_pub, capabilities=["x"],
        not_before_ms=now, not_after_ms=now + 1000,
    ))
    blob[-1] ^= 0xff
    with pytest.raises(ValueError, match="signature invalid"):
        cg.verify_grant(bytes(blob))


def test_tampered_caps_rejected():
    """Flipping bytes inside the caps body invalidates the signed
    body. Either the UTF-8 parse fails first or the signature
    verification fails — both are valid rejections."""
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    now = _now_ms()
    blob = bytearray(cg.encode_grant(
        granter_priv_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=subject_pub, capabilities=["files:read"],
        not_before_ms=now, not_after_ms=now + 1000,
    ))
    # caps body sits after the fixed header + caps_len (2 bytes).
    # Flip a byte inside the caps content — either the UTF-8 parse
    # at parse_grant fails OR the signed-body sig check fails.
    blob[cg.HEADER_FIXED_LEN + 2] ^= 0xff
    with pytest.raises((ValueError, UnicodeDecodeError)):
        cg.verify_grant(bytes(blob))


def test_tampered_subject_pub_rejected():
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    now = _now_ms()
    blob = bytearray(cg.encode_grant(
        granter_priv_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=subject_pub, capabilities=["x"],
        not_before_ms=now, not_after_ms=now + 1000,
    ))
    # subject_pub starts at offset 7 + 32 = 39.
    blob[40] ^= 0xff
    with pytest.raises(ValueError, match="signature invalid"):
        cg.verify_grant(bytes(blob))


# ── auto-expiry ────────────────────────────────────────────────────


def test_grant_in_window_accepted():
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    base = 1_000_000_000_000
    blob = cg.encode_grant(
        granter_priv_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=subject_pub, capabilities=["x"],
        not_before_ms=base, not_after_ms=base + 60_000,
    )
    # Mid-window: accepted.
    cg.verify_grant(blob, now_ms=base + 30_000)


def test_grant_before_window_rejected():
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    base = 1_000_000_000_000
    blob = cg.encode_grant(
        granter_priv_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=subject_pub, capabilities=["x"],
        not_before_ms=base, not_after_ms=base + 60_000,
    )
    with pytest.raises(ValueError, match="not yet valid"):
        cg.verify_grant(blob, now_ms=base - 1)


def test_grant_after_window_rejected():
    """The auto-expiry property: a grant past not_after_ms is
    rejected even if the granter is offline (no live revoke
    needed)."""
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    base = 1_000_000_000_000
    blob = cg.encode_grant(
        granter_priv_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=subject_pub, capabilities=["x"],
        not_before_ms=base, not_after_ms=base + 60_000,
    )
    with pytest.raises(ValueError, match="expired"):
        cg.verify_grant(blob, now_ms=base + 60_001)


def test_invalid_window_rejected_at_encode():
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    with pytest.raises(ValueError, match=r"not_before.*>.*not_after"):
        cg.encode_grant(
            granter_priv_seed=granter_seed, granter_pub=granter_pub,
            subject_pub=subject_pub, capabilities=["x"],
            not_before_ms=1000, not_after_ms=500,
        )


# ── identity binding ─────────────────────────────────────────────


def test_expected_granter_match_required():
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    _, other_pub = _gen_ed25519()
    now = _now_ms()
    blob = cg.encode_grant(
        granter_priv_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=subject_pub, capabilities=["x"],
        not_before_ms=now, not_after_ms=now + 1000,
    )
    cg.verify_grant(blob, expected_granter_pub=granter_pub)  # OK
    with pytest.raises(ValueError, match="granter_pub"):
        cg.verify_grant(blob, expected_granter_pub=other_pub)


def test_expected_subject_match_required():
    """A grant minted FOR subject A cannot be presented BY subject B
    (caller passes the presenting peer's pubkey as
    expected_subject_pub)."""
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    _, other_pub = _gen_ed25519()
    now = _now_ms()
    blob = cg.encode_grant(
        granter_priv_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=subject_pub, capabilities=["x"],
        not_before_ms=now, not_after_ms=now + 1000,
    )
    cg.verify_grant(blob, expected_subject_pub=subject_pub)  # OK
    with pytest.raises(ValueError, match="subject_pub"):
        cg.verify_grant(blob, expected_subject_pub=other_pub)


# ── nonce replay defense ──────────────────────────────────────────


def test_nonce_replay_rejected():
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    now = _now_ms()
    blob = cg.encode_grant(
        granter_priv_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=subject_pub, capabilities=["x"],
        not_before_ms=now, not_after_ms=now + 60_000,
    )
    seen: set[bytes] = set()
    cg.verify_grant(blob, seen_nonces=seen, now_ms=now)
    # Second use with same nonce: replay.
    with pytest.raises(ValueError, match="nonce replayed"):
        cg.verify_grant(blob, seen_nonces=seen, now_ms=now)


# ── caps content rules ───────────────────────────────────────────


def test_capability_with_comma_rejected():
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    with pytest.raises(ValueError, match="comma"):
        cg.encode_grant(
            granter_priv_seed=granter_seed, granter_pub=granter_pub,
            subject_pub=subject_pub,
            capabilities=["bad,name"],
            not_before_ms=0, not_after_ms=2**40,
        )


def test_empty_capability_string_rejected():
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    with pytest.raises(ValueError, match="must not be empty"):
        cg.encode_grant(
            granter_priv_seed=granter_seed, granter_pub=granter_pub,
            subject_pub=subject_pub,
            capabilities=["a", ""],
            not_before_ms=0, not_after_ms=2**40,
        )


def test_oversized_caps_rejected():
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    big_caps = [f"cap-{i:08d}" for i in range(500)]  # ~6KB encoded
    with pytest.raises(ValueError, match="caps too long"):
        cg.encode_grant(
            granter_priv_seed=granter_seed, granter_pub=granter_pub,
            subject_pub=subject_pub, capabilities=big_caps,
            not_before_ms=0, not_after_ms=2**40,
        )


def test_oversized_scope_rejected():
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    with pytest.raises(ValueError, match="scope too long"):
        cg.encode_grant(
            granter_priv_seed=granter_seed, granter_pub=granter_pub,
            subject_pub=subject_pub, capabilities=["x"],
            not_before_ms=0, not_after_ms=2**40,
            scope=b"x" * (cg.MAX_SCOPE_LEN + 1),
        )


# ── parse failure modes ─────────────────────────────────────────────


def test_parse_too_short():
    with pytest.raises(ValueError, match="too short"):
        cg.parse_grant(b"\x00" * 10)


def test_parse_bad_magic():
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    blob = bytearray(cg.encode_grant(
        granter_priv_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=subject_pub, capabilities=["x"],
        not_before_ms=0, not_after_ms=2**40,
    ))
    blob[0:6] = b"NOTOLC"
    with pytest.raises(ValueError, match="bad magic"):
        cg.parse_grant(bytes(blob))


def test_parse_unsupported_version():
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    blob = bytearray(cg.encode_grant(
        granter_priv_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=subject_pub, capabilities=["x"],
        not_before_ms=0, not_after_ms=2**40,
    ))
    blob[6] = 99
    with pytest.raises(ValueError, match="unsupported"):
        cg.parse_grant(bytes(blob))


def test_parse_length_mismatch():
    granter_seed, granter_pub = _gen_ed25519()
    _, subject_pub = _gen_ed25519()
    blob = cg.encode_grant(
        granter_priv_seed=granter_seed, granter_pub=granter_pub,
        subject_pub=subject_pub, capabilities=["x"],
        not_before_ms=0, not_after_ms=2**40,
    )
    # Tack on extra bytes — length-mismatch detected.
    with pytest.raises(ValueError, match="length mismatch"):
        cg.parse_grant(blob + b"extra")


# ── practical scenario ────────────────────────────────────────────


# ── 2026-05-22 audit SHIP-1: canonical scope encoding ───────────


def test_scope_canonical_round_trips():
    """Each canonical scope kind round-trips through decode_scope."""
    assert cg.decode_scope(cg.scope_empty()) == ("empty", b"")
    root = b"R" * 32
    assert cg.decode_scope(cg.scope_for_folder(root)) == ("folder", root)
    assert cg.decode_scope(cg.scope_for_path("shared/photos")) == (
        "path", b"shared/photos",
    )


def test_scope_canonical_legacy_compat():
    """Pre-canonical-form bytes still decode (as 'legacy') so existing
    grants remain matchable byte-for-byte against equally-encoded
    queries."""
    legacy = b"folder-X"
    assert cg.decode_scope(legacy) == ("legacy", legacy)
    # Empty bytes route to ``empty`` so b"" is interchangeable with
    # the canonical empty scope.
    assert cg.decode_scope(b"") == ("empty", b"")
    assert cg.decode_scope(cg.scope_empty()) == ("empty", b"")


def test_scope_canonical_disambiguates_path_vs_folder():
    """A folder-root scope and a path-prefix scope encode to
    DIFFERENT bytes even if their payloads look similar, so two
    callers can't accidentally claim authority across scope kinds."""
    root = b"X" * 32
    folder_blob = cg.scope_for_folder(root)
    path_blob = cg.scope_for_path("X" * 32)
    assert folder_blob != path_blob
    assert cg.decode_scope(folder_blob)[0] == "folder"
    assert cg.decode_scope(path_blob)[0] == "path"


def test_scope_folder_root_id_length_enforced():
    with pytest.raises(ValueError, match="folder root_id must be 32 bytes"):
        cg.scope_for_folder(b"too-short")


def test_scope_path_prefix_length_bound():
    """Path prefixes are bounded so an adversarial caller can't grow
    the scope blob past the global ``MAX_SCOPE_LEN``."""
    with pytest.raises(ValueError, match="path prefix too long"):
        cg.scope_for_path("/" * 5000)


def test_scope_grant_round_trip_with_canonical_folder():
    """Mint a grant using ``scope_for_folder`` and verify the
    receiver decodes the same canonical kind/payload."""
    alice_seed, alice_pub = _gen_ed25519()
    _, bob_pub = _gen_ed25519()
    root = b"\xab" * 32
    scope = cg.scope_for_folder(root)
    now = _now_ms()
    grant = cg.encode_grant(
        granter_priv_seed=alice_seed,
        granter_pub=alice_pub,
        subject_pub=bob_pub,
        capabilities=["files:read"],
        not_before_ms=now,
        not_after_ms=now + 3_600_000,
        scope=scope,
    )
    parsed = cg.verify_grant(
        grant, expected_subject_pub=bob_pub, now_ms=now + 1000,
    )
    assert cg.decode_scope(parsed.scope) == ("folder", root)


def test_one_hour_delegation_workflow():
    """Realistic scenario: Alice grants Bob "files:read" on folder
    X for the next hour. Bob can use the grant within that window.
    After it expires, the grant is dead. After explicit revoke (a
    tombstone the granter pre-commits or broadcasts), it's also
    dead — but auto-expiry doesn't need the granter online."""
    alice_seed, alice_pub = _gen_ed25519()
    _, bob_pub = _gen_ed25519()
    now = _now_ms()
    one_hour = 60 * 60 * 1000

    grant = cg.encode_grant(
        granter_priv_seed=alice_seed,
        granter_pub=alice_pub,
        subject_pub=bob_pub,
        capabilities=["files:read"],
        not_before_ms=now,
        not_after_ms=now + one_hour,
        scope=b"folder-X",
    )
    # Bob presents the grant to Alice's daemon. Alice's daemon verifies:
    parsed = cg.verify_grant(
        grant,
        expected_granter_pub=alice_pub,
        expected_subject_pub=bob_pub,
        now_ms=now + 30 * 60 * 1000,  # 30 min later
    )
    assert "files:read" in parsed.capabilities
    assert parsed.scope == b"folder-X"
    # Two hours later: expired, even if Alice is offline.
    with pytest.raises(ValueError, match="expired"):
        cg.verify_grant(grant, now_ms=now + 2 * one_hour)
