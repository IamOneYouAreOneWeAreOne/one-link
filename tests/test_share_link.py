"""Unit tests for the Wave 2g share-link primitive.

Covers the registry's mint / lookup / redeem / expire / revoke /
prune contract in isolation from the daemon. Integration with
the wire frame + control endpoint is exercised in a separate
test module.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from one_link.share_link import (
    DEFAULT_TTL_SECONDS,
    SAS_PHRASE_WORDS,
    SCHEMA_VERSION,
    TOKEN_LEN,
    ShareLink,
    ShareLinkRegistry,
    derive_sas_phrase,
    load,
    mint_token,
    persist,
    scan,
    sidecar_path,
)


def test_mint_token_is_random_and_correct_length() -> None:
    a = mint_token()
    b = mint_token()
    assert len(a) == TOKEN_LEN
    assert len(b) == TOKEN_LEN
    assert a != b, "two consecutive mints must not collide"


def test_derive_sas_phrase_is_stable() -> None:
    """Same token must derive the same phrase. Sender and
    recipient computing independently must agree."""
    token = bytes(range(TOKEN_LEN))
    p1 = derive_sas_phrase(token)
    p2 = derive_sas_phrase(token)
    assert p1 == p2
    # 8 single-space-separated words.
    assert len(p1.split(" ")) == SAS_PHRASE_WORDS


def test_derive_sas_phrase_differs_per_token() -> None:
    """Different tokens must produce different phrases — otherwise
    the SAS would tell the user nothing about which token they
    have."""
    p1 = derive_sas_phrase(mint_token())
    p2 = derive_sas_phrase(mint_token())
    assert p1 != p2, "two different tokens must produce different SAS phrases"


def test_registry_mint_and_lookup(tmp_path: Path) -> None:
    reg = ShareLinkRegistry(tmp_path)
    link = reg.mint(
        blob_hex="a" * 64,
        name="paper.pdf",
        size=2048,
        source_path=str(tmp_path / "paper.pdf"),
    )
    assert link.token_hex
    assert len(link.token_hex) == TOKEN_LEN * 2
    assert link.sas_phrase
    # Lookups both directions.
    assert reg.lookup_by_token(link.token_hex) is link
    assert reg.lookup_by_blob("a" * 64) is link
    # Sidecar landed on disk.
    sp = sidecar_path(tmp_path, "a" * 64)
    assert sp.is_file()


def test_remint_replaces_prior_link(tmp_path: Path) -> None:
    """Re-minting for the same blob must invalidate the old
    token + replace with a fresh one. The sidecar follows."""
    reg = ShareLinkRegistry(tmp_path)
    l1 = reg.mint(blob_hex="a" * 64, name="x", size=10, source_path="/x")
    l2 = reg.mint(blob_hex="a" * 64, name="x", size=10, source_path="/x")
    assert l1.token_hex != l2.token_hex
    # Old token must not resolve anymore.
    assert reg.lookup_by_token(l1.token_hex) is None
    # New token resolves.
    assert reg.lookup_by_token(l2.token_hex) is l2


def test_redeem_consumes_link_once(tmp_path: Path) -> None:
    reg = ShareLinkRegistry(tmp_path)
    link = reg.mint(blob_hex="a" * 64, name="x", size=10, source_path="/x")
    out, reason = reg.redeem(link.token_hex, by_peer_fp="P" * 64)
    assert out is link
    assert reason == "ok"
    assert link.is_consumed()
    assert link.redeemed_by_hint == "P" * 64
    # Second redeem fails with the canonical reason.
    out2, reason2 = reg.redeem(link.token_hex)
    assert out2 is None
    assert reason2 == "already_redeemed"


def test_redeem_unknown_token(tmp_path: Path) -> None:
    reg = ShareLinkRegistry(tmp_path)
    out, reason = reg.redeem("0" * 64)
    assert out is None
    assert reason == "not_found"


def test_expired_link_rejected_on_redeem(tmp_path: Path) -> None:
    """A link whose TTL has elapsed must be rejected AND swept
    from the registry so it doesn't accumulate."""
    reg = ShareLinkRegistry(tmp_path)
    link = reg.mint(
        blob_hex="a" * 64, name="x", size=10, source_path="/x",
        ttl_seconds=1,
    )
    # Backdate expiry.
    link.expires_at_ms = int(time.time() * 1000) - 1000
    persist(tmp_path, link)
    out, reason = reg.redeem(link.token_hex)
    assert out is None
    assert reason == "expired"
    # Registry forgot it.
    assert reg.lookup_by_token(link.token_hex) is None
    assert reg.lookup_by_blob("a" * 64) is None
    assert not sidecar_path(tmp_path, "a" * 64).exists()


def test_redeem_idempotency_after_consumption(tmp_path: Path) -> None:
    """Once consumed, the registry must persist the consumed
    state through a registry reload — a crash mid-redeem
    must NOT let a second peer re-redeem the same token."""
    reg = ShareLinkRegistry(tmp_path)
    link = reg.mint(blob_hex="a" * 64, name="x", size=10, source_path="/x")
    reg.redeem(link.token_hex)
    # Fresh registry reading from disk should see the consumed
    # state.
    reg2 = ShareLinkRegistry(tmp_path)
    reg2.load_from_disk()
    out, reason = reg2.redeem(link.token_hex)
    assert out is None
    assert reason == "already_redeemed"


def test_revoke_removes_link(tmp_path: Path) -> None:
    reg = ShareLinkRegistry(tmp_path)
    link = reg.mint(blob_hex="a" * 64, name="x", size=10, source_path="/x")
    assert reg.revoke("a" * 64) is True
    assert reg.lookup_by_token(link.token_hex) is None
    assert not sidecar_path(tmp_path, "a" * 64).exists()
    # Idempotent.
    assert reg.revoke("a" * 64) is False


def test_load_from_disk_round_trip(tmp_path: Path) -> None:
    reg = ShareLinkRegistry(tmp_path)
    link = reg.mint(blob_hex="a" * 64, name="x.bin", size=42, source_path="/x")

    reg2 = ShareLinkRegistry(tmp_path)
    assert reg2.load_from_disk() == 1
    hit = reg2.lookup_by_token(link.token_hex)
    assert hit is not None
    assert hit.blob_hex == link.blob_hex
    assert hit.sas_phrase == link.sas_phrase


def test_load_from_disk_prunes_expired(tmp_path: Path) -> None:
    """Loading at startup must drop expired entries so the
    registry doesn't carry stale junk forward."""
    reg = ShareLinkRegistry(tmp_path)
    fresh = reg.mint(blob_hex="a" * 64, name="fresh", size=1, source_path="/")
    stale = reg.mint(blob_hex="b" * 64, name="stale", size=1, source_path="/")
    # Backdate the stale one.
    stale.expires_at_ms = int(time.time() * 1000) - 1000
    persist(tmp_path, stale)

    reg2 = ShareLinkRegistry(tmp_path)
    n = reg2.load_from_disk()
    assert n == 1
    assert reg2.lookup_by_token(fresh.token_hex) is not None
    assert reg2.lookup_by_token(stale.token_hex) is None
    assert not sidecar_path(tmp_path, "b" * 64).exists()


def test_prune_expired_in_place(tmp_path: Path) -> None:
    reg = ShareLinkRegistry(tmp_path)
    fresh = reg.mint(blob_hex="a" * 64, name="x", size=1, source_path="/")
    stale = reg.mint(blob_hex="b" * 64, name="x", size=1, source_path="/")
    stale.expires_at_ms = int(time.time() * 1000) - 1000
    persist(tmp_path, stale)
    # Refresh registry view of stale's expiry.
    reg._by_token[stale.token_hex].expires_at_ms = stale.expires_at_ms
    reg._by_blob[stale.blob_hex].expires_at_ms = stale.expires_at_ms
    pruned = reg.prune_expired()
    assert pruned == 1
    assert reg.lookup_by_token(fresh.token_hex) is not None
    assert reg.lookup_by_token(stale.token_hex) is None


def test_snapshot_omits_raw_token(tmp_path: Path) -> None:
    """The control-API snapshot must NOT leak the bearer token —
    the SAS phrase is the user-facing identifier; the raw token
    is a secret."""
    reg = ShareLinkRegistry(tmp_path)
    link = reg.mint(blob_hex="a" * 64, name="x", size=1, source_path="/")
    snap = reg.snapshot()
    assert len(snap) == 1
    entry = snap[0]
    assert entry["sas_phrase"] == link.sas_phrase
    assert "token_hex" not in entry
    assert "token" not in entry


def test_corrupt_sidecar_is_dropped(tmp_path: Path) -> None:
    """A flipped bit / hand-edited sidecar must be ignored at
    load + auto-cleaned, not crash the daemon."""
    d = tmp_path / "share_links"
    d.mkdir()
    (d / ("a" * 64 + ".json")).write_text("not valid json")
    reg = ShareLinkRegistry(tmp_path)
    n = reg.load_from_disk()
    assert n == 0
    # Garbage file should be unlinked.
    assert not (d / ("a" * 64 + ".json")).exists()


def test_sas_phrase_words_are_in_vocab(tmp_path: Path) -> None:
    """Every word in the SAS phrase must be from the bundled
    256-word vocab — guards against an accidental switch to a
    different wordlist that breaks recipient-side decoding."""
    from one_link.identity_sas import SAS_VOCAB
    vocab_set = set(SAS_VOCAB)
    token = mint_token()
    phrase = derive_sas_phrase(token)
    for w in phrase.split(" "):
        assert w in vocab_set, (
            f"SAS word {w!r} is not in identity_sas.SAS_VOCAB — "
            f"wordlist must match for recipient lookup to work"
        )
