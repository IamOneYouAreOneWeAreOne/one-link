"""Tests for first-call SAS verification + master_vk rotation handling."""

from __future__ import annotations

import pytest

from one_link.identity_sas import (
    SAS_VOCAB,
    SAS_WORDS,
    RotationDecision,
    SASChallenge,
    TrustRecord,
    VerificationState,
    derive_sas_transcript_hash,
    derive_sas_words,
    evaluate_rotation,
    format_sas_phrase,
    verification_label,
)


# ---------------------------------------------------------------------------
# Vocab integrity
# ---------------------------------------------------------------------------

def test_sas_vocab_is_256_words() -> None:
    assert len(SAS_VOCAB) == 256


def test_sas_words_short_for_phone_display() -> None:
    """Doctrine — each word must comfortably fit on a phone screen
    when 5 are shown together. Cap individual length at 12."""
    for w in SAS_VOCAB:
        assert 1 <= len(w) <= 12, f"sas word {w!r} too long"


def test_sas_vocab_all_lowercase() -> None:
    """Mixed-case would invite Doctrine §3.9 issues (looks like hex)."""
    for w in SAS_VOCAB:
        assert w == w.lower()


# ---------------------------------------------------------------------------
# Transcript hash
# ---------------------------------------------------------------------------

def test_transcript_hash_symmetric_in_pubkeys() -> None:
    """Both sides compute identical SAS regardless of which side
    is 'originator'. Achieved by sorting the two pubkeys."""
    a = b"\x01" * 32
    b = b"\x02" * 32
    h1 = derive_sas_transcript_hash(
        originator_master_vk=a, recipient_master_vk=b,
        call_id="call-x", dh_shared_secret=b"\xab" * 32,
    )
    h2 = derive_sas_transcript_hash(
        originator_master_vk=b, recipient_master_vk=a,
        call_id="call-x", dh_shared_secret=b"\xab" * 32,
    )
    assert h1 == h2


def test_transcript_hash_differs_on_call_id() -> None:
    a = b"\x01" * 32
    b = b"\x02" * 32
    h1 = derive_sas_transcript_hash(
        originator_master_vk=a, recipient_master_vk=b,
        call_id="call-x", dh_shared_secret=b"\xab" * 32,
    )
    h2 = derive_sas_transcript_hash(
        originator_master_vk=a, recipient_master_vk=b,
        call_id="call-y", dh_shared_secret=b"\xab" * 32,
    )
    assert h1 != h2


def test_transcript_hash_differs_on_shared_secret() -> None:
    a = b"\x01" * 32
    b = b"\x02" * 32
    h1 = derive_sas_transcript_hash(
        originator_master_vk=a, recipient_master_vk=b,
        call_id="call-x", dh_shared_secret=b"\xab" * 32,
    )
    h2 = derive_sas_transcript_hash(
        originator_master_vk=a, recipient_master_vk=b,
        call_id="call-x", dh_shared_secret=b"\xcd" * 32,
    )
    assert h1 != h2


def test_transcript_hash_rejects_short_secret() -> None:
    with pytest.raises(ValueError, match="≥16"):
        derive_sas_transcript_hash(
            originator_master_vk=b"\x01" * 32, recipient_master_vk=b"\x02" * 32,
            call_id="x", dh_shared_secret=b"short",
        )


def test_transcript_hash_rejects_empty_call_id() -> None:
    with pytest.raises(ValueError, match="call_id"):
        derive_sas_transcript_hash(
            originator_master_vk=b"\x01" * 32, recipient_master_vk=b"\x02" * 32,
            call_id="", dh_shared_secret=b"\xab" * 32,
        )


# ---------------------------------------------------------------------------
# Word derivation
# ---------------------------------------------------------------------------

def test_derive_sas_words_returns_five() -> None:
    h = b"\x00\x05\x0a\x0f\x14\xff" * 4
    words = derive_sas_words(h)
    assert len(words) == SAS_WORDS


def test_derive_sas_words_deterministic() -> None:
    h = b"\x42" * 32
    assert derive_sas_words(h) == derive_sas_words(h)


def test_derive_sas_words_uses_vocab_only() -> None:
    h = bytes(range(32))
    for w in derive_sas_words(h):
        assert w in SAS_VOCAB


def test_format_sas_phrase_double_spaced() -> None:
    words = ("amber", "river", "canyon", "meadow", "stone")
    assert format_sas_phrase(words) == "amber  river  canyon  meadow  stone"


# ---------------------------------------------------------------------------
# Challenge matching
# ---------------------------------------------------------------------------

def test_sas_challenge_matches_identical_words() -> None:
    ch = SASChallenge(
        call_id="call-x",
        peer_master_vk_hex="abc",
        words=("amber", "river", "canyon", "meadow", "stone"),
        transcript_hash_hex="deadbeef",
    )
    assert ch.matches(("amber", "river", "canyon", "meadow", "stone"))


def test_sas_challenge_rejects_different_words() -> None:
    ch = SASChallenge(
        call_id="call-x",
        peer_master_vk_hex="abc",
        words=("amber", "river", "canyon", "meadow", "stone"),
        transcript_hash_hex="deadbeef",
    )
    assert not ch.matches(("amber", "river", "canyon", "meadow", "WRONG"))


# ---------------------------------------------------------------------------
# Rotation evaluation
# ---------------------------------------------------------------------------

def _allow_chain(_a: str, _b: str, _sig: bytes) -> bool:
    return True


def _reject_chain(_a: str, _b: str, _sig: bytes) -> bool:
    return False


def test_rotation_first_contact_unverified() -> None:
    decision = evaluate_rotation(
        inbound_master_vk_hex="abc",
        inbound_signature_from_prior=None,
        existing=None,
        verify_prior_signature=_reject_chain,
    )
    assert decision.new_state == VerificationState.UNVERIFIED
    assert decision.allow_call is True
    assert decision.needs_reverify is True


def test_rotation_same_key_skips_reverify() -> None:
    existing = TrustRecord(
        peer_master_vk_hex="abc",
        verified_at_ms=1_000_000,
        state=VerificationState.TRUSTED,
    )
    decision = evaluate_rotation(
        inbound_master_vk_hex="abc",
        inbound_signature_from_prior=None,
        existing=existing,
        verify_prior_signature=_reject_chain,
    )
    assert decision.new_state == VerificationState.TRUSTED
    assert decision.allow_call is True
    assert decision.needs_reverify is False


def test_rotation_chained_signature_allows_with_reverify() -> None:
    existing = TrustRecord(
        peer_master_vk_hex="old-key",
        verified_at_ms=1_000_000,
        state=VerificationState.TRUSTED,
    )
    decision = evaluate_rotation(
        inbound_master_vk_hex="new-key",
        inbound_signature_from_prior=b"sig-bytes",
        existing=existing,
        verify_prior_signature=_allow_chain,
    )
    assert decision.new_state == VerificationState.KEY_ROTATED_CHAIN_OK
    assert decision.allow_call is True
    assert decision.needs_reverify is True


def test_rotation_broken_chain_refuses_call() -> None:
    """Doctrine: refuse the call rather than 'maybe Mom.'
    Plain-language explanation, no hex."""
    existing = TrustRecord(
        peer_master_vk_hex="old-key",
        verified_at_ms=1_000_000,
        state=VerificationState.TRUSTED,
    )
    decision = evaluate_rotation(
        inbound_master_vk_hex="impostor",
        inbound_signature_from_prior=b"bogus",
        existing=existing,
        verify_prior_signature=_reject_chain,
    )
    assert decision.new_state == VerificationState.KEY_ROTATED_CHAIN_BROKEN
    assert decision.allow_call is False
    # Doctrine-compliant: no hex / no error code in the message.
    for token in ("0x", "ff", "0b", "abc", "error", "code"):
        assert token not in decision.explanation.lower()


def test_rotation_no_signature_falls_through_to_broken() -> None:
    """If the peer rotated without supplying a prior-key signature,
    we treat it as broken chain — call refused."""
    existing = TrustRecord(
        peer_master_vk_hex="old-key",
        verified_at_ms=1_000_000,
        state=VerificationState.TRUSTED,
    )
    decision = evaluate_rotation(
        inbound_master_vk_hex="new-key",
        inbound_signature_from_prior=None,    # no chain offered
        existing=existing,
        verify_prior_signature=_allow_chain,
    )
    assert decision.new_state == VerificationState.KEY_ROTATED_CHAIN_BROKEN
    assert decision.allow_call is False


def test_rotation_verify_callable_raising_treated_as_broken() -> None:
    """If the verify callback raises, treat as chain failure
    (defensive — daemon must never crash on signature parse)."""
    def boom(*a: object) -> bool:
        raise RuntimeError("oh no")
    existing = TrustRecord(
        peer_master_vk_hex="old-key",
        verified_at_ms=1_000_000,
        state=VerificationState.TRUSTED,
    )
    decision = evaluate_rotation(
        inbound_master_vk_hex="new-key",
        inbound_signature_from_prior=b"sig",
        existing=existing,
        verify_prior_signature=boom,
    )
    assert decision.new_state == VerificationState.KEY_ROTATED_CHAIN_BROKEN
    assert decision.allow_call is False


# ---------------------------------------------------------------------------
# UI labels — doctrine compliance
# ---------------------------------------------------------------------------

_FORBIDDEN_UI_TOKENS = (
    "fingerprint", "hex", "ed25519", "0x", "trust score", "%",
)


def test_verification_labels_are_plain_language() -> None:
    for state in VerificationState:
        label = verification_label(state).lower()
        for tok in _FORBIDDEN_UI_TOKENS:
            assert tok not in label, (
                f"verification_label({state.name}) leaks {tok!r}: {label!r}"
            )


# ---------------------------------------------------------------------------
# End-to-end: two parties derive the same SAS
# ---------------------------------------------------------------------------

def test_both_parties_derive_identical_sas() -> None:
    """The whole point of SAS: Alice and Bob, computing
    independently from their own local data, see THE SAME words."""
    alice_pub = b"\xa1" * 32
    bob_pub = b"\xb1" * 32
    shared = b"\xc1" * 32
    call_id = "first-call-ever"

    # Alice (originator)
    alice_hash = derive_sas_transcript_hash(
        originator_master_vk=alice_pub,
        recipient_master_vk=bob_pub,
        call_id=call_id,
        dh_shared_secret=shared,
    )
    alice_words = derive_sas_words(alice_hash)

    # Bob (recipient) — from his perspective the roles are flipped
    bob_hash = derive_sas_transcript_hash(
        originator_master_vk=bob_pub,
        recipient_master_vk=alice_pub,
        call_id=call_id,
        dh_shared_secret=shared,
    )
    bob_words = derive_sas_words(bob_hash)

    assert alice_words == bob_words
