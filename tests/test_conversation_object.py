"""Tests for conversation-as-object capabilities."""

from __future__ import annotations

import threading

import pytest

from one_link.conversation_object import (
    ALL_CAPS,
    CapabilityDecision,
    ConversationCap,
    ConversationGrant,
    ConversationRights,
    ConversationRightsStore,
    check_action,
    derive_grant_token,
    fresh_grant,
    grant_request_label,
    grant_revoked_label,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ALICE = "alice-vk-hex"
MOM = "mom-vk-hex"
ATTACKER = "evil-vk-hex"

CHAIN_KEY = b"\xab" * 32


def _empty(conv_id: str = "conv-1") -> ConversationRights:
    return ConversationRights(
        conversation_id=conv_id,
        participants_vk_hex=frozenset({ALICE, MOM}),
    )


def _grant(
    cap: ConversationCap, granter: str = ALICE, *, ts: int = 1_000,
    expires_at_ms=None, revoked: bool = False,
) -> ConversationGrant:
    return ConversationGrant(
        cap=cap, granter_vk_hex=granter, granted_at_ms=ts,
        expires_at_ms=expires_at_ms, revoked=revoked,
    )


# ---------------------------------------------------------------------------
# Default state (refuses everything)
# ---------------------------------------------------------------------------

def test_empty_conversation_holds_no_caps() -> None:
    r = _empty()
    for cap in ConversationCap:
        assert not r.holds_cap_at(cap, now_ms=1_000)


def test_all_caps_listed() -> None:
    """ALL_CAPS contains every defined capability."""
    assert ALL_CAPS == frozenset(ConversationCap)


# ---------------------------------------------------------------------------
# Asymmetric grants (one participant can unilaterally grant)
# ---------------------------------------------------------------------------

def test_asymmetric_grant_takes_effect() -> None:
    r = _empty().with_grant(_grant(ConversationCap.PERSIST_LOCALLY))
    assert r.holds_cap_at(ConversationCap.PERSIST_LOCALLY, now_ms=2_000)


def test_unilateral_grant_for_summarize() -> None:
    """SUMMARIZE is asymmetric — Alice grants → SUMMARIZE holds
    on Alice's data even without Mom's grant."""
    r = _empty().with_grant(_grant(ConversationCap.SUMMARIZE))
    assert r.holds_cap_at(ConversationCap.SUMMARIZE, now_ms=2_000)


# ---------------------------------------------------------------------------
# Symmetric / mutual grants (BOTH parties required)
# ---------------------------------------------------------------------------

def test_mutual_cap_requires_both_grants() -> None:
    """RECORD is mutual. One participant alone is not enough."""
    r = _empty().with_grant(_grant(ConversationCap.RECORD, granter=ALICE))
    assert not r.holds_cap_at(ConversationCap.RECORD, now_ms=2_000)
    r = r.with_grant(_grant(ConversationCap.RECORD, granter=MOM))
    assert r.holds_cap_at(ConversationCap.RECORD, now_ms=2_000)


def test_share_excerpt_is_mutual() -> None:
    r = _empty().with_grant(_grant(ConversationCap.SHARE_EXCERPT, granter=ALICE))
    assert not r.holds_cap_at(ConversationCap.SHARE_EXCERPT, now_ms=2_000)
    r = r.with_grant(_grant(ConversationCap.SHARE_EXCERPT, granter=MOM))
    assert r.holds_cap_at(ConversationCap.SHARE_EXCERPT, now_ms=2_000)


# ---------------------------------------------------------------------------
# Expiration
# ---------------------------------------------------------------------------

def test_grant_expires() -> None:
    r = _empty().with_grant(_grant(
        ConversationCap.PERSIST_LOCALLY, ts=1_000, expires_at_ms=5_000,
    ))
    assert r.holds_cap_at(ConversationCap.PERSIST_LOCALLY, now_ms=4_999)
    assert not r.holds_cap_at(ConversationCap.PERSIST_LOCALLY, now_ms=5_000)
    assert not r.holds_cap_at(ConversationCap.PERSIST_LOCALLY, now_ms=10_000)


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------

def test_granter_can_revoke_own_grant() -> None:
    r = _empty().with_grant(_grant(
        ConversationCap.PERSIST_LOCALLY, granter=ALICE, ts=1_000,
    ))
    assert r.holds_cap_at(ConversationCap.PERSIST_LOCALLY, now_ms=2_000)
    r = r.with_revoked(
        ConversationCap.PERSIST_LOCALLY, granter_vk_hex=ALICE, revoked_at_ms=3_000,
    )
    assert not r.holds_cap_at(ConversationCap.PERSIST_LOCALLY, now_ms=4_000)


def test_revoke_keeps_audit_trail() -> None:
    """Revoked grants are kept in the grant list with revoked=True."""
    r = _empty().with_grant(_grant(
        ConversationCap.PERSIST_LOCALLY, granter=ALICE, ts=1_000,
    ))
    r = r.with_revoked(
        ConversationCap.PERSIST_LOCALLY, granter_vk_hex=ALICE, revoked_at_ms=2_000,
    )
    assert len(r.grants) == 1
    assert r.grants[0].revoked is True
    assert r.grants[0].revoked_at_ms == 2_000


def test_revoke_one_participant_breaks_mutual() -> None:
    """Both parties granted RECORD. One revokes — the cap no longer
    holds (mutual requires both active)."""
    r = _empty()
    r = r.with_grant(_grant(ConversationCap.RECORD, granter=ALICE))
    r = r.with_grant(_grant(ConversationCap.RECORD, granter=MOM))
    assert r.holds_cap_at(ConversationCap.RECORD, now_ms=2_000)
    # Alice revokes
    r = r.with_revoked(
        ConversationCap.RECORD, granter_vk_hex=ALICE, revoked_at_ms=3_000,
    )
    assert not r.holds_cap_at(ConversationCap.RECORD, now_ms=4_000)


# ---------------------------------------------------------------------------
# Granter must be a participant
# ---------------------------------------------------------------------------

def test_non_participant_cannot_grant() -> None:
    r = _empty()
    with pytest.raises(ValueError, match="participant"):
        r.with_grant(_grant(ConversationCap.RECORD, granter=ATTACKER))


# ---------------------------------------------------------------------------
# check_action decisions + explanations
# ---------------------------------------------------------------------------

def test_check_action_allowed_when_cap_held() -> None:
    r = _empty().with_grant(_grant(ConversationCap.PERSIST_LOCALLY))
    result = check_action(
        rights=r, cap=ConversationCap.PERSIST_LOCALLY,
        actor_vk_hex=ALICE, now_ms=2_000,
    )
    assert result.decision == CapabilityDecision.ALLOWED


def test_check_action_refused_no_grant_explains_clearly() -> None:
    r = _empty()
    result = check_action(
        rights=r, cap=ConversationCap.PERSIST_LOCALLY,
        actor_vk_hex=ALICE, now_ms=2_000,
    )
    assert result.decision == CapabilityDecision.REFUSED_NO_GRANT
    # Doctrine: explanation is plain language, no error codes
    assert "saving" in result.explanation
    for forbidden in ("0x", "error", "code", "denied"):
        assert forbidden not in result.explanation.lower()


def test_check_action_refused_when_actor_not_participant() -> None:
    r = _empty()
    result = check_action(
        rights=r, cap=ConversationCap.PERSIST_LOCALLY,
        actor_vk_hex=ATTACKER, now_ms=2_000,
    )
    assert result.decision == CapabilityDecision.REFUSED_NOT_PARTICIPANT


def test_check_action_refused_revoked() -> None:
    r = _empty().with_grant(_grant(ConversationCap.PERSIST_LOCALLY))
    r = r.with_revoked(
        ConversationCap.PERSIST_LOCALLY, granter_vk_hex=ALICE, revoked_at_ms=1_500,
    )
    result = check_action(
        rights=r, cap=ConversationCap.PERSIST_LOCALLY,
        actor_vk_hex=ALICE, now_ms=2_000,
    )
    assert result.decision == CapabilityDecision.REFUSED_REVOKED


def test_check_action_refused_expired() -> None:
    r = _empty().with_grant(_grant(
        ConversationCap.PERSIST_LOCALLY, expires_at_ms=2_000,
    ))
    result = check_action(
        rights=r, cap=ConversationCap.PERSIST_LOCALLY,
        actor_vk_hex=ALICE, now_ms=10_000,
    )
    assert result.decision == CapabilityDecision.REFUSED_EXPIRED


# ---------------------------------------------------------------------------
# Token derivation
# ---------------------------------------------------------------------------

def test_derive_grant_token_deterministic() -> None:
    t1 = derive_grant_token(
        conversation_id="c1", cap=ConversationCap.RECORD,
        granter_vk_hex=ALICE, granted_at_ms=1_000, chain_key=CHAIN_KEY,
    )
    t2 = derive_grant_token(
        conversation_id="c1", cap=ConversationCap.RECORD,
        granter_vk_hex=ALICE, granted_at_ms=1_000, chain_key=CHAIN_KEY,
    )
    assert t1 == t2


def test_derive_grant_token_distinguishes_caps() -> None:
    t1 = derive_grant_token(
        conversation_id="c1", cap=ConversationCap.RECORD,
        granter_vk_hex=ALICE, granted_at_ms=1_000, chain_key=CHAIN_KEY,
    )
    t2 = derive_grant_token(
        conversation_id="c1", cap=ConversationCap.SUMMARIZE,
        granter_vk_hex=ALICE, granted_at_ms=1_000, chain_key=CHAIN_KEY,
    )
    assert t1 != t2


def test_derive_grant_token_rejects_wrong_chain_key_length() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        derive_grant_token(
            conversation_id="c1", cap=ConversationCap.RECORD,
            granter_vk_hex=ALICE, granted_at_ms=1_000,
            chain_key=b"too-short",
        )


def test_fresh_grant_builds_with_token() -> None:
    g = fresh_grant(
        conversation_id="c1", cap=ConversationCap.RECORD,
        granter_vk_hex=ALICE, granted_at_ms=1_000, chain_key=CHAIN_KEY,
    )
    assert len(g.token) == 32
    assert g.cap == ConversationCap.RECORD


# ---------------------------------------------------------------------------
# UI labels
# ---------------------------------------------------------------------------

_FORBIDDEN_UI_TOKENS = ("0x", "error", "code", "captcha", "denied")


def test_grant_request_labels_doctrine_compliant() -> None:
    for cap in ConversationCap:
        label = grant_request_label(cap).lower()
        for tok in _FORBIDDEN_UI_TOKENS:
            assert tok not in label, (
                f"grant_request_label({cap.name}) leaks {tok!r}"
            )


def test_grant_revoked_labels_doctrine_compliant() -> None:
    for cap in ConversationCap:
        label = grant_revoked_label(cap).lower()
        for tok in _FORBIDDEN_UI_TOKENS:
            assert tok not in label


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

def test_store_open_idempotent() -> None:
    s = ConversationRightsStore()
    r1 = s.open(
        conversation_id="c1",
        participants_vk_hex=frozenset({ALICE, MOM}),
    )
    r2 = s.open(
        conversation_id="c1",
        participants_vk_hex=frozenset({ALICE, MOM}),
    )
    assert r1 is r2
    assert len(s) == 1


def test_store_replace_round_trip() -> None:
    s = ConversationRightsStore()
    r = s.open(
        conversation_id="c1", participants_vk_hex=frozenset({ALICE, MOM}),
    )
    r2 = r.with_grant(_grant(ConversationCap.PERSIST_LOCALLY))
    s.replace(r2)
    fetched = s.get("c1")
    assert fetched is not None
    assert fetched.holds_cap_at(ConversationCap.PERSIST_LOCALLY, now_ms=2_000)


def test_store_thread_safety_under_concurrent_replace() -> None:
    s = ConversationRightsStore()
    r = s.open(
        conversation_id="c1", participants_vk_hex=frozenset({ALICE, MOM}),
    )
    errors: list[BaseException] = []

    def worker(seed: int) -> None:
        try:
            for i in range(50):
                cap = ConversationCap(i % len(ConversationCap))
                r_new = s.get("c1")
                if r_new is None:
                    continue
                # Only mutate using a valid participant
                try:
                    r2 = r_new.with_grant(_grant(
                        cap, granter=ALICE if seed % 2 == 0 else MOM,
                        ts=seed * 1000 + i,
                    ))
                    s.replace(r2)
                except ValueError:
                    pass
        except BaseException as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


# ---------------------------------------------------------------------------
# Edge: actor not in conversation gets a polite refusal not crash
# ---------------------------------------------------------------------------

def test_unknown_actor_refusal_uses_plain_language() -> None:
    r = _empty()
    result = check_action(
        rights=r, cap=ConversationCap.SUMMARIZE,
        actor_vk_hex="random-stranger", now_ms=1,
    )
    assert result.decision == CapabilityDecision.REFUSED_NOT_PARTICIPANT
    assert "part of this conversation" in result.explanation
