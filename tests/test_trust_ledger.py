"""Tests for the TrustLedger — audit C2 closure surface.

Verifies the ledger correctly threads through
:func:`identity_sas.evaluate_rotation` for every rotation case:

  - First contact: UNVERIFIED + allow + needs_reverify
  - Same key: TRUSTED + allow + skip reverify
  - Different key, valid chain: ROTATED_CHAIN_OK + allow + reverify
  - Different key, broken chain: ROTATED_CHAIN_BROKEN + refuse
"""

from __future__ import annotations

import threading

import pytest

from one_link.identity_sas import (
    RotationDecision,
    TrustRecord,
    VerificationState,
)
from one_link.trust_ledger import TrustLedger


ALICE_VK = "alice-master-vk-hex"
ALICE_ROTATED_VK = "alice-rotated-vk-hex"
BOB_VK = "bob-master-vk-hex"
ATTACKER_VK = "attacker-vk-hex"


def _allow_chain(_a: str, _b: str, _sig: bytes) -> bool:
    return True


def _reject_chain(_a: str, _b: str, _sig: bytes) -> bool:
    return False


# ---------------------------------------------------------------------------
# Construction + basic record/get
# ---------------------------------------------------------------------------

def test_empty_ledger_returns_none() -> None:
    l = TrustLedger(verify_prior_signature=_reject_chain)
    assert l.get(ALICE_VK) is None
    assert len(l) == 0


def test_record_pinned_then_get() -> None:
    l = TrustLedger(verify_prior_signature=_reject_chain)
    l.record_pinned(peer_master_vk_hex=ALICE_VK, verified_at_ms=1_000)
    r = l.get(ALICE_VK)
    assert r is not None
    assert r.peer_master_vk_hex == ALICE_VK
    assert r.state == VerificationState.TRUSTED
    assert r.verified_at_ms == 1_000


def test_record_pinned_idempotent() -> None:
    l = TrustLedger(verify_prior_signature=_reject_chain)
    l.record_pinned(peer_master_vk_hex=ALICE_VK, verified_at_ms=1_000)
    l.record_pinned(peer_master_vk_hex=ALICE_VK, verified_at_ms=2_000)
    assert len(l) == 1
    assert l.get(ALICE_VK).verified_at_ms == 2_000


def test_forget_removes_record() -> None:
    l = TrustLedger(verify_prior_signature=_reject_chain)
    l.record_pinned(peer_master_vk_hex=ALICE_VK, verified_at_ms=1_000)
    l.forget(ALICE_VK)
    assert l.get(ALICE_VK) is None


# ---------------------------------------------------------------------------
# Rotation decisions through check_inbound
# ---------------------------------------------------------------------------

def test_first_contact_unverified_allow() -> None:
    l = TrustLedger(verify_prior_signature=_reject_chain)
    d = l.check_inbound(
        inbound_master_vk_hex=ALICE_VK,
        inbound_signature_from_prior=None,
    )
    assert d.new_state == VerificationState.UNVERIFIED
    assert d.allow_call is True
    assert d.needs_reverify is True


def test_same_key_trusted_skip_reverify() -> None:
    l = TrustLedger(verify_prior_signature=_reject_chain)
    l.record_pinned(peer_master_vk_hex=ALICE_VK, verified_at_ms=1_000)
    d = l.check_inbound(
        inbound_master_vk_hex=ALICE_VK,
        inbound_signature_from_prior=None,
    )
    assert d.new_state == VerificationState.TRUSTED
    assert d.allow_call is True
    assert d.needs_reverify is False


def test_rotation_with_valid_chain_allow_with_reverify() -> None:
    l = TrustLedger(verify_prior_signature=_allow_chain)
    l.record_pinned(peer_master_vk_hex=ALICE_VK, verified_at_ms=1_000)
    d = l.check_inbound(
        inbound_master_vk_hex=ALICE_ROTATED_VK,
        inbound_signature_from_prior=b"valid-chain-sig",
        previous_pin_hex=ALICE_VK,
    )
    assert d.new_state == VerificationState.KEY_ROTATED_CHAIN_OK
    assert d.allow_call is True
    assert d.needs_reverify is True


def test_rotation_with_broken_chain_refuse_call() -> None:
    l = TrustLedger(verify_prior_signature=_reject_chain)
    l.record_pinned(peer_master_vk_hex=ALICE_VK, verified_at_ms=1_000)
    d = l.check_inbound(
        inbound_master_vk_hex=ATTACKER_VK,
        inbound_signature_from_prior=b"bogus-sig",
        previous_pin_hex=ALICE_VK,
    )
    assert d.new_state == VerificationState.KEY_ROTATED_CHAIN_BROKEN
    assert d.allow_call is False
    # Doctrine — plain language refusal
    msg = d.explanation.lower()
    assert "error" not in msg
    assert "verify in person" in msg


def test_rotation_with_no_signature_treated_as_broken() -> None:
    l = TrustLedger(verify_prior_signature=_allow_chain)
    l.record_pinned(peer_master_vk_hex=ALICE_VK, verified_at_ms=1_000)
    d = l.check_inbound(
        inbound_master_vk_hex=ATTACKER_VK,
        inbound_signature_from_prior=None,
        previous_pin_hex=ALICE_VK,
    )
    assert d.new_state == VerificationState.KEY_ROTATED_CHAIN_BROKEN
    assert d.allow_call is False


# ---------------------------------------------------------------------------
# apply_decision
# ---------------------------------------------------------------------------

def test_apply_decision_pins_on_first_contact() -> None:
    l = TrustLedger(verify_prior_signature=_reject_chain)
    d = l.check_inbound(
        inbound_master_vk_hex=ALICE_VK,
        inbound_signature_from_prior=None,
    )
    l.apply_decision(
        inbound_master_vk_hex=ALICE_VK,
        decision=d,
        verified_at_ms=1_000,
    )
    r = l.get(ALICE_VK)
    assert r is not None
    assert r.state == VerificationState.UNVERIFIED


def test_apply_decision_does_not_pin_on_broken_chain() -> None:
    l = TrustLedger(verify_prior_signature=_reject_chain)
    l.record_pinned(peer_master_vk_hex=ALICE_VK, verified_at_ms=1_000)
    d = l.check_inbound(
        inbound_master_vk_hex=ATTACKER_VK,
        inbound_signature_from_prior=None,
        previous_pin_hex=ALICE_VK,
    )
    l.apply_decision(
        inbound_master_vk_hex=ATTACKER_VK,
        decision=d,
        verified_at_ms=2_000,
        previous_pin_hex=ALICE_VK,
    )
    # Attacker's key must NOT be in the ledger.
    assert l.get(ATTACKER_VK) is None
    # Original pin still intact.
    assert l.get(ALICE_VK) is not None


def test_apply_decision_rotates_pin_with_chain() -> None:
    l = TrustLedger(verify_prior_signature=_allow_chain)
    l.record_pinned(peer_master_vk_hex=ALICE_VK, verified_at_ms=1_000)
    d = l.check_inbound(
        inbound_master_vk_hex=ALICE_ROTATED_VK,
        inbound_signature_from_prior=b"good-sig",
        previous_pin_hex=ALICE_VK,
    )
    l.apply_decision(
        inbound_master_vk_hex=ALICE_ROTATED_VK,
        decision=d,
        verified_at_ms=2_000,
        previous_pin_hex=ALICE_VK,
    )
    r = l.get(ALICE_ROTATED_VK)
    assert r is not None
    assert r.state == VerificationState.KEY_ROTATED_CHAIN_OK
    assert r.previous_master_vk_hex == ALICE_VK


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def test_snapshot_round_trip() -> None:
    a = TrustLedger(verify_prior_signature=_reject_chain)
    a.record_pinned(peer_master_vk_hex=ALICE_VK, verified_at_ms=1_000)
    a.record_pinned(peer_master_vk_hex=BOB_VK, verified_at_ms=2_000)

    snap = a.snapshot()
    assert len(snap) == 2

    b = TrustLedger(verify_prior_signature=_reject_chain)
    b.restore(snap)
    assert b.get(ALICE_VK) is not None
    assert b.get(BOB_VK) is not None
    assert b.get(ALICE_VK).verified_at_ms == 1_000


def test_restore_skips_malformed_entries() -> None:
    """A garbled snapshot row must not crash restore; it's just
    dropped. The remaining valid rows still load."""
    l = TrustLedger(verify_prior_signature=_reject_chain)
    snap = [
        {"peer_master_vk_hex": ALICE_VK, "verified_at_ms": 1_000, "state": 1},
        {},                                              # missing fields
        {"peer_master_vk_hex": "", "verified_at_ms": 0},  # empty key
        {"peer_master_vk_hex": BOB_VK, "verified_at_ms": "not-a-number"},
    ]
    l.restore(snap)
    assert l.get(ALICE_VK) is not None
    # BOB's verified_at_ms got coerced to 0; key still present.
    assert l.get(BOB_VK) is not None


def test_clear_empties_ledger() -> None:
    l = TrustLedger(verify_prior_signature=_reject_chain)
    l.record_pinned(peer_master_vk_hex=ALICE_VK, verified_at_ms=1_000)
    l.clear()
    assert len(l) == 0


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------

def test_concurrent_record_and_check_safe() -> None:
    l = TrustLedger(verify_prior_signature=_reject_chain)
    errors: list[BaseException] = []

    def writer(start: int) -> None:
        try:
            for i in range(100):
                vk = f"vk-{start * 100 + i}"
                l.record_pinned(peer_master_vk_hex=vk, verified_at_ms=i)
                l.check_inbound(
                    inbound_master_vk_hex=vk,
                    inbound_signature_from_prior=None,
                )
        except BaseException as e:
            errors.append(e)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(l) == 400


# ---------------------------------------------------------------------------
# Verify-callable raising is handled
# ---------------------------------------------------------------------------

def test_verify_callable_raising_treated_as_broken_chain() -> None:
    def boom(*_args: object) -> bool:
        raise RuntimeError("oh no")
    l = TrustLedger(verify_prior_signature=boom)
    l.record_pinned(peer_master_vk_hex=ALICE_VK, verified_at_ms=1_000)
    d = l.check_inbound(
        inbound_master_vk_hex=ATTACKER_VK,
        inbound_signature_from_prior=b"sig",
        previous_pin_hex=ALICE_VK,
    )
    assert d.new_state == VerificationState.KEY_ROTATED_CHAIN_BROKEN
    assert d.allow_call is False
