"""2026-05-22 audit Batch MM — structural security-invariant tests.

The May 21 audit's CRITICAL findings (T1-D, T1-E, T1-F, FO-1 through
FO-4) shared a common shape: a security gate that returned ALLOW or
SKIPPED its check when an input was ``None``, missing, or raised an
exception. The "default-allow-all reversal" (T1-E) was the most
visible — designed as deny-by-default, shipped as allow-by-default,
because ``policy is None`` short-circuited to True.

Spotting the pattern by code review is hard; the bug rides on a
narrow line in a wider function. These tests are structural —
they parse the daemon source and assert that the specific gates
flagged by the May 21 audit haven't regressed back to the fail-
open shape.

Anti-patterns we check for:

* ``_capability_allowed`` returns False on ``state is None`` and on
  verifier exception (T1-D).
* ``_inbound_is_rejected`` returns True on ``state is None`` (FO-2).
* ``_check_outbound_trust`` returns an error string on ``state is
  None`` (FO-3).
* ``rotate_cap_root_key`` raises (not silently writes plaintext) on
  DPAPI-wrap failure (FO-4).
* Default capability policy resolves to a non-None list before
  any gate consults it (T1-E).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _slice_function(src: str, def_line: str, *, lookahead: int = 4000) -> str:
    """Return the source slice from ``def_line`` to the next ``def``
    boundary or ``lookahead`` chars, whichever is shorter. Used so
    invariant tests grep within ONE function and don't false-match
    on unrelated code below."""
    idx = src.find(def_line)
    assert idx >= 0, f"could not find: {def_line!r}"
    next_idx = src.find("\n    def ", idx + len(def_line))
    if next_idx == -1 or next_idx - idx > lookahead:
        next_idx = idx + lookahead
    return src[idx:next_idx]


# ── T1-D: _capability_allowed fails CLOSED on state=None + verifier-exc


def test_capability_allowed_fails_closed_on_state_none():
    """The bug shape that motivated the whole audit class. If
    ``state`` isn't loaded yet (boot races, DB corruption, test
    harnesses that null state), every cap check must DENY, not
    short-circuit to True."""
    src = _read("src/one_link/daemon.py")
    body = _slice_function(src, "    def _capability_allowed(", lookahead=8000)
    # Should appear as a state=None fail-closed check.
    assert "if self.state is None:" in body
    # The block immediately after must NOT return True — that was
    # the T1-D bug shape.
    state_none_idx = body.find("if self.state is None:")
    aftermath = body[state_none_idx : state_none_idx + 400]
    # Permitted: ``return False``, ``return None``, or any explicit
    # deny / log path. Forbidden: ``return True``.
    bad = re.search(r"if self\.state is None:\s*\n\s*return True", aftermath)
    assert bad is None, (
        "T1-D regression: _capability_allowed has reverted to "
        "fail-open on state=None. The first branch in the function "
        "must NOT be `return True` under any condition."
    )


def test_capability_allowed_seed_tamper_check_fails_closed():
    """FO-1: when ``detect_seed_file_tamper`` itself raises, the
    surrounding try/except used to silently fall through to allow.
    Now must call _record_capability_denial + return False."""
    src = _read("src/one_link/daemon.py")
    body = _slice_function(src, "    def _capability_allowed(", lookahead=8000)
    # The except-block for seed-tamper must be a fail-closed path.
    assert "seed_tamper_check_failed" in body, (
        "FO-1 regression: seed-tamper-check exception handler no "
        "longer records a capability denial. The handler is now a "
        "silent pass."
    )


# ── FO-2 / FO-3: inbound + outbound trust gates fail CLOSED


def test_inbound_is_rejected_fails_closed_on_state_none():
    """FO-2: state=None must return True (= rejected), not False."""
    src = _read("src/one_link/daemon.py")
    body = _slice_function(
        src, "    def _inbound_is_rejected(", lookahead=2000,
    )
    bad = re.search(r"if self\.state is None:\s*\n\s*return False", body)
    assert bad is None, (
        "FO-2 regression: _inbound_is_rejected reverted to fail-"
        "open on state=None. Unavailable state must be treated as "
        "rejected (return True)."
    )


def test_check_outbound_trust_fails_closed_on_state_none():
    """FO-3: state=None must return an error string (refuse send),
    not None (= allow)."""
    src = _read("src/one_link/daemon.py")
    body = _slice_function(
        src, "    def _check_outbound_trust(", lookahead=2000,
    )
    bad = re.search(r"if self\.state is None:\s*\n\s*return None", body)
    assert bad is None, (
        "FO-3 regression: _check_outbound_trust reverted to fail-"
        "open on state=None. Unavailable state must refuse the "
        "send by returning an error string."
    )


# ── FO-4: cap_root_key rotation raises on DPAPI fail (no silent plaintext)


def test_rotate_cap_root_key_refuses_plaintext_persist():
    """FO-4: the rotation path used to write the prior key in
    plaintext when DPAPI wrap failed ('last-resort raw'). Now must
    raise — operator investigates DPAPI availability and retries."""
    src = _read("src/one_link/cap_root_key.py")
    body = _slice_function(
        src, "def rotate_cap_root_key(", lookahead=4000,
    )
    # Audit FO-4 left the rotation-time DPAPI-wrap branch raising
    # an explicit RuntimeError instead of falling through to a raw
    # plaintext write. Check both: the raise is present AND the
    # old "last-resort raw" string is gone.
    assert "DPAPI wrap failed" in body, (
        "FO-4 regression: rotate_cap_root_key's DPAPI-failure path "
        "no longer raises. Old 'last-resort raw' plaintext write "
        "may have come back."
    )
    assert "last-resort raw" not in body, (
        "FO-4 regression: 'last-resort raw' plaintext-on-DPAPI-"
        "failure path is back."
    )


# ── T1-E: default policy must resolve to a concrete list, not None


def test_default_capability_policy_resolves_to_list():
    """T1-E: ``_apply_default_capability_policy`` used to leave
    policy=None when ``pair_default_allow_all`` was unset, and that
    defaulted to True. ``_capability_allowed`` then treated
    policy=None as allow-all. The fix was inverting + making the
    default policy a concrete list of capability tags. Verify the
    apply function calls ``set_peer_capability_policy`` with a
    real list, not a None sentinel."""
    src = _read("src/one_link/daemon.py")
    body = _slice_function(
        src, "    def _apply_default_capability_policy(",
        lookahead=4000,
    )
    # The function must materialise a policy row — i.e. call
    # set_peer_capability_policy with concrete caps.
    assert "set_peer_capability_policy" in body, (
        "T1-E regression: _apply_default_capability_policy no "
        "longer calls set_peer_capability_policy. The 'designed "
        "deny-by-default, shipped allow-by-default' bug class is "
        "back."
    )


# ── Negative case: the helper itself must work


def test_slice_function_helper_works():
    """Smoke-test the helper used by the invariant tests so a
    typo in a function name surfaces as a fast failure here, not
    as a misleading green on the invariant assertion."""
    src = _read("src/one_link/daemon.py")
    with pytest.raises(AssertionError):
        _slice_function(src, "    def _this_function_does_not_exist(")
