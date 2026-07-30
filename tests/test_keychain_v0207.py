"""Keychain access must never be able to hang One Link at startup."""

from __future__ import annotations

import re
import time
from pathlib import Path

import pytest


def test_os_keychain_call_cannot_hang_the_daemon_forever():
    """A blocked keychain is reported as an unavailable backend.

    macOS Keychain Services can block indefinitely when the keychain is
    missing, locked, or unreachable from a non-interactive session (a locked
    Mac, an SSH shell, a fresh profile). This module promises a local-key
    fallback, but an unbounded call can never REACH it -- the daemon simply
    never finishes starting, which is exactly how the frozen macOS release
    binary failed to publish its control port.
    """

    from one_link import keychain

    original = keychain.KEYCHAIN_CALL_TIMEOUT_SECONDS
    keychain.KEYCHAIN_CALL_TIMEOUT_SECONDS = 0.5
    try:
        started = time.monotonic()
        with pytest.raises(keychain.KeychainBackendError, match="did not respond"):
            keychain._bounded_keychain_call(lambda: time.sleep(30))
        assert time.monotonic() - started < 5.0
    finally:
        keychain.KEYCHAIN_CALL_TIMEOUT_SECONDS = original
        # That timeout armed the cooldown; clear it or every assertion below
        # short-circuits on a verdict this test manufactured.
        keychain.reset_keychain_breaker()

    # Normal results and errors are untouched by the wrapper.
    assert keychain._bounded_keychain_call(lambda a, b=0: a + b, 2, b=3) == 5

    class _Boom(RuntimeError):
        pass

    def _raise() -> None:
        raise _Boom("propagated")

    with pytest.raises(_Boom):
        keychain._bounded_keychain_call(_raise)


def test_one_timeout_is_not_paid_twice():
    """The deadline bounds a call; the cooldown bounds a HOST.

    Without this, a Mac with a locked login keychain pays the full deadline
    on every keychain touch for as long as the daemon runs. Those calls are
    made from the event-loop thread, so each one freezes the daemon whole:
    listeners keep accepting connections the daemon will never read from,
    and every authenticated control request times out against a daemon whose
    own log looks perfectly healthy. That is how the frozen macOS release
    binary failed its two-daemon E2E.
    """
    from one_link import keychain

    original = keychain.KEYCHAIN_CALL_TIMEOUT_SECONDS
    keychain.KEYCHAIN_CALL_TIMEOUT_SECONDS = 0.5
    keychain.reset_keychain_breaker()
    try:
        with pytest.raises(keychain.KeychainUnresponsiveError):
            keychain._bounded_keychain_call(lambda: time.sleep(30))

        # The second call must not wait at all -- and must not reach the
        # backend, which is the whole point.
        reached = []
        started = time.monotonic()
        with pytest.raises(keychain.KeychainUnresponsiveError, match="not asking again"):
            keychain._bounded_keychain_call(lambda: reached.append(1))
        assert time.monotonic() - started < 0.2
        assert reached == [], "breaker was open yet the backend was still called"

        # A cooldown that never expires would strand a user who unlocks their
        # Mac mid-session on the local key forever.
        keychain.reset_keychain_breaker()
        assert keychain._bounded_keychain_call(lambda: "answered") == "answered"
    finally:
        keychain.KEYCHAIN_CALL_TIMEOUT_SECONDS = original
        keychain.reset_keychain_breaker()

    assert keychain.KEYCHAIN_UNRESPONSIVE_COOLDOWN_SECONDS > 0


def test_a_backend_that_answers_clears_the_cooldown():
    """An answer -- even an error -- proves the host is not wedged."""
    from one_link import keychain

    original = keychain.KEYCHAIN_CALL_TIMEOUT_SECONDS
    keychain.KEYCHAIN_CALL_TIMEOUT_SECONDS = 0.5
    keychain.reset_keychain_breaker()
    try:
        with pytest.raises(keychain.KeychainUnresponsiveError):
            keychain._bounded_keychain_call(lambda: time.sleep(30))
        assert keychain._keychain_breaker_is_open() is True

        keychain.reset_keychain_breaker()

        class _Boom(RuntimeError):
            pass

        def _raise() -> None:
            raise _Boom("the backend answered, with a refusal")

        with pytest.raises(_Boom):
            keychain._bounded_keychain_call(_raise)
        assert keychain._keychain_breaker_is_open() is False
    finally:
        keychain.KEYCHAIN_CALL_TIMEOUT_SECONDS = original
        keychain.reset_keychain_breaker()


def test_every_keyring_call_is_deadline_bounded():
    """Twin-copy guard: an unwrapped call site reintroduces the hang."""
    source = (
        Path(__file__).resolve().parents[1] / "src" / "one_link" / "keychain.py"
    ).read_text(encoding="utf-8")
    unwrapped = re.findall(r"(?<!_bounded_keychain_call\()\bkr\.(?:get|set|delete)_password\(", source)
    assert not unwrapped, f"unbounded keychain calls: {unwrapped}"


def test_read_timeout_falls_back_but_write_timeout_never_invents_a_key():
    """The two timeouts are NOT the same and must not be conflated.

    A lookup that never answers is side-effect-free: the host has no usable
    credential store right now, which is the documented local-key case. A
    WRITE that never answers may have succeeded, so inventing a local key
    would orphan the encrypted database -- that call site must keep
    refusing. Conflating them either hangs the daemon (too strict) or risks
    data loss (too loose).
    """
    from one_link import keychain

    assert keychain._keyring_has_no_backend(
        keychain.KeychainUnresponsiveError("timed out")
    ) is True
    assert keychain._keyring_has_no_backend(
        keychain.KeychainBackendError("some other failure")
    ) is False
    assert issubclass(keychain.KeychainUnresponsiveError, keychain.KeychainBackendError)

    source = (
        Path(__file__).resolve().parents[1] / "src" / "one_link" / "keychain.py"
    ).read_text(encoding="utf-8")
    assert "write outcome is unknown" in source, (
        "the unknown-write refusal is a data-safety guarantee and must remain"
    )
