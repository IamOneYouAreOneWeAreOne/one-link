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

    # Normal results and errors are untouched by the wrapper.
    assert keychain._bounded_keychain_call(lambda a, b=0: a + b, 2, b=3) == 5

    class _Boom(RuntimeError):
        pass

    def _raise() -> None:
        raise _Boom("propagated")

    with pytest.raises(_Boom):
        keychain._bounded_keychain_call(_raise)


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
