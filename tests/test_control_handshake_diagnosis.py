"""A slow handshake must not be reported as a bad secret.

windows-latest/py3.12 failed with:

    challenge = {'error': 'unauthorized', 'ok': False}
    ControlAuthenticationError: daemon did not authenticate the control protocol

The daemon catches asyncio.TimeoutError in the SAME clause as a protocol error
and answers with one deliberately indistinguishable "unauthorized" frame, so a
local prober cannot learn which half of the handshake failed. That part is
correct and must not change. What was wrong is that the cause was then discarded
entirely: the daemon logged nothing, so a handshake that merely exceeded
CONTROL_HANDSHAKE_TIMEOUT_S looked exactly like a wrong control secret to the
client AND left no trace for an operator.

These tests pin both halves of the contract: the wire response stays byte
identical across causes, and the daemon's own log names the real one.
"""

from __future__ import annotations

import asyncio

from one_link import control_ipc


def test_the_unauthorized_frame_is_identical_for_every_cause() -> None:
    """The anti-probing property. If this ever differs, the daemon leaks."""

    frames: list[bytes] = []

    class _Writer:
        def write(self, data: bytes) -> None:
            frames.append(data)

        async def drain(self) -> None:
            return None

    from one_link.daemon import Daemon

    async def _exercise() -> None:
        writer = _Writer()
        await Daemon._unauthenticated_control_error(writer)
        await Daemon._unauthenticated_control_error(writer)

    asyncio.run(_exercise())
    assert len(frames) == 2
    assert frames[0] == frames[1], "the rejection frame must not vary"
    assert b"unauthorized" in frames[0]
    # It must not name the cause on the wire.
    for leak in (b"timeout", b"timed out", b"secret", b"nonce", b"mac"):
        assert leak not in frames[0].lower(), f"wire response leaks {leak!r}"


def test_oversize_is_the_only_distinguished_cause() -> None:
    """Oversize is safe to distinguish (documented) -- nothing else is."""

    frames: list[bytes] = []

    class _Writer:
        def write(self, data: bytes) -> None:
            frames.append(data)

        async def drain(self) -> None:
            return None

    from one_link.daemon import Daemon

    async def _exercise() -> None:
        writer = _Writer()
        await Daemon._unauthenticated_control_error(writer, oversized=True)

    asyncio.run(_exercise())
    assert b"byte limit" in frames[0]


def test_handshake_timeout_budget_exceeds_loaded_host_jitter() -> None:
    """The regression that caused the phantom auth failure.

    3.0s sat below worst-case event-loop scheduling jitter on a loaded runner,
    so the daemon aborted handshakes clients were still waiting on. The cap must
    stay above this module's own default client round trip, or the daemon gives
    up before the client it is serving does.
    """

    assert control_ipc.CONTROL_HANDSHAKE_TIMEOUT_S >= 10.0, (
        "handshake cap regressed below the loaded-host floor"
    )
    import inspect

    default = inspect.signature(control_ipc.request_control).parameters["timeout"].default
    assert control_ipc.CONTROL_HANDSHAKE_TIMEOUT_S > default, (
        "the daemon must not abort a handshake sooner than its own client waits"
    )


def test_daemon_logs_timeout_distinctly_from_a_protocol_error() -> None:
    """The operator-facing half: our log must name what the wire cannot."""

    import inspect

    from one_link import daemon as daemon_module

    source = inspect.getsource(daemon_module.Daemon._handle_control)
    assert "isinstance(handshake_error, asyncio.TimeoutError)" in source, (
        "the handshake handler no longer distinguishes a timeout from a protocol error"
    )
    assert "not a bad control secret" in source, (
        "the timeout log must say plainly that this is not an auth failure"
    )
    # And the distinguishing branch must be a log call, never a response change.
    timeout_branch = source.split("isinstance(handshake_error, asyncio.TimeoutError)")[1]
    timeout_branch = timeout_branch.split("else:")[0]
    assert "log.warning" in timeout_branch
    assert "_unauthenticated_control_error" not in timeout_branch, (
        "the timeout branch must not send a different frame"
    )
