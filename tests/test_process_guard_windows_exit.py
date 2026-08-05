"""An exited Windows process must READ as exited, not raise.

Found on 2026-08-05 by running the update ceremony against a real frozen
bundle on real Windows -- `scripts/frozen_update_ceremony.py`. Nothing in the
suite could have found it, because every existing process-guard test supplies a
synthetic identity reader.

What happens on Windows:

    a process that has exited still has a process OBJECT for as long as any
    handle to it remains open

so `OpenProcess` SUCCEEDS for a pid that is already dead. The code then called
`QueryFullProcessImageNameW`, which fails for a terminated process with
ERROR_GEN_FAILURE (31). That code is not in the set the OpenProcess branch
treats as "gone" ({5, 87, 1168}), so `read_process_identity` raised
PermissionError instead of reporting the exit.

`require_guarded_process_exit` is the step where the updater waits for the old
application to go away before swapping the install tree. With the reader
raising, that step cannot succeed: the real observed failure was

    PermissionError: [WinError 31] A device attached to the system is not
    functioning.

for a daemon that had genuinely exited. A Windows self-update stalls there.

The fix reads `lpExitTime` from `GetProcessTimes`, which the function already
called and never inspected. Windows leaves it zero for a process that has not
exited, so it cannot mistake a live process for a dead one -- which is why this
is safe in the direction that matters. The tests below pin both halves.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

from one_link.update_transaction import (
    capture_process_guard,
    read_process_identity,
    require_guarded_process_exit,
)

pytestmark = pytest.mark.skipif(
    os.name != "nt", reason="this is a Windows process-object behaviour"
)


@pytest.fixture
def exited_child():
    """A process that has really exited, whose handle we still hold.

    Holding the handle is what keeps the process object alive and reproduces
    the condition. Popen does exactly this, and so does any launcher that
    spawned the daemon -- which is the real-world shape.
    """
    process = subprocess.Popen(
        [sys.executable, "-c", "pass"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    process.wait(timeout=60)
    time.sleep(0.3)
    yield process
    # The Popen object stays referenced for the duration of the test, which is
    # the point; releasing it here is only tidiness.


def test_reading_an_exited_process_returns_gone_instead_of_raising(exited_child):
    """The exact regression. This used to raise PermissionError [WinError 31]."""
    assert read_process_identity(exited_child.pid) is None, (
        "an exited process must read as gone"
    )


def test_the_guard_accepts_the_exit_of_that_process(exited_child):
    """The product-level consequence, not just the primitive.

    This is the call the external helper makes before swapping the install
    tree. If it raises, the update stops here.

    The guard is constructed directly rather than through
    capture_process_guard, which correctly refuses a pid that is not running --
    my first version of this test called it on the already-dead child and got
    "cannot guard a process that is not running", which is the API behaving
    properly. The realistic sequence (capture while alive, then stop) is
    covered by test_an_exit_is_observed_after_a_real_process_is_stopped; this
    one isolates the exited-pid read that used to raise WinError 31.
    """
    from one_link.update_transaction import ProcessGuard

    guard = ProcessGuard(
        pid=exited_child.pid,
        instance_token="f" * 64,
        executable=sys.executable,
    )
    require_guarded_process_exit(guard, timeout=5.0)


def test_a_LIVE_process_still_reads_as_live():
    """CONTROL, and the one that matters for safety.

    Every assertion above is satisfied by a reader that returns None for
    everything -- which would tell the updater that a RUNNING application had
    exited and let it swap the install tree out from under a live process.
    This is what forbids that.
    """
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(0.6)
        identity = read_process_identity(process.pid)
        assert identity is not None, "a running process read as gone"
        assert identity.pid == process.pid
        assert identity.instance_token, "a live process must yield a token"
        assert identity.executable, "a live process must yield an executable"
    finally:
        process.terminate()
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive
            process.kill()
            process.wait(timeout=30)


def test_the_guard_refuses_while_the_process_is_alive():
    """The other half of the control, at the product level.

    require_guarded_process_exit must block on a live instance. Together with
    the test above, this is what says the fix reports exits without ever
    reporting a false one.
    """
    from one_link.update_transaction import UpdateTransactionError

    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(0.6)
        guard = capture_process_guard(process.pid)
        with pytest.raises(UpdateTransactionError):
            require_guarded_process_exit(guard, timeout=1.0)
    finally:
        process.terminate()
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive
            process.kill()
            process.wait(timeout=30)


def test_an_exit_is_observed_after_a_real_process_is_stopped():
    """End to end, the way the updater experiences it.

    Capture a guard from a live process, stop it, and require the exit --
    which is precisely the sequence that failed on real hardware.
    """
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    guard = None
    try:
        time.sleep(0.6)
        guard = capture_process_guard(process.pid)
        assert guard.instance_token
    finally:
        process.terminate()
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive
            process.kill()
            process.wait(timeout=30)

    require_guarded_process_exit(guard, timeout=30.0)
