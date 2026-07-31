"""An unroutable interface is not a crash.

zeroconf logs per-interface send failures with ``exc_info``, so a laptop
between networks -- or a CI runner with one virtual NIC that has no route --
prints a full ``Traceback (most recent call last)`` into the daemon log for a
condition One Link handles by simply announcing on the interfaces that work.

That is not merely cosmetic. The release gate scans a frozen daemon's log:

    if "Traceback (most recent call last)" in text or " CRITICAL " in text:
        raise GateFailure("frozen daemon logged a traceback/critical failure")

Both macOS daemons in release run #38 logged exactly that for
``[Errno 65] No route to host`` on 192.168.64.10, so the binary would have
failed its gate even in a run where the whole E2E succeeded.
"""

from __future__ import annotations

import errno
import logging

import pytest

from one_link import discovery


@pytest.fixture
def zc_logger(caplog):
    log = logging.getLogger("zeroconf")
    original = list(log.filters)
    for f in original:
        log.removeFilter(f)
    yield log
    for f in list(log.filters):
        log.removeFilter(f)
    for f in original:
        log.addFilter(f)


def _emit(log, exc: BaseException, *, shape: str = "instance") -> None:
    """Emit the way zeroconf really does.

    ``QuietLogger.log_exception_once`` does ``logger(*args, exc_info=exc)`` --
    it passes the exception INSTANCE, not ``True``. Logger._log normalises
    both to a 3-tuple, so the filter behaves identically, but a test that
    only ever exercised ``exc_info=True`` would not be testing what ships.
    """
    try:
        raise exc
    except BaseException as raised:
        log.warning(
            "Error with socket 23 (('192.168.64.10', 5353))): %s",
            raised,
            exc_info=raised if shape == "instance" else True,
        )


def _rendered(caplog) -> str:
    formatter = logging.Formatter("%(levelname)s %(name)s: %(message)s")
    return "\n".join(formatter.format(r) for r in caplog.records)


@pytest.mark.parametrize("shape", ["instance", "true"])
def test_no_route_to_host_keeps_its_warning_but_loses_its_traceback(
    shape, zc_logger, caplog
):
    discovery._quiet_zeroconf_unreachable_interfaces()

    with caplog.at_level(logging.WARNING, logger="zeroconf"):
        _emit(zc_logger, OSError(errno.EHOSTUNREACH, "No route to host"), shape=shape)

    rendered = _rendered(caplog)
    assert "Traceback (most recent call last)" not in rendered, (
        "the traceback survived; the release gate reads this as a crash"
    )
    # The information the operator actually needs is still there.
    assert "192.168.64.10" in rendered
    assert "No route to host" in rendered
    assert len(caplog.records) == 1, "the record must be kept, not suppressed"


@pytest.mark.parametrize(
    "name", ["EHOSTUNREACH", "ENETUNREACH", "ENETDOWN", "EADDRNOTAVAIL"]
)
def test_every_unreachable_interface_errno_is_covered(name, zc_logger, caplog):
    code = getattr(errno, name, None)
    if code is None:
        pytest.skip(f"{name} not defined on this platform")
    discovery._quiet_zeroconf_unreachable_interfaces()

    with caplog.at_level(logging.WARNING, logger="zeroconf"):
        _emit(zc_logger, OSError(code, name))

    assert "Traceback (most recent call last)" not in _rendered(caplog)


def test_a_real_failure_keeps_its_traceback(zc_logger, caplog):
    """The filter must not become a blanket traceback suppressor."""
    discovery._quiet_zeroconf_unreachable_interfaces()

    with caplog.at_level(logging.WARNING, logger="zeroconf"):
        _emit(zc_logger, RuntimeError("something genuinely broke"))

    rendered = _rendered(caplog)
    assert "Traceback (most recent call last)" in rendered, (
        "a real error lost its traceback -- this filter would then hide bugs"
    )
    assert "something genuinely broke" in rendered


def test_an_unrelated_oserror_keeps_its_traceback(zc_logger, caplog):
    discovery._quiet_zeroconf_unreachable_interfaces()

    with caplog.at_level(logging.WARNING, logger="zeroconf"):
        _emit(zc_logger, OSError(errno.EACCES, "permission denied"))

    assert "Traceback (most recent call last)" in _rendered(caplog)


def test_installation_is_idempotent(zc_logger):
    for _ in range(5):
        discovery._quiet_zeroconf_unreachable_interfaces()
    installed = [
        f for f in zc_logger.filters
        if isinstance(f, discovery._QuietUnreachableInterfaceFilter)
    ]
    assert len(installed) == 1


def test_both_zeroconf_entry_points_install_it():
    """Twin-copy guard: discovery.py is not the only place One Link starts it."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "src" / "one_link"
    for name in ("discovery.py", "lan_discovery.py"):
        text = (root / name).read_text(encoding="utf-8")
        if "AsyncZeroconf(" not in text:
            continue
        assert "_quiet_zeroconf_unreachable_interfaces()" in text, (
            f"{name} starts zeroconf without installing the filter, so "
            "unroutable-interface tracebacks still reach the log from there"
        )
