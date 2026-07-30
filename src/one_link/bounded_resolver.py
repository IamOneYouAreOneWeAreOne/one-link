"""Deadline-bounded name resolution.

The C resolver takes no timeout and cannot be cancelled. ``getaddrinfo``,
``gethostbyname_ex`` and friends block the calling thread for as long as the
system resolver wants, and on macOS the machine's own name is typically a
``.local`` name answered over mDNS -- so on a host whose network is degraded
these calls block for a minute or more.

Called from an event-loop thread that is not merely slow, it is an outage
that looks exactly like health: the kernel keeps accepting connections on
every listener the process opened, nothing is ever read from them, and the
process logs nothing because the code that would log is not running. One
Link shipped that twice -- once while minting its TLS cert, once while
announcing its endpoints -- so the bound lives in one place now rather than
being re-derived at each call site.

The worker is abandoned as a daemon thread rather than joined: there is no
way to interrupt a call already inside the system resolver, and waiting for
it is the very thing being avoided.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Callable, TypeVar

log = logging.getLogger("one_link.resolver")

# Long enough for a healthy resolver on a cold host, short enough that a
# wedged one is an inconvenience rather than an outage.
RESOLVE_TIMEOUT_SECONDS = 5.0

T = TypeVar("T")
# The fallback is deliberately a SEPARATE variable rather than the operation's
# own return type. Binding both to one T makes an empty-literal default such
# as ``default=[]`` bind T to ``list[Never]`` before the operation is ever
# considered, and every real resolver call is then rejected against it.
D = TypeVar("D")


def resolve_bounded(
    operation: Callable[..., T],
    *args: Any,
    default: D,
    label: str,
    timeout: float | None = None,
    **kwargs: Any,
) -> T | D:
    """Run one resolver call with a deadline, or return ``default``.

    ``default`` is required and has no implicit value on purpose: every
    caller must decide what a missing answer means for it. Errors from the
    resolver are NOT swallowed -- only slowness is handled here.
    """

    deadline = RESOLVE_TIMEOUT_SECONDS if timeout is None else float(timeout)
    outcome: dict[str, Any] = {}

    def _run() -> None:
        try:
            outcome["value"] = operation(*args, **kwargs)
        except BaseException as exc:  # surfaced verbatim to the caller
            outcome["error"] = exc

    worker = threading.Thread(
        target=_run,
        name="one-link-resolve",
        daemon=True,
    )
    worker.start()
    worker.join(deadline)
    if worker.is_alive():
        log.info(
            "%s: the system resolver did not answer within %.0fs; continuing "
            "without it rather than waiting",
            label,
            deadline,
        )
        return default
    error = outcome.get("error")
    if error is not None:
        raise error  # type: ignore[misc]
    return outcome["value"]  # type: ignore[return-value]
