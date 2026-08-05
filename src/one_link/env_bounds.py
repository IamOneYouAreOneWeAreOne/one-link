"""Validated numeric environment overrides.

Nine module-level constants across daemon.py and server.py were built as bare
``int(os.environ.get(NAME, default))``. Three separate failure modes followed
from that, all confirmed by running the code:

    ONE_LINK_MAX_PEERS=abc              -> ValueError at IMPORT. The daemon
                                           cannot start, and the traceback is
                                           the only thing that names the cause.
    ONE_LINK_MAX_PEERS=0                -> accepted. The global peer-connection
                                           ceiling becomes zero, so the node
                                           accepts nobody, silently.
    ONE_LINK_MAX_PEERS_PER_FP=-1        -> accepted. A negative bound.

The first is the worst class -- a typo in a service unit or a launchd plist
takes the whole application down before logging exists, on a code path with no
handler above it. The second and third are worse in kind though quieter: the
process comes up looking healthy while a protection has been set to a value
that disables it.

The rule here: a malformed or out-of-range override never crashes startup and
never silently takes effect. It falls back to the shipped default (or the
nearest legal bound), and says so. An operator who set the variable gets a line
naming the variable, the value, and what was used instead.

Clamping rather than refusing is deliberate: these are operational knobs, and a
node that boots with a sane bound and a loud warning is more useful than one
that will not boot. The security-relevant switches are NOT in this family --
those live behind explicit allow-lists that fail closed, because a downgrade
must never be reachable by accident. See tests/test_no_dark_env_switches.py.
"""

from __future__ import annotations

import logging
import os
from typing import Mapping

log = logging.getLogger("one_link.env_bounds")

__all__ = ["env_int", "env_float"]


def _raw(name: str, environ: Mapping[str, str] | None) -> str | None:
    source = os.environ if environ is None else environ
    value = source.get(name)
    if value is None:
        return None
    value = value.strip()
    # An empty or whitespace-only override is a common shell accident
    # (`export ONE_LINK_MAX_PEERS=` or an unset variable expanded into a unit
    # file). Treat it as "not set" rather than as a parse failure, so it does
    # not produce a warning for something the operator did not really do.
    return value or None


def _clamp(
    value: float,
    *,
    name: str,
    minimum: float | None,
    maximum: float | None,
) -> float:
    if minimum is not None and value < minimum:
        log.warning(
            "%s=%s is below the supported minimum %s; using %s",
            name, value, minimum, minimum,
        )
        return minimum
    if maximum is not None and value > maximum:
        log.warning(
            "%s=%s is above the supported maximum %s; using %s",
            name, value, maximum, maximum,
        )
        return maximum
    return value


def env_int(
    name: str,
    default: int,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
    environ: Mapping[str, str] | None = None,
) -> int:
    """Read ``name`` as an int, clamped to [minimum, maximum].

    Returns ``default`` for an absent, empty, or unparseable value. Never
    raises -- callers are module-level constants with no handler above them.
    """
    raw = _raw(name, environ)
    if raw is None:
        return default
    try:
        parsed = int(raw, 10)
    except ValueError:
        log.warning(
            "%s=%r is not an integer; using the default %s", name, raw, default
        )
        return default
    return int(_clamp(parsed, name=name, minimum=minimum, maximum=maximum))


def env_float(
    name: str,
    default: float,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
    environ: Mapping[str, str] | None = None,
) -> float:
    """Read ``name`` as a float, clamped to [minimum, maximum].

    Rejects NaN and the infinities in addition to unparseable text. ``float()``
    accepts all three by name, and an infinite deadline is indistinguishable
    from a hang while NaN makes every comparison against it false -- so a
    timeout set to either stops being a timeout at all.
    """
    raw = _raw(name, environ)
    if raw is None:
        return default
    try:
        parsed = float(raw)
    except ValueError:
        log.warning(
            "%s=%r is not a number; using the default %s", name, raw, default
        )
        return default
    if parsed != parsed or parsed in (float("inf"), float("-inf")):
        log.warning(
            "%s=%r is not a finite number; using the default %s",
            name, raw, default,
        )
        return default
    return float(_clamp(parsed, name=name, minimum=minimum, maximum=maximum))
