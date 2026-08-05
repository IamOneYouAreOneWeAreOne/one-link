"""A misconfigured numeric override must not crash startup or disable a bound.

Found 2026-08-05 while writing real reasons for the dark-switch registry. The
registry entry for ONE_LINK_MAX_PEERS said "peer table bound." -- true, and
uninformative enough that nobody had looked at the line it described:

    MAX_TOTAL_PEER_CONNECTIONS = int(os.environ.get("ONE_LINK_MAX_PEERS", "256"))

Three failure modes, each reproduced against the real module before the fix:

    ONE_LINK_MAX_PEERS=abc         ValueError at IMPORT -- daemon cannot start
    ONE_LINK_MAX_PEERS=0           accepted; the node then accepts no peers
    ONE_LINK_MAX_PEERS_PER_FP=-1   accepted; a negative connection bound

The first is loud but happens before logging exists, on a path with no handler
above it, so a typo in a service unit is indistinguishable from a broken build.
The other two are the dangerous ones: the process comes up looking healthy with
a protection configured to a value that disables it.

These tests are written against the CONSTANTS, imported by a fresh interpreter
under a modified environment, not against env_int/env_float alone. Testing the
helper only would prove the helper works while leaving open the thing that
actually broke -- a call site that never adopted it.

The subprocess is not incidental. The first version used importlib.reload() and
that was a genuine mistake, described at the call-site section below: it broke
31 tests in five unrelated files, every one of which passed in isolation.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

from one_link.env_bounds import env_float, env_int


# ── the helper ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("512", 512),      # a legal override takes effect
        ("abc", 256),      # unparseable -> default
        ("", 256),         # empty -> treated as unset
        ("   ", 256),      # whitespace-only -> treated as unset
        ("0", 1),          # clamped up to the minimum
        ("-5", 1),         # negative clamped up
        ("999999", 1000),  # clamped down to the maximum
        ("1e3", 256),      # int() rejects float syntax -> default, not 1000
        ("0x10", 256),     # base is pinned to 10, so this is not 16
    ],
)
def test_env_int_never_raises_and_lands_in_range(raw: str, expected: int) -> None:
    assert env_int(
        "X", 256, minimum=1, maximum=1000, environ={"X": raw}
    ) == expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("3.5", 3.5),
        ("soon", 2.0),
        ("", 2.0),
        ("0.0", 0.1),      # clamped up
        ("1000", 60.0),    # clamped down
        ("inf", 2.0),      # float() accepts these three by name...
        ("-inf", 2.0),
        ("nan", 2.0),      # ...and each destroys the meaning of a timeout
    ],
)
def test_env_float_rejects_the_non_finite_values_float_accepts(
    raw: str, expected: float
) -> None:
    """`float("inf")` and `float("nan")` succeed, which is the trap.

    An infinite deadline is indistinguishable from a hang. NaN makes every
    comparison against it false, so `elapsed > deadline` never fires and the
    timeout silently stops existing. Neither is a parse error, so a helper that
    only caught ValueError would pass both straight through.
    """
    assert env_float(
        "X", 2.0, minimum=0.1, maximum=60.0, environ={"X": raw}
    ) == expected


def test_an_absent_variable_is_silent(caplog: pytest.LogCaptureFixture) -> None:
    """No warning for something the operator did not do.

    A helper that logged on every default would bury the real warnings.
    """
    with caplog.at_level(logging.WARNING, logger="one_link.env_bounds"):
        assert env_int("ABSENT_XYZ", 7, environ={}) == 7
    assert caplog.records == []


@pytest.mark.parametrize(
    "raw,fragment",
    [("abc", "not an integer"), ("0", "below the supported minimum")],
)
def test_a_rejected_value_names_itself_in_the_log(
    raw: str, fragment: str, caplog: pytest.LogCaptureFixture
) -> None:
    """The operator has to be able to find out what happened.

    Silent fallback is how a node runs for months on a default the operator
    believes they overrode.
    """
    with caplog.at_level(logging.WARNING, logger="one_link.env_bounds"):
        env_int("ONE_LINK_MAX_PEERS", 256, minimum=1, environ={"ONE_LINK_MAX_PEERS": raw})
    assert len(caplog.records) == 1
    message = caplog.records[0].getMessage()
    assert fragment in message
    assert "ONE_LINK_MAX_PEERS" in message, "the message must name the variable"


# ── the call sites, which is what actually broke ──────────────────────
#
# These read the CONSTANTS under a modified environment, because testing
# env_int/env_float alone would prove the helper works while leaving open the
# thing that actually broke: a call site that never adopted it.
#
# In a SUBPROCESS, deliberately. The first version used importlib.reload() on
# one_link.daemon and it was a bad mistake: reloading a module rebinds its
# classes and constants, while every other module that did `from one_link.daemon
# import X` keeps pointing at the old objects. Isinstance checks and patch
# targets silently stop matching. It cost 31 failures across five unrelated
# files -- all of which passed in isolation, which is what made it look like
# flakiness rather than contamination.
#
# A subprocess is also the more honest test. The defect was that IMPORTING the
# module raised, and only a fresh interpreter actually imports it.


def _daemon_constant(name: str, **env: str):
    """Import one_link.daemon in a fresh interpreter and read one constant."""
    child = dict(os.environ)
    for key in (
        "ONE_LINK_MAX_PEERS",
        "ONE_LINK_MAX_PEERS_PER_FP",
        "ONE_LINK_FOREGROUND_ACK_DEADLINE_S",
        "ONE_LINK_QUIC_FRAME_DEADLINE_S",
    ):
        child.pop(key, None)
    child.update(env)
    result = subprocess.run(
        [sys.executable, "-c",
         f"import one_link.daemon as d; print(repr(d.{name}))"],
        capture_output=True, text=True, timeout=180, env=child,
        cwd=str(Path(__file__).resolve().parents[1]),
    )
    assert result.returncode == 0, (
        f"importing one_link.daemon failed with {env}: {result.stderr}"
    )
    printed = result.stdout.strip().splitlines()
    assert printed, f"no value printed; stderr: {result.stderr}"
    return eval(printed[-1])  # noqa: S307 - our own repr(), from our own child


def test_the_daemon_module_imports_with_a_garbage_peer_bound() -> None:
    """The regression that motivated all of this: import used to RAISE."""
    assert _daemon_constant(
        "MAX_TOTAL_PEER_CONNECTIONS", ONE_LINK_MAX_PEERS="abc"
    ) == 256


def test_the_daemon_module_imports_with_a_garbage_deadline() -> None:
    assert _daemon_constant(
        "FOREGROUND_ACK_DEADLINE_S", ONE_LINK_FOREGROUND_ACK_DEADLINE_S="soon"
    ) == 2.0


def test_a_zero_peer_ceiling_cannot_be_configured() -> None:
    """A ceiling of zero means the node accepts nobody, silently."""
    assert _daemon_constant("MAX_TOTAL_PEER_CONNECTIONS", ONE_LINK_MAX_PEERS="0") >= 1


def test_a_negative_per_fingerprint_bound_cannot_be_configured() -> None:
    assert _daemon_constant(
        "MAX_PEER_CONNECTIONS_PER_FP", ONE_LINK_MAX_PEERS_PER_FP="-1"
    ) >= 1


def test_an_infinite_frame_deadline_cannot_be_configured() -> None:
    """float() accepts "inf" by name, and an infinite deadline is a hang."""
    assert _daemon_constant(
        "QUIC_FRAME_DEADLINE_S", ONE_LINK_QUIC_FRAME_DEADLINE_S="inf"
    ) == 2.0


def test_a_legal_override_still_takes_effect() -> None:
    """CONTROL.

    Every assertion above is satisfied by a helper that ignores the environment
    entirely. This is the one that says the overrides still work at all.
    """
    assert _daemon_constant(
        "MAX_TOTAL_PEER_CONNECTIONS", ONE_LINK_MAX_PEERS="512"
    ) == 512


@pytest.mark.parametrize(
    "constant,expected",
    [
        ("MAX_TOTAL_PEER_CONNECTIONS", 256),
        ("MAX_PEER_CONNECTIONS_PER_FP", 4),
        ("FOREGROUND_ACK_DEADLINE_S", 2.0),
        ("QUIC_FRAME_DEADLINE_S", 2.0),
    ],
)
def test_the_shipped_defaults_are_unchanged(constant: str, expected) -> None:
    """CONTROL: routing through the helper must not have moved any default."""
    assert _daemon_constant(constant) == expected


# ── the gate that keeps this closed ───────────────────────────────────


def test_no_module_level_numeric_env_parse_is_left_unguarded() -> None:
    """Prevent the next one from being introduced.

    Fixing nine call sites is worth little if the tenth is written next month.
    This walks every shipped module and fails on `int(os.environ...)` or
    `float(os.environ...)` evaluated at import, which is precisely the shape
    that takes the daemon down before it can log why.

    It is scoped to module level deliberately: inside a function the same call
    has a handler above it and a chance to recover, so a blanket ban would be a
    noisy gate rather than a true one.
    """
    import ast
    import pathlib

    src = pathlib.Path(__file__).resolve().parents[1] / "src"
    offenders: list[str] = []

    class _Scan(ast.NodeVisitor):
        def __init__(self, path: pathlib.Path) -> None:
            self.path = path

        def visit_Call(self, node: ast.Call) -> None:
            func = node.func
            if (
                isinstance(func, ast.Name)
                and func.id in ("int", "float")
                and node.args
                and "environ" in ast.dump(node.args[0])
            ):
                offenders.append(
                    f"{self.path.relative_to(src)}:{node.lineno} "
                    f"{func.id}(os.environ...) at import"
                )
            self.generic_visit(node)

    for path in sorted(src.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for statement in tree.body:  # module level only
            _Scan(path).visit(statement)

    assert not offenders, (
        "use env_int/env_float from one_link.env_bounds -- a bare parse here "
        "raises at import, before logging exists:\n  " + "\n  ".join(offenders)
    )


def test_the_gate_above_can_actually_fail() -> None:
    """CALIBRATION: an AST gate that matches nothing passes for free.

    The scan above found nine real sites before the fix. Now that they are all
    converted it reports zero, and a zero from a broken matcher looks identical.
    This feeds it the exact source it is meant to catch and requires a hit.
    """
    import ast

    tree = ast.parse('X = int(os.environ.get("Y", "1"))\n')
    found: list[int] = []

    class _Scan(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            func = node.func
            if (
                isinstance(func, ast.Name)
                and func.id in ("int", "float")
                and node.args
                and "environ" in ast.dump(node.args[0])
            ):
                found.append(node.lineno)
            self.generic_visit(node)

    for statement in tree.body:
        _Scan().visit(statement)
    assert found == [1], "the matcher no longer recognises the pattern it bans"
