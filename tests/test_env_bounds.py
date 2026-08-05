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

These tests are written against the CONSTANTS as re-imported under a modified
environment, not against env_int/env_float alone. Testing the helper only would
prove the helper works while leaving open the thing that actually broke -- a
call site that never adopted it.
"""

from __future__ import annotations

import importlib
import logging

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


def _daemon_with(monkeypatch: pytest.MonkeyPatch, **env: str):
    import one_link.daemon as daemon

    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return importlib.reload(daemon)


@pytest.fixture(autouse=True)
def _restore_daemon_module():
    """Reloading daemon under a modified env must not leak into other tests."""
    yield
    import one_link.daemon as daemon

    importlib.reload(daemon)


def test_the_daemon_module_imports_with_a_garbage_peer_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The regression that motivated all of this: import used to raise."""
    daemon = _daemon_with(monkeypatch, ONE_LINK_MAX_PEERS="abc")
    assert daemon.MAX_TOTAL_PEER_CONNECTIONS == 256


def test_the_daemon_module_imports_with_a_garbage_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon = _daemon_with(monkeypatch, ONE_LINK_FOREGROUND_ACK_DEADLINE_S="soon")
    assert daemon.FOREGROUND_ACK_DEADLINE_S == 2.0


def test_a_zero_peer_ceiling_cannot_be_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ceiling of zero means the node accepts nobody, silently."""
    daemon = _daemon_with(monkeypatch, ONE_LINK_MAX_PEERS="0")
    assert daemon.MAX_TOTAL_PEER_CONNECTIONS >= 1


def test_a_negative_per_fingerprint_bound_cannot_be_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon = _daemon_with(monkeypatch, ONE_LINK_MAX_PEERS_PER_FP="-1")
    assert daemon.MAX_PEER_CONNECTIONS_PER_FP >= 1


def test_a_legal_override_still_takes_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CONTROL.

    Every assertion above is satisfied by a helper that ignores the environment
    entirely. This is the one that says the overrides still work at all.
    """
    daemon = _daemon_with(monkeypatch, ONE_LINK_MAX_PEERS="512")
    assert daemon.MAX_TOTAL_PEER_CONNECTIONS == 512


def test_the_shipped_defaults_are_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CONTROL: routing through the helper must not have moved any default."""
    for name in (
        "ONE_LINK_MAX_PEERS",
        "ONE_LINK_MAX_PEERS_PER_FP",
        "ONE_LINK_FOREGROUND_ACK_DEADLINE_S",
        "ONE_LINK_QUIC_FRAME_DEADLINE_S",
    ):
        monkeypatch.delenv(name, raising=False)
    import one_link.daemon as daemon

    daemon = importlib.reload(daemon)
    assert daemon.MAX_TOTAL_PEER_CONNECTIONS == 256
    assert daemon.MAX_PEER_CONNECTIONS_PER_FP == 4
    assert daemon.FOREGROUND_ACK_DEADLINE_S == 2.0
    assert daemon.QUIC_FRAME_DEADLINE_S == 2.0


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
