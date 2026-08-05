"""A switch the product reads, that nobody can know about, is a dark gate.

This is the systemic version of a defect found by hand:
ONE_LINK_ALLOW_CLASSICAL_HANDSHAKE disables the post-quantum handshake -- no
ML-KEM, so no harvest-now-decrypt-later protection -- and had zero tests and
zero documentation, while its twin ONE_LINK_ALLOW_V1_HELLO (same function,
same call site, same consequence) had six test files. The product's own
refusal message even told operators to set the UNTESTED one.

The class is not "that variable": it is that the source can read a switch which
changes behaviour while nothing outside the source knows it exists. Nobody can
test it, document it, or audit whether it is safe by default.

So this gate compares every ONE_LINK_* variable the source READS against
everything that could set, document or test it -- tests, docs, workflows,
scripts, README, shipped web assets. Anything reachable from nowhere else must
be listed below WITH A REASON, which makes adding a dark switch a deliberate
act rather than an oversight.

The registry is not a ratchet on soundness. It is a named list that must
SHRINK: a switch that becomes reachable has to leave it, so the list cannot
quietly go stale in the flattering direction.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src" / "one_link"

# Matches every way the source READS a switch. env_int/env_float are the
# validated numeric readers added 2026-08-05; when nine constants moved onto
# them, this regex -- which only knew about os.environ -- stopped seeing those
# nine entirely. The gate would have gone on reporting "no dark switches" while
# no longer looking at them. A scan that silently narrows is worse than no scan,
# because it still produces a green result.
_READ = re.compile(
    r'(?:environ(?:\.get)?[\(\[]|env_int\(|env_float\()\s*["\'](ONE_LINK_[A-Z0-9_]+)'
)

# Switches the source reads that nothing else mentions. Each needs a reason.
# Triaged 2026-08-05; the security-relevant ones are called out because an
# undocumented switch that WEAKENS something is the dangerous member of this
# family, not a tuning knob.
KNOWN_UNREACHABLE: dict[str, str] = {
    # EMPTY, 2026-08-05. Every switch the source reads is now reachable from
    # outside src/ -- by a test, a workflow, or docs/ENVIRONMENT.md.
    #
    # It started at 17 entries. Each removal was forced by the staleness
    # assertion below rather than chosen: covering a switch made its entry a
    # false claim that a gap still existed, and the only way to make the suite
    # green again was to delete the entry. The list can only shrink.
    #
    # An empty registry does NOT mean this file has nothing left to do. Its job
    # is test_no_new_dark_switch: the next switch someone adds without a test
    # or a doc line fails immediately, instead of living unnoticed the way
    # ONE_LINK_ALLOW_CLASSICAL_HANDSHAKE did.
    #
    # If you are adding an entry here, you are re-opening a closed class. Write
    # a real reason, and prefer a test.
}


SELF = Path(__file__).resolve()


def _text_of(*globs: tuple[Path, str]) -> str:
    """Read matching files, EXCLUDING this one.

    The registry below names every switch it declares unreachable, and it lives
    in tests/. Scanning itself would make each registered name look covered.
    The staleness check caught exactly that on its first run.
    """
    out = []
    for base, pattern in globs:
        if not base.exists():
            continue
        for p in base.rglob(pattern):
            if p.is_file() and p.resolve() != SELF:
                out.append(p.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(out)


def switches_read_by_source() -> set[str]:
    body = _text_of((SRC, "*.py"))
    return set(_READ.findall(body))


def everything_that_could_reach_them() -> str:
    parts = [
        _text_of((REPO / "tests", "*.py")),
        _text_of((REPO / "docs", "*.md")),
        _text_of((REPO / ".github" / "workflows", "*.yml")),
        _text_of((REPO / "scripts", "*.py"), (REPO / "scripts", "*.ps1"),
                 (REPO / "scripts", "*.sh")),
        _text_of((SRC / "web", "*")),
    ]
    readme = REPO / "README.md"
    if readme.exists():
        parts.append(readme.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(parts)


def test_the_scanner_finds_the_switches_it_is_supposed_to() -> None:
    """Control. A regex that matched nothing would make this gate vacuous."""
    found = switches_read_by_source()
    assert len(found) >= 55, f"only {len(found)} switches found; the scan broke"
    # A switch known to exist and known to be covered.
    assert "ONE_LINK_ALLOW_V1_HELLO" in found
    # Read via env_int(), not os.environ. Pinned by name because the regex once
    # matched only os.environ and silently stopped seeing nine switches when
    # they moved to the validated readers -- the gate stayed green while its
    # coverage shrank. Losing these names again must fail loudly.
    assert "ONE_LINK_MAX_PEERS" in found, (
        "the scan no longer sees switches read through env_int/env_float"
    )
    assert "ONE_LINK_QUIC_FRAME_DEADLINE_S" in found


def test_no_new_dark_switch() -> None:
    """Every switch the source reads must be reachable, or registered."""
    reachable = everything_that_could_reach_them()
    unreachable = {s for s in switches_read_by_source() if s not in reachable}
    undeclared = sorted(unreachable - set(KNOWN_UNREACHABLE))
    assert not undeclared, (
        "these switches change behaviour but nothing outside src/ mentions "
        "them -- nobody can test, document or audit them:\n  "
        + "\n  ".join(undeclared)
        + "\n\nAdd a test or a doc line. If it is genuinely internal, add it to "
        "KNOWN_UNREACHABLE with a reason."
    )


def test_the_registry_shrinks_and_does_not_go_stale() -> None:
    """A switch that became reachable must LEAVE the list.

    Without this the registry rots in the flattering direction: entries would
    accumulate and keep claiming a gap that has since been closed, which is
    how a known-gaps list stops being believed.
    """
    reachable = everything_that_could_reach_them()
    now_covered = sorted(s for s in KNOWN_UNREACHABLE if s in reachable)
    assert not now_covered, (
        "these are now referenced outside src/, so remove them from "
        "KNOWN_UNREACHABLE:\n  " + "\n  ".join(now_covered)
    )


def test_no_security_weakening_switch_is_still_dark() -> None:
    """The dangerous member of this family is a switch that WEAKENS a default.

    A tuning knob nobody documents is untidy. An undocumented switch that
    disables a protection is the actual hazard.

    This test used to NAME the two `ALLOW_*` switches and assert they were in
    the registry with good reasons. Once they were covered they had to leave the
    registry, and this assertion failed -- correctly, but for a reason that says
    the test was written at the wrong level. A gate should assert the rule, not
    enumerate today's violations of it, or closing a violation breaks the gate.

    The rule: no `ONE_LINK_ALLOW_*` switch may sit in the dark registry at all.
    Something that turns a protection OFF must be reachable from a test.
    """
    still_dark = sorted(n for n in KNOWN_UNREACHABLE if "_ALLOW_" in n)
    assert not still_dark, (
        "these switches WEAKEN a default and nothing outside src/ exercises "
        "them; cover them rather than registering them: "
        + "; ".join(f"{n}: {KNOWN_UNREACHABLE[n]}" for n in still_dark)
    )


def test_every_registered_reason_is_substantive() -> None:
    """A registry entry earns its place with a reason, not a placeholder.

    Without this, the gate above is trivially satisfiable by writing "todo"
    next to a switch.
    """
    thin = {n: r for n, r in KNOWN_UNREACHABLE.items() if len(r.strip()) < 15}
    assert not thin, f"these registry entries lack a real reason: {thin}"


def test_the_weakening_switches_are_covered_not_registered() -> None:
    """The two that motivated the rule above, pinned individually.

    Same shape as the handshake assertion below: reachable from outside src/,
    and absent from the registry. Naming them here is right where naming them
    in a registry-membership test was wrong -- this asserts the END state, so
    closing the gap satisfies it instead of breaking it.
    """
    reachable = everything_that_could_reach_them()
    for name in ("ONE_LINK_ALLOW_FIXED_COURIER_TARGETS",
                 "ONE_LINK_ALLOW_LEGACY_RELAY_IDENTITY_ROUTE"):
        assert name in reachable, f"{name} went dark again"
        assert name not in KNOWN_UNREACHABLE, f"{name} was re-registered as dark"


def test_the_handshake_downgrade_is_no_longer_dark() -> None:
    """The switch that motivated this gate must stay covered.

    ONE_LINK_ALLOW_CLASSICAL_HANDSHAKE disables ML-KEM on a live channel. It is
    named in the product's own refusal message, so it is the one an operator is
    most likely to reach for.
    """
    reachable = everything_that_could_reach_them()
    assert "ONE_LINK_ALLOW_CLASSICAL_HANDSHAKE" in reachable
    assert "ONE_LINK_ALLOW_CLASSICAL_HANDSHAKE" not in KNOWN_UNREACHABLE
