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

_READ = re.compile(r'environ(?:\.get)?[\(\[]\s*["\'](ONE_LINK_[A-Z0-9_]+)')

# Switches the source reads that nothing else mentions. Each needs a reason.
# Triaged 2026-08-05; the security-relevant ones are called out because an
# undocumented switch that WEAKENS something is the dangerous member of this
# family, not a tuning knob.
KNOWN_UNREACHABLE: dict[str, str] = {
    # -- security posture: these WEAKEN a default. Highest priority to cover.
    "ONE_LINK_ALLOW_FIXED_COURIER_TARGETS":
        "lets courier files land on FIXED drives; the code comment says "
        "production must not spray them onto C:. Test-only opt-in, untested.",
    "ONE_LINK_ALLOW_LEGACY_RELAY_IDENTITY_ROUTE":
        "re-enables a legacy relay identity route, and accepts a LOOSE value "
        "set {1,true,yes,on} plus a stored setting -- unlike the handshake "
        "switch, which requires exactly '1'. Inconsistent posture, untested.",
    "ONE_LINK_SMART_SELECTOR_ENFORCE": "changes transport-selection enforcement.",
    "ONE_LINK_COVER_TRAFFIC": "privacy feature toggle.",
    # -- credentials
    "ONE_LINK_TURN_CREDENTIAL": "TURN credential injection point.",
    "ONE_LINK_TURN_USERNAME": "TURN username injection point.",
    # -- resource / DoS bounds
    "ONE_LINK_MAX_PEERS": "peer table bound.",
    "ONE_LINK_MAX_PEERS_PER_FP": "per-fingerprint peer bound.",
    # -- timing and tuning knobs
    "ONE_LINK_CASCADE_THRESHOLD": "tuning knob.",
    "ONE_LINK_FOREGROUND_ACK_DEADLINE_S": "tuning knob.",
    "ONE_LINK_QUIC_FRAME_DEADLINE_S": "tuning knob.",
    "ONE_LINK_QUIC_TRANSPORT": "transport selection override.",
    "ONE_LINK_RECONCILE_DISAGREEMENTS_ACKED": "reconciliation behaviour.",
    "ONE_LINK_RELAY_PROBE_TIMEOUT_SECONDS": "tuning knob.",
    "ONE_LINK_UI_UPLOAD_IDLE_TIMEOUT_SECONDS": "tuning knob.",
    "ONE_LINK_WAVE_FORECAST": "research feature, shipped DISABLED by default.",
    "ONE_LINK_WAVE_FORECAST_DT": "research feature parameter.",
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
    assert len(found) >= 40, f"only {len(found)} switches found; the scan broke"
    # A switch known to exist and known to be covered.
    assert "ONE_LINK_ALLOW_V1_HELLO" in found


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


def test_the_security_weakening_switches_are_called_out() -> None:
    """The dangerous member of this family is a switch that WEAKENS a default.

    A tuning knob nobody documents is untidy. An undocumented switch that
    disables a protection is the actual hazard, and the reason strings must say
    so rather than blending in with the knobs.
    """
    for name in ("ONE_LINK_ALLOW_FIXED_COURIER_TARGETS",
                 "ONE_LINK_ALLOW_LEGACY_RELAY_IDENTITY_ROUTE"):
        assert name in KNOWN_UNREACHABLE, f"{name} dropped out of the registry"
        reason = KNOWN_UNREACHABLE[name]
        assert len(reason) > 40, f"{name} needs a real reason, got {reason!r}"


def test_the_handshake_downgrade_is_no_longer_dark() -> None:
    """The switch that motivated this gate must stay covered.

    ONE_LINK_ALLOW_CLASSICAL_HANDSHAKE disables ML-KEM on a live channel. It is
    named in the product's own refusal message, so it is the one an operator is
    most likely to reach for.
    """
    reachable = everything_that_could_reach_them()
    assert "ONE_LINK_ALLOW_CLASSICAL_HANDSHAKE" in reachable
    assert "ONE_LINK_ALLOW_CLASSICAL_HANDSHAKE" not in KNOWN_UNREACHABLE
