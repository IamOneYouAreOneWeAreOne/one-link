"""Skips that run NOWHERE must be registered, not discovered.

A skipped test reads as a passing test in every summary line this project
prints. "9060 passed, 202 skipped" looks like full coverage and is not.

Auditing all 202 skips from a full local run put each one in a category and
asked, for each, whether ANY workflow runs it:

    150  live-daemon integration (ONE_LINK_RUN_LIVE_INTEGRATION)
             -> COVERED. tests.yml runs a named lane with the variable set,
                and both tagged-release quality jobs run the whole suite with
                it. test_release_workflow_v0210 enforces that.
     40  symlink / POSIX-only, skipped on Windows
             -> COVERED. full-suite runs ubuntu-latest as well, where they run.
      3  native wheel / native CDC absent locally
             -> COVERED. CI builds the engine before the suite.
      1  TLA+ TLC jar not set
             -> COVERED by a different route: formal_verification.yml downloads
                a pinned, hash-checked tla2tools.jar and runs TLC directly.
      1  host filesystem cannot represent a unicode collision
             -> environmental, and the assertion is about a filesystem that CAN.

That leaves the three mechanisms below, which run on NO runner and NO
developer machine by default. They are real gaps. This file exists so they
stay a short, deliberate list instead of drifting upward unnoticed: adding a
new never-run gate means adding it here on purpose.

The precedent for why this matters is in tests.yml itself. test_four_peer_swarm
was gated behind ONE_LINK_RUN_LIVE_INTEGRATION while every step that set that
variable enumerated files explicitly and omitted it, so a shipped multi-peer
capability had its live tests execute nowhere at all -- and nothing said so.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO / ".github" / "workflows"

# Each entry: the file holding never-run tests, the marker proving the gate is
# still the one described, and the token whose ABSENCE from every workflow is
# what makes it dark.
DARK_GATES = {
    "test_onnx_oracles.py": {
        "marker": "torch",
        "ci_token": "torch",
        "why": (
            "ONNX-vs-torch parity. The file's central claim is byte-equivalent "
            "inference against the torch oracles, and torch is in no extra and "
            "no workflow, so the parity claim itself has never been checked "
            "anywhere. The ML substrate is preview-only and stable artifacts "
            "omit it, which is why this is a gap and not a release blocker."
        ),
    },
    "test_confidential_native.py": {
        "marker": "unstable-deterministic-provider",
        "ci_token": "unstable-deterministic-provider",
        "why": (
            "SoftwareProvider.from_seed is behind a Cargo feature no workflow "
            "enables, so the deterministic-provider path is unexercised. The "
            "other 17 tests in the file do run."
        ),
    },
    "test_windows_hardened_m6.py": {
        "marker": "windows-tpm",
        "ci_token": "windows-tpm",
        "why": (
            "The live TPM 2.0 seal/sign/attest round trip needs a wheel built "
            "with --features windows-tpm AND real TPM hardware. No runner has "
            "both. The structural assertions around it do run; only the "
            "hardware round trip is dark, which the module docstring already "
            "states plainly."
        ),
    },
}


def workflow_text() -> str:
    return "\n".join(
        p.read_text(encoding="utf-8", errors="replace")
        for p in sorted(WORKFLOWS.glob("*.yml"))
    )


def test_the_registry_points_at_files_that_exist() -> None:
    # A renamed file would make every assertion below vacuous.
    for name in DARK_GATES:
        assert (REPO / "tests" / name).is_file(), f"{name} is registered but missing"


@pytest.mark.parametrize("name", sorted(DARK_GATES))
def test_each_registered_gate_still_gates_the_way_it_is_described(name: str) -> None:
    source = (REPO / "tests" / name).read_text(encoding="utf-8", errors="replace")
    marker = DARK_GATES[name]["marker"]
    assert marker in source, (
        f"{name} no longer mentions {marker!r}. If the gate changed or was "
        f"removed, update DARK_GATES -- the registry is describing something "
        f"that is not there any more.\nRecorded reason: {DARK_GATES[name]['why']}"
    )


@pytest.mark.parametrize("name", sorted(DARK_GATES))
def test_a_gate_that_became_covered_must_leave_the_registry(name: str) -> None:
    """The registry must shrink when a gap closes, not quietly go stale.

    If someone adds torch to a workflow, or builds a wheel with the TPM
    feature, these tests stop being dark -- and this list would otherwise keep
    claiming they are, which is its own kind of wrong answer.
    """
    token = DARK_GATES[name]["ci_token"]
    assert token not in workflow_text(), (
        f"{token!r} now appears in a workflow, so {name} may no longer be "
        f"dark. Confirm it actually runs, then remove it from DARK_GATES."
    )


def test_the_dark_set_stays_small_and_deliberate() -> None:
    # Not a coverage metric -- a tripwire. Growth here means never-run tests
    # are accumulating, which is exactly what nobody notices.
    assert len(DARK_GATES) == 3, (
        "the number of never-run test gates changed. Add the new one with a "
        "reason, or remove one that is now covered."
    )
