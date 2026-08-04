"""The reproducibility gate compares two builds, so the two builds must match.

`reproducible_release.yml` builds the native wheel twice on isolated Linux
runners and asserts the results are byte-identical. That claim is only worth
anything if the two builds are configured the same way -- and for 39 runs they
were not.

`build_artifacts` installed the Rust toolchain with `--component rust-src`;
`verify_reproducibility` did not. With std sources present in the sysroot,
rustc translates std panic locations from the virtual `/rustc/<hash>/library/`
form back to the real local path, so the candidate wheel carried 27 strings
reading `/home/runner/.rustup/toolchains/1.96.0-.../library/...` that the
rebuild did not have. Longer strings grew `.rodata` by a page and shifted
`.data.rel.ro` and `.rela.dyn` with it. `.text` was byte-identical in both
builds the entire time: code generation was never the problem, and every run
that blamed it was chasing the wrong thing.

The failure is invisible in review because both steps LOOK like a pinned
toolchain install. These tests compare them as text, which is the only way the
difference shows up.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
REPRODUCIBLE = WORKFLOWS / "reproducible_release.yml"
RELEASE = WORKFLOWS / "release.yml"

TOOLCHAIN_INSTALL = re.compile(r"^\s*(rustup toolchain install \S+ .*)$", re.MULTILINE)


def toolchain_installs(path: Path) -> list[str]:
    """Every `rustup toolchain install` command line in a workflow, normalised."""
    text = path.read_text(encoding="utf-8")
    return [" ".join(m.split()) for m in TOOLCHAIN_INSTALL.findall(text)]


def test_reproducibility_workflow_exists() -> None:
    # A missing file would make every assertion below vacuously pass.
    assert REPRODUCIBLE.is_file(), f"{REPRODUCIBLE} is missing"
    assert RELEASE.is_file(), f"{RELEASE} is missing"


def test_both_reproducibility_builds_install_the_same_toolchain() -> None:
    installs = toolchain_installs(REPRODUCIBLE)
    assert len(installs) == 2, (
        "expected exactly two toolchain installs in reproducible_release.yml "
        f"(the candidate build and the rebuild), found {len(installs)}: {installs}"
    )
    candidate, rebuild = installs
    assert candidate == rebuild, (
        "the two builds this workflow compares do not install the same "
        "toolchain, so a byte difference between them proves nothing about "
        f"determinism:\n  candidate: {candidate}\n  rebuild:   {rebuild}"
    )


def test_the_reproducibility_candidate_installs_no_extra_components() -> None:
    # `rust-src` specifically re-points std panic locations at the builder's
    # own home directory. Any component that changes what lands in the wheel
    # has the same effect, so the candidate build takes the minimal profile and
    # nothing else.
    for install in toolchain_installs(REPRODUCIBLE):
        assert "--component" not in install, (
            "a reproducibility build must not add toolchain components: they "
            "can change the emitted artifact, and no released wheel is built "
            f"with them.\n  {install}"
        )


def test_the_rebuild_matches_how_releases_are_actually_built() -> None:
    # A rebuild that differs from the release build cannot speak for released
    # bytes even if it compares equal to its own twin.
    release_installs = {
        i for i in toolchain_installs(RELEASE) if "--component" not in i
    }
    assert release_installs, "release.yml has no component-free toolchain install"
    repro_installs = set(toolchain_installs(REPRODUCIBLE))
    assert repro_installs <= release_installs, (
        "the reproducibility build does not match any native build in "
        f"release.yml:\n  reproducibility: {sorted(repro_installs)}\n"
        f"  release.yml:     {sorted(release_installs)}"
    )


@pytest.mark.parametrize(
    "flag",
    ["--release", "--strip", "--locked"],
)
def test_both_builds_use_the_same_maturin_flags(flag: str) -> None:
    text = REPRODUCIBLE.read_text(encoding="utf-8")
    commands = [line for line in text.splitlines() if "maturin build" in line]
    assert len(commands) == 2, f"expected two maturin builds, found {commands}"
    for command in commands:
        assert flag in command, f"{flag} missing from a compared build: {command}"


def test_an_empty_comparison_is_a_failure_not_a_pass() -> None:
    # The comparison reports success when nothing diverged. With no wheels on
    # either side nothing CAN diverge, so a build step that stopped emitting a
    # wheel would turn this gate green while certifying nothing.
    text = REPRODUCIBLE.read_text(encoding="utf-8")
    assert "REPRODUCIBILITY VACUOUS" in text, (
        "the comparison must refuse an empty wheel set explicitly"
    )


def test_no_rustflags_are_injected_into_either_build() -> None:
    # Released wheels are built with no RUSTFLAGS. A rebuild that sets them is
    # measuring a different artifact. `-C target-feature=+crt-static` was set
    # here once and broke every run: it reaches proc-macro crates, which must
    # be dylibs.
    text = REPRODUCIBLE.read_text(encoding="utf-8")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        assert not stripped.startswith("RUSTFLAGS"), (
            f"RUSTFLAGS must not be set in the reproducibility workflow: {line}"
        )
