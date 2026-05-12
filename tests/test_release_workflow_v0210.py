"""Structural tests for .github/workflows/release.yml.

A tagged-release run must produce:
    1. A pure-Python sdist + wheel (existing).
    2. A native wheel per OS (Linux, macOS, Windows), built via maturin
       and shipping the Rust hot-path crates.
    3. A SHA256SUMS manifest covering every file attached to the release.
    4. Sigstore-signed bundles for every artifact.

The workflow is the single point of truth for "what gets uploaded to a
GitHub Release," so we lock in its structural contract here. If a future
edit drops the native_wheels job, or breaks the dependency chain, the
suite fails before the YAML ever fires in CI.

These tests do NOT actually run GitHub Actions; they parse the YAML and
assert invariants. The next time anyone tags a release we'll see the
real run, but the gate here keeps the foot-gun off the workflow itself.
"""

from __future__ import annotations

from pathlib import Path

import pytest


WORKFLOW = (
    Path(__file__).resolve().parent.parent
    / ".github" / "workflows" / "release.yml"
)


@pytest.fixture(scope="module")
def workflow():
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


# ─── trigger contract ──────────────────────────────────────────────────

def test_release_fires_on_version_tag_push(workflow):
    """The workflow must trigger when a `v*` tag is pushed. If someone
    accidentally narrows the trigger (e.g. to a specific branch), releases
    silently stop happening; this test catches that."""
    # PyYAML parses YAML `on:` as Python `True` because YAML treats `on`/`off`
    # as boolean aliases. Look up via the boolean key as well as the string.
    on = workflow.get("on") or workflow.get(True)
    assert on is not None, "workflow has no trigger block"
    push = on.get("push", {})
    tags = push.get("tags", [])
    assert "v*" in tags, f"v*-tag trigger missing; got tags={tags!r}"


# ─── jobs that must exist ──────────────────────────────────────────────

def test_workflow_has_required_jobs(workflow):
    """build (sdist+wheel), native_wheels (rust crates per OS), sign
    (sigstore + release attachment) — every release run must have all three."""
    jobs = workflow["jobs"]
    for name in ("build", "native_wheels", "sign"):
        assert name in jobs, f"missing job: {name!r}"


# ─── native_wheels job structure ───────────────────────────────────────

def test_native_wheels_matrix_covers_all_three_oses(workflow):
    """A native wheel must be produced on each supported platform.
    Dropping any one of these means users on that OS can't install
    one-link[native] from the release page."""
    matrix = (
        workflow["jobs"]["native_wheels"]["strategy"]["matrix"]["include"]
    )
    oses = {entry["os"] for entry in matrix}
    assert oses >= {"ubuntu-latest", "macos-latest", "windows-latest"}, (
        f"native wheel matrix is missing an OS: {oses}"
    )


def test_native_wheels_uploads_one_artifact_per_os(workflow):
    """Each matrix leg uploads under a unique artifact name so the sign
    job can download all three independently. If two legs use the same
    artifact name the second upload silently overwrites the first."""
    matrix = (
        workflow["jobs"]["native_wheels"]["strategy"]["matrix"]["include"]
    )
    names = [entry["artifact"] for entry in matrix]
    assert len(names) == len(set(names)), (
        f"duplicate artifact names: {names}"
    )
    for name in names:
        assert name.startswith("native-wheel-"), (
            f"artifact name should start with native-wheel-: {name!r}"
        )


def test_native_wheels_uses_maturin_release_strip(workflow):
    """We build with `maturin build --release --strip` so the wheel is
    optimized AND strip()s debug symbols (cuts ~10-20MB on Linux). If
    someone changes this to `maturin develop` (venv-only) or drops
    --release, the workflow stops producing real distribution artifacts.
    """
    steps = workflow["jobs"]["native_wheels"]["steps"]
    build_step = next(
        (s for s in steps if "maturin build" in s.get("run", "")),
        None,
    )
    assert build_step is not None, "no `maturin build` step in native_wheels"
    cmd = build_step["run"]
    assert "--release" in cmd, "native_wheels must use --release"
    assert "build" in cmd, "must use `maturin build`, not `develop`"


def test_native_wheels_runs_after_build_so_versions_align(workflow):
    """We pass SOURCE_DATE_EPOCH from the build job into the maturin
    build for reproducibility. native_wheels therefore must declare a
    dependency on build, or the env-var passthrough will resolve to
    empty and the wheels won't be bit-identical across rebuilds."""
    needs = workflow["jobs"]["native_wheels"].get("needs")
    assert needs == "build" or needs == ["build"] or "build" in (needs or []), (
        f"native_wheels.needs must include 'build': got {needs!r}"
    )


# ─── sign job: must consume + sign all artifacts ──────────────────────

def test_sign_waits_for_both_build_and_native_wheels(workflow):
    """If sign starts before native_wheels finishes, the release will be
    cut without native wheels attached. The Phase-1 contract is that
    `pip install one_link_native --find-links <release>` works the
    moment the release is published."""
    needs = workflow["jobs"]["sign"]["needs"]
    if isinstance(needs, str):
        needs = [needs]
    assert "build" in needs
    assert "native_wheels" in needs


def test_sign_downloads_native_wheels_into_dist(workflow):
    """The sign job downloads every native-wheel-* artifact into dist/
    so sigstore-sign picks them up and softprops/action-gh-release
    uploads them. If a future refactor changes the artifact name
    pattern, this test catches it before the broken release ships."""
    steps = workflow["jobs"]["sign"]["steps"]
    download_steps = [
        s for s in steps
        if isinstance(s.get("uses"), str)
        and s["uses"].startswith("actions/download-artifact")
    ]
    artifact_names = [s.get("with", {}).get("name", "") for s in download_steps]
    for required in ("dist", "native-wheel-linux",
                     "native-wheel-macos", "native-wheel-windows"):
        assert required in artifact_names, (
            f"sign job must download artifact {required!r}; "
            f"got {artifact_names!r}"
        )


def test_sign_recomputes_sha256sums_after_native_wheels_arrive(workflow):
    """The build job's SHA256SUMS only covers pure-Python artifacts.
    Once the native wheels land in dist/ they must be added to the
    manifest, otherwise consumers can't verify their downloads."""
    steps = workflow["jobs"]["sign"]["steps"]
    recompute = next(
        (s for s in steps if "sha256sum" in s.get("run", "")
         and "SHA256SUMS" in s.get("run", "")),
        None,
    )
    assert recompute is not None, (
        "sign job does not recompute SHA256SUMS — native wheels would "
        "be attached without verifiable hashes"
    )


def test_sign_attaches_wheels_to_release(workflow):
    """Final step: softprops/action-gh-release uploads `dist/*.whl`.
    With native wheels merged into dist/, the same glob covers both
    pure-Python and native. If a future change pins specific filenames,
    native wheels would silently stop being attached."""
    steps = workflow["jobs"]["sign"]["steps"]
    release_step = next(
        (s for s in steps if isinstance(s.get("uses"), str)
         and s["uses"].startswith("softprops/action-gh-release")),
        None,
    )
    assert release_step is not None, "no gh-release upload step"
    files = release_step["with"]["files"]
    assert "dist/*.whl" in files, (
        f"release upload doesn't include dist/*.whl: {files!r}"
    )


# ─── pyproject.toml: declares the native optional dep ─────────────────

def test_workflow_has_binaries_job(workflow):
    """End-users download .exe / mac binary / linux binary from the
    website. The binaries job is what produces those — without it,
    the website's download button 404s."""
    assert "binaries" in workflow["jobs"]


def test_binaries_matrix_covers_all_three_oses(workflow):
    matrix = workflow["jobs"]["binaries"]["strategy"]["matrix"]["include"]
    oses = {entry["os"] for entry in matrix}
    assert oses >= {"ubuntu-latest", "macos-latest", "windows-latest"}


def test_binaries_asset_names_match_landing_page_expectations(workflow):
    """The landing-page JS expects assets named exactly:
        one-link-windows.exe
        one-link-macos
        one-link-linux-x86_64
    If the workflow changes the asset name, the website's download
    button breaks. This test pins the contract on both ends."""
    matrix = workflow["jobs"]["binaries"]["strategy"]["matrix"]["include"]
    names = {entry["asset_name"] for entry in matrix}
    required = {
        "one-link-windows.exe",
        "one-link-macos",
        "one-link-linux-x86_64",
    }
    assert required <= names, (
        f"binaries job is missing required asset name(s); "
        f"have {names}, need {required}"
    )


def test_binaries_job_installs_native_wheel_before_pyinstaller(workflow):
    """For the bundled binary to include the Rust hot-path, the
    matching native wheel must be installed in the build env BEFORE
    `python scripts/build_binary.py` runs. The script's auto-detect
    only finds one_link_native via the active site-packages."""
    steps = workflow["jobs"]["binaries"]["steps"]
    step_names = [s.get("name", "") for s in steps]
    # The install-native-wheel step must come before the
    # build-standalone-binary step.
    try:
        install_idx = next(
            i for i, n in enumerate(step_names)
            if "install native wheel" in n.lower()
        )
        build_idx = next(
            i for i, n in enumerate(step_names)
            if "build standalone" in n.lower()
        )
    except StopIteration:
        pytest.fail(
            f"binaries job missing required steps; got {step_names!r}"
        )
    assert install_idx < build_idx, (
        f"native wheel install must precede binary build, got "
        f"install at {install_idx}, build at {build_idx}"
    )


def test_sign_attaches_binaries_to_release(workflow):
    """The standalone binaries must end up on the GitHub Release
    page so the website's download links resolve."""
    steps = workflow["jobs"]["sign"]["steps"]
    release_step = next(
        (s for s in steps if isinstance(s.get("uses"), str)
         and s["uses"].startswith("softprops/action-gh-release")),
        None,
    )
    assert release_step is not None
    files = release_step["with"]["files"]
    assert "dist/one-link-*" in files, (
        f"release upload doesn't include one-link-* binaries: {files!r}"
    )


def test_sign_signs_binaries_with_sigstore(workflow):
    """The standalone binaries are the highest-stakes artifact
    (they're what end users execute). They must be sigstore-signed
    so anyone can verify the .exe was built by Actions from the
    matching tag."""
    steps = workflow["jobs"]["sign"]["steps"]
    sign_step = next(
        (s for s in steps if "sigstore sign" in s.get("run", "")),
        None,
    )
    assert sign_step is not None
    cmd = sign_step["run"]
    assert "one-link-*" in cmd, (
        "sigstore-sign loop doesn't cover the standalone binaries"
    )


def test_pyproject_declares_native_optional_dependency():
    """`pip install one-link[native]` must resolve a real package name
    so users have a single-command install path. The Phase-1 contract
    is that the [native] extra exists and points at one_link_native."""
    pyproject = (
        Path(__file__).resolve().parent.parent / "pyproject.toml"
    )
    text = pyproject.read_text(encoding="utf-8")
    # Lightweight check that doesn't pull in tomllib for older test
    # configurations: search for the section + dep name in raw text.
    assert "[project.optional-dependencies]" in text
    # The extra is on its own line as `native = [...]`.
    assert "native = [" in text or "\nnative =[" in text, (
        "no [native] optional dependency declared"
    )
    assert "one_link_native" in text, (
        "[native] extra exists but doesn't list one_link_native"
    )
