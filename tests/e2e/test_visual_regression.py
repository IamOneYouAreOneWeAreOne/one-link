"""Capture key UI surfaces for human review.

This is deliberately *not* a pixel-diff visual-regression gate. Chromium,
font, and operating-system rendering differences make a single cross-platform
baseline unsuitable for deterministic pass/fail assertions. The tests verify
that each surface renders and that a review image is produced; CI uploads the
images as artifacts.

Normal runs write only to the ignored ``test-results/screenshots`` artifact
directory. Set ``ONE_LINK_VISUAL_CAPTURE_DIR`` to an explicit artifact path
when a runner needs a different destination. Checked-in reference images under
``tests/e2e/screenshots`` are immutable unless the operator explicitly sets
``ONE_LINK_UPDATE_VISUAL_BASELINES=1``. That opt-in should be used only for an
intentional, separately reviewed baseline-refresh commit.
"""
from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import NamedTuple

import pytest


_REPO_ROOT = Path(__file__).resolve().parents[2]
_BASELINE_DIR = Path(__file__).resolve().parent / "screenshots"
_ARTIFACT_ROOT = _REPO_ROOT / "test-results"
_DEFAULT_CAPTURE_DIR = _ARTIFACT_ROOT / "screenshots"
_CAPTURE_DIR_ENV = "ONE_LINK_VISUAL_CAPTURE_DIR"
_UPDATE_BASELINES_ENV = "ONE_LINK_UPDATE_VISUAL_BASELINES"
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"", "0", "false", "no", "off"})
_SAFE_CAPTURE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


class VisualCaptureConfigurationError(ValueError):
    """Raised before any filesystem write for an unsafe capture target."""


class VisualCaptureConfiguration(NamedTuple):
    directory: Path
    updates_baselines: bool


def _is_within(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def _parse_update_flag(environ: Mapping[str, str]) -> bool:
    raw = environ.get(_UPDATE_BASELINES_ENV, "").strip().lower()
    if raw in _TRUE_VALUES:
        return True
    if raw in _FALSE_VALUES:
        return False
    raise VisualCaptureConfigurationError(
        f"{_UPDATE_BASELINES_ENV} must be one of "
        "1/true/yes/on or 0/false/no/off"
    )


def _validate_resolved_directory(directory: Path, *, update_baselines: bool) -> None:
    baseline = _BASELINE_DIR.resolve(strict=False)
    repo_root = _REPO_ROOT.resolve(strict=True)
    artifact_root = _ARTIFACT_ROOT.resolve(strict=False)

    if directory.parent == directory:
        raise VisualCaptureConfigurationError(
            "visual captures may not target a filesystem root"
        )
    if directory.exists() and not directory.is_dir():
        raise VisualCaptureConfigurationError(
            f"visual-capture target exists but is not a directory: {directory}"
        )
    if update_baselines:
        if directory != baseline:
            raise VisualCaptureConfigurationError(
                f"{_UPDATE_BASELINES_ENV}=1 may target only {baseline}"
            )
        return
    if _is_within(directory, baseline):
        raise VisualCaptureConfigurationError(
            "refusing to overwrite checked-in screenshots without "
            f"{_UPDATE_BASELINES_ENV}=1"
        )
    if directory == repo_root or directory in repo_root.parents:
        raise VisualCaptureConfigurationError(
            "visual captures may not target the repository or one of its parents"
        )
    if _is_within(directory, repo_root) and not _is_within(directory, artifact_root):
        raise VisualCaptureConfigurationError(
            "in-repository captures must stay under the ignored test-results directory"
        )


def _resolve_capture_configuration(
    environ: Mapping[str, str] | None = None,
) -> VisualCaptureConfiguration:
    """Resolve and validate the output policy without touching the filesystem."""
    env = os.environ if environ is None else environ
    update_baselines = _parse_update_flag(env)

    override_present = _CAPTURE_DIR_ENV in env
    override = env.get(_CAPTURE_DIR_ENV, "").strip()
    if override_present and not override:
        raise VisualCaptureConfigurationError(
            f"{_CAPTURE_DIR_ENV} was set but is empty"
        )

    default_path = _BASELINE_DIR if update_baselines else _DEFAULT_CAPTURE_DIR
    raw_path = Path(override).expanduser() if override else default_path
    if not raw_path.is_absolute():
        raw_path = _REPO_ROOT / raw_path
    try:
        directory = raw_path.resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise VisualCaptureConfigurationError(
            f"unable to resolve visual-capture directory: {exc}"
        ) from exc

    _validate_resolved_directory(directory, update_baselines=update_baselines)
    return VisualCaptureConfiguration(directory, update_baselines)


def _prepare_capture_configuration(
    environ: Mapping[str, str] | None = None,
) -> VisualCaptureConfiguration:
    configuration = _resolve_capture_configuration(environ)
    configuration.directory.mkdir(parents=True, exist_ok=True)
    # Resolve once more after creation so a pre-existing symlink cannot redirect
    # a normal artifact capture into the tracked baseline tree.
    actual = configuration.directory.resolve(strict=True)
    if actual != configuration.directory:
        raise VisualCaptureConfigurationError(
            "visual-capture directory changed during preparation"
        )
    _validate_resolved_directory(
        actual, update_baselines=configuration.updates_baselines
    )
    return configuration


@pytest.fixture(scope="module")
def visual_capture_configuration() -> VisualCaptureConfiguration:
    return _prepare_capture_configuration()


def _capture(
    page,
    name: str,
    *,
    configuration: VisualCaptureConfiguration,
    locator=None,
    full_page: bool = False,
):
    """Capture one named review image under the validated output directory."""
    if not _SAFE_CAPTURE_NAME.fullmatch(name) or name in {".", ".."}:
        raise VisualCaptureConfigurationError(f"unsafe screenshot name: {name!r}")
    try:
        directory = configuration.directory.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise VisualCaptureConfigurationError(
            f"unable to resolve prepared visual-capture directory: {exc}"
        ) from exc
    if directory != configuration.directory:
        raise VisualCaptureConfigurationError(
            "visual-capture directory changed after preparation"
        )
    _validate_resolved_directory(
        directory, update_baselines=configuration.updates_baselines
    )
    out = directory / f"{name}.png"
    # Stabilize: hide time-varying elements (ping ms, presence
    # timestamps, animated chrome) so successive captures of the
    # same state are pixel-stable across runs on the same machine.
    page.add_style_tag(content="""
        .latency-pill, [data-pulse-ts], #activity-since-clock,
        #presence-ts, time, .toast, .toast-container,
        #onboarding-backdrop { visibility: hidden !important; }
        * { animation-duration: 0s !important;
            transition-duration: 0s !important; }
    """)
    if locator is not None:
        locator.screenshot(path=str(out))
    else:
        page.screenshot(path=str(out), full_page=full_page)
    return out


def _require_visible_unique(locator, label: str):
    """Return one required UI landmark or fail the release gate."""
    assert locator.count() == 1, (
        f"expected exactly one {label}; found {locator.count()}"
    )
    locator.wait_for(state="visible", timeout=5_000)
    assert locator.is_visible(), f"{label} exists but is not visible"
    return locator


def _require_open_pane(ui_page, *, button_id: str, pane_id: str, heading: str):
    """Open a primary pane and prove its tab, root, and heading are live."""
    button = _require_visible_unique(
        ui_page.locator(f"#{button_id}"), f"{heading} navigation tab"
    )
    pane = ui_page.locator(f"#{pane_id}")
    assert pane.count() == 1, (
        f"expected exactly one {heading} pane root; found {pane.count()}"
    )

    button.click()
    pane.wait_for(state="visible", timeout=5_000)
    assert pane.is_visible(), f"{heading} pane did not become visible after click"
    assert "active" in (button.get_attribute("class") or "").split(), (
        f"{heading} tab did not become active after click"
    )
    assert pane.locator(".section-h > span").first.inner_text().strip() == heading, (
        f"{heading} pane rendered without its stable section heading"
    )
    return pane


# ── named captures ──────────────────────────────────────────────────


def test_capture_initial_ui(ui_page, visual_capture_configuration):
    """The boot state every user sees on first connect."""
    ui_page.wait_for_load_state("networkidle")
    path = _capture(
        ui_page,
        "01_initial_ui",
        configuration=visual_capture_configuration,
        full_page=False,
    )
    assert path.is_file()


def test_capture_top_navigation(ui_page, visual_capture_configuration):
    """Top nav: Chat / Files / Folders / Activity + identity chip."""
    ui_page.wait_for_load_state("networkidle")
    header = _require_visible_unique(ui_page.locator("header.top"), "top header")
    nav = _require_visible_unique(ui_page.locator("#pane-tabs"), "primary navigation")
    for pane, label in (
        ("convo", "Chat"),
        ("files", "Files"),
        ("folders", "Folders"),
        ("mesh", "Activity"),
    ):
        tab = _require_visible_unique(
            nav.locator(f'button[data-pane="{pane}"]'), f"{label} navigation tab"
        )
        assert tab.inner_text().strip() == label
    _require_visible_unique(
        header.locator("#presence-pill"), "local identity/presence control"
    )
    path = _capture(
        ui_page,
        "02_top_navigation",
        configuration=visual_capture_configuration,
        locator=header,
    )
    assert path.is_file()


def test_capture_sidebar(ui_page, visual_capture_configuration):
    """Left sidebar with identity + devices + pair button."""
    ui_page.wait_for_load_state("networkidle")
    # Index.html uses <aside class="side"> for the left rail; older
    # builds used .sidebar / #sidebar so we keep those as fallbacks.
    sidebar = ui_page.locator("aside.side, .sidebar, #sidebar").first
    assert sidebar.count() > 0, (
        "sidebar selector matched no element — left rail missing "
        "from the rendered UI (this is a real coverage gap, not a "
        "skip-worthy condition)"
    )
    path = _capture(
        ui_page,
        "03_sidebar_empty",
        configuration=visual_capture_configuration,
        locator=sidebar,
    )
    assert path.is_file()


def test_capture_files_pane(ui_page, visual_capture_configuration):
    """Files pane (empty inbox state)."""
    ui_page.wait_for_load_state("networkidle")
    pane = _require_open_pane(
        ui_page,
        button_id="btn-files",
        pane_id="files-panel",
        heading="Files",
    )
    _require_visible_unique(pane.locator("#filelist"), "Files history root")
    _require_visible_unique(
        pane.locator("#btn-files-received"), "Files Received selector"
    )
    _require_visible_unique(
        pane.locator("#btn-send-file-panel"), "Files Send action"
    )
    path = _capture(
        ui_page, "04_files_pane", configuration=visual_capture_configuration
    )
    assert path.is_file()


def test_capture_folders_pane(ui_page, visual_capture_configuration):
    """Folders pane with the Add form + Browse button - the
    surface we just fixed the picker bug in."""
    ui_page.wait_for_load_state("networkidle")
    pane = _require_open_pane(
        ui_page,
        button_id="btn-folders",
        pane_id="folders-panel",
        heading="Shared folders",
    )
    _require_visible_unique(pane.locator("#folderlist"), "Folders list root")
    _require_visible_unique(pane.locator("#folder-name"), "Folder name input")
    _require_visible_unique(pane.locator("#folder-path"), "Folder path input")
    _require_visible_unique(
        pane.locator("#btn-browse-folder"), "Folder Browse action"
    )
    _require_visible_unique(pane.locator("#btn-add-folder"), "Folder Add action")
    path = _capture(
        ui_page, "05_folders_pane", configuration=visual_capture_configuration
    )
    assert path.is_file()


def test_capture_activity_pane(ui_page, visual_capture_configuration):
    """Activity pane (empty state on a fresh daemon)."""
    ui_page.wait_for_load_state("networkidle")
    pane = _require_open_pane(
        ui_page,
        button_id="btn-mesh",
        pane_id="mesh-panel",
        heading="Activity",
    )
    _require_visible_unique(pane.locator("#mesh-summary"), "Activity summary")
    _require_visible_unique(pane.locator("#activity-list"), "Activity event list")
    _require_visible_unique(
        pane.locator("#activity-search-input"), "Activity search input"
    )
    _require_visible_unique(
        pane.locator("#btn-refresh-mesh"), "Activity Refresh action"
    )
    path = _capture(
        ui_page, "06_activity_pane", configuration=visual_capture_configuration
    )
    assert path.is_file()


def test_capture_search_input_open(ui_page, visual_capture_configuration):
    """The search input we just fixed (icon-trigger vs placeholder
    overlap). Force-show + capture the open state via clip-region
    so we don't depend on the parent .convo-h visibility (which
    requires a peer to be selected)."""
    ui_page.wait_for_load_state("networkidle")
    # The search-wrap lives inside `.convo-h` (header above the
    # conversation), which has its own display rules. To capture it
    # regardless of parent state, REPARENT the element to <body> so
    # no ancestor visibility rule can hide it, then apply the
    # fixed-position style + open class.
    ui_page.evaluate(
        """() => {
            const w = document.getElementById('search-wrap');
            if (!w) return;
            // Remove any ancestor that could be hiding it.
            document.body.appendChild(w);
            w.classList.add('open');
            w.style.cssText =
                'position:fixed;top:8px;right:8px;'
              + 'display:flex;width:280px;z-index:99999;'
              + 'background:var(--bg-2);padding:6px;border-radius:6px;'
              + 'visibility:visible;opacity:1;pointer-events:auto;';
        }"""
    )
    ui_page.wait_for_timeout(300)
    search = ui_page.locator("#search-wrap").first
    assert search.count() > 0, (
        "#search-wrap missing from the rendered UI — search input "
        "not wired into index.html"
    )
    assert search.is_visible(), (
        "#search-wrap exists but is not visible even after we "
        "reparented it to <body> with explicit fixed-position CSS "
        "— a CSS rule is overriding inline styles or display:none "
        "is being re-applied by JS"
    )
    path = _capture(
        ui_page,
        "07_search_input_open",
        configuration=visual_capture_configuration,
        locator=search,
    )
    assert path.is_file()
