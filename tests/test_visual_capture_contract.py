"""Safety contract for browser-review screenshot destinations."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
VISUAL_CAPTURE_MODULE = REPO_ROOT / "tests" / "e2e" / "test_visual_regression.py"


def _load_visual_capture_module():
    module_name = "_one_link_visual_capture_contract_target"
    spec = importlib.util.spec_from_file_location(module_name, VISUAL_CAPTURE_MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


visual = _load_visual_capture_module()


class _FakePage:
    def __init__(self) -> None:
        self.style_injected = False

    def add_style_tag(self, *, content: str) -> None:
        assert content
        self.style_injected = True

    def screenshot(self, *, path: str, full_page: bool) -> None:
        assert self.style_injected
        assert full_page is False
        Path(path).write_bytes(b"contract-capture")


def _baseline_snapshot() -> dict[str, tuple[int, bytes]]:
    return {
        path.name: (path.stat().st_mtime_ns, path.read_bytes())
        for path in visual._BASELINE_DIR.glob("*.png")
    }


def test_default_capture_writes_only_to_ignored_artifact_directory() -> None:
    before = _baseline_snapshot()
    configuration = visual._prepare_capture_configuration({})
    assert configuration.directory == (
        REPO_ROOT / "test-results" / "screenshots"
    ).resolve()
    assert configuration.updates_baselines is False
    assert not visual._is_within(configuration.directory, visual._BASELINE_DIR.resolve())
    assert "/test-results/" in (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")

    output = visual._capture(
        _FakePage(),
        "00_contract_default_destination",
        configuration=configuration,
    )
    try:
        assert output == configuration.directory / "00_contract_default_destination.png"
        assert output.read_bytes() == b"contract-capture"
        assert _baseline_snapshot() == before
    finally:
        output.unlink(missing_ok=True)


def test_ci_retains_review_captures_on_success_and_failure() -> None:
    workflow = (REPO_ROOT / ".github" / "workflows" / "full_suite_and_e2e.yml").read_text(
        encoding="utf-8"
    )
    step = workflow.split(
        "- name: upload browser review captures + traces", maxsplit=1
    )[1].split("\n      - name:", maxsplit=1)[0]
    assert "if: always()" in step
    assert "test-results/" in step
    assert "actions/upload-artifact@" in step


@pytest.mark.parametrize(
    "environ",
    [
        {"ONE_LINK_VISUAL_CAPTURE_DIR": ""},
        {"ONE_LINK_VISUAL_CAPTURE_DIR": "tests/e2e/screenshots"},
        {"ONE_LINK_VISUAL_CAPTURE_DIR": "tests/e2e/screenshots/nested"},
        {"ONE_LINK_VISUAL_CAPTURE_DIR": "tests/e2e/review-output"},
        {"ONE_LINK_VISUAL_CAPTURE_DIR": "."},
        {"ONE_LINK_UPDATE_VISUAL_BASELINES": "ambiguous"},
        {
            "ONE_LINK_UPDATE_VISUAL_BASELINES": "1",
            "ONE_LINK_VISUAL_CAPTURE_DIR": "test-results/screenshots",
        },
    ],
)
def test_unsafe_or_ambiguous_output_configuration_fails_closed(environ) -> None:
    with pytest.raises(visual.VisualCaptureConfigurationError):
        visual._resolve_capture_configuration(environ)


def test_explicit_external_artifact_override_is_supported(tmp_path: Path) -> None:
    requested = tmp_path / "browser-artifacts"
    configuration = visual._prepare_capture_configuration(
        {"ONE_LINK_VISUAL_CAPTURE_DIR": str(requested)}
    )
    assert configuration.directory == requested.resolve()
    assert configuration.directory.is_dir()
    assert configuration.updates_baselines is False


def test_existing_file_cannot_be_used_as_capture_directory(tmp_path: Path) -> None:
    output_file = tmp_path / "not-a-directory"
    output_file.write_text("sentinel", encoding="utf-8")
    with pytest.raises(visual.VisualCaptureConfigurationError):
        visual._resolve_capture_configuration(
            {"ONE_LINK_VISUAL_CAPTURE_DIR": str(output_file)}
        )
    assert output_file.read_text(encoding="utf-8") == "sentinel"


def test_baseline_refresh_requires_explicit_opt_in_and_exact_target() -> None:
    configuration = visual._resolve_capture_configuration(
        {"ONE_LINK_UPDATE_VISUAL_BASELINES": "true"}
    )
    assert configuration.directory == visual._BASELINE_DIR.resolve()
    assert configuration.updates_baselines is True


@pytest.mark.parametrize(
    "configuration",
    [
        visual.VisualCaptureConfiguration(visual._BASELINE_DIR.resolve(), False),
        visual.VisualCaptureConfiguration(
            (REPO_ROOT / "test-results" / "screenshots").resolve(), True
        ),
    ],
)
def test_forged_capture_configuration_is_revalidated_before_page_interaction(
    configuration,
) -> None:
    before = _baseline_snapshot()
    page = _FakePage()
    with pytest.raises(visual.VisualCaptureConfigurationError):
        visual._capture(page, "forged_configuration", configuration=configuration)
    assert page.style_injected is False
    assert _baseline_snapshot() == before


@pytest.mark.parametrize("name", ["../escape", "nested/name", "..", "", "a\\b"])
def test_capture_name_path_traversal_fails_before_page_interaction(
    tmp_path: Path, name: str
) -> None:
    configuration = visual.VisualCaptureConfiguration(tmp_path, False)
    page = _FakePage()
    with pytest.raises(visual.VisualCaptureConfigurationError):
        visual._capture(page, name, configuration=configuration)
    assert page.style_injected is False
    assert not list(tmp_path.iterdir())
