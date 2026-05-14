from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UI_FILES = [
    ROOT / "src" / "one_link" / "web" / "index.html",
    ROOT / "src" / "one_link" / "web" / "peer.html",
]


class _ControlCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.controls: list[tuple[str, dict[str, str]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = {k: v or "" for k, v in attrs}
        if tag in {"button", "select", "textarea"}:
            self.controls.append((tag, data))
            return
        if tag == "input":
            kind = data.get("type", "text")
            if kind in {"button", "checkbox", "file", "radio", "range", "submit"}:
                self.controls.append((tag, data))


def _camel_data_attr(name: str) -> str:
    parts = name[5:].split("-")
    return parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:])


def _script_blocks(html: str) -> str:
    return "\n".join(
        re.findall(r"<script[^>]*>([\s\S]*?)</script>", html, flags=re.I)
    )


def _is_wired(control: dict[str, str], js: str) -> bool:
    control_id = control.get("id")
    if control_id:
        needles = {
            f"#{control_id}",
            f'getElementById("{control_id}")',
            f"getElementById('{control_id}')",
            f'$("#{control_id}")',
            f"$('#{control_id}')",
        }
        if any(needle in js for needle in needles):
            return True

    name = control.get("name")
    if name and (
        f'name="{name}"' in js
        or f"name='{name}'" in js
        or f'input[name="{name}"]' in js
        or f"input[name='{name}']" in js
    ):
        return True

    for attr in control:
        if attr.startswith("data-"):
            dataset = _camel_data_attr(attr)
            if (
                f"[{attr}]" in js
                or f"[{attr}=" in js
                or attr in js
                or f"dataset.{dataset}" in js
            ):
                return True

    return False


def test_static_ui_controls_have_event_wiring() -> None:
    """Every static user control must be wired directly or by delegation."""
    failures: list[str] = []
    for path in UI_FILES:
        html = path.read_text(encoding="utf-8")
        js = _script_blocks(html)
        parser = _ControlCollector()
        parser.feed(html)
        for tag, control in parser.controls:
            if "disabled" in control:
                continue
            if not _is_wired(control, js):
                label = control.get("id") or control.get("name") or str(control)
                failures.append(f"{path.relative_to(ROOT)}: <{tag}> {label}")

    assert not failures, "Unwired UI controls:\n" + "\n".join(failures)
