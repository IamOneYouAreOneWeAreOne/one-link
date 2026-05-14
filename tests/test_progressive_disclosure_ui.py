from pathlib import Path


def test_route_setup_codes_are_advanced_not_default_sidebar_noise() -> None:
    src = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    assert 'id="route-bootstrap-advanced"' in src
    assert "Advanced path setup" in src
    advanced_idx = src.index('id="route-bootstrap-advanced"')
    section = src[advanced_idx:src.index("</details>", advanced_idx)]
    assert 'id="route-bootstrap-token"' in section
    assert 'id="btn-copy-route-bootstrap"' in section
    assert 'id="btn-import-route-bootstrap"' in section
    assert "Copy setup code" in section
    assert "Import setup code" in section


def test_route_setup_uses_plain_language_for_users() -> None:
    src = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    assert "Setup code ready" in src
    assert "Path check queued" in src
    assert "Paste a setup code first." in src
    assert "Route token ready" not in src
    assert "Paste a route token first." not in src
