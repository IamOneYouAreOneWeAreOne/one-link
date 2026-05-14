from pathlib import Path


def test_courier_panel_is_user_first_and_progressive() -> None:
    src = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    assert ">Offline delivery<" in src
    assert "Move a file when the internet, router, or other device is not reachable." in src
    assert 'id="courier-advanced"' in src
    assert "Advanced offline options" in src
    assert ">Download bundle<" in src
    assert ">Import selected<" in src
    assert ">Copy unlock code<" in src
    assert ">Save bundle<" in src
    assert ">Copy to USB<" in src
    assert ">Pull from USB<" in src


def test_courier_panel_hides_power_user_controls_by_default() -> None:
    src = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    advanced_idx = src.index('id="courier-advanced"')
    default_idx = src.index('id="courier-kit"')
    assert default_idx < advanced_idx
    advanced = src[advanced_idx:src.index('id="courier-wizard"', advanced_idx)]
    for control_id in (
        "courier-outbox-select",
        "courier-removable-select",
        "courier-removable-file-select",
        "courier-chunks",
        "btn-courier-stage",
        "btn-courier-copy-removable",
        "btn-courier-pull-removable",
    ):
        assert f'id="{control_id}"' in advanced


def test_courier_copy_uses_plain_language() -> None:
    src = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    assert "Duplicate protection remembers" in src
    assert "Share the unlock code separately" in src
    assert "Import it and let One Link verify it" in src
    assert "Offline bundle ready" in src
    assert "Courier bundle ready" not in src
    assert "Replay guard remembers" not in src
