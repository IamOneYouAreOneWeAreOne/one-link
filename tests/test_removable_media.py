from __future__ import annotations

from pathlib import Path

from one_link.removable_media import (
    RemovableEventDetector,
    find_removable_target,
    list_removable_targets,
    removable_event_source_status,
)


def test_posix_removable_targets_from_env_root(tmp_path: Path, monkeypatch):
    root = tmp_path / "media"
    drive = root / "USB"
    drive.mkdir(parents=True)
    monkeypatch.setenv("ONE_LINK_COURIER_MEDIA_ROOTS", str(root))

    targets = list_removable_targets()

    assert any(t.label == "USB" and t.path == drive.resolve() for t in targets)
    found = find_removable_target(next(t.id for t in targets if t.label == "USB"))
    assert found is not None
    assert found.path == drive.resolve()


def test_removable_event_detector_emits_attach_and_remove(tmp_path: Path, monkeypatch):
    root = tmp_path / "media"
    root.mkdir()
    monkeypatch.setenv("ONE_LINK_COURIER_MEDIA_ROOTS", str(root))
    detector = RemovableEventDetector()

    first = detector.poll()
    assert first["changed"] is False
    assert first["events"] == []

    drive = root / "USB"
    drive.mkdir()
    attached = detector.poll()
    assert attached["changed"] is True
    assert [event["kind"] for event in attached["events"]] == ["attached"]
    assert attached["events"][0]["target"]["label"] == "USB"
    assert attached["event_count"] == 1

    drive.rmdir()
    removed = detector.poll()
    assert removed["changed"] is True
    assert [event["kind"] for event in removed["events"]] == ["removed"]
    assert removed["events"][0]["target"]["label"] == "USB"
    assert removed["event_count"] == 2


def test_removable_event_detector_can_emit_initial_targets(tmp_path: Path, monkeypatch):
    root = tmp_path / "media"
    drive = root / "USB"
    drive.mkdir(parents=True)
    monkeypatch.setenv("ONE_LINK_COURIER_MEDIA_ROOTS", str(root))

    first = RemovableEventDetector(emit_initial=True).poll()

    assert first["changed"] is True
    assert [event["kind"] for event in first["events"]] == ["attached"]
    assert first["targets"][0]["label"] == "USB"


def test_removable_event_source_status_describes_event_contract():
    status = removable_event_source_status()

    assert status["mode"] == "native_compatible_inventory_events"
    assert set(status["semantics"]) == {"attached", "removed", "changed"}
