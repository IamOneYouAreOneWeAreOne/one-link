from pathlib import Path


def test_activity_panel_contains_self_mesh_surface():
    src = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    assert 'id="self-mesh-kit"' in src
    assert 'id="self-mesh-devices"' in src
    assert "renderSelfMesh()" in src
    assert "refreshSelfMesh()" in src


def test_self_mesh_ui_fetches_and_listens_for_daemon_events():
    src = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    assert 'selfMesh() { return this.get("/api/self-mesh"); }' in src
    assert 'm.type === "self_mesh_changed"' in src
    assert "state.selfMesh = await api.selfMesh()" in src
