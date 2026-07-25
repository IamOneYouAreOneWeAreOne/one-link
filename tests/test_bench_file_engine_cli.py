from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

from scripts import bench_file_engine
from tests.harness import LIVE_INTEGRATION_ENV, live_integration_enabled


def test_file_engine_cli_explicitly_enables_its_live_daemon_lane(monkeypatch) -> None:
    monkeypatch.setenv(LIVE_INTEGRATION_ENV, "0")
    assert live_integration_enabled() is False

    bench_file_engine._enable_live_benchmark_lane()

    assert live_integration_enabled() is True


def test_benchmark_pair_pins_and_grants_files_on_both_sides(monkeypatch, tmp_path) -> None:
    pair = SimpleNamespace(
        a=SimpleNamespace(home=tmp_path / "a", short_id="aaaa1111"),
        b=SimpleNamespace(home=tmp_path / "b", short_id="bbbb2222"),
    )

    @contextmanager
    def fake_pair():
        yield pair

    def fake_wait(_home, short_id):
        return {"fingerprint": f"fp-{short_id}"}

    calls: list[tuple[object, str, str, object]] = []

    def fake_api(home, method, path, body=None):
        calls.append((home, method, path, body))
        return {"ok": True}

    monkeypatch.setattr(bench_file_engine, "_daemon_pair", fake_pair)
    monkeypatch.setattr(bench_file_engine, "_wait_api_peer", fake_wait)
    monkeypatch.setattr(bench_file_engine, "_api", fake_api)

    with bench_file_engine.daemon_pair() as yielded:
        assert yielded is pair

    trust_calls = [call for call in calls if call[2].endswith("/trust")]
    capability_calls = [call for call in calls if call[2].endswith("/capabilities")]
    assert len(trust_calls) == 2
    assert len(capability_calls) == 2
    assert all(call[3] == {"trust": "pinned"} for call in trust_calls)
    assert all(call[3]["allowed"] == ["chat", "files"] for call in capability_calls)
