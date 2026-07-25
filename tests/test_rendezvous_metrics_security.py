"""Reverse-proxy and secret-boundary regressions for rendezvous metrics."""

from __future__ import annotations

from pathlib import Path

import aiohttp
import pytest

from one_link.rendezvous_server import (
    RendezvousApp,
    ServerConfig,
    _parse_args,
    _read_metrics_token_file,
)


_TOKEN = "m" * 64


async def _start(config: ServerConfig) -> tuple[str, aiohttp.web.AppRunner]:
    runner = aiohttp.web.AppRunner(RendezvousApp(config).make_app())
    await runner.setup()
    site = aiohttp.web.TCPSite(runner, host="127.0.0.1", port=0)
    await site.start()
    sockets = list(site._server.sockets)
    port = sockets[0].getsockname()[1]
    return f"http://127.0.0.1:{port}", runner


@pytest.mark.asyncio
async def test_proxy_loopback_cannot_bypass_metrics_without_token() -> None:
    base, runner = await _start(
        ServerConfig(
            host="0.0.0.0",
            port=0,
            trust_proxy_headers=True,
        )
    )
    try:
        cases = (
            {},
            {"X-Forwarded-For": "not-an-ip"},
            {"X-Forwarded-For": "198.51.100.7"},
            {"X-Forwarded-For": "127.0.0.1, 198.51.100.8"},
            {"X-Forwarded-For": "127.0.0.1"},
        )
        async with aiohttp.ClientSession() as session:
            for headers in cases:
                async with session.get(f"{base}/metrics", headers=headers) as response:
                    assert response.status == 403
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_proxy_metrics_requires_constant_time_bearer_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link import rendezvous_server

    calls: list[tuple[str, str]] = []
    real_compare = rendezvous_server.hmac.compare_digest

    def observed_compare(supplied: str, expected: str) -> bool:
        calls.append((supplied, expected))
        return real_compare(supplied, expected)

    monkeypatch.setattr(rendezvous_server.hmac, "compare_digest", observed_compare)
    base, runner = await _start(
        ServerConfig(
            host="0.0.0.0",
            port=0,
            trust_proxy_headers=True,
            metrics_token=_TOKEN,
        )
    )
    try:
        external = {"X-Forwarded-For": "203.0.113.9"}
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{base}/metrics", headers=external) as response:
                assert response.status == 401
                assert response.headers["WWW-Authenticate"] == "Bearer"
            async with session.get(
                f"{base}/metrics",
                headers={**external, "Authorization": "Bearer wrong"},
            ) as response:
                assert response.status == 401
            async with session.get(
                f"{base}/metrics",
                headers={**external, "Authorization": f"Bearer {_TOKEN}"},
            ) as response:
                assert response.status == 200
                assert (await response.json())["registrations"] == 0
            async with session.get(
                f"{base}/metrics",
                headers={**external, "Authorization": f"bearer {_TOKEN}"},
            ) as response:
                assert response.status == 200
        assert calls == [
            ("", _TOKEN),
            ("wrong", _TOKEN),
            (_TOKEN, _TOKEN),
            (_TOKEN, _TOKEN),
        ]
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_untrusted_forwarding_headers_never_grant_wildcard_listener_access() -> None:
    base, runner = await _start(
        ServerConfig(
            host="0.0.0.0",
            port=0,
            trust_proxy_headers=False,
        )
    )
    try:
        async with aiohttp.ClientSession() as session:
            for spoofed in ("127.0.0.1", "::1", "198.51.100.1"):
                async with session.get(
                    f"{base}/metrics",
                    headers={"X-Forwarded-For": spoofed},
                ) as response:
                    assert response.status == 403
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_exclusive_loopback_listener_preserves_local_operator_path() -> None:
    base, runner = await _start(
        ServerConfig(
            host="127.0.0.1",
            port=0,
            trust_proxy_headers=False,
        )
    )
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{base}/metrics",
                headers={"X-Forwarded-For": "127.0.0.1"},
            ) as response:
                assert response.status == 200
    finally:
        await runner.cleanup()


@pytest.mark.parametrize(
    "token",
    [
        "",
        "short",
        "has whitespace " + "x" * 32,
        "\u00e9" * 32,
        '"' + "x" * 31,
        "x=" + "y" * 31,
    ],
)
def test_metrics_token_policy_rejects_weak_or_ambiguous_secrets(token: str) -> None:
    with pytest.raises(ValueError, match="metrics_token"):
        RendezvousApp(ServerConfig(metrics_token=token))


def test_metrics_token_file_is_bounded_and_cli_wired(tmp_path: Path) -> None:
    token_file = tmp_path / "metrics-token"
    token_file.write_text(_TOKEN + "\n", encoding="utf-8")
    assert _read_metrics_token_file(str(token_file)) == _TOKEN
    config = _parse_args(
        [
            "--host",
            "127.0.0.1",
            "--metrics-token-file",
            str(token_file),
        ]
    )
    assert config.metrics_token == _TOKEN

    token_file.write_text(_TOKEN + "\n\n", encoding="utf-8")
    with pytest.raises(ValueError, match="exactly one token"):
        _read_metrics_token_file(str(token_file))


def test_metrics_token_file_rejects_symlink_and_oversize(
    tmp_path: Path,
) -> None:
    oversized = tmp_path / "oversized-token"
    oversized.write_bytes(b"x" * 4098)
    with pytest.raises(ValueError, match="at most 4096"):
        _read_metrics_token_file(str(oversized))

    target = tmp_path / "real-token"
    target.write_text(_TOKEN, encoding="utf-8")
    link = tmp_path / "linked-token"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("file symlinks are unavailable on this host")
    with pytest.raises(ValueError, match="non-symlink"):
        _read_metrics_token_file(str(link))


def test_deployment_defaults_deny_public_metrics_and_use_secret_files() -> None:
    repo = Path(__file__).resolve().parents[1]
    nginx = (repo / "deploy/rendezvous/nginx.conf.example").read_text(encoding="utf-8")
    entrypoint = (repo / "deploy/rendezvous/entrypoint.sh").read_text(encoding="utf-8")
    deploy_readme = (repo / "deploy/rendezvous/README.md").read_text(encoding="utf-8")
    runbook = (repo / "docs/RENDEZVOUS_DEPLOY.md").read_text(encoding="utf-8")

    assert "location = /metrics" in nginx
    assert nginx.index("location = /metrics") < nginx.index("location / {")
    assert "ONE_LINK_RDZ_METRICS_TOKEN_FILE" in entrypoint
    assert "--metrics-token-file" in entrypoint
    assert "?token=" not in entrypoint + deploy_readme + runbook
    assert "https://rendezvous.example.com/metrics" not in runbook
    assert "mounted secret" in deploy_readme
