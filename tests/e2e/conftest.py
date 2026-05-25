"""Shared fixtures for the browser E2E suite.

The `live_daemon` fixture spawns a real one-link daemon in a temp
ONE_LINK_HOME, waits for it to write `ui.token` + `server.port`,
and yields an object with the base URL + auth token a Playwright
test can navigate to.

The `page` fixture (provided by pytest-playwright) gives each test
its own browser context + page; we add a small wrapper that
auto-navigates to the live daemon with the bearer token in the
query string.
"""
from __future__ import annotations

import contextlib
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import pytest


@dataclass
class LiveDaemon:
    home: Path
    port: int
    token: str
    proc: subprocess.Popen
    log: Path

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def auth_url(self) -> str:
        """Top-level URL with bootstrap token. The daemon sets the
        ol_ui cookie on this load so subsequent requests succeed."""
        return f"{self.base_url}/?t={self.token}"


def _find_free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_for_file(path: Path, timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.is_file() and path.stat().st_size > 0:
            return True
        time.sleep(0.1)
    return False


@pytest.fixture
def live_daemon(tmp_path: Path) -> Iterator[LiveDaemon]:
    """Spawn a real daemon for E2E. Each test gets its own clean
    ONE_LINK_HOME so tests can't bleed state into each other. The
    daemon binds a free port automatically; we read it back from
    `data/server.port` once the HTTP server is up."""
    home = tmp_path / "daemon_home"
    home.mkdir()
    log_path = tmp_path / "daemon.log"

    env = os.environ.copy()
    env["ONE_LINK_HOME"] = str(home)
    # Loopback-only so we don't spam the LAN with mDNS during tests.
    env["ONE_LINK_BIND_HOST"] = "127.0.0.1"
    # Disable any prompt that might open a folder picker etc.
    env["ONE_LINK_DISABLE_NATIVE_PICKER"] = "1"
    # The daemon auto-discovers a free port starting at 7117 and
    # falls through to 7118..7132 if taken, then OS-assigned. Since
    # ONE_LINK_HOME is fresh + isolated, we read the chosen port
    # back from data/server.port once it's up - no env override
    # needed.

    log_fh = open(log_path, "ab", buffering=0)
    proc = subprocess.Popen(
        [sys.executable, "-m", "one_link.cli", "daemon"],
        env=env,
        stdout=log_fh,
        stderr=subprocess.STDOUT,
        cwd=str(Path(__file__).resolve().parents[2]),
    )

    try:
        port_file = home / "data" / "server.port"
        token_file = home / "data" / "ui.token"
        if not _wait_for_file(port_file, timeout=30.0):
            log_text = log_path.read_text(encoding="utf-8", errors="replace")[-3000:]
            raise RuntimeError(
                f"daemon never wrote server.port within 30s\n--- log ---\n{log_text}"
            )
        if not _wait_for_file(token_file, timeout=10.0):
            log_text = log_path.read_text(encoding="utf-8", errors="replace")[-3000:]
            raise RuntimeError(
                f"daemon never wrote ui.token within 10s\n--- log ---\n{log_text}"
            )
        port = int(port_file.read_text().strip())
        token = token_file.read_text().strip()
        yield LiveDaemon(
            home=home, port=port, token=token, proc=proc, log=log_path,
        )
    finally:
        with contextlib.suppress(Exception):
            proc.terminate()
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5.0)
        with contextlib.suppress(Exception):
            log_fh.close()


@pytest.fixture
def ui_page(live_daemon, page):
    """A Playwright `page` already navigated to the live daemon's
    UI with the bootstrap token applied + the first-launch
    onboarding modal dismissed. Most tests want this over the
    raw `page` fixture - it skips the boilerplate of
    `page.goto(...)` + the onboarding click.
    """
    page.goto(live_daemon.auth_url, wait_until="networkidle")
    page.wait_for_selector("body", timeout=15000)
    # Dismiss first-launch onboarding if it's blocking the UI.
    # Fresh ONE_LINK_HOME means every E2E run hits the onboarding
    # overlay; without dismissing it every click is intercepted
    # by the backdrop's pointer-events: all.
    if page.locator("#onboarding-skip").count():
        try:
            page.locator("#onboarding-skip").click(timeout=2000)
            # Wait for the backdrop to actually go away.
            page.wait_for_selector(
                "#onboarding-backdrop",
                state="hidden",
                timeout=5000,
            )
        except Exception:
            pass  # already dismissed or never shown
    # Same for the one-setup modal (a second first-launch wizard).
    if page.locator("#one-setup-skip, #btn-one-setup-skip").count():
        try:
            page.locator("#one-setup-skip, #btn-one-setup-skip").first.click(timeout=1500)
        except Exception:
            pass
    return page


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    """Shared browser context tweaks. Loopback HTTP is not 'secure'
    by HTTPS standards but is treated as a secure context by
    Chromium since the daemon is on 127.0.0.1. Set viewport big
    enough that the conversation header + sidebar fit without the
    responsive-mode collapse logic firing."""
    return {
        **browser_context_args,
        "viewport": {"width": 1400, "height": 900},
        # Don't follow OS dark/light mode; pin to a known scheme so
        # screenshot diffs are stable.
        "color_scheme": "dark",
        "ignore_https_errors": True,
    }
