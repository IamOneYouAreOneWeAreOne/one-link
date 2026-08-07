"""A credential that reaches a command line must be worthless a moment later.

THE DEFECT THIS CLOSES, measured on Windows 2026-08-06. The desktop launcher opens the UI with
``msedge.exe --app=http://127.0.0.1:PORT/?t=TOKEN``, and that URL carried ``UIServer.token`` -- the
bearer that grants a full owner session for the daemon's whole lifetime. A command line is readable
by any process running as the same user with **no elevation**: a marker planted in a child's argv
came back in full to an unprivileged ``Get-CimInstance Win32_Process`` reader.

That made argv the *only* place the token left process memory. ``_load_or_create_token`` mints a
fresh ``secrets.token_urlsafe(32)`` per process and persists nothing on purpose -- "no at-rest value
is an authority for the next process" -- so there was no token file to read instead. The command
line was the whole exposure, and it contradicted this module's own posture: ``$BROWSER`` refused,
PATH isolated, executables validated, all because a local process is not trusted.

A secret on a command line cannot be hidden, so the fix is to put something there that stops being a
secret: a single-use, TTL-bounded launch nonce. The tests below are the ones that would fail if the
mechanism were decorative -- reuse refused, expiry refused, and the launcher no longer emitting the
long-lived token at all.
"""

from __future__ import annotations

import time

import pytest

from one_link.server import UIServer


class _Nonces:
    """The nonce mechanism, exercised without standing up an aiohttp server.

    `mint_launch_nonce` / `consume_launch_nonce` touch only `self._launch_nonces`, so binding
    them to a bare object tests the real code rather than a copy of it.
    """

    def __init__(self) -> None:
        self._launch_nonces: dict[str, float] = {}

    mint = UIServer.mint_launch_nonce
    consume = UIServer.consume_launch_nonce
    _expire_launch_nonces = UIServer._expire_launch_nonces
    LAUNCH_NONCE_TTL_S = UIServer.LAUNCH_NONCE_TTL_S
    LAUNCH_NONCE_MAX = UIServer.LAUNCH_NONCE_MAX


@pytest.fixture
def nonces() -> _Nonces:
    return _Nonces()


# ── the claim ─────────────────────────────────────────────────────────


def test_a_minted_nonce_is_redeemable_once(nonces):
    n = nonces.mint()
    assert nonces.consume(n) is True


def test_a_REUSED_nonce_is_refused(nonces):
    """THE property. An attacker reading argv arrives after the browser has redeemed."""
    n = nonces.mint()
    assert nonces.consume(n) is True
    assert nonces.consume(n) is False, (
        "a launch nonce was redeemable twice -- anyone who reads the command line gets the "
        "same session the browser got, which is the defect this replaced")


def test_an_EXPIRED_nonce_is_refused(nonces, monkeypatch):
    """A stale argv snapshot -- from a crash dump, an EDR log, a process listing taken
    minutes later -- must be worthless even if it was never redeemed."""
    n = nonces.mint()
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + UIServer.LAUNCH_NONCE_TTL_S + 1.0)
    assert nonces.consume(n) is False


def test_an_unminted_value_is_refused(nonces):
    nonces.mint()
    for guess in ("", "x", "A" * 43, None, 42, b"bytes"):
        assert nonces.consume(guess) is False


def test_redeeming_one_nonce_does_not_burn_another(nonces):
    """Two launches in flight must not cancel each other -- a launcher that opened two
    windows would otherwise leave one dead, and the pressure would be to make nonces
    reusable again."""
    a, b = nonces.mint(), nonces.mint()
    assert nonces.consume(a) is True
    assert nonces.consume(b) is True


def test_nonces_are_distinct_and_full_entropy(nonces):
    minted = {nonces.mint() for _ in range(16)}
    assert len(minted) == 16
    assert all(len(m) >= 40 for m in minted), "a short nonce is guessable within its TTL"


def test_the_store_is_capacity_bounded(nonces):
    """A launcher minting in a loop must not grow the daemon's memory."""
    for _ in range(UIServer.LAUNCH_NONCE_MAX * 3):
        nonces.mint()
    assert len(nonces._launch_nonces) <= UIServer.LAUNCH_NONCE_MAX


def test_the_newest_nonce_survives_eviction(nonces):
    """Eviction must drop the OLDEST. If it dropped the newest, the launch happening
    right now would be the one that fails."""
    for _ in range(UIServer.LAUNCH_NONCE_MAX):
        nonces.mint()
    fresh = nonces.mint()
    assert nonces.consume(fresh) is True


# ── the launcher no longer emits the long-lived token ─────────────────


def test_the_launch_URL_carries_the_NONCE_and_not_the_token():
    """The end-to-end claim, at the exact line that feeds `--app=`.

    Reads the source rather than mocking a daemon: what matters is that no code path
    interpolates `info.token` into the URL without the loud warning beside it.
    """
    from pathlib import Path

    src = Path(__file__).resolve().parents[1] / "src" / "one_link" / "app.py"
    text = src.read_text(encoding="utf-8")

    assert 'f"http://127.0.0.1:{info.server_port}/?t={info.launch_nonce}"' in text, (
        "the launch URL no longer builds from the nonce -- if this was an intentional "
        "change, the argv exposure is back and this test is the record of why it mattered")
    token_urls = text.count('/?t={info.token}')
    assert token_urls <= 1, f"{token_urls} launch URLs still interpolate the long-lived token"
    if token_urls:
        # The single permitted occurrence is the unreachable degraded path, and it is only
        # permitted because it announces itself.
        idx = text.index('/?t={info.token}')
        assert "WARNING" in text[max(0, idx - 1200):idx], (
            "the token-in-URL fallback is silent -- a fallback nobody can see is how the "
            "original defect would return")


def test_ui_launch_info_mints_a_nonce_for_every_caller():
    """The daemon must hand out a fresh credential per launch, not cache one."""
    from pathlib import Path

    src = Path(__file__).resolve().parents[1] / "src" / "one_link" / "daemon.py"
    text = src.read_text(encoding="utf-8")
    assert '"launch_nonce": (' in text and "mint_launch_nonce()" in text, (
        "ui_launch_info no longer mints a launch nonce, so the launcher has nothing "
        "safe to put in the URL")


# ── end to end: a real UIServer over real HTTP ────────────────────────
#
# The unit tests above prove the mint/consume algebra and the source tests prove the
# launcher emits a nonce. Neither proves the two MEET -- that a nonce minted by the
# server is actually accepted by the index handler, and actually refused the second
# time. That gap is where a wiring bug lives, so it is closed here against a real
# aiohttp server rather than a mock.

from pathlib import Path

import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.state import State

#: THE ONLY HONEST SIGNAL THAT A SESSION WAS GRANTED -- and it is calibrated, not guessed.
#: The first version of these tests looked for ``ol_session_token``, which is present on EVERY
#: response including an unauthenticated one (it appears in the app's own JS). That assertion
#: passed whether or not a bootstrap happened, so it could not have caught a broken nonce.
#: Measured against a live server: this marker appears ONLY when the index handler injects a
#: bearer. `test_the_bootstrap_marker_is_actually_discriminating` keeps that honest.
BOOTSTRAP_MARKER = "sessionStorage.setItem('ol_session_token'"


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(private=sk, public=pub_obj, public_bytes=pub_bytes,
                    fingerprint=fp, short_id=fp[:8], hostname="nonce-host")


@pytest_asyncio.fixture
async def live(tmp_path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(_identity())
    daemon.state = state
    daemon.discovery = None
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    daemon.folder_engine = None

    server = UIServer(daemon)
    client = TestClient(TestServer(server.app))
    await client.start_server()
    try:
        yield client, server
    finally:
        await client.close()
        state.close()


@pytest.mark.asyncio
async def test_a_freshly_minted_nonce_BOOTSTRAPS_the_ui(live):
    """The wiring claim: what the daemon mints, the index handler accepts."""
    client, server = live
    resp = await client.get("/", params={"t": server.mint_launch_nonce()})
    assert resp.status == 200, f"a valid launch nonce was refused ({resp.status})"
    assert BOOTSTRAP_MARKER in await resp.text(), (
        "the page loaded but handed out no session bearer -- the launch would appear to "
        "work and then every API call would 401")


@pytest.mark.asyncio
async def test_the_SAME_nonce_a_second_time_does_NOT_bootstrap(live):
    """THE security claim, over real HTTP.

    This is the request an attacker who read the command line would make. It must not
    yield a session, and it must not 200 into the app.
    """
    client, server = live
    nonce = server.mint_launch_nonce()

    first = await client.get("/", params={"t": nonce})
    assert first.status == 200

    second = await client.get("/", params={"t": nonce})
    assert BOOTSTRAP_MARKER not in await second.text(), (
        "a launch nonce read from argv still granted a session on reuse -- the single-use "
        "property does not survive the HTTP path even though it holds in the unit test")
    assert second.status != 200, f"the reused nonce still returned {second.status}"


@pytest.mark.asyncio
async def test_an_attacker_supplied_value_never_bootstraps(live):
    """No nonce, no guessed nonce, no empty nonce."""
    client, server = live
    server.mint_launch_nonce()                       # one live, unrelated
    for guess in ("", "A" * 43, "not-a-nonce"):
        resp = await client.get("/", params={"t": guess})
        assert BOOTSTRAP_MARKER not in await resp.text(), (
            f"the value {guess!r} bootstrapped a session")


@pytest.mark.asyncio
async def test_the_bootstrap_marker_is_actually_discriminating(live):
    """CALIBRATION. An instrument that reads the same on both sides measures nothing.

    Every assertion above rests on `BOOTSTRAP_MARKER` distinguishing a granted session
    from a refused one. If it ever appears on an unauthenticated response, those tests
    silently stop testing -- which is exactly what the first version of this file did
    with the substring `ol_session_token`.
    """
    client, server = live
    granted = await (await client.get("/", params={"t": server.mint_launch_nonce()})).text()
    refused = await (await client.get("/")).text()

    assert BOOTSTRAP_MARKER in granted
    assert BOOTSTRAP_MARKER not in refused, (
        "the marker appears WITHOUT any credential, so every test in this file that "
        "asserts its absence would pass against a completely broken nonce")
    assert "ol_session_token" in refused, (
        "the naive substring no longer appears unauthenticated -- harmless, but the "
        "calibration note above is now wrong and should be corrected")


# ── every browser-bound URL, not just the one that was found ──────────
#
# The defect was reported at ONE site (the desktop app-mode launcher). There were four:
# the app-mode launcher, the CLI auto-open, the tray click, and the deep-link handler.
# A guard on one of several paths is a coincidence, not a control -- so these tests are
# about the tree, not the branch.


def _src(name: str) -> str:
    return (Path(__file__).resolve().parents[1] / "src" / "one_link" / name).read_text(
        encoding="utf-8")


def test_no_browser_bound_URL_in_the_cli_still_carries_the_bearer():
    """The CLI built `?t={token}` in three places. None may remain."""
    text = _src("cli.py")
    for leak in ("?t={token}", "?t={ui_token}"):
        assert leak not in text, (
            f"cli.py still builds a browser URL with {leak} -- that credential reaches "
            "the browser's command line via os.startfile and is readable by any "
            "same-user process")


def test_the_tray_does_not_CACHE_a_credential():
    """A stored single-use credential opens the app once and then looks broken.

    The tray must mint at click time. This asserts the provider seam exists and that
    both menu paths go through it -- `Open` and `Connect device` were two separate
    call sites, and fixing one would have left the other live.
    """
    text = _src("tray.py")
    assert "url_provider" in text and "_authenticated_url" in text
    assert text.count("self._authenticated_url()") >= 2, (
        "only one tray path mints a fresh credential; the other still replays a "
        "stored URL")


def test_the_tray_mints_a_FRESH_credential_on_EVERY_click():
    """The behaviour, not just the seam: two clicks must draw two credentials."""
    from one_link.tray import TrayIcon

    minted: list[str] = []

    def provider() -> str:
        minted.append(f"http://127.0.0.1:7117/?t=nonce-{len(minted)}")
        return minted[-1]

    tray = TrayIcon(on_quit=lambda: None, url_provider=provider)
    first, second = tray._authenticated_url(), tray._authenticated_url()

    assert first != second, (
        "the tray handed out the same credential twice -- with single-use nonces the "
        "second click would open a dead window")
    assert len(minted) == 2


def test_a_tray_with_no_provider_opens_UNAUTHENTICATED_rather_than_replaying():
    """The fallback must degrade to 'show the auth prompt', never to 'reuse a secret'."""
    from one_link.tray import TrayIcon

    tray = TrayIcon(on_quit=lambda: None, url="http://127.0.0.1:7117/")
    assert "?t=" not in tray._authenticated_url()


def test_a_failing_provider_does_not_kill_the_tray():
    """A dead daemon must not make the tray raise into pystray's callback."""
    from one_link.tray import TrayIcon

    def boom() -> str:
        raise RuntimeError("daemon not available")

    tray = TrayIcon(on_quit=lambda: None, url="http://127.0.0.1:7117/", url_provider=boom)
    assert tray._authenticated_url() == "http://127.0.0.1:7117/"
