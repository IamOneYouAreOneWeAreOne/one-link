"""v0.10.5 — system tray icon.

Optional surface that turns the daemon from "always have a browser
tab open" into "lives in your tray quietly until you need it."

The tray icon is purely a presence + control surface — the actual
UI still renders in the user's browser at http://127.0.0.1:<port>/.
Click the tray icon → opens the browser; right-click → menu with
Open / Open inbox folder / Quit.

Optional dependency: pystray + Pillow. Wrapped in try/except so a
fresh install without those packages still runs the daemon
headlessly. Install with `pip install one_link[tray]`.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import webbrowser
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:
    import pystray

log = logging.getLogger("one_link.tray")


def _display_url(url: str) -> str:
    """Return the tray-title version of a UI URL without auth query data."""
    try:
        parts = urlsplit(url)
        path = parts.path.rstrip("/") or "/"
        return urlunsplit((parts.scheme, parts.netloc, path, "", ""))
    except Exception:
        return (url or "").split("?", 1)[0].rstrip("/") or url


def _icon_image():
    """Build the tray icon. Prefers the bundled one-glyph.png; falls
    back to a tiny solid-color square if the asset is missing."""
    try:
        from PIL import Image
    except Exception:
        return None
    here = Path(__file__).parent
    candidates = [
        here / "web" / "assets" / "one-glyph.png",
        here / "web" / "assets" / "one-glyph.ico",
    ]
    for p in candidates:
        if p.is_file():
            try:
                img = Image.open(p)
                # Pystray on Windows wants a small bitmap, ideally 16/32/64.
                # Resize to a comfortable tray size.
                return img.convert("RGBA").resize((64, 64))
            except Exception as e:
                log.warning("failed to load tray icon %s: %s", p, e)
    # Fallback: 64x64 purple square.
    try:
        return Image.new("RGBA", (64, 64), (124, 92, 255, 255))
    except Exception:
        return None


class TrayIcon:
    """Lightweight wrapper around pystray that runs in its own
    thread (pystray on Windows requires the icon to live on the
    main thread of an alive message pump, but we run it in a
    background thread when the daemon owns main).

    Caller wires the URL via `set_url(...)` after the UI server
    binds its port. Status updates via `set_status('online' |
    'away' | 'dnd' | 'offline')` re-tint the icon.
    """

    def __init__(
        self,
        *,
        on_quit: Callable[[], None],
        url: str = "http://127.0.0.1:7117/",
        inbox_path: Optional[Path] = None,
    ):
        self._on_quit = on_quit
        self._url = url
        self._inbox_path = inbox_path
        # Lazy-imported pystray Icon — None until ``start()`` creates
        # the real one. Local stubs live under ``stubs/pystray.pyi``.
        self._icon: Optional["pystray.Icon"] = None
        self._thread: Optional[threading.Thread] = None
        self._available = False
        try:
            import pystray  # noqa: F401  # stubs under stubs/pystray.pyi
            self._available = True
        except Exception as e:
            log.info(
                "system tray unavailable (pystray not installed): %s. "
                "Daemon runs headlessly; access via the browser at %s.",
                e, url,
            )

    @property
    def available(self) -> bool:
        return self._available

    def set_url(self, url: str) -> None:
        """Update the URL the tray click should open."""
        self._url = url
        if self._icon is not None:
            self._icon.menu = self._build_menu()
            # 2026-05-22 UX: refresh the hover title too.
            try:
                self._icon.title = f"One Link - {_display_url(url)}"
            except Exception:
                pass

    def set_inbox_path(self, path: Path) -> None:
        self._inbox_path = path
        if self._icon is not None:
            self._icon.menu = self._build_menu()

    def set_status(self, status: str) -> None:
        """Re-tint the icon by status. 'online' = default,
        'away' = yellow border, 'dnd' = red border, 'offline'
        = grayscale. Best-effort — failures don't crash the
        daemon."""
        if self._icon is None:
            return
        try:
            self._icon.icon = self._tinted_icon(status)
        except Exception as e:
            log.warning("tray status tint failed: %s", e)

    @staticmethod
    def _tinted_icon(status: str):
        try:
            from PIL import Image, ImageDraw
        except Exception:
            return None
        base = _icon_image()
        if base is None:
            return None
        # Add a status-colored ring around the icon for at-a-glance
        # state visibility.
        s = (status or "online").lower()
        ring_color = {
            "online":  (76, 209, 154, 255),
            "away":    (245, 196, 81, 255),
            "dnd":     (255, 107, 107, 255),
            "offline": (138, 147, 166, 255),
        }.get(s, (76, 209, 154, 255))
        out = base.copy()
        draw = ImageDraw.Draw(out)
        draw.ellipse([(2, 2), (61, 61)], outline=ring_color, width=4)
        return out

    def _build_menu(self) -> "pystray.Menu":
        from pystray import MenuItem, Menu
        items: list[MenuItem] = [
            MenuItem("Open One Link", self._on_open, default=True),
            # 2026-05-22 UX: top-level "Connect a device" so a phone /
            # second laptop pair flow is one click from the tray, not
            # buried inside the Setup pane. Deep-link query param tells
            # the web UI to auto-open the Add Device modal + mint a
            # fresh QR on load.
            MenuItem("Connect a device", self._on_connect_device),
        ]
        if self._inbox_path is not None:
            items.append(MenuItem("Open inbox folder", self._on_open_inbox))
        items.extend([
            Menu.SEPARATOR,
            MenuItem("Quit", self._on_quit_clicked),
        ])
        return Menu(*items)

    def _on_open(self, icon, item) -> None:
        try:
            webbrowser.open(self._url)
        except Exception as e:
            log.warning("tray: failed to open browser: %s", e)

    def _on_connect_device(self, icon, item) -> None:
        """Open the web UI with a deep-link the UI recognises and
        auto-opens the Add Device modal + mints a fresh invite QR.
        Same target as ``Open One Link`` plus ``?setup=add-device``."""
        try:
            separator = "&" if "?" in self._url else "?"
            target = f"{self._url}{separator}setup=add-device"
            webbrowser.open(target)
        except Exception as e:
            log.warning("tray: failed to open connect-device flow: %s", e)

    def _on_open_inbox(self, icon, item) -> None:
        if self._inbox_path is None:
            return
        try:
            if sys.platform == "win32":
                os.startfile(str(self._inbox_path))  # noqa: S606
            elif sys.platform == "darwin":
                import subprocess
                subprocess.Popen(["open", str(self._inbox_path)])
            else:
                import subprocess
                subprocess.Popen(["xdg-open", str(self._inbox_path)])
        except Exception as e:
            log.warning("tray: failed to open inbox: %s", e)

    def _on_quit_clicked(self, icon, item) -> None:
        try:
            icon.stop()
        except Exception:
            pass
        try:
            self._on_quit()
        except Exception as e:
            log.warning("tray: on_quit handler raised: %s", e)

    def start(self) -> None:
        if not self._available:
            return
        try:
            from pystray import Icon
        except Exception as e:
            log.warning("tray start aborted (pystray import): %s", e)
            return
        try:
            base_icon = self._tinted_icon("online")
            if base_icon is None:
                log.warning(
                    "tray start skipped: no icon image available. "
                    "Daemon continues without a tray icon."
                )
                self._available = False
                return
            # 2026-05-22 UX: hovering over the tray icon shows the
            # daemon's URL so the user always knows where to point
            # a phone browser. Without this they'd have to dig into
            # Settings or guess the port.
            title = "One Link"
            try:
                title = f"One Link - {_display_url(self._url)}"
            except Exception:
                pass
            self._icon = Icon(
                "one_link",
                icon=base_icon,
                title=title,
                menu=self._build_menu(),
            )
        except Exception as e:
            log.warning("tray start failed (Icon construction): %s", e)
            return
        # pystray's run() blocks on the OS message pump. Run it on
        # a daemon thread so the asyncio loop in the parent stays
        # responsive. Quit ⇒ stop the icon ⇒ thread exits.
        self._thread = threading.Thread(
            target=self._run_safely, daemon=True, name="one-link-tray",
        )
        self._thread.start()

    def _run_safely(self) -> None:
        if self._icon is None:
            return
        try:
            self._icon.run()
        except Exception as e:
            log.warning("tray run loop crashed: %s", e)

    def stop(self) -> None:
        if self._icon is not None:
            try:
                self._icon.stop()
            except Exception:
                pass
        self._icon = None
