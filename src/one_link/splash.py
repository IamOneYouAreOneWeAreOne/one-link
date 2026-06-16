"""Native splash window for the launcher.

The launcher spawns a few subprocesses + waits for the daemon to bind
its UI port — up to ~30 seconds of "nothing visible is happening" on
a cold start. Without a splash, the user sees nothing for that whole
window (or, worse, a console window with cryptic "starting daemon"
text). With the splash, the moment they double-click the icon they
get a borderless dark window with the ONE Glyph + "Starting One
Link…" copy. When the daemon is up and the browser tab opens, the
splash closes itself.

Design contract:

  * Runs in its own process (spawned by the launcher). tkinter wants
    the main thread for its mainloop; the launcher's main thread is
    busy with subprocess + sleep, so a child process is cleaner than
    threading.
  * Closes when stdin reaches EOF — i.e. when the launcher process
    exits OR explicitly closes the pipe. No IPC protocol to design,
    no race conditions on signal handling.
  * Cross-platform: tkinter ships in the Python stdlib on every
    platform we target. The window is borderless and centered.
  * Quietly degrades: if tkinter isn't importable for any reason
    (broken stdlib install on a stripped Python build, no DISPLAY on
    a headless Linux), the splash exits 0 silently — the launcher
    continues, the user just loses the splash, no other harm.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path

BG_COLOR = "#0e1117"
FG_COLOR = "#e9edf6"
ACCENT_COLOR = "#7c5cff"
DIM_COLOR = "#8a92a5"
WINDOW_W = 380
WINDOW_H = 220


def _find_icon() -> Path | None:
    """Locate the ONE Glyph icon for the splash window.

    In a PyInstaller bundle the assets live under ``sys._MEIPASS``;
    in a source checkout they live next to the package. Either way
    we want the .png form (tkinter can't load .ico without Pillow
    on most platforms). Falls back to None — the splash still
    renders text without it.
    """
    candidates: list[Path] = []
    bundle_dir = getattr(sys, "_MEIPASS", None)
    if bundle_dir:
        candidates.append(Path(bundle_dir) / "one_link" / "web" / "assets" / "one-glyph.png")
    pkg_dir = Path(__file__).resolve().parent
    candidates.append(pkg_dir / "web" / "assets" / "one-glyph.png")
    for p in candidates:
        if p.is_file():
            return p
    return None


def _on_parent_disconnect(callback) -> None:
    """Spawn a daemon thread that watches stdin for EOF.

    When the launcher exits (or closes our stdin pipe), the read
    returns empty and we fire ``callback`` to close the window. No
    polling — the read blocks until something happens.
    """
    def _watch() -> None:
        try:
            sys.stdin.buffer.read()  # blocks until EOF
        except Exception:
            pass
        try: callback()
        except Exception: pass
    t = threading.Thread(target=_watch, daemon=True, name="splash-parent-watch")
    t.start()


def run_splash() -> int:
    """Show the splash; block until stdin closes; return 0.

    Returns non-zero ONLY when tkinter itself can't initialize (which
    is a launcher-skip-the-splash signal, not an error).
    """
    try:
        import tkinter as tk
    except Exception:
        return 1
    try:
        root = tk.Tk()
    except Exception:
        return 1

    root.overrideredirect(True)  # borderless
    root.configure(bg=BG_COLOR)
    root.attributes("-topmost", True)
    try:
        root.attributes("-alpha", 0.0)  # fade in (Windows + macOS)
    except tk.TclError:
        pass

    # Center on the primary monitor.
    screen_w = root.winfo_screenwidth()
    screen_h = root.winfo_screenheight()
    x = (screen_w - WINDOW_W) // 2
    y = (screen_h - WINDOW_H) // 2 - 40  # slightly above center reads as natural
    root.geometry(f"{WINDOW_W}x{WINDOW_H}+{x}+{y}")

    # Border via a 1px frame underneath the content.
    border = tk.Frame(root, bg=ACCENT_COLOR, bd=0)
    border.pack(fill="both", expand=True, padx=0, pady=0)
    inner = tk.Frame(border, bg=BG_COLOR, bd=0)
    inner.pack(fill="both", expand=True, padx=1, pady=1)

    # Glyph (or text fallback).
    icon_path = _find_icon()
    if icon_path is not None:
        try:
            img = tk.PhotoImage(file=str(icon_path))
            # Scale down if the source is huge; tkinter PhotoImage
            # supports integer subsample only.
            iw = img.width()
            if iw > 96:
                img = img.subsample(max(1, iw // 96))
            icon_label = tk.Label(inner, image=img, bg=BG_COLOR, bd=0)
            icon_label.image = img  # keep a reference (tkinter GC quirk)
            icon_label.pack(pady=(28, 12))
        except Exception:
            icon_path = None
    if icon_path is None:
        # Fallback glyph: a hollow circle made of unicode. Beats nothing.
        glyph = tk.Label(
            inner, text="⊙", fg=ACCENT_COLOR, bg=BG_COLOR,
            font=("Segoe UI", 56, "bold"),
        )
        glyph.pack(pady=(20, 4))

    title = tk.Label(
        inner, text="One Link", fg=FG_COLOR, bg=BG_COLOR,
        font=("Segoe UI", 18, "bold"),
    )
    title.pack(pady=(0, 6))

    status = tk.Label(
        inner, text="Starting…", fg=DIM_COLOR, bg=BG_COLOR,
        font=("Segoe UI", 11),
    )
    status.pack(pady=(0, 8))

    # Subtle pulse on the status line so the user sees it's alive.
    def _pulse(step: int = 0) -> None:
        colors = (DIM_COLOR, "#a8b0c3", DIM_COLOR, "#5b6376")
        try:
            status.configure(fg=colors[step % len(colors)])
            root.after(280, _pulse, step + 1)
        except tk.TclError:
            pass  # window destroyed
    _pulse()

    # Fade in over ~150ms.
    def _fade_in(alpha: float = 0.0) -> None:
        try:
            root.attributes("-alpha", alpha)
            if alpha < 1.0:
                root.after(15, _fade_in, alpha + 0.07)
        except tk.TclError:
            pass
    _fade_in()

    # Close handler: schedule destroy on the tk thread.
    def _close() -> None:
        try:
            root.after(0, root.destroy)
        except Exception:
            pass

    _on_parent_disconnect(_close)
    # Also close on Esc — escape hatch in case anything goes wrong.
    root.bind("<Escape>", lambda _e: _close())

    try:
        root.mainloop()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(run_splash())
