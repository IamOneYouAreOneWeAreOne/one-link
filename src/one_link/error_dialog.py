"""Friendly error dialog when the daemon fails to come up.

Replaces the silent-exit behavior where the launcher hit a timeout
and just disappeared, leaving the user staring at nothing. Now they
see a real window saying what happened in plain language, with three
useful buttons:

  * **Try again** — re-runs the launcher's start sequence.
  * **Open logs folder** — pops the data dir so the user (or a
    friend helping them) can read the actual error.
  * **Quit** — closes the dialog without re-launching.

Doctrinally: no shame, no jargon, no "ERROR CODE 0xFA12", no support
URL. The dialog is a human telling another human "something didn't
start; here's what to try." If a daemon-launch.err.log line names a
specific cause, we surface it verbatim under the explainer. Otherwise
we just say what we know and offer the buttons.

Tkinter is stdlib — no new dep. Falls back to a Windows MessageBox
via ctypes if tkinter cannot initialize at all (rare; broken stdlib
install).
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from one_link.fault_observability import report_best_effort_failure
from one_link.process_security import launch_system_opener

log = logging.getLogger(__name__)

BG_COLOR = "#0e1117"
PANEL_COLOR = "#161b25"
FG_COLOR = "#e9edf6"
DIM_COLOR = "#8a92a5"
ACCENT_COLOR = "#7c5cff"
BAD_COLOR = "#ff6b6b"
WINDOW_W = 460
WINDOW_H = 320


def _reveal_in_file_manager(path: Path) -> None:
    """Open the OS file manager pointed at ``path``. Best-effort —
    nothing here is critical to the user's recovery flow."""
    try:
        launch_system_opener(path)
    except (OSError, ValueError):
        pass


def _read_log_tail(log_path: Path, max_lines: int = 5) -> str:
    """Return the last few lines of ``log_path``, or empty string."""
    try:
        with open(log_path, "rb") as f:
            try:
                f.seek(-4096, os.SEEK_END)
            except OSError:
                f.seek(0)
            raw = f.read().decode("utf-8", errors="replace")
    except OSError:
        return ""
    lines = [l for l in raw.splitlines() if l.strip()]
    return "\n".join(lines[-max_lines:])


def _windows_messagebox_fallback(title: str, detail: str) -> str:
    """Last-ditch fallback when tkinter cannot initialize. Returns
    one of: "retry" / "quit"."""
    try:
        import ctypes
        # MB_RETRYCANCEL = 5, IDRETRY = 4, IDCANCEL = 2
        rc = ctypes.windll.user32.MessageBoxW(0, detail, title, 5)
        return "retry" if rc == 4 else "quit"
    except Exception:
        return "quit"


def show_startup_failure(
    *,
    reason: str = "",
    log_path: Optional[Path] = None,
    data_dir: Optional[Path] = None,
) -> str:
    """Show the friendly startup-failure dialog and block until the
    user picks an action.

    Returns one of:
      ``"retry"`` — user wants to try again (launcher should re-run).
      ``"quit"``  — user wants to give up; launcher should exit.

    ``reason`` is a short human-readable line shown under the title
    (e.g. "the daemon didn't bind its UI port within 30 seconds").
    ``log_path`` is the file the "Open logs folder" button reveals
    when clicked; if absent, the button is hidden. ``data_dir`` is
    a fallback target for the same button when ``log_path`` isn't
    available.
    """
    try:
        import tkinter as tk
    except Exception:
        if os.name == "nt":
            return _windows_messagebox_fallback(
                "One Link didn't start",
                (reason or "Something prevented One Link from starting.")
                + "\n\nRetry to try again, or Cancel to quit.",
            )
        return "quit"

    choice = {"value": "quit"}
    try:
        root = tk.Tk()
    except Exception:
        return "quit"

    root.title("One Link")
    root.configure(bg=BG_COLOR)
    root.resizable(False, False)
    root.attributes("-topmost", True)

    # Center on the primary monitor.
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    root.geometry(
        f"{WINDOW_W}x{WINDOW_H}+{(sw - WINDOW_W) // 2}+{(sh - WINDOW_H) // 2 - 30}"
    )

    inner = tk.Frame(root, bg=BG_COLOR, padx=28, pady=24)
    inner.pack(fill="both", expand=True)

    # Headline — human, not "ERROR".
    tk.Label(
        inner, text="One Link didn't start", fg=FG_COLOR, bg=BG_COLOR,
        font=("Segoe UI", 16, "bold"), anchor="w",
    ).pack(fill="x", pady=(0, 8))

    # Plain-language explanation.
    explain = reason or (
        "The background daemon couldn't come up within the startup "
        "window. This is usually a temporary thing — another copy "
        "already running, a port in use, or a slow disk on first launch."
    )
    tk.Label(
        inner, text=explain, fg=DIM_COLOR, bg=BG_COLOR,
        font=("Segoe UI", 11), wraplength=WINDOW_W - 56, justify="left",
        anchor="w",
    ).pack(fill="x", pady=(0, 14))

    # Optional log-tail panel, only when we have something useful to show.
    if log_path is not None:
        tail = _read_log_tail(log_path)
        if tail:
            panel = tk.Frame(inner, bg=PANEL_COLOR, bd=0)
            panel.pack(fill="both", expand=False, pady=(0, 14))
            tk.Label(
                panel, text="Last lines from the launch log",
                fg=DIM_COLOR, bg=PANEL_COLOR,
                font=("Segoe UI", 9), anchor="w",
            ).pack(fill="x", padx=12, pady=(8, 2))
            tk.Label(
                panel, text=tail, fg=FG_COLOR, bg=PANEL_COLOR,
                font=("Consolas", 9), anchor="w", justify="left",
                wraplength=WINDOW_W - 80,
            ).pack(fill="x", padx=12, pady=(0, 10))

    # Action row.
    btn_row = tk.Frame(inner, bg=BG_COLOR)
    btn_row.pack(fill="x", side="bottom")

    def _btn(parent, text, command, accent=False) -> tk.Button:
        return tk.Button(
            parent, text=text, command=command,
            bg=(ACCENT_COLOR if accent else PANEL_COLOR),
            fg=("#ffffff" if accent else FG_COLOR),
            activebackground=(ACCENT_COLOR if accent else PANEL_COLOR),
            activeforeground=("#ffffff" if accent else FG_COLOR),
            relief="flat", bd=0, padx=18, pady=8,
            font=("Segoe UI", 10, "bold" if accent else "normal"),
            cursor="hand2",
        )

    def _pick(value: str) -> None:
        choice["value"] = value
        try:
            root.destroy()
        except Exception as exc:
            report_best_effort_failure(
                log,
                "error_dialog_destroy",
                exc,
                level=logging.DEBUG,
            )

    target_dir = (
        log_path.parent if log_path is not None and log_path.exists()
        else data_dir
    )
    if target_dir is not None:
        _btn(btn_row, "Open logs folder",
             lambda: _reveal_in_file_manager(target_dir)).pack(
            side="left",
        )
    _btn(btn_row, "Quit", lambda: _pick("quit")).pack(side="right", padx=(8, 0))
    _btn(btn_row, "Try again", lambda: _pick("retry"), accent=True).pack(
        side="right",
    )

    root.bind("<Escape>", lambda _e: _pick("quit"))
    root.bind("<Return>", lambda _e: _pick("retry"))
    root.protocol("WM_DELETE_WINDOW", lambda: _pick("quit"))

    try:
        root.mainloop()
    except KeyboardInterrupt:
        return "quit"
    return choice["value"]


if __name__ == "__main__":  # pragma: no cover — manual smoke
    rc = show_startup_failure(
        reason="The daemon didn't bind its UI port within 30 seconds.",
    )
    print(f"user chose: {rc}")
