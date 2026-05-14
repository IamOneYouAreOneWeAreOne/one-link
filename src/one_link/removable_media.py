from __future__ import annotations

import ctypes
import time
import os
import platform
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RemovableTarget:
    id: str
    label: str
    path: Path
    kind: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "path": str(self.path),
            "kind": self.kind,
        }


@dataclass(frozen=True)
class RemovableEvent:
    kind: str
    target_id: str
    target: RemovableTarget
    source: str
    timestamp_ms: int

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "target_id": self.target_id,
            "target": self.target.to_dict(),
            "source": self.source,
            "timestamp_ms": self.timestamp_ms,
        }


class RemovableEventDetector:
    """Stable removable-media attach/remove detector.

    The detector is intentionally snapshot based. Windows, macOS, Linux, and
    test/dev environments expose different native event APIs, but all safe
    courier operations already pass through the same removable target inventory.
    This turns that inventory into a deterministic event source with native
    watcher backends able to plug in later without changing the API contract.
    """

    def __init__(self, *, emit_initial: bool = False, source: str = "inventory_poll") -> None:
        self.emit_initial = bool(emit_initial)
        self.source = source
        self._primed = False
        self._previous: dict[str, tuple[RemovableTarget, tuple[str, str, str, str]]] = {}
        self.last_scan_ms = 0
        self.event_count = 0

    def poll(self) -> dict:
        targets = list_removable_targets()
        now_ms = int(time.time() * 1000)
        current = {t.id: (t, _target_signature(t)) for t in targets}
        events: list[RemovableEvent] = []

        if not self._primed:
            if self.emit_initial:
                for target_id, (target, _) in sorted(current.items()):
                    events.append(RemovableEvent(
                        kind="attached",
                        target_id=target_id,
                        target=target,
                        source=self.source,
                        timestamp_ms=now_ms,
                    ))
            self._primed = True
        else:
            previous_ids = set(self._previous)
            current_ids = set(current)
            for target_id in sorted(current_ids - previous_ids):
                target = current[target_id][0]
                events.append(RemovableEvent(
                    kind="attached",
                    target_id=target_id,
                    target=target,
                    source=self.source,
                    timestamp_ms=now_ms,
                ))
            for target_id in sorted(previous_ids - current_ids):
                target = self._previous[target_id][0]
                events.append(RemovableEvent(
                    kind="removed",
                    target_id=target_id,
                    target=target,
                    source=self.source,
                    timestamp_ms=now_ms,
                ))
            for target_id in sorted(current_ids & previous_ids):
                target, sig = current[target_id]
                if sig != self._previous[target_id][1]:
                    events.append(RemovableEvent(
                        kind="changed",
                        target_id=target_id,
                        target=target,
                        source=self.source,
                        timestamp_ms=now_ms,
                    ))

        self._previous = current
        self.last_scan_ms = now_ms
        self.event_count += len(events)
        return {
            "changed": bool(events),
            "events": [event.to_dict() for event in events],
            "targets": [target.to_dict() for target in targets],
            "last_scan_ms": self.last_scan_ms,
            "event_count": self.event_count,
            "mode": self.mode,
        }

    @property
    def mode(self) -> str:
        return "native_compatible_inventory_events"


def removable_event_source_status() -> dict:
    return {
        "mode": "native_compatible_inventory_events",
        "source": "list_removable_targets",
        "semantics": [
            "attached",
            "removed",
            "changed",
        ],
        "fallback": "portable_polling",
    }


def list_removable_targets() -> list[RemovableTarget]:
    out = _list_env_removable()
    if os.name == "nt":
        out.extend(_list_windows_removable())
    else:
        out.extend(_list_posix_removable())
    seen: set[str] = set()
    deduped: list[RemovableTarget] = []
    for target in out:
        key = str(target.path).lower() if os.name == "nt" else str(target.path)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(target)
    return deduped


def find_removable_target(target_id: str) -> RemovableTarget | None:
    want = str(target_id or "").strip()
    if not want:
        return None
    for target in list_removable_targets():
        if target.id == want:
            return target
    return None


def _list_windows_removable() -> list[RemovableTarget]:
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    drives_mask = int(kernel32.GetLogicalDrives())
    out: list[RemovableTarget] = []
    for idx in range(26):
        if not drives_mask & (1 << idx):
            continue
        letter = chr(ord("A") + idx)
        root = f"{letter}:\\"
        drive_type = int(kernel32.GetDriveTypeW(ctypes.c_wchar_p(root)))
        # DRIVE_REMOVABLE=2. Include fixed drives only when an explicit test
        # env opt-in is set; production should not spray courier files onto C:.
        if drive_type != 2 and os.environ.get("ONE_LINK_ALLOW_FIXED_COURIER_TARGETS") != "1":
            continue
        path = Path(root)
        if not _usable_dir(path):
            continue
        out.append(RemovableTarget(
            id=f"win:{letter}",
            label=f"{letter}: removable",
            path=path,
            kind="removable" if drive_type == 2 else "fixed-dev",
        ))
    return out


def _list_posix_removable() -> list[RemovableTarget]:
    roots: list[Path] = []
    system = platform.system().lower()
    home = Path.home()
    if system == "darwin":
        roots.append(Path("/Volumes"))
    else:
        roots.extend([Path("/media") / home.name, Path("/run/media") / home.name, Path("/mnt")])
    out: list[RemovableTarget] = []
    seen: set[Path] = set()
    for root in roots:
        if not root.is_dir():
            continue
        for child in root.iterdir():
            try:
                resolved = child.resolve()
                if resolved in seen or not _usable_dir(resolved):
                    continue
                seen.add(resolved)
                out.append(RemovableTarget(
                    id=f"posix:{_stable_id(resolved)}",
                    label=resolved.name,
                    path=resolved,
                    kind="removable",
                ))
            except OSError:
                continue
    return out


def _list_env_removable() -> list[RemovableTarget]:
    out: list[RemovableTarget] = []
    extra = os.environ.get("ONE_LINK_COURIER_MEDIA_ROOTS", "")
    for raw in extra.split(os.pathsep):
        if not raw.strip():
            continue
        root = Path(raw.strip()).expanduser()
        if not root.is_dir():
            continue
        for child in root.iterdir():
            try:
                resolved = child.resolve()
                if not _usable_dir(resolved):
                    continue
                out.append(RemovableTarget(
                    id=f"env:{_stable_id(resolved)}",
                    label=resolved.name,
                    path=resolved,
                    kind="removable-dev",
                ))
            except OSError:
                continue
    return out


def _usable_dir(path: Path) -> bool:
    try:
        return path.is_dir() and os.access(path, os.R_OK | os.W_OK)
    except OSError:
        return False


def _target_signature(target: RemovableTarget) -> tuple[str, str, str, str]:
    return (
        target.id,
        target.label,
        str(target.path),
        target.kind,
    )


def _stable_id(path: Path) -> str:
    import hashlib

    raw = str(path).encode("utf-8", "surrogatepass")
    return hashlib.sha256(raw).hexdigest()[:16]
