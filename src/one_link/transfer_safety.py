"""Receiver-side transfer admission control.

The transfer protocol is intentionally optimistic: a trusted peer can offer a
huge file and the receiver replies with the exact chunks it wants. This module
is the hard safety gate in front of that optimism. It keeps "send anything" from
turning into "let anyone allocate anything".
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


TIB = 1024 ** 4


DEFAULT_MAX_DECLARED_BYTES = 16 * TIB
DEFAULT_MIN_FREE_RESERVE_BYTES = 2 * 1024 ** 3
DEFAULT_FREE_RESERVE_RATIO = 0.05
DEFAULT_MAX_ACTIVE_INBOUND_TRANSFERS_PER_PEER = 3
DEFAULT_MAX_ACTIVE_INBOUND_BYTES_PER_PEER = 2 * TIB

HIGH_RISK_FILE_EXTENSIONS = {
    "app",
    "apk",
    "bat",
    "cmd",
    "com",
    "dll",
    "dmg",
    "exe",
    "hta",
    "jar",
    "js",
    "jse",
    "lnk",
    "msi",
    "pkg",
    "ps1",
    "reg",
    "scr",
    "sh",
    "sys",
    "vb",
    "vbe",
    "vbs",
    "ws",
    "wsf",
}

MEDIUM_RISK_FILE_EXTENSIONS = {
    "7z",
    "doc",
    "docm",
    "iso",
    "rar",
    "tar",
    "xls",
    "xlsm",
    "zip",
}


@dataclass(frozen=True)
class TransferAdmissionPolicy:
    max_declared_bytes: int = DEFAULT_MAX_DECLARED_BYTES
    min_free_reserve_bytes: int = DEFAULT_MIN_FREE_RESERVE_BYTES
    free_reserve_ratio: float = DEFAULT_FREE_RESERVE_RATIO
    max_active_inbound_transfers_per_peer: int = DEFAULT_MAX_ACTIVE_INBOUND_TRANSFERS_PER_PEER
    max_active_inbound_bytes_per_peer: int = DEFAULT_MAX_ACTIVE_INBOUND_BYTES_PER_PEER


@dataclass(frozen=True)
class TransferAdmissionContext:
    incoming_dir: Path
    active_inbound_count_for_peer: int = 0
    active_inbound_bytes_for_peer: int = 0
    already_known_bytes: int = 0


@dataclass(frozen=True)
class TransferAdmissionDecision:
    ok: bool
    reason: str = ""
    user_message: str = ""
    reserve_bytes: int = 0
    free_bytes: int = 0
    required_free_bytes: int = 0
    declared_size: int = 0
    already_known_bytes: int = 0

    def wire_reason(self) -> str:
        return self.reason or "admission_denied"

    def to_metadata(self) -> dict:
        return {
            "ok": self.ok,
            "reason": self.reason,
            "user_message": self.user_message,
            "reserve_bytes": self.reserve_bytes,
            "free_bytes": self.free_bytes,
            "required_free_bytes": self.required_free_bytes,
            "declared_size": self.declared_size,
            "already_known_bytes": self.already_known_bytes,
        }


def _disk_free_bytes(path: Path) -> int:
    try:
        path.mkdir(parents=True, exist_ok=True)
        return int(shutil.disk_usage(path).free)
    except Exception:
        return 0


def _clean_size(value: int | float | str | None) -> int | None:
    if value is None:
        return None
    try:
        size = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return size if size >= 0 else None


def known_bytes_from_chunks(chunks: Iterable[dict], known_hashes: set[str]) -> int:
    total = 0
    seen: set[str] = set()
    for c in chunks:
        try:
            h = str(c.get("hash") or "")
            size = int(c.get("size") or 0)
        except Exception:
            continue
        if not h or h in seen or h not in known_hashes or size <= 0:
            continue
        seen.add(h)
        total += size
    return total


def classify_file_risk(name: str) -> dict:
    """Return user-facing risk metadata for a received file.

    This is not antivirus and deliberately does not pretend to be. It is a
    zero-trust UX guardrail: One Link can transfer any file, but files that are
    commonly executable or scriptable should be surfaced as reveal/download
    only and never treated like harmless media.
    """

    safe_name = Path(str(name or "")).name
    suffixes = [
        part.lower().lstrip(".")
        for part in Path(safe_name).suffixes
        if part and part != "."
    ]
    ext = suffixes[-1] if suffixes else ""
    risky_suffixes = [e for e in suffixes if e in HIGH_RISK_FILE_EXTENSIONS]
    archive_suffixes = [e for e in suffixes if e in MEDIUM_RISK_FILE_EXTENSIONS]
    if risky_suffixes:
        return {
            "level": "high",
            "extension": ext,
            "reason": "executable_or_script",
            "label": "Executable file",
            "user_message": (
                "One Link received this safely, but it can run code. "
                "Open it only if you trust the sender and expected this file."
            ),
            "open_policy": "reveal_only",
        }
    if archive_suffixes:
        return {
            "level": "medium",
            "extension": ext,
            "reason": "archive_or_macro_document",
            "label": "Archive or macro-capable file",
            "user_message": (
                "One Link received this safely. Check the contents before opening anything inside."
            ),
            "open_policy": "cautious",
        }
    return {
        "level": "low",
        "extension": ext,
        "reason": "",
        "label": "File",
        "user_message": "",
        "open_policy": "normal",
    }


def evaluate_transfer_admission(
    *,
    name: str,
    size: int | float | str | None,
    peer_fp: str,
    policy: TransferAdmissionPolicy,
    context: TransferAdmissionContext,
) -> TransferAdmissionDecision:
    del name, peer_fp
    clean_size = _clean_size(size)
    if clean_size is None:
        return TransferAdmissionDecision(
            ok=False,
            reason="invalid_size",
            user_message="One Link blocked a file offer with an invalid size.",
        )
    if clean_size > int(policy.max_declared_bytes):
        return TransferAdmissionDecision(
            ok=False,
            reason="declared_size_too_large",
            user_message="One Link blocked a file offer that was too large to handle safely.",
            declared_size=clean_size,
        )
    if (
        policy.max_active_inbound_transfers_per_peer > 0
        and context.active_inbound_count_for_peer
        >= policy.max_active_inbound_transfers_per_peer
    ):
        return TransferAdmissionDecision(
            ok=False,
            reason="peer_inbound_transfer_quota",
            user_message="One Link paused this sender because too many files are already incoming.",
            declared_size=clean_size,
        )
    if (
        policy.max_active_inbound_bytes_per_peer > 0
        and context.active_inbound_bytes_for_peer + clean_size
        > policy.max_active_inbound_bytes_per_peer
    ):
        return TransferAdmissionDecision(
            ok=False,
            reason="peer_inbound_byte_quota",
            user_message="One Link paused this sender because their incoming queue is too large.",
            declared_size=clean_size,
        )

    already_known = max(0, min(clean_size, int(context.already_known_bytes)))
    reserve_bytes = max(0, clean_size - already_known)
    free_bytes = _disk_free_bytes(context.incoming_dir)
    reserve_floor = max(
        int(policy.min_free_reserve_bytes),
        int(free_bytes * max(0.0, float(policy.free_reserve_ratio))),
    )
    required = reserve_bytes + reserve_floor
    if reserve_bytes > 0 and free_bytes < required:
        return TransferAdmissionDecision(
            ok=False,
            reason="insufficient_disk_space",
            user_message=(
                "One Link is waiting for enough free space before accepting this file."
            ),
            reserve_bytes=reserve_bytes,
            free_bytes=free_bytes,
            required_free_bytes=required,
            declared_size=clean_size,
            already_known_bytes=already_known,
        )
    return TransferAdmissionDecision(
        ok=True,
        reserve_bytes=reserve_bytes,
        free_bytes=free_bytes,
        required_free_bytes=required,
        declared_size=clean_size,
        already_known_bytes=already_known,
    )
