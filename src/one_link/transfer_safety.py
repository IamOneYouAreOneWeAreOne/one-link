"""Receiver-side transfer admission control.

The transfer protocol is intentionally optimistic: a trusted peer can offer a
huge file and the receiver replies with the exact chunks it wants. This module
is the hard safety gate in front of that optimism. It keeps "send anything" from
turning into "let anyone allocate anything".
"""

from __future__ import annotations

import os
import shutil
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


TIB = 1024 ** 4


DEFAULT_MAX_DECLARED_BYTES = 16 * TIB
DEFAULT_MIN_FREE_RESERVE_BYTES = 2 * 1024 ** 3
DEFAULT_FREE_RESERVE_RATIO = 0.05
DEFAULT_MAX_ACTIVE_INBOUND_TRANSFERS_PER_PEER = 3
DEFAULT_MAX_ACTIVE_INBOUND_BYTES_PER_PEER = 2 * TIB
DEFAULT_MAX_ACTIVE_INBOUND_TRANSFERS = 12
DEFAULT_MAX_ACTIVE_INBOUND_BYTES = 8 * TIB

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

# Formats that a browser can interpret as an active document.  These are a
# distinct class from ordinary executables: serving one inline from the local
# authenticated UI origin can turn a transferred file into stored XSS.  Keep
# the set extension based as well as MIME based because platform MIME tables
# are not consistent (notably for .mht, .svgz, and .xht).
ACTIVE_CONTENT_FILE_EXTENSIONS = {
    "atom",
    "css",
    "eml",
    "htm",
    "html",
    "mht",
    "mhtml",
    "rss",
    "shtm",
    "shtml",
    "svg",
    "svgz",
    "webarchive",
    "xbl",
    "xht",
    "xhtml",
    "xml",
    "xsl",
    "xslt",
}

ACTIVE_CONTENT_MIME_TYPES = {
    "application/ecmascript",
    "application/hta",
    "application/javascript",
    "application/atom+xml",
    "application/mhtml",
    "application/rss+xml",
    "application/svg+xml",
    "application/xhtml+xml",
    "application/xml",
    "application/x-mimearchive",
    "application/xslt+xml",
    "application/x-webarchive",
    "image/svg+xml",
    "message/rfc822",
    "multipart/related",
    "text/css",
    "text/ecmascript",
    "text/html",
    "text/javascript",
    "text/mhtml",
    "text/xml",
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
    max_active_inbound_transfers: int = DEFAULT_MAX_ACTIVE_INBOUND_TRANSFERS
    max_active_inbound_bytes: int = DEFAULT_MAX_ACTIVE_INBOUND_BYTES


@dataclass(frozen=True)
class TransferAdmissionContext:
    incoming_dir: Path
    active_inbound_count_for_peer: int = 0
    active_inbound_bytes_for_peer: int = 0
    active_inbound_count: int = 0
    active_inbound_bytes: int = 0
    # Bytes promised to transfers which have passed admission but have not
    # been committed to the destination volume yet. ``disk_usage().free``
    # cannot see those promises, so every later admission must subtract them.
    reserved_disk_bytes: int = 0
    # Only bytes already verified in this transfer's destination partial may
    # reduce the new disk reservation. Bytes in the global CDC cache do not:
    # assembling the final inbox file still needs another copy of them.
    already_allocated_bytes: int = 0
    # Additional new bytes the protocol must materialize outside the final
    # destination file (for example, missing CDC cache entries). This is
    # bounded to the declared file size by the evaluator.
    additional_storage_bytes: int = 0
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
    already_allocated_bytes: int = 0
    outstanding_reserved_bytes: int = 0
    additional_storage_bytes: int = 0
    reservation_reused: bool = False

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
            "already_allocated_bytes": self.already_allocated_bytes,
            "outstanding_reserved_bytes": self.outstanding_reserved_bytes,
            "additional_storage_bytes": self.additional_storage_bytes,
            "reservation_reused": self.reservation_reused,
        }


@dataclass(frozen=True)
class InboundTransferReservation:
    """One atomically-admitted inbound transfer.

    ``declared_size`` drives peer/global abuse quotas. ``remaining_bytes`` is
    the still-uncommitted promise against the destination volume and shrinks
    only after a successful write. Keeping the two separate prevents a peer
    from evading its quota by claiming cache hits while also avoiding double
    counting bytes which have genuinely landed on disk.
    """

    reservation_id: str
    peer_fp: str
    declared_size: int
    remaining_bytes: int
    created_monotonic_ns: int


class InboundTransferReservationLedger:
    """Process-local, thread-safe admission and disk-reservation ledger.

    Admission and insertion happen under one lock. That closes the classic
    check-then-act race where several channels all observe the same free disk
    and per-peer counters before any of them publishes an in-flight transfer.
    The daemon owns one ledger for the lifetime of a process and clears it on
    shutdown; restart recovery re-admits only transfers a peer actually
    resumes, while existing partial-file allocation is supplied explicitly.
    """

    def __init__(self, incoming_dir: Path):
        self._incoming_dir = Path(incoming_dir)
        self._lock = threading.RLock()
        self._reservations: dict[str, InboundTransferReservation] = {}

    @property
    def incoming_dir(self) -> Path:
        return self._incoming_dir

    def reserve(
        self,
        *,
        reservation_id: str,
        name: str,
        size: int | float | str | None,
        peer_fp: str,
        policy: TransferAdmissionPolicy,
        already_allocated_bytes: int = 0,
        additional_storage_bytes: int = 0,
        already_known_bytes: int = 0,
    ) -> TransferAdmissionDecision:
        clean_id = str(reservation_id or "")
        clean_peer = str(peer_fp or "")
        if not clean_id or not clean_peer:
            return TransferAdmissionDecision(
                ok=False,
                reason="invalid_reservation_identity",
                user_message="One Link blocked a file offer with invalid sender metadata.",
            )
        clean_size = _clean_size(size)
        with self._lock:
            existing = self._reservations.get(clean_id)
            if existing is not None:
                if (
                    existing.peer_fp != clean_peer
                    or clean_size is None
                    or existing.declared_size != clean_size
                ):
                    return TransferAdmissionDecision(
                        ok=False,
                        reason="reservation_conflict",
                        user_message=(
                            "One Link blocked a conflicting retry for an active file transfer."
                        ),
                        declared_size=max(0, clean_size or 0),
                    )
                return TransferAdmissionDecision(
                    ok=True,
                    reserve_bytes=existing.remaining_bytes,
                    declared_size=existing.declared_size,
                    already_known_bytes=max(0, int(already_known_bytes)),
                    already_allocated_bytes=max(0, int(already_allocated_bytes)),
                    outstanding_reserved_bytes=self._remaining_bytes_locked(),
                    additional_storage_bytes=max(
                        0, min(clean_size, int(additional_storage_bytes)),
                    ),
                    reservation_reused=True,
                )

            peer_reservations = [
                item
                for item in self._reservations.values()
                if item.peer_fp == clean_peer
            ]
            context = TransferAdmissionContext(
                incoming_dir=self._incoming_dir,
                active_inbound_count_for_peer=len(peer_reservations),
                active_inbound_bytes_for_peer=sum(
                    item.declared_size for item in peer_reservations
                ),
                active_inbound_count=len(self._reservations),
                active_inbound_bytes=sum(
                    item.declared_size for item in self._reservations.values()
                ),
                reserved_disk_bytes=self._remaining_bytes_locked(),
                already_allocated_bytes=already_allocated_bytes,
                additional_storage_bytes=additional_storage_bytes,
                already_known_bytes=already_known_bytes,
            )
            decision = evaluate_transfer_admission(
                name=name,
                size=size,
                peer_fp=clean_peer,
                policy=policy,
                context=context,
            )
            if not decision.ok or clean_size is None:
                return decision
            self._reservations[clean_id] = InboundTransferReservation(
                reservation_id=clean_id,
                peer_fp=clean_peer,
                declared_size=clean_size,
                remaining_bytes=decision.reserve_bytes,
                created_monotonic_ns=time.monotonic_ns(),
            )
            return decision

    def consume(self, reservation_id: str, committed_bytes: int) -> int:
        """Mark bytes successfully written and return the remaining promise."""

        try:
            clean_count = int(committed_bytes)
        except (TypeError, ValueError, OverflowError):
            return 0
        if clean_count <= 0:
            with self._lock:
                current = self._reservations.get(str(reservation_id or ""))
                return current.remaining_bytes if current is not None else 0
        clean_id = str(reservation_id or "")
        with self._lock:
            current = self._reservations.get(clean_id)
            if current is None:
                return 0
            remaining = max(0, current.remaining_bytes - clean_count)
            self._reservations[clean_id] = InboundTransferReservation(
                reservation_id=current.reservation_id,
                peer_fp=current.peer_fp,
                declared_size=current.declared_size,
                remaining_bytes=remaining,
                created_monotonic_ns=current.created_monotonic_ns,
            )
            return remaining

    def resize_remaining(
        self,
        *,
        reservation_id: str,
        remaining_bytes: int,
        peer_fp: str,
        policy: TransferAdmissionPolicy,
    ) -> TransferAdmissionDecision:
        """Atomically resize one owner's uncommitted storage promise.

        Adaptive CDC retries may publish a different valid chunk map for the
        same whole-file hash. The cache-volume requirement can therefore grow
        or shrink while the logical transfer size remains unchanged. Shrinks
        are always safe. Growth re-checks current free space plus all other
        promises under the same lock, without exposing a release/re-acquire
        overbooking window.
        """

        clean_id = str(reservation_id or "")
        clean_peer = str(peer_fp or "")
        clean_remaining = _clean_size(remaining_bytes)
        with self._lock:
            current = self._reservations.get(clean_id)
            if (
                current is None
                or current.peer_fp != clean_peer
                or clean_remaining is None
            ):
                return TransferAdmissionDecision(
                    ok=False,
                    reason="reservation_conflict",
                    user_message=(
                        "One Link blocked a conflicting retry for an active file transfer."
                    ),
                )
            if clean_remaining > 2 * max(0, int(policy.max_declared_bytes)):
                return TransferAdmissionDecision(
                    ok=False,
                    reason="declared_size_too_large",
                    user_message=(
                        "One Link blocked a storage promise that was too large to handle safely."
                    ),
                    declared_size=current.declared_size,
                )
            outstanding_other = sum(
                item.remaining_bytes
                for key, item in self._reservations.items()
                if key != clean_id
            )
            free_bytes = 0
            required = clean_remaining + outstanding_other
            if clean_remaining > current.remaining_bytes:
                free_bytes = _disk_free_bytes(self._incoming_dir)
                reserve_floor = _reserve_floor_bytes(policy, free_bytes)
                required += reserve_floor
                if free_bytes < required:
                    return TransferAdmissionDecision(
                        ok=False,
                        reason="insufficient_disk_space",
                        user_message=(
                            "One Link is waiting for enough free space before accepting this file."
                        ),
                        reserve_bytes=clean_remaining,
                        free_bytes=free_bytes,
                        required_free_bytes=required,
                        declared_size=current.declared_size,
                        outstanding_reserved_bytes=outstanding_other,
                    )
            self._reservations[clean_id] = InboundTransferReservation(
                reservation_id=current.reservation_id,
                peer_fp=current.peer_fp,
                declared_size=current.declared_size,
                remaining_bytes=clean_remaining,
                created_monotonic_ns=current.created_monotonic_ns,
            )
            return TransferAdmissionDecision(
                ok=True,
                reserve_bytes=clean_remaining,
                free_bytes=free_bytes,
                required_free_bytes=required,
                declared_size=current.declared_size,
                outstanding_reserved_bytes=outstanding_other,
                reservation_reused=True,
            )

    def release(self, reservation_id: str, *, peer_fp: str | None = None) -> bool:
        """Release exactly one reservation, optionally owner-checked."""

        clean_id = str(reservation_id or "")
        with self._lock:
            current = self._reservations.get(clean_id)
            if current is None:
                return False
            if peer_fp is not None and current.peer_fp != str(peer_fp):
                return False
            del self._reservations[clean_id]
            return True

    def clear(self) -> None:
        with self._lock:
            self._reservations.clear()

    def snapshot(self) -> tuple[InboundTransferReservation, ...]:
        with self._lock:
            return tuple(self._reservations.values())

    def get(self, reservation_id: str) -> InboundTransferReservation | None:
        with self._lock:
            return self._reservations.get(str(reservation_id or ""))

    def _remaining_bytes_locked(self) -> int:
        return sum(item.remaining_bytes for item in self._reservations.values())


def same_storage_volume(first: Path, second: Path) -> bool:
    """Best-effort identity check for reservation-ledger sharing.

    Independent ledgers on one volume can both promise the same free bytes.
    Callers which stage into different directories should share a ledger when
    those directories resolve to the same device. ``st_dev`` is authoritative
    on POSIX and supported by Python on Windows; anchor comparison is the
    fail-safe fallback before either directory exists.
    """

    def _identity(path: Path) -> tuple[str, int | str]:
        candidate = Path(path)
        with_parent = candidate
        while not with_parent.exists() and with_parent != with_parent.parent:
            with_parent = with_parent.parent
        try:
            return ("device", int(os.stat(with_parent).st_dev))
        except OSError:
            anchor = candidate.resolve(strict=False).anchor.casefold()
            return ("anchor", anchor)

    return _identity(first) == _identity(second)


def _disk_free_bytes(path: Path) -> int:
    try:
        path.mkdir(parents=True, exist_ok=True)
        return int(shutil.disk_usage(path).free)
    except OSError:
        # Admission remains fail-closed when the destination volume cannot be
        # inspected.  Unexpected programming failures must propagate instead
        # of being misreported as an ordinary "disk full" transfer stall.
        return 0


def _reserve_floor_bytes(policy: TransferAdmissionPolicy, free_bytes: int) -> int:
    try:
        ratio = float(policy.free_reserve_ratio)
        if ratio < 0.0 or ratio != ratio or ratio == float("inf"):
            ratio = 0.0
    except (TypeError, ValueError, OverflowError):
        ratio = 0.0
    return max(
        0,
        int(policy.min_free_reserve_bytes),
        int(max(0, free_bytes) * ratio),
    )


def _clean_size(value: int | float | str | None) -> int | None:
    if value is None:
        return None
    # JSON numbers used for byte counts must be exact integers. Accepting a
    # float truncates (1.9 -> 1); accepting bool turns true into one byte.
    if isinstance(value, bool) or not isinstance(value, int):
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
        # This metadata originates in decoded JSON, whose objects are exact
        # dictionaries.  Reject alien objects and non-integral sizes instead
        # of invoking arbitrary ``get``/``__int__`` implementations behind a
        # blanket exception handler.
        if not isinstance(c, dict):
            continue
        raw_hash = dict.get(c, "hash")
        raw_size = dict.get(c, "size")
        if not isinstance(raw_hash, str):
            continue
        if isinstance(raw_size, bool) or not isinstance(raw_size, int):
            continue
        h = raw_hash
        size = raw_size
        if not h or h in seen or h not in known_hashes or size <= 0:
            continue
        seen.add(h)
        total += size
    return total


def is_active_content_file(name: str, mime_type: str | None = None) -> bool:
    """Return whether a file must never be served as an inline document.

    All suffixes are inspected so a misleading double extension such as
    ``invoice.svg.txt`` is still classified conservatively.  MIME parameters
    are ignored (``text/html; charset=utf-8`` is active), and malformed MIME
    values simply fall back to the filename decision.
    """

    safe_name = Path(str(name or "")).name
    suffixes = {
        part.lower().lstrip(".")
        for part in Path(safe_name).suffixes
        if part and part != "."
    }
    if suffixes.intersection(ACTIVE_CONTENT_FILE_EXTENSIONS):
        return True
    normalized_mime = str(mime_type or "").partition(";")[0].strip().lower()
    return normalized_mime in ACTIVE_CONTENT_MIME_TYPES


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
    if is_active_content_file(safe_name):
        return {
            "level": "high",
            "extension": ext,
            "reason": "active_web_content",
            "label": "Active web content",
            "user_message": (
                "One Link received this safely, but a browser could run "
                "content inside it. It is available only as a download or "
                "an inert source preview."
            ),
            "open_policy": "download_only",
        }
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

    if (
        policy.max_active_inbound_transfers > 0
        and context.active_inbound_count >= policy.max_active_inbound_transfers
    ):
        return TransferAdmissionDecision(
            ok=False,
            reason="global_inbound_transfer_quota",
            user_message="One Link paused incoming files because the device is already busy.",
            declared_size=clean_size,
        )
    if (
        policy.max_active_inbound_bytes > 0
        and context.active_inbound_bytes + clean_size
        > policy.max_active_inbound_bytes
    ):
        return TransferAdmissionDecision(
            ok=False,
            reason="global_inbound_byte_quota",
            user_message="One Link paused incoming files because the device queue is full.",
            declared_size=clean_size,
        )

    already_known = max(0, min(clean_size, int(context.already_known_bytes)))
    already_allocated = max(
        0, min(clean_size, int(context.already_allocated_bytes)),
    )
    additional_storage = max(
        0, min(clean_size, int(context.additional_storage_bytes)),
    )
    reserve_bytes = max(0, clean_size - already_allocated) + additional_storage
    outstanding_reserved = max(0, int(context.reserved_disk_bytes))
    free_bytes = _disk_free_bytes(context.incoming_dir)
    reserve_floor = _reserve_floor_bytes(policy, free_bytes)
    required = reserve_bytes + outstanding_reserved + reserve_floor
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
            already_allocated_bytes=already_allocated,
            outstanding_reserved_bytes=outstanding_reserved,
            additional_storage_bytes=additional_storage,
        )
    return TransferAdmissionDecision(
        ok=True,
        reserve_bytes=reserve_bytes,
        free_bytes=free_bytes,
        required_free_bytes=required,
        declared_size=clean_size,
        already_known_bytes=already_known,
        already_allocated_bytes=already_allocated,
        outstanding_reserved_bytes=outstanding_reserved,
        additional_storage_bytes=additional_storage,
    )
