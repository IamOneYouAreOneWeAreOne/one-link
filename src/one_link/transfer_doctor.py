"""Transfer Doctor: user-safe diagnosis and auto-healing decisions.

The daemon already keeps durable transfer rows. This module turns those raw
rows into a small, stable contract:

* what the user should see;
* what One Link should do next;
* whether the issue is transient or needs human attention.

It is intentionally deterministic and side-effect free so the UI, daemon, and
torture simulator can all rely on the same diagnosis vocabulary.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


AUTO_ACTIONS = {
    "wait_for_peer",
    "retry_with_backoff",
    "reopen_secure_session",
    "refresh_route",
    "retry_missing_chunk",
    "fallback_protocol",
}


@dataclass(frozen=True)
class TransferDiagnosis:
    code: str
    label: str
    user_message: str
    action: str
    automatic: bool
    transient: bool
    severity: str
    next_retry_ms: int | None = None
    retry_in_ms: int | None = None
    route_action: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "label": self.label,
            "user_message": self.user_message,
            "action": self.action,
            "automatic": self.automatic,
            "transient": self.transient,
            "severity": self.severity,
            "next_retry_ms": self.next_retry_ms,
            "retry_in_ms": self.retry_in_ms,
            "route_action": self.route_action,
        }


@dataclass(frozen=True)
class RouteObservation:
    route: str
    ok: bool
    latency_ms: float | None = None
    bandwidth_bps: float | None = None
    error_code: str | None = None
    at_ms: int = 0


@dataclass(frozen=True)
class RouteCandidate:
    route: str
    score: float
    attempts: int
    successes: int
    failures: int
    latency_ms: float | None
    bandwidth_bps: float | None


def _metadata(rec: Any) -> Mapping[str, Any]:
    md = getattr(rec, "metadata", None)
    if isinstance(rec, Mapping):
        md = rec.get("metadata", md)
    return md if isinstance(md, Mapping) else {}


def _field(rec: Any, name: str, default: Any = None) -> Any:
    if isinstance(rec, Mapping):
        return rec.get(name, default)
    return getattr(rec, name, default)


def _now_delta(next_retry_ms: int | None, now_ms: int | None) -> int | None:
    if next_retry_ms is None or now_ms is None:
        return None
    return max(0, int(next_retry_ms) - int(now_ms))


def diagnose_transfer(rec: Any, *, now_ms: int | None = None) -> TransferDiagnosis:
    """Diagnose a transfer record into user-safe state.

    The labels are intentionally product language, not implementation language.
    Raw errors stay in metadata/debug logs; the user sees what One Link is doing.
    """

    status = str(_field(rec, "status", "queued") or "queued")
    direction = str(_field(rec, "direction", "out") or "out")
    md = _metadata(rec)
    delivery_state = str(md.get("delivery_state") or "").lower()
    err_class = str(md.get("error_class") or "")
    err = str(md.get("error") or "")
    code_src = " ".join((delivery_state, err_class, err)).lower()
    next_retry = md.get("next_retry_ms")
    next_retry_ms = int(next_retry) if isinstance(next_retry, (int, float)) else None
    retry_in_ms = _now_delta(next_retry_ms, now_ms)

    if status == "complete":
        return TransferDiagnosis(
            code="done",
            label="Done",
            user_message="Verified and delivered.",
            action="none",
            automatic=True,
            transient=False,
            severity="ok",
        )

    if status in ("queued", "offered") and delivery_state in ("queued", ""):
        return TransferDiagnosis(
            code="queued",
            label="Sending",
            user_message="One Link is preparing the send.",
            action="retry_with_backoff",
            automatic=True,
            transient=True,
            severity="info",
            next_retry_ms=next_retry_ms,
            retry_in_ms=retry_in_ms,
        )

    if status == "active" or delivery_state == "sending":
        return TransferDiagnosis(
            code="sending",
            label="Sending",
            user_message="One Link is moving verified pieces now.",
            action="continue",
            automatic=True,
            transient=True,
            severity="info",
        )

    if "ratchet" in code_src or "desync" in code_src or "invalidtag" in code_src:
        return TransferDiagnosis(
            code="secure_session_desync",
            label="Resuming",
            user_message="One Link is refreshing the secure session and will continue automatically.",
            action="reopen_secure_session",
            automatic=True,
            transient=True,
            severity="warn",
            next_retry_ms=next_retry_ms,
            retry_in_ms=retry_in_ms,
            route_action="reopen_secure_session",
        )

    if "version" in code_src or "compat" in code_src or "protocol" in code_src:
        return TransferDiagnosis(
            code="protocol_fallback",
            label="Resuming",
            user_message="One Link is switching to the best protocol both devices understand.",
            action="fallback_protocol",
            automatic=True,
            transient=True,
            severity="info",
            next_retry_ms=next_retry_ms,
            retry_in_ms=retry_in_ms,
            route_action="fallback_protocol",
        )

    if "chunk" in code_src or "integrity" in code_src or "hash" in code_src:
        return TransferDiagnosis(
            code="chunk_retry",
            label="Resuming",
            user_message="One Link is retrying only the piece that did not verify.",
            action="retry_missing_chunk",
            automatic=True,
            transient=True,
            severity="warn",
            next_retry_ms=next_retry_ms,
            retry_in_ms=retry_in_ms,
            route_action="retry_missing_chunk",
        )

    if "resum" in delivery_state:
        return TransferDiagnosis(
            code="resuming",
            label="Resuming",
            user_message="One Link is continuing from the verified pieces already delivered.",
            action="retry_missing_chunk",
            automatic=True,
            transient=True,
            severity="info",
            next_retry_ms=next_retry_ms,
            retry_in_ms=retry_in_ms,
            route_action="retry_missing_chunk",
        )

    if "offline" in code_src or "unreachable" in code_src or "timeout" in code_src:
        return TransferDiagnosis(
            code="waiting_for_device",
            label="Waiting for device",
            user_message="One Link is waiting quietly and will resume when the device is reachable.",
            action="wait_for_peer",
            automatic=True,
            transient=True,
            severity="info",
            next_retry_ms=next_retry_ms,
            retry_in_ms=retry_in_ms,
            route_action="refresh_route",
        )

    if "route" in code_src or "address" in code_src or "port" in code_src:
        return TransferDiagnosis(
            code="route_refresh",
            label="Resuming",
            user_message="One Link is refreshing the device route and trying again.",
            action="refresh_route",
            automatic=True,
            transient=True,
            severity="info",
            next_retry_ms=next_retry_ms,
            retry_in_ms=retry_in_ms,
            route_action="refresh_route",
        )

    if status == "paused" or bool(md.get("transient")):
        return TransferDiagnosis(
            code="retrying",
            label="Waiting for device",
            user_message="One Link saved the transfer and will retry automatically.",
            action="retry_with_backoff",
            automatic=True,
            transient=True,
            severity="info",
            next_retry_ms=next_retry_ms,
            retry_in_ms=retry_in_ms,
        )

    if "source file" in code_src or "filenotfound" in code_src:
        return TransferDiagnosis(
            code="source_missing",
            label="Needs attention",
            user_message="The original file moved or was deleted before One Link could finish.",
            action="choose_file_again",
            automatic=False,
            transient=False,
            severity="error",
        )

    if status == "failed":
        return TransferDiagnosis(
            code="needs_attention",
            label="Needs attention",
            user_message="One Link needs your attention before it can continue this transfer.",
            action="manual_review",
            automatic=False,
            transient=False,
            severity="error",
        )

    return TransferDiagnosis(
        code="unknown",
        label="Sending" if direction == "out" else "Receiving",
        user_message="One Link is tracking this transfer.",
        action="observe",
        automatic=True,
        transient=True,
        severity="info",
    )


def diagnose_exception(exc: BaseException) -> TransferDiagnosis:
    """Classify a send exception before it becomes transfer metadata."""

    class _R:
        status = "paused"
        direction = "out"
        metadata = {
            "error": str(exc),
            "error_class": type(exc).__name__,
            "transient": not isinstance(exc, (FileNotFoundError, PermissionError)),
        }

    if isinstance(exc, asyncio.TimeoutError):
        _R.metadata["error"] = "timeout"
    return diagnose_transfer(_R)


def enrich_transfer_event(event: dict[str, Any], *, now_ms: int | None = None) -> dict[str, Any]:
    """Attach doctor diagnosis to a transfer event dict."""

    diag = diagnose_transfer(event, now_ms=now_ms).to_dict()
    out = dict(event)
    out["doctor"] = diag
    # Flatten the highest-value fields for older UI code and tests.
    out["display_state"] = diag["label"]
    out["user_message"] = diag["user_message"]
    return out


class RouteMemory:
    """Tiny deterministic route scorer for a peer.

    This is intentionally independent from networking. The daemon can feed it
    observations later; the simulator can already prove decisions.
    """

    def __init__(self) -> None:
        self._routes: dict[str, list[RouteObservation]] = {}

    def observe(self, obs: RouteObservation) -> None:
        self._routes.setdefault(obs.route, []).append(obs)

    def candidates(self) -> tuple[RouteCandidate, ...]:
        out: list[RouteCandidate] = []
        for route, rows in self._routes.items():
            attempts = len(rows)
            successes = sum(1 for r in rows if r.ok)
            failures = attempts - successes
            latencies = [r.latency_ms for r in rows if r.ok and r.latency_ms is not None]
            bandwidths = [r.bandwidth_bps for r in rows if r.ok and r.bandwidth_bps is not None]
            reliability = successes / max(1, attempts)
            latency = sum(latencies) / len(latencies) if latencies else None
            bandwidth = sum(bandwidths) / len(bandwidths) if bandwidths else None
            score = reliability * 100.0
            if bandwidth:
                score += min(50.0, bandwidth / 10_000_000.0)
            if latency is not None:
                score -= min(40.0, latency / 25.0)
            score -= failures * 2.0
            out.append(RouteCandidate(
                route=route,
                score=round(score, 4),
                attempts=attempts,
                successes=successes,
                failures=failures,
                latency_ms=latency,
                bandwidth_bps=bandwidth,
            ))
        return tuple(sorted(out, key=lambda c: (-c.score, c.route)))

    def best_route(self, fallback: str = "lan") -> str:
        ranked = self.candidates()
        return ranked[0].route if ranked else fallback
