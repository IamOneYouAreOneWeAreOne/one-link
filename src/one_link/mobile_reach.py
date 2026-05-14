"""Phone and native reach planning for the comms fabric.

Phones are helpers, not a separate trust universe. This module turns connected
browser/native peers into explicit route-bridge, courier, and chunk-helper
plans that higher layers can show or use without bypassing One Link identity,
capabilities, encryption, or storage budgets.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Iterable, Mapping


DEFAULT_PHONE_STORAGE_BUDGET_BYTES = 256 * 1024 * 1024
MIN_PHONE_COURIER_BYTES = 8 * 1024 * 1024
MIN_PHONE_CHUNK_BRIDGE_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class PhoneReachPlan:
    fingerprint: str
    connected: bool
    paired: bool
    control_bridge: bool
    chunk_bridge: bool
    courier: bool
    background_resume: bool
    storage_budget_bytes: int
    route_hints: tuple[str, ...]
    actions: tuple[str, ...]
    safeguards: tuple[str, ...]
    reason: str
    last_activity_ms: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "fingerprint": self.fingerprint,
            "connected": self.connected,
            "paired": self.paired,
            "control_bridge": self.control_bridge,
            "chunk_bridge": self.chunk_bridge,
            "courier": self.courier,
            "background_resume": self.background_resume,
            "storage_budget_bytes": self.storage_budget_bytes,
            "route_hints": list(self.route_hints),
            "actions": list(self.actions),
            "safeguards": list(self.safeguards),
            "reason": self.reason,
            "last_activity_ms": self.last_activity_ms,
        }


def mobile_storage_budget_from_env(env: Mapping[str, str] | None = None) -> int:
    env = env or os.environ
    raw = str(env.get("ONE_LINK_PHONE_STORAGE_BUDGET_BYTES") or "").strip()
    if not raw:
        return DEFAULT_PHONE_STORAGE_BUDGET_BYTES
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError("ONE_LINK_PHONE_STORAGE_BUDGET_BYTES must be an integer") from exc
    if value < 0:
        raise ValueError("ONE_LINK_PHONE_STORAGE_BUDGET_BYTES must be non-negative")
    return min(value, 8 * 1024 * 1024 * 1024)


def plan_mobile_reach(
    peers: Iterable[object],
    *,
    storage_budget_bytes: int | None = None,
    now_ms: int | None = None,
) -> dict[str, object]:
    budget = int(DEFAULT_PHONE_STORAGE_BUDGET_BYTES if storage_budget_bytes is None else storage_budget_bytes)
    now_ms = int(now_ms or time.time() * 1000)
    plans = tuple(_plan_peer(peer, storage_budget_bytes=budget, now_ms=now_ms) for peer in peers)
    connected = sum(1 for p in plans if p.connected)
    paired = sum(1 for p in plans if p.paired)
    return {
        "ok": True,
        "mode": "phone_native_reach",
        "connected": connected,
        "paired": paired,
        "control_bridges": sum(1 for p in plans if p.control_bridge),
        "chunk_bridges": sum(1 for p in plans if p.chunk_bridge),
        "couriers": sum(1 for p in plans if p.courier),
        "background_resume": sum(1 for p in plans if p.background_resume),
        "storage_budget_bytes": budget,
        "plans": [p.to_dict() for p in plans],
        "safeguards": [
            "phones do not bypass pairing or peer verification",
            "route hints are control-plane only until promoted by a key-confirmed session",
            "courier/chunk use is bounded by local mobile storage budget",
            "payload chunks remain encrypted and content-address verified",
        ],
    }


def _plan_peer(peer: object, *, storage_budget_bytes: int, now_ms: int) -> PhoneReachPlan:
    fp = str(getattr(peer, "fingerprint", "") or "")
    closed = bool(getattr(peer, "closed", False))
    control_dc = getattr(peer, "control_dc", None)
    bulk_dc = getattr(peer, "bulk_dc", None)
    connected_ms = int(getattr(peer, "connected_ms", 0) or 0)
    last_activity_ms = int(getattr(peer, "last_activity_ms", 0) or connected_ms or now_ms)
    paired_ms = getattr(peer, "paired_ms", None)
    paired = paired_ms is not None
    connected = bool(fp and not closed)
    control_bridge = bool(connected and paired and control_dc is not None)
    chunk_bridge = bool(control_bridge and bulk_dc is not None and storage_budget_bytes >= MIN_PHONE_CHUNK_BRIDGE_BYTES)
    courier = bool(connected and paired and storage_budget_bytes >= MIN_PHONE_COURIER_BYTES)
    background_resume = bool(paired and fp)
    route_hints = []
    actions = []
    if control_bridge:
        route_hints.append("route_token_exchange")
        actions.append("exchange_route_hints")
    if chunk_bridge:
        route_hints.append("browser_peer_bulk_datachannel")
        actions.append("cache_or_forward_verified_chunks")
    if courier:
        route_hints.append("phone_courier")
        actions.append("stage_encrypted_courier_bundle")
    if not connected:
        actions.append("scan_pair_phone_qr")
    elif not paired:
        actions.append("finish_phone_pairing")
    elif not control_bridge:
        actions.append("wait_for_control_channel")
    reason = _reason(
        connected=connected,
        paired=paired,
        control_bridge=control_bridge,
        chunk_bridge=chunk_bridge,
        courier=courier,
        storage_budget_bytes=storage_budget_bytes,
    )
    return PhoneReachPlan(
        fingerprint=fp,
        connected=connected,
        paired=paired,
        control_bridge=control_bridge,
        chunk_bridge=chunk_bridge,
        courier=courier,
        background_resume=background_resume,
        storage_budget_bytes=storage_budget_bytes,
        route_hints=tuple(route_hints),
        actions=tuple(actions),
        safeguards=(
            "browser peer identity is pubkey-bound",
            "phone route hints do not grant file access",
            "chunk and courier payloads stay encrypted above WebRTC/native transport",
            "mobile storage use is budgeted before bulk helper modes activate",
        ),
        reason=reason,
        last_activity_ms=last_activity_ms,
    )


def _reason(
    *,
    connected: bool,
    paired: bool,
    control_bridge: bool,
    chunk_bridge: bool,
    courier: bool,
    storage_budget_bytes: int,
) -> str:
    if not connected:
        return "phone is not connected"
    if not paired:
        return "phone connection is not paired yet"
    if storage_budget_bytes < MIN_PHONE_COURIER_BYTES:
        return "mobile storage budget is too small for courier mode"
    if control_bridge and chunk_bridge and courier:
        return "phone can bridge route hints, carry chunks, and act as courier"
    if control_bridge and courier:
        return "phone can bridge route hints and carry courier bundles"
    if control_bridge:
        return "phone can bridge route hints"
    return "phone is paired; waiting for DataChannel readiness"
