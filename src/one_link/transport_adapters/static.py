"""Safe initial adapters for the Universal Comms Fabric.

These adapters do not create networks yet. They expose existing or planned
paths to the route brain in a deterministic way so daemon integration can
begin without destabilizing current transfers.
"""

from __future__ import annotations

from dataclasses import dataclass

from one_link.hardware_inventory import HardwarePath

from .base import AdapterProbe, PreparedRoute, RouteScore


_PRIVACY_WEIGHT = {
    "same_machine": 1.0,
    "direct_local": 0.95,
    "offline_physical": 0.90,
    "proximity": 0.82,
    "in_person": 0.82,
    "direct_or_relayed_internet": 0.62,
    "experimental_hardware": 0.40,
}


@dataclass(frozen=True)
class StaticPathAdapter:
    """Adapter backed by a HardwarePath snapshot."""

    path: HardwarePath

    @property
    def adapter_id(self) -> str:
        return self.path.adapter_id or self.path.kind

    @property
    def kind(self) -> str:
        return self.path.kind

    def probe(self) -> AdapterProbe:
        return AdapterProbe(
            adapter_id=self.adapter_id,
            kind=self.path.kind,
            available=self.path.available,
            bulk_capable=self.path.bulk_capable,
            control_capable=self.path.control_capable,
            estimated_bps=float(self.path.estimated_bps),
            latency_ms=_default_latency_ms(self.path.kind),
            privacy=self.path.privacy,
            range_hint=self.path.range_hint,
            requires_user_action=self.path.requires_user_action,
            requires_admin=self.path.requires_admin,
            safety_state=self.path.safety_state,
            notes=self.path.notes,
        )

    def score(self, *, intent: object | None = None, peer: object | None = None) -> RouteScore:
        probe = self.probe()
        return score_probe(probe, intent=intent, peer=peer)

    async def prepare(
        self,
        *,
        peer: object | None = None,
        intent: object | None = None,
    ) -> PreparedRoute:
        return PreparedRoute(
            adapter_id=self.adapter_id,
            route_name=self.probe().route_name,
            metadata={
                "kind": self.kind,
                "probe_only": True,
                "notes": list(self.path.notes),
            },
        )


def score_probe(
    probe: AdapterProbe,
    *,
    intent: object | None = None,
    peer: object | None = None,
) -> RouteScore:
    """Score a route candidate using only truthful probe-level evidence."""

    if not probe.available:
        return RouteScore(
            adapter_id=probe.adapter_id,
            route_name=probe.route_name,
            score=0.0,
            estimated_bps=0.0,
            latency_ms=probe.latency_ms,
            reliability=0.0,
            privacy=probe.privacy,
            reason="adapter unavailable",
            usable_for_bulk=False,
            usable_for_control=False,
        )
    speed_score = min(1.0, max(0.0, probe.estimated_bps) / 1_000_000_000.0)
    latency = probe.latency_ms if probe.latency_ms is not None else _default_latency_ms(probe.kind)
    latency_score = 1.0 / (1.0 + max(0.0, latency) / 50.0)
    privacy_score = _PRIVACY_WEIGHT.get(probe.privacy, 0.5)
    friction = 0.22 if probe.requires_user_action else 0.0
    admin = 0.20 if probe.requires_admin else 0.0
    safety = 0.30 if probe.safety_state not in {"ok", "rx_only_until_safety_gate"} else 0.0
    bulk_weight = 1.0 if probe.bulk_capable else 0.45
    reliability = max(0.05, min(0.995, 1.0 - float(probe.loss)))
    score = (
        0.34 * speed_score * bulk_weight
        + 0.22 * latency_score
        + 0.20 * privacy_score
        + 0.16 * reliability
        + 0.08 * (1.0 if probe.control_capable else 0.0)
        - friction
        - admin
        - safety
    )
    return RouteScore(
        adapter_id=probe.adapter_id,
        route_name=probe.route_name,
        score=max(0.0, min(1.0, score)),
        estimated_bps=max(0.0, float(probe.estimated_bps)),
        latency_ms=latency,
        reliability=reliability,
        privacy=probe.privacy,
        reason=_score_reason(probe),
        usable_for_bulk=probe.available and probe.bulk_capable,
        usable_for_control=probe.available and probe.control_capable,
    )


def adapters_from_paths(paths: tuple[HardwarePath, ...] | list[HardwarePath]) -> tuple[StaticPathAdapter, ...]:
    return tuple(StaticPathAdapter(p) for p in paths)


def _default_latency_ms(kind: str) -> float:
    return {
        "loopback": 1.0,
        "lan": 6.0,
        "ethernet": 2.0,
        "wifi_direct": 7.0,
        "private_hotspot": 10.0,
        "webrtc": 70.0,
        "sealed_relay": 120.0,
        "ble_control": 45.0,
        "qr_control": 500.0,
        "audio_control": 700.0,
        "storage_courier": 10_000.0,
        "onefield": 250.0,
    }.get(kind, 100.0)


def _score_reason(probe: AdapterProbe) -> str:
    if probe.bulk_capable and probe.control_capable:
        return f"{probe.kind} can carry control and bulk data"
    if probe.control_capable:
        return f"{probe.kind} is control-plane only"
    return f"{probe.kind} is visible but not usable yet"

