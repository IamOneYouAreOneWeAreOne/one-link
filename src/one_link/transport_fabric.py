"""Universal Comms Fabric route spine.

This module connects the new hardware/adapter world to One Link's existing
AdaptiveTransferBrain. It does not replace the live daemon path yet; it
produces deterministic route truth that the daemon can opt into.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Iterable, Mapping

from .hardware_inventory import HardwareInventory, collect_hardware_inventory
from .transfer_brain import (
    MeshNodeSignal,
    TransferBrainDecision,
    TransferRouteObservation,
    decision_from_observations,
)
from .transport_activation import (
    ActivationIntent,
    ActivationPlan,
    activation_plans_for,
)
from .transport_adapters.base import AdapterProbe, RouteScore, TransportAdapter
from .transport_adapters.onefield import onefield_adapters_from_paths
from .transport_adapters.route_memory import adapters_from_route_candidates
from .transport_adapters.static import adapters_from_paths, score_probe


@dataclass(frozen=True)
class FabricPlan:
    probes: tuple[AdapterProbe, ...]
    scores: tuple[RouteScore, ...]
    activation: tuple[ActivationPlan, ...]
    observations: tuple[TransferRouteObservation, ...]
    transfer_decision: TransferBrainDecision
    timing_ms: Mapping[str, object] | None = None

    @property
    def best_score(self) -> RouteScore | None:
        return self.scores[0] if self.scores else None

    @property
    def best_activation(self) -> ActivationPlan | None:
        return self.activation[0] if self.activation else None

    def route_truth(self) -> dict[str, object]:
        best = self.best_score
        activation = self.best_activation
        decision = self.transfer_decision.to_dict()
        return {
            "route": best.route_name if best else decision.get("route"),
            "adapter_id": best.adapter_id if best else None,
            "kind": _user_route_kind(best) if best else "Waiting for device",
            "state": _state_from_decision(decision),
            "estimated_bps": best.estimated_bps if best else 0.0,
            "latency_ms": best.latency_ms if best else None,
            "reliability": best.reliability if best else 0.0,
            "privacy": best.privacy if best else "unknown",
            "reason": best.reason if best else "no path currently available",
            "activation_state": activation.state.value if activation else "unavailable",
            "activation_risk": activation.risk.value if activation else "low",
            "activation_next_action": activation.next_action if activation else "wait_for_path",
            "automatic": bool(activation and activation.automatic),
            "needs_user": bool(activation and activation.needs_user),
            "safeguards": list(activation.safeguards) if activation else [],
            "transfer": decision,
        }

    def to_dict(self) -> dict[str, object]:
        return {
            "probes": [p.to_dict() for p in self.probes],
            "scores": [s.to_dict() for s in self.scores],
            "activation": [a.to_dict() for a in self.activation],
            "observations": [
                {
                    "route": o.route,
                    "ok": o.ok,
                    "latency_ms": o.latency_ms,
                    "bandwidth_bps": o.bandwidth_bps,
                    "energy_cost": o.energy_cost,
                }
                for o in self.observations
            ],
            "route_truth": self.route_truth(),
            "performance": dict(self.timing_ms or {}),
        }


class UniversalCommsFabric:
    """Probe adapters and feed route evidence into the transfer brain."""

    def __init__(self, adapters: Iterable[TransportAdapter]) -> None:
        self._adapters = tuple(adapters)

    @classmethod
    def from_inventory(cls, inventory: HardwareInventory | None = None) -> "UniversalCommsFabric":
        inventory = inventory or collect_hardware_inventory()
        return cls(_adapters_from_inventory_paths(inventory.paths))

    @classmethod
    def from_inventory_and_candidates(
        cls,
        inventory: HardwareInventory | None = None,
        candidates: Iterable[Mapping[str, object]] | None = None,
    ) -> "UniversalCommsFabric":
        inventory = inventory or collect_hardware_inventory()
        remembered = adapters_from_route_candidates(tuple(candidates or ()))
        return cls((*_adapters_from_inventory_paths(inventory.paths), *remembered))

    def probes(self) -> tuple[AdapterProbe, ...]:
        out: list[AdapterProbe] = []
        for adapter in self._adapters:
            try:
                out.append(adapter.probe())
            except Exception as exc:
                adapter_id = getattr(adapter, "adapter_id", adapter.__class__.__name__)
                kind = getattr(adapter, "kind", "unknown")
                out.append(AdapterProbe(
                    adapter_id=str(adapter_id),
                    kind=str(kind),
                    available=False,
                    notes=(f"probe failed: {exc}",),
                ))
        return tuple(out)

    def scores(
        self,
        *,
        intent: object | None = None,
        peer: object | None = None,
        probes: Iterable[AdapterProbe] | None = None,
    ) -> tuple[RouteScore, ...]:
        scored: list[RouteScore] = []
        probes_by_id = {p.adapter_id: p for p in tuple(probes or ())}
        for adapter in self._adapters:
            try:
                adapter_id = str(getattr(adapter, "adapter_id", ""))
                probe = probes_by_id.get(adapter_id)
                score_from_probe = getattr(adapter, "score_from_probe", None)
                if probe is not None and callable(score_from_probe):
                    scored.append(score_from_probe(probe, intent=intent, peer=peer))
                else:
                    scored.append(adapter.score(intent=intent, peer=peer))
            except Exception:
                try:
                    probe = probes_by_id.get(str(getattr(adapter, "adapter_id", ""))) or adapter.probe()
                    scored.append(score_probe(probe, intent=intent, peer=peer))
                except Exception as exc:
                    adapter_id = getattr(adapter, "adapter_id", adapter.__class__.__name__)
                    kind = getattr(adapter, "kind", "unknown")
                    scored.append(RouteScore(
                        adapter_id=str(adapter_id),
                        route_name=str(kind),
                        score=0.0,
                        estimated_bps=0.0,
                        latency_ms=None,
                        reliability=0.0,
                        privacy="unknown",
                        reason=f"score failed: {exc}",
                    ))
        return tuple(sorted(
            scored,
            key=lambda s: (
                -s.score,
                -s.estimated_bps,
                s.latency_ms if s.latency_ms is not None else 1_000_000.0,
                s.adapter_id,
            ),
        ))

    def plan(
        self,
        *,
        size_bytes: int,
        supports_cdc: bool,
        supports_swarm: bool = False,
        prior_hit_rate: float | None = None,
        mesh_nodes: Iterable[MeshNodeSignal] | None = None,
        speeds: Mapping[str, float] | None = None,
        activation_intent: ActivationIntent | None = None,
        intent: object | None = None,
        peer: object | None = None,
    ) -> FabricPlan:
        t0 = time.perf_counter_ns()
        probes = self.probes()
        t_probes = time.perf_counter_ns()
        scores = self.scores(intent=intent, peer=peer, probes=probes)
        t_scores = time.perf_counter_ns()
        activation = activation_plans_for(
            scores,
            probes,
            intent=activation_intent,
            peer=peer,
        )
        t_activation = time.perf_counter_ns()
        observations = observations_from_scores(scores)
        t_observations = time.perf_counter_ns()
        live_bulk_routes = tuple(dict.fromkeys(
            s.route_name
            for s in scores
            if s.score > 0.0 and s.usable_for_bulk and s.route_name not in {"courier"}
        ))
        fallback_routes = tuple(dict.fromkeys(s.route_name for s in scores if s.score > 0.0))
        routes = live_bulk_routes or fallback_routes
        decision = decision_from_observations(
            size_bytes=size_bytes,
            supports_cdc=supports_cdc,
            supports_swarm=supports_swarm,
            prior_hit_rate=prior_hit_rate,
            observations=observations,
            routes=routes or ("offline",),
            mesh_nodes=mesh_nodes,
            speeds=speeds,
        )
        t_decision = time.perf_counter_ns()
        timing_ms = {
            "adapter_count": float(len(self._adapters)),
            "probe_ms": _elapsed_ms(t0, t_probes),
            "score_ms": _elapsed_ms(t_probes, t_scores),
            "activation_ms": _elapsed_ms(t_scores, t_activation),
            "observation_ms": _elapsed_ms(t_activation, t_observations),
            "decision_ms": _elapsed_ms(t_observations, t_decision),
            "total_ms": _elapsed_ms(t0, t_decision),
        }
        timing_ms["health"] = _timing_health(timing_ms["total_ms"], len(self._adapters))
        return FabricPlan(
            probes=probes,
            scores=scores,
            activation=activation,
            observations=observations,
            transfer_decision=decision,
            timing_ms=timing_ms,
        )


def observations_from_scores(scores: Iterable[RouteScore]) -> tuple[TransferRouteObservation, ...]:
    out: list[TransferRouteObservation] = []
    for score in scores:
        if score.score <= 0.0:
            out.append(TransferRouteObservation(
                route=score.route_name,
                ok=False,
                latency_ms=score.latency_ms,
                bandwidth_bps=0.0,
                energy_cost=2.0,
            ))
            continue
        energy = 1.0
        if score.privacy in {"direct_or_relayed_internet", "experimental_hardware"}:
            energy += 0.35
        if not score.usable_for_bulk:
            energy += 0.45
        out.append(TransferRouteObservation(
            route=score.route_name,
            ok=True,
            latency_ms=score.latency_ms,
            bandwidth_bps=score.estimated_bps,
            energy_cost=energy,
        ))
    return tuple(out)


def _adapters_from_inventory_paths(paths: tuple | list) -> tuple[TransportAdapter, ...]:
    static_paths = tuple(p for p in paths if getattr(p, "kind", "") != "onefield")
    onefield = onefield_adapters_from_paths(paths)
    return (*adapters_from_paths(static_paths), *onefield)


def _user_route_kind(score: RouteScore | None) -> str:
    if score is None:
        return "Waiting for device"
    return {
        "lan": "Local network",
        "loopback": "This device",
        "wifi_direct": "Wi-Fi direct",
        "private_hotspot": "Private hotspot",
        "webrtc": "Internet direct",
        "relay": "Relay fallback",
        "courier": "Offline courier",
        "onefield": "OneField hardware",
        "ble_control": "Bluetooth control",
    }.get(score.route_name, score.route_name.replace("_", " ").title())


def _state_from_decision(decision: Mapping[str, object]) -> str:
    action = str(decision.get("action") or "")
    health = str(decision.get("health") or "")
    if action == "send" and health == "healthy":
        return "Sending"
    if "repair" in action or health == "repair":
        return "Repairing route"
    if action == "collect_more_route_evidence":
        return "Measuring route"
    return "Ready"


def _elapsed_ms(start_ns: int, end_ns: int) -> float:
    return round(max(0, end_ns - start_ns) / 1_000_000.0, 3)


def _timing_health(total_ms: float, adapter_count: int) -> str:
    # A route brain that scans hundreds of candidates should still feel
    # instant. Scale the budget gently with adapter count so large trusted
    # meshes are judged fairly without hiding pathological slowness.
    budget_ms = 8.0 + min(92.0, max(0, adapter_count) * 0.18)
    if total_ms <= budget_ms:
        return "fast"
    if total_ms <= budget_ms * 2.5:
        return "warm"
    return "slow"
