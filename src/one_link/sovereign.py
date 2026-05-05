"""Sovereign-network doctrine and capability surface.

The point of One Link is not just "chat on a LAN." It is a local-first,
people-owned network stack whose advanced pieces stay inspectable, optional,
and free from mandatory third-party servers.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class TransportProfile:
    name: str
    status: str
    serverless: bool
    purpose: str
    source: str


PRINCIPLES = (
    "no accounts",
    "no mandatory cloud",
    "no telemetry",
    "local-first identity",
    "mutual authentication",
    "end-to-end encryption",
    "content-addressed data",
    "eventual consistency",
    "open-source distribution",
)


TRANSPORTS = (
    TransportProfile(
        name="lan_tcp_mdns",
        status="active",
        serverless=True,
        purpose="zero-config local discovery plus encrypted peer TCP",
        source="One Link",
    ),
    TransportProfile(
        name="content_defined_dedup",
        status="implemented_primitive",
        serverless=True,
        purpose="skip chunks the receiver already has",
        source="OneField Mesh transport/cdc_dedup.cl",
    ),
    TransportProfile(
        name="merkle_drift_sync",
        status="implemented_primitive",
        serverless=True,
        purpose="compare large manifests with one root hash, then only divergent leaves",
        source="OneField Mesh sync/merkle_drift_sync.cl",
    ),
    TransportProfile(
        name="vector_clock_crdt",
        status="active",
        serverless=True,
        purpose="merge folder state without a central authority",
        source="coherence_lang bootstrap runtime/crdt.py",
    ),
    TransportProfile(
        name="session_typed_protocols",
        status="design_import",
        serverless=True,
        purpose="make wire conversations explicit and mechanically auditable",
        source="coherence_lang bootstrap runtime/sessions.py",
    ),
    TransportProfile(
        name="rf_audio_quic_future",
        status="roadmap",
        serverless=True,
        purpose="pluggable transports when LAN TCP is not enough",
        source="OneField Mesh transport and RF world-model doctrine",
    ),
)


def doctrine() -> dict:
    return {
        "mission": (
            "A free, inspectable, serverless P2P network for ordinary people: "
            "simple at the surface, advanced underneath, and not dependent on "
            "big-company infrastructure."
        ),
        "principles": list(PRINCIPLES),
        "capabilities": [asdict(t) for t in TRANSPORTS],
        "privacy_guarantees": {
            "external_telemetry": False,
            "mandatory_relay": False,
            "account_required": False,
            "local_ui_only": True,
        },
    }
