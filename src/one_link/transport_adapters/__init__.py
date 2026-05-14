"""Transport adapter contracts for the Universal Comms Fabric."""

from .base import (
    AdapterProbe,
    PreparedRoute,
    RepairResult,
    RouteScore,
    SessionStats,
    TransportAdapter,
    TransportSession,
)
from .onefield import OneFieldLoopbackAdapter, OneFieldLoopbackSession

__all__ = [
    "AdapterProbe",
    "PreparedRoute",
    "RepairResult",
    "RouteScore",
    "SessionStats",
    "TransportAdapter",
    "TransportSession",
    "OneFieldLoopbackAdapter",
    "OneFieldLoopbackSession",
]
