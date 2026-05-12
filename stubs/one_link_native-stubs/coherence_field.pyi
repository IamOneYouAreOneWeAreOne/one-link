"""Type stubs for ``one_link_native.coherence_field`` (Phase E)."""

from typing import Any, Dict, List, Optional, Tuple

__version__: str
G_A_GALAXY_PLANCK: float


class GraphLaplacian:
    def __init__(self, n: int) -> None: ...

    def add_edge(self, i: int, j: int, weight: float) -> None: ...
    def node_count(self) -> int: ...
    def degree(self, i: int) -> float: ...


def solve_helmholtz(
    graph: GraphLaplacian,
    d: float,
    gamma: float,
    source: List[float],
    max_iters: int = ...,
    tolerance: float = ...,
) -> Dict[str, Any]: ...


def green_function(
    graph: GraphLaplacian,
    d: float,
    gamma: float,
    destination: int,
    sources: List[int],
    max_iters: int = ...,
    tolerance: float = ...,
) -> List[float]: ...


def be_rar(y: float) -> float: ...
def screening_length(d: float, gamma: float) -> Optional[float]: ...
def apparent_horizon_anchor(c_wire: float, h_swarm: float) -> Optional[float]: ...
def linear_source(density: List[float], weight: float) -> List[float]: ...
def identity_dual_source(
    density: List[float], flux: List[float], alpha: float, beta: float
) -> List[float]: ...
def support_phase_kernel(
    c_support: List[float], c0: float = ..., w_phase: float = ...
) -> List[float]: ...
def inject_fragility_events(
    source: List[float],
    events: List[Tuple[List[int], float]],
    coupling_strength: float,
) -> Tuple[List[float], List[float]]: ...
def prefetch_priorities(
    field: List[float],
    requester: int,
    holders: List[int],
    route_weight: float,
) -> List[Tuple[int, float, float]]: ...
def rotation_cadence_multiplier(
    field: List[float], baseline_bytes: int, mu_max: float, power: float
) -> List[Tuple[int, float, int]]: ...
def one_link_calibration() -> Dict[str, Any]: ...
def one_field_calibration() -> Dict[str, Any]: ...
def bio_mesh_calibration() -> Dict[str, Any]: ...
