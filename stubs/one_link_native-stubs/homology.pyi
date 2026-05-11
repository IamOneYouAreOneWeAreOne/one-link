"""Type stubs for ``one_link_native.homology`` (ADR-0033 Phase D #4)."""

from typing import Dict, List, Tuple


class ComponentReport:
    n_components: int
    sizes: List[int]
    singletons: List[str]


class FragilityScore:
    chunk_id: str
    n_peers_holding: int
    is_bridge: bool
    score: float


def components_of(
    nodes: List[str], edges: List[Tuple[str, str]]
) -> ComponentReport: ...


def fragility_score(
    nodes: List[str],
    edges: List[Tuple[str, str]],
    holders: Dict[str, int],
) -> Tuple[List[FragilityScore], List[str]]: ...
