"""Type stubs for ``one_link_native.prefetch`` (ADR-0033 Phase D #3)."""

from typing import List, Self, Tuple, final

__version__: str
MAX_CO_OCCURRENCE_GAP_MS: int


@final
class Predictor:
    def __new__(
        cls, half_life_ms: int = ..., decay_factor: float = ...
    ) -> Self: ...

    half_life_ms: int
    decay_factor: float

    def observe(self, peer: bytes, file_id: bytes, t_ms: int) -> None: ...
    def predict_top_n(self, peer: bytes, n: int) -> List[Tuple[bytes, float]]: ...
    def decay_counts(self) -> None: ...
    def transfer_prior_from(
        self, source_peer: bytes, target_peer: bytes, weight: float
    ) -> None: ...
    def storage_entries(self) -> int: ...
