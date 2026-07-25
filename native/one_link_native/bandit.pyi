"""Type stubs for ``one_link_native.bandit`` (ADR-0019)."""

from typing import List, Self, Tuple, final

__version__: str
MAX_ARMS: int
__all__: list[str]


@final
class Bandit:
    def __new__(cls, n_arms: int, seed: int = ...) -> Self: ...

    n_arms: int

    def select(self) -> int: ...
    def update(self, arm_idx: int, reward: float) -> None: ...
    def best_arm(self) -> int: ...
    def arms(self) -> List[Tuple[float, float]]: ...
    def reseed(self, seed: int) -> None: ...
