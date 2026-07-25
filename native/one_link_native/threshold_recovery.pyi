"""Type stubs for one_link_native.threshold_recovery (Phase F1.1)."""

from typing import List, Self, final

MAX_SECRET_BYTES: int

@final
class FieldWitness:
    """Public commitment to the coherence-field state at mint time."""

    def __new__(
        cls,
        field_seed: bytes,
        holder_scores: List[float],
        epoch_ns: int,
    ) -> Self: ...

    @staticmethod
    def placeholder(n: int) -> "FieldWitness": ...

    def is_placeholder(self) -> bool: ...
    def field_seed(self) -> bytes: ...
    def holder_scores(self) -> List[float]: ...
    def epoch_ns(self) -> int: ...
    def __repr__(self) -> str: ...

# Plain Shamir.
def shamir_split(
    secret: bytes, k: int, n: int, seed: int
) -> List[bytes]: ...
def shamir_split_secure(secret: bytes, k: int, n: int) -> List[bytes]: ...
def shamir_reconstruct(
    xs: bytes | List[int], streams: List[bytes], k: int
) -> bytes: ...
def shamir_max_participants() -> int: ...
def shamir_params_valid(k: int, n: int) -> bool: ...

# Field-bound (alien-tech) layer.
def field_bound_split(
    secret: bytes, k: int, n: int, seed: int, witness: FieldWitness
) -> List[bytes]: ...
def field_bound_split_secure(
    secret: bytes, k: int, n: int, witness: FieldWitness
) -> List[bytes]: ...
def field_bound_reconstruct(
    xs: bytes | List[int],
    streams: List[bytes],
    share_indices: List[int],
    k: int,
    witness: FieldWitness,
) -> bytes: ...

PyFieldWitness = FieldWitness
field_bound_split_py = field_bound_split
field_bound_split_secure_py = field_bound_split_secure
field_bound_reconstruct_py = field_bound_reconstruct
