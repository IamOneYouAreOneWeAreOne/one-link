"""Type stubs for one_link_native.proximity_pair (Phase F1.4)."""

from typing import List

AMPLIFIED_KEY_BYTES: int
OBSERVATION_BYTES_DEFAULT: int
GUARD_BAND_DEFAULT: float
SYNDROME_BLOCK_BITS_DEFAULT: int
CASCADE_PASSES_DEFAULT: int

def quantize_observations(
    observations: bytes,
    min_bytes: int = ...,
    guard_band: float = ...,
) -> bytes: ...
def block_syndrome(bits: bytes, block_bits: int = ...) -> bytes: ...
def reconcile_with_syndrome(
    my_bits: bytes, peer_syndrome: bytes, block_bits: int = ...
) -> bytes: ...
def multi_pass_syndromes(
    my_bits: bytes,
    block_bits: int = ...,
    passes: int = ...,
    permutation_seed: int = ...,
) -> List[bytes]: ...
def multi_pass_reconcile(
    my_bits: bytes,
    peer_syndromes: List[bytes],
    block_bits: int = ...,
    passes: int = ...,
    permutation_seed: int = ...,
) -> bytes: ...
def permutation_for_pass(
    seed: int, pass_idx: int, n: int
) -> List[int]: ...
def privacy_amplify(reconciled_bits: bytes, salt: bytes) -> bytes: ...
def derive_factor2_secret(
    my_observations: bytes,
    peer_syndrome: bytes,
    salt: bytes,
    min_bytes: int = ...,
    guard_band: float = ...,
    block_bits: int = ...,
) -> bytes: ...
