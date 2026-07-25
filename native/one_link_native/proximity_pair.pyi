"""Type stubs for one_link_native.proximity_pair (Phase F1.4)."""

from typing import List

AMPLIFIED_KEY_BYTES: int
OBSERVATION_BYTES_DEFAULT: int
GUARD_BAND_DEFAULT: float
SYNDROME_BLOCK_BITS_DEFAULT: int
CASCADE_PASSES_DEFAULT: int
HAMMING_CODEWORD_BITS: int
HAMMING_DATA_BITS: int
HAMMING_PARITY_BITS: int

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
def permutation_for_pass(seed: int, pass_idx: int, n: int) -> List[int]: ...
def hamming_parity(bits: bytes) -> bytes: ...
def hamming_reconcile(my_bits: bytes, peer_parity: bytes) -> bytes: ...
def privacy_amplify(reconciled_bits: bytes, salt: bytes) -> bytes: ...
def derive_unconfirmed_candidate(
    my_observations: bytes,
    peer_syndrome: bytes,
    salt: bytes,
    min_bytes: int = ...,
    guard_band: float = ...,
    block_bits: int = ...,
) -> bytes: ...

py_quantize_observations = quantize_observations
py_block_syndrome = block_syndrome
py_reconcile_with_syndrome = reconcile_with_syndrome
py_multi_pass_syndromes = multi_pass_syndromes
py_multi_pass_reconcile = multi_pass_reconcile
py_permutation_for_pass = permutation_for_pass
py_hamming_parity = hamming_parity
py_hamming_reconcile = hamming_reconcile
py_privacy_amplify = privacy_amplify
py_derive_unconfirmed_candidate = derive_unconfirmed_candidate
