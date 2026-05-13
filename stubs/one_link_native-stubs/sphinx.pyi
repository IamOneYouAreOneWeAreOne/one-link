"""Type stubs for one_link_native.sphinx (Phase F3.5 Sphinx Coherence)."""

from typing import List, Optional, Tuple

HOP_ID_LEN: int
MAX_HOPS: int
SPHINX_MAX_USER_PAYLOAD: int
SPHINX_PACKET_LEN: int
PQ_SPHINX_PACKET_LEN: int
ML_KEM_CT_LEN: int
ML_KEM_EK_LEN: int

# Standard Sphinx (Ristretto255 alpha blinding).
def generate_keypair() -> Tuple[bytes, bytes]: ...
def derive_pubkey_from_scalar(sk: bytes) -> bytes: ...
def build_sphinx(
    eph_sk: bytes,
    circuit: List[Tuple[bytes, bytes]],
    payload: bytes,
) -> bytes: ...
def peel_sphinx(
    relay_sk: bytes, packet: bytes
) -> Tuple[str, bytes, bytes]: ...

# PQ-hybrid Sphinx (ML-KEM-768 at entry).
def generate_pq_keypair() -> Tuple[bytes, bytes]: ...
def build_pq_sphinx(
    eph_sk: bytes,
    circuit: List[Tuple[bytes, bytes, Optional[bytes]]],
    payload: bytes,
) -> bytes: ...
def peel_pq_sphinx_entry(
    relay_x_sk: bytes, relay_pq_dk: bytes, packet: bytes
) -> Tuple[str, bytes, bytes]: ...
def peel_pq_sphinx_intermediate(
    relay_x_sk: bytes, packet: bytes
) -> Tuple[str, bytes, bytes]: ...
