"""Type stubs for one_link_native.onion (Phase F3)."""

from typing import List, Tuple

MAX_HOPS: int
MAX_USER_PAYLOAD: int
HOP_ID_LEN: int

def build_onion(
    circuit: List[Tuple[bytes, bytes]], payload: bytes
) -> bytes: ...
def peel_one_layer(
    relay_static_sk: bytes, packet_bytes: bytes
) -> Tuple[str, bytes, bytes]: ...
def derive_pubkey(static_sk: bytes) -> bytes: ...
