"""Types for :mod:`one_link_native.store`."""

from typing import Self, TypedDict, final, type_check_only

CHUNK_RECORD_HEADER_LEN: int
MANIFEST_RECORD_HEADER_LEN: int
STRIPE_DESCRIPTOR_LEN: int
MAX_CHUNK_CIPHERTEXT_LEN: int
MAX_MANIFEST_BODY_LEN: int

@type_check_only
class StoreStats(TypedDict):
    indexed_chunks: int
    manifest_records: int
    bytes_scanned_at_replay: int
    files_truncated: int
    orphaned_manifest_records: int

@final
class StripeDescriptor:
    def __new__(
        cls,
        stripe_id_lo64: int = ...,
        role: str = ...,
        stripe_index: int = ...,
        stripe_k: int = ...,
        stripe_m: int = ...,
        cohort_id_lo64: int = ...,
    ) -> Self: ...
    @property
    def stripe_id_lo64(self) -> int: ...
    @property
    def role(self) -> str: ...
    @property
    def stripe_index(self) -> int: ...
    @property
    def stripe_k(self) -> int: ...
    @property
    def stripe_m(self) -> int: ...
    @property
    def cohort_id_lo64(self) -> int: ...

@final
class ChunkLocation:
    @property
    def file_id(self) -> int: ...
    @property
    def wal_offset(self) -> int: ...
    @property
    def length_plaintext(self) -> int: ...
    @property
    def length_ciphertext(self) -> int: ...
    @property
    def ratchet_key_id(self) -> bytes: ...
    @property
    def stripe(self) -> StripeDescriptor: ...

@final
class ReadChunk:
    @property
    def kind(self) -> str: ...
    @property
    def address_kind(self) -> str: ...
    @property
    def aead_kind(self) -> str: ...
    @property
    def compressed(self) -> bool: ...
    @property
    def format_aware(self) -> bool: ...
    @property
    def length_plaintext(self) -> int: ...
    @property
    def chunk_id(self) -> bytes: ...
    @property
    def ratchet_key_id(self) -> bytes: ...
    @property
    def ciphertext(self) -> bytes: ...
    @property
    def stripe(self) -> StripeDescriptor: ...

@final
class ChunkStore:
    def append_chunk(
        self,
        record_kind: str,
        address_kind: str,
        aead_kind: str,
        chunk_id: bytes,
        ratchet_key_id: bytes,
        length_plaintext: int,
        ciphertext: bytes,
        compressed: bool = ...,
        format_aware: bool = ...,
        stripe: StripeDescriptor | None = ...,
    ) -> int: ...
    def append_manifest(
        self,
        record_kind: str,
        hlc_timestamp: int,
        actor_id: bytes,
        body: bytes,
        flags: int = ...,
        chunk_log_anchor: int = ...,
    ) -> None: ...
    def flush(self) -> None: ...
    def has_chunk(self, chunk_id: bytes) -> bool: ...
    def locate_chunk(self, chunk_id: bytes) -> ChunkLocation | None: ...
    def read_chunk(self, chunk_id: bytes) -> ReadChunk: ...
    def stats(self) -> StoreStats: ...
    def close(self) -> None: ...

def open_store(root: str) -> ChunkStore: ...
