"""Types for :mod:`one_link_native.radio_batcher`."""

from typing import Self, TypedDict, final, type_check_only

__version__: str
DEFAULT_DRX_WINDOW_MS: int
DEFAULT_MAX_QUEUE_SIZE: int
DEFAULT_MAX_AGE_MS: int
MAX_QUEUE_SIZE_LIMIT: int
MAX_ENTRY_PAYLOAD_BYTES: int
DEFAULT_MAX_QUEUE_BYTES: int
MAX_QUEUE_BYTES_LIMIT: int

@type_check_only
class QueueEntry(TypedDict):
    peer_fp: str
    payload: bytes
    priority: str
    enqueued_at_ms: int

@type_check_only
class DrainOutcome(TypedDict):
    drained: int
    remaining: int
    force_drained_due_to_age: bool

@type_check_only
class BatcherStats(TypedDict):
    enqueued: int
    urgent_bypasses: int
    batches_emitted: int
    messages_batched: int
    total_wait_ms: int

@final
class RadioBatcher:
    def __new__(
        cls,
        drx_window_ms: int = ...,
        max_queue_size: int = ...,
        max_age_ms: int = ...,
        max_queue_bytes: int = ...,
    ) -> Self: ...
    def enqueue(self, peer_fp: str, payload: bytes, priority: str, now_ms: int) -> None: ...
    def drain(self, now_ms: int) -> tuple[list[QueueEntry], DrainOutcome]: ...
    def drain_all(self) -> list[QueueEntry]: ...
    def set_radio_state(self, state: str) -> None: ...
    def radio_state(self) -> str: ...
    @property
    def len(self) -> int: ...
    @property
    def is_empty(self) -> bool: ...
    @property
    def queued_bytes(self) -> int: ...
    @property
    def max_queue_bytes(self) -> int: ...
    @property
    def drx_window_ms(self) -> int: ...
    def stats(self) -> BatcherStats: ...
    def __repr__(self) -> str: ...
