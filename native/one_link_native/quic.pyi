"""Types for :mod:`one_link_native.quic`."""

from collections.abc import Callable
from typing import Self, TypeAlias, final

ALPN: bytes
MAX_BULK_FRAME_BYTES: int
MAX_CONTROL_FRAME_BYTES: int
MAX_PENDING_RESPONSE_STREAMS: int
MAX_NATIVE_BATCH_ITEMS: int
MAX_NATIVE_BATCH_BYTES: int
FRAME_CHUNK_REQUEST: int
FRAME_CHUNK_RESPONSE: int
FRAME_CHUNK_NOT_FOUND: int
FRAME_MANIFEST_SYNC: int
FRAME_MANIFEST_RECORD: int
FRAME_MANIFEST_SYNC_END: int
FRAME_BLOOM_FILTER: int
FRAME_MISSING_CHUNKS: int
FRAME_FOUNTAIN_BURST: int
FRAME_FOUNTAIN_ACK: int
FRAME_FOUNTAIN_REQUEST: int
FRAME_SCOPED_BLOOM_FILTER: int
FRAME_CAPABILITY_CHECK: int
FRAME_CAPABILITY_ACK: int
FRAME_PING: int
FRAME_PONG: int
FRAME_PROTO_ERROR: int
FRAME_CLOSE: int

Frame: TypeAlias = tuple[int, bytes]
InboundFrame: TypeAlias = tuple[int, int, bytes]
Response: TypeAlias = tuple[int, int, bytes]

@final
class Identity:
    @staticmethod
    def generate() -> Identity: ...
    @staticmethod
    def from_pkcs8_pem(pem: str) -> Identity: ...
    @property
    def fingerprint(self) -> bytes: ...
    @property
    def fingerprint_hex(self) -> str: ...
    @property
    def public_key_bytes(self) -> bytes: ...
    def to_pkcs8_pem(self) -> str: ...
    def __repr__(self) -> str: ...

@final
class EndpointConfig:
    def __new__(
        cls,
        bind: str | None = ...,
        idle_timeout_ms: int | None = ...,
        keepalive_interval_ms: int | None = ...,
        max_concurrent_bidi_streams: int | None = ...,
        stream_receive_window_bytes: int | None = ...,
        send_window_bytes: int | None = ...,
        send_fairness: bool | None = ...,
    ) -> Self: ...
    @property
    def bind(self) -> str: ...
    @property
    def idle_timeout_ms(self) -> int: ...
    @property
    def keepalive_interval_ms(self) -> int: ...
    @property
    def max_concurrent_bidi_streams(self) -> int: ...
    @property
    def stream_receive_window_bytes(self) -> int: ...
    @property
    def send_window_bytes(self) -> int: ...
    @property
    def send_fairness(self) -> bool: ...
    def __repr__(self) -> str: ...

@final
class Endpoint:
    @staticmethod
    def server(
        identity: Identity,
        is_paired_callback: Callable[[bytes], bool],
        config: EndpointConfig,
    ) -> Endpoint: ...
    @staticmethod
    def client(identity: Identity, config: EndpointConfig) -> Endpoint: ...
    @property
    def local_addr(self) -> str: ...
    @property
    def fingerprint(self) -> bytes: ...
    def connect_blocking(
        self, addr: str, expected_fingerprint: bytes, timeout_ms: int
    ) -> Connection: ...
    def accept_blocking(self, timeout_ms: int) -> Connection | None: ...
    def close(self, error_code: int, reason: bytes) -> None: ...

@final
class InboundStream: ...

@final
class Connection:
    @property
    def remote_address(self) -> str: ...
    def peer_fingerprint(self) -> bytes | None: ...
    def send_frame_round_trip(self, frame_kind: int, payload: bytes) -> Frame: ...
    def send_frame_round_trips(self, frame_kind: int, payloads: list[bytes]) -> list[Frame]: ...
    def send_frame_round_trips_parallel(
        self, frame_kind: int, payloads: list[bytes], max_in_flight: int | None = ...
    ) -> list[Frame]: ...
    def send_frame_stream_round_trips(
        self, frame_kind: int, payloads: list[bytes]
    ) -> list[Frame]: ...
    def send_frame_stream_round_trips_parallel(
        self, frame_kind: int, payloads: list[bytes], lanes: int | None = ...
    ) -> list[Frame]: ...
    def send_frame_stream_round_trips_count(
        self, frame_kind: int, payloads: list[bytes], expected_response_kind: int
    ) -> int: ...
    def send_frame_stream_round_trips_count_parallel(
        self,
        frame_kind: int,
        payloads: list[bytes],
        expected_response_kind: int,
        lanes: int | None = ...,
    ) -> int: ...
    def recv_frame_blocking(self, timeout_ms: int) -> InboundFrame | None: ...
    def recv_frames_blocking(
        self, max_frames: int, timeout_ms: int, idle_timeout_us: int | None = ...
    ) -> list[InboundFrame]: ...
    def send_response_on(self, stream_id: int, frame_kind: int, payload: bytes) -> None: ...
    def send_responses_on(
        self, responses: list[Response], max_in_flight: int | None = ...
    ) -> None: ...
    def serve_fixed_responses_blocking(
        self,
        requests: int,
        response_kind: int,
        payload: bytes,
        max_in_flight: int | None = ...,
    ) -> int: ...
    def serve_fixed_stream_responses_blocking(
        self,
        streams: int,
        requests_per_stream: int,
        response_kind: int,
        payload: bytes,
        max_in_flight: int | None = ...,
    ) -> int: ...
    @property
    def rtt_ms(self) -> int: ...
    def close(self, error_code: int, reason: bytes) -> None: ...
