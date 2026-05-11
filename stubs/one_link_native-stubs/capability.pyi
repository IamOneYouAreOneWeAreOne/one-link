"""Type stubs for ``one_link_native.capability`` (ADR-0021)."""

from typing import Iterable

__version__: str
CAP_ID_LEN: int
ROOT_KEY_LEN: int
SIGNATURE_LEN: int


class Capability:
    @staticmethod
    def root(id: bytes, root_key: bytes) -> "Capability": ...
    @staticmethod
    def decode(bytes_: bytes) -> "Capability": ...

    def encode(self) -> bytes: ...
    def cap_id(self) -> bytes: ...
    def signature(self) -> bytes: ...
    def num_caveats(self) -> int: ...

    def attenuate_expires_at(self, ms: int) -> "Capability": ...
    def attenuate_peer(self, fp: bytes) -> "Capability": ...
    def attenuate_path_prefix(self, prefix: str) -> "Capability": ...
    def attenuate_operation_in(self, ops: Iterable[str]) -> "Capability": ...
    def attenuate_audit_tag(self, tag: str) -> "Capability": ...

    def verify(
        self,
        root_key: bytes,
        now_ms: int | None = ...,
        peer: bytes | None = ...,
        path: str | None = ...,
        operation: str | None = ...,
    ) -> None: ...

    def accepts(
        self,
        root_key: bytes,
        now_ms: int | None = ...,
        peer: bytes | None = ...,
        path: str | None = ...,
        operation: str | None = ...,
    ) -> bool: ...
