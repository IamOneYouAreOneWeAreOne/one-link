"""Types for :mod:`one_link_native.erasure`."""

import builtins

from typing import Self, final
from typing_extensions import Buffer

__version__: str
MAX_SHARD_BYTES: int
MAX_STRIPE_PLAINTEXT_BYTES: int

@final
class StripeParams:
    EPHEMERAL: StripeParams
    STANDARD: StripeParams
    ARCHIVAL: StripeParams
    def __new__(cls, k: int, m: int) -> Self: ...
    @property
    def k(self) -> int: ...
    @property
    def m(self) -> int: ...
    def __repr__(self) -> str: ...

@final
class Shard:
    def __new__(
        cls,
        stripe_id: builtins.bytes,
        index: int,
        role: str,
        plaintext_len: int,
        bytes: builtins.bytes,
    ) -> Self: ...
    @property
    def bytes(self) -> builtins.bytes: ...
    @property
    def role(self) -> str: ...
    @property
    def index(self) -> int: ...
    @property
    def plaintext_len(self) -> int: ...
    @property
    def stripe_id(self) -> builtins.bytes: ...
    def __repr__(self) -> str: ...

def encode_stripe(plaintext: bytes, params: StripeParams) -> list[Shard]: ...
def decode_stripe(params: StripeParams, present: list[Shard | None]) -> bytes: ...
def stripe_id(plaintext: Buffer, params: StripeParams) -> bytes: ...
