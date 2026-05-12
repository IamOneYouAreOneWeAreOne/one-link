"""Adapter for the Coherence Mesh F2 pair-by-QR Factor-1 trust
primitive (``ol_pair_qr`` via ``one_link_native``).

Per COHERENCE_MESH_PLAN.md Phase F2 — in-person pair-by-QR trust
establishment. Two devices that have never met derive a shared
chain key by exchanging an Ed25519-signed QR code + a network
response, then comparing a short authentication string (SAS) out
of band. No third-party server is trusted at any point.

Typical daemon usage:

.. code-block:: python

    from one_link import pair_qr_native as pq

    # Inviter side — generate QR
    inviter = pq.Inviter(id_seed=master_seed,
                         expiry_unix=int(time.time()) + 300,
                         scope=b"contact:josh")
    qr_bytes = inviter.invite_bytes()
    qr_png = qrcode_layer.render(qr_bytes)

    # Scanner side — read QR, build response
    scanner, response_bytes = pq.Scanner.scan(
        id_seed=master_seed,
        invite_bytes=scanned_qr_payload,
        now_unix=int(time.time()),
    )
    # Send response_bytes back to inviter over fresh network channel

    # Inviter side — receive response, display SAS for user
    sas_inviter = inviter.receive_response(response_bytes)
    print(f"Read out loud: {sas_inviter}")

    # Scanner side — also display SAS
    sas_scanner = scanner.sas()  # same value when honest
    print(f"Should match: {sas_scanner}")

    # User confirms SAS verbally → both call confirm
    confirm_bytes, chain_key = inviter.confirm()
    chain_key_scanner = scanner.receive_confirm(confirm_bytes)
    assert chain_key == chain_key_scanner  # byte-identical

    # Optional Factor-2 channel-reciprocity mix-in (alongside
    # ol_proximity_pair) for remote-relay-resistance:
    # confirm_bytes, chain_key = inviter.confirm_with_factor2(f2_key)
    # chain_key_scanner = scanner.receive_confirm_with_factor2(
    #     confirm_bytes, f2_key)
"""

from __future__ import annotations

import logging
from typing import Optional, Tuple

log = logging.getLogger(__name__)

try:
    from one_link_native import pair_qr as _native_pq  # type: ignore[import-not-found,attr-defined]

    HAS_NATIVE: bool = True
    SAS_WORD_COUNT: int = _native_pq.SAS_WORD_COUNT
    SAS_BITS: int = _native_pq.SAS_BITS
    CHAIN_KEY_LEN: int = _native_pq.CHAIN_KEY_LEN
    INVITE_NONCE_LEN: int = _native_pq.INVITE_NONCE_LEN
    INVITE_MAX_BYTES: int = _native_pq.INVITE_MAX_BYTES
    INVITE_VERSION: int = _native_pq.INVITE_VERSION
except ImportError as exc:
    HAS_NATIVE = False
    _native_pq = None  # type: ignore[assignment]
    SAS_WORD_COUNT = 5
    SAS_BITS = 30
    CHAIN_KEY_LEN = 32
    INVITE_NONCE_LEN = 32
    INVITE_MAX_BYTES = 512
    INVITE_VERSION = 1
    log.info(
        "one_link_native.pair_qr not installed (%s); pair-by-QR "
        "Factor-1 trust unavailable. Build via "
        "`cd native && maturin develop --release`.",
        exc,
    )


class NativeMissingError(RuntimeError):
    """Raised when the native pair_qr surface is not available."""


def _require_native() -> None:
    if not HAS_NATIVE:
        raise NativeMissingError(
            "one_link_native.pair_qr unavailable; rebuild native crate "
            "via `cd native && maturin develop --release`"
        )


class Inviter:
    """Inviter side state machine (the QR-generating device)."""

    def __init__(
        self,
        id_seed: bytes,
        expiry_unix: int,
        scope: Optional[bytes] = None,
    ) -> None:
        _require_native()
        if len(id_seed) != 32:
            raise ValueError(
                f"id_seed must be 32 bytes, got {len(id_seed)}"
            )
        self._native = _native_pq.Inviter(id_seed, expiry_unix, scope)

    def invite_bytes(self) -> bytes:
        """QR-encodable invite payload."""
        return bytes(self._native.invite_bytes())

    def id_pubkey(self) -> bytes:
        """Identity Ed25519 pubkey (32 bytes) baked into the invite."""
        return bytes(self._native.id_pubkey())

    def state(self) -> str:
        """Current state machine state (for telemetry / logging)."""
        return str(self._native.state())

    def receive_response(self, response_bytes: bytes) -> str:
        """Verify the scanner's response. Returns the SAS string.

        The SAS is 5 space-joined words. The user reads it aloud and
        the scanner-side user confirms it matches what they see.
        """
        return str(self._native.receive_response(response_bytes))

    def sas(self) -> Optional[str]:
        """The SAS string (after `receive_response`)."""
        out = self._native.sas()
        return None if out is None else str(out)

    def confirm(self) -> Tuple[bytes, bytes]:
        """User confirmed SAS matches. Returns
        `(confirm_bytes, chain_key)`.

        `confirm_bytes` is sent to the scanner over the same channel.
        `chain_key` is the 32-byte shared secret — feed to the
        Double Ratchet / AEAD layer.
        """
        cb, ck = self._native.confirm()
        return bytes(cb), bytes(ck)

    def confirm_with_factor2(
        self, factor2_key: bytes
    ) -> Tuple[bytes, bytes]:
        """Like `confirm()` but mixes in a 32-byte Factor-2 key.

        Use the output of
        `proximity_pair_native.derive_factor2_secret` as
        `factor2_key`. BOTH peers MUST supply the same factor-2 key;
        otherwise the chain keys diverge silently.
        """
        if len(factor2_key) != 32:
            raise ValueError(
                f"factor2_key must be 32 bytes, got {len(factor2_key)}"
            )
        cb, ck = self._native.confirm_with_factor2(factor2_key)
        return bytes(cb), bytes(ck)

    def abort(self) -> None:
        """User said SAS doesn't match. Discard ephemeral material."""
        self._native.abort()


class Scanner:
    """Scanner side state machine (the QR-reading device)."""

    def __init__(self, _native: object) -> None:
        # Construct via `Scanner.scan`, not directly.
        self._native = _native

    @classmethod
    def scan(
        cls,
        id_seed: bytes,
        invite_bytes: bytes,
        now_unix: int,
    ) -> Tuple["Scanner", bytes]:
        """Decode + verify an invite, generate a response.

        Returns `(scanner, response_bytes)`. Send response_bytes to
        the inviter over the freshly-discovered network channel.
        """
        _require_native()
        if len(id_seed) != 32:
            raise ValueError(
                f"id_seed must be 32 bytes, got {len(id_seed)}"
            )
        scanner_native, response_bytes = _native_pq.Scanner.scan(
            id_seed, invite_bytes, now_unix
        )
        return cls(scanner_native), bytes(response_bytes)

    def sas(self) -> str:
        """SAS string to display + verbally compare against inviter."""
        return str(self._native.sas())  # type: ignore[attr-defined]

    def inviter_pubkey(self) -> bytes:
        """Inviter's Ed25519 identity pubkey (32 bytes)."""
        return bytes(self._native.inviter_pubkey())  # type: ignore[attr-defined]

    def state(self) -> str:
        """Current state machine state."""
        return str(self._native.state())  # type: ignore[attr-defined]

    def receive_confirm(self, confirm_bytes: bytes) -> bytes:
        """Verify inviter's confirm. Returns the 32-byte chain key."""
        return bytes(
            self._native.receive_confirm(confirm_bytes)  # type: ignore[attr-defined]
        )

    def receive_confirm_with_factor2(
        self, confirm_bytes: bytes, factor2_key: bytes
    ) -> bytes:
        """Like `receive_confirm` but mixes in 32-byte Factor-2 key."""
        if len(factor2_key) != 32:
            raise ValueError(
                f"factor2_key must be 32 bytes, got {len(factor2_key)}"
            )
        return bytes(
            self._native.receive_confirm_with_factor2(  # type: ignore[attr-defined]
                confirm_bytes, factor2_key
            )
        )

    def abort(self) -> None:
        """User said SAS doesn't match. Discard ephemeral material."""
        self._native.abort()  # type: ignore[attr-defined]


def decode_invite(invite_bytes: bytes) -> Tuple[bytes, bytes, bytes, int, bytes]:
    """Decode + verify an invite WITHOUT committing to a response.

    Returns `(id_pubkey, ephemeral_x25519_pk, nonce, expiry_unix,
    scope_bytes)`. Useful for UI display before the scanner agrees
    to pair (e.g. "you are about to pair with: <fingerprint>").
    """
    _require_native()
    return _native_pq.decode_invite(invite_bytes)


def sas_from_transcript(transcript: bytes) -> str:
    """Derive the SAS from a 32-byte transcript hash. For testing /
    audit paths that already have the transcript bytes."""
    _require_native()
    if len(transcript) != 32:
        raise ValueError(
            f"transcript must be 32 bytes, got {len(transcript)}"
        )
    return str(_native_pq.sas_from_transcript(transcript))


__all__ = [
    "HAS_NATIVE",
    "Inviter",
    "Scanner",
    "NativeMissingError",
    "decode_invite",
    "sas_from_transcript",
    "SAS_WORD_COUNT",
    "SAS_BITS",
    "CHAIN_KEY_LEN",
    "INVITE_NONCE_LEN",
    "INVITE_MAX_BYTES",
    "INVITE_VERSION",
]
