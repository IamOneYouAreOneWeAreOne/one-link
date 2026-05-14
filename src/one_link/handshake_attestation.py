"""Row 10 peer-handshake attestation helper.

Wraps the ``confidential_native`` SoftwareProvider/AttestationDoc
surface in a convenience API that fits the daemon's peer-handshake
flow:

    # Local side ── peer asked us to attest
    challenge = handshake_attestation.fresh_challenge_for_peer()
    doc = handshake_attestation.issue_for_challenge(
        sealed_master, challenge, my_field_witness_or_None
    )
    send(doc.to_wire_bytes())

    # Remote side ── verify what the peer just sent us
    doc = handshake_attestation.AttestationWire.from_wire_bytes(blob)
    handshake_attestation.verify_doc(
        doc,
        expected_peer_nonce=challenge_we_sent,
        expected_field_witness=our_local_witness_or_None,
    )

The wire format is a length-prefixed concat that survives JSON-safe
encoding (each field is wrapped as base64 inside a stable JSON shape
when crossing WebRTC data channels) — see ``to_wire_dict`` /
``from_wire_dict`` for the JSON-mediated path.
"""

from __future__ import annotations

import base64
import logging
import time
from dataclasses import dataclass
from typing import Dict, Optional

from one_link.confidential_native import (
    HAS_NATIVE,
    AttestationDoc,
    SealedMasterIdentity,
    attestation_freshness_window_secs,
    fresh_attestation_nonce,
    verify_attestation,
)

log = logging.getLogger(__name__)


class HandshakeAttestationNotInstalled(RuntimeError):
    """Native confidential module unavailable; caller should fall
    back to non-attested handshake."""


def _require_native() -> None:
    if not HAS_NATIVE:
        raise HandshakeAttestationNotInstalled(
            "one_link_native.confidential unavailable. Build with "
            "`cd native && maturin develop --release`."
        )


def fresh_challenge_for_peer() -> bytes:
    """Generate a fresh 32-byte challenge nonce. The peer's
    attestation response binds to this nonce so replay across
    different challenges fails."""
    _require_native()
    return fresh_attestation_nonce()


def issue_for_challenge(
    sealed_master: SealedMasterIdentity,
    peer_challenge: bytes,
    field_witness: Optional[bytes] = None,
    now_unix: Optional[int] = None,
    freshness_window_secs: Optional[int] = None,
) -> AttestationDoc:
    """Issue an attestation doc binding ``sealed_master`` to the
    peer's challenge nonce. The window defaults to the
    crate-level ``ATTESTATION_FRESHNESS_WINDOW_SECS`` (30 s).
    """
    _require_native()
    if now_unix is None:
        now_unix = int(time.time())
    if freshness_window_secs is None:
        freshness_window_secs = attestation_freshness_window_secs()
    deadline_unix = now_unix + freshness_window_secs
    return sealed_master.attest(
        peer_challenge,
        now_unix,
        deadline_unix,
        field_witness,
    )


def verify_doc(
    doc: AttestationDoc,
    expected_peer_nonce: bytes,
    expected_field_witness: Optional[bytes] = None,
    now_unix: Optional[int] = None,
) -> None:
    """Verify a peer's attestation doc against our challenge.
    Raises ``ValueError`` on any failure (bad sig, expired,
    nonce mismatch, witness mismatch)."""
    _require_native()
    if now_unix is None:
        now_unix = int(time.time())
    verify_attestation(
        doc,
        expected_peer_nonce,
        now_unix,
        expected_field_witness,
    )


@dataclass(frozen=True)
class AttestationWire:
    """JSON-safe wire form of an AttestationDoc. Survives base64
    round-trips through WebRTC data channels / Signal-style relays /
    any text-only side channel.

    Fields mirror ``AttestationDoc`` 1:1; binary blobs become base64
    strings. ``to_wire_dict()`` returns a dict the daemon can wrap in
    its existing message envelope; ``from_wire_dict()`` parses back.
    """

    provider_tag: int
    master_vk_b64: str
    peer_nonce_b64: str
    issued_unix: int
    deadline_unix: int
    field_witness_commitment_b64: Optional[str]
    platform_quote_b64: str
    master_sig_b64: str

    @classmethod
    def from_doc(cls, doc: AttestationDoc) -> "AttestationWire":
        return cls(
            provider_tag=doc.provider_tag,
            master_vk_b64=base64.b64encode(doc.master_vk).decode("ascii"),
            peer_nonce_b64=base64.b64encode(doc.peer_nonce).decode("ascii"),
            issued_unix=doc.issued_unix,
            deadline_unix=doc.deadline_unix,
            field_witness_commitment_b64=(
                base64.b64encode(doc.field_witness_commitment).decode("ascii")
                if doc.field_witness_commitment is not None
                else None
            ),
            platform_quote_b64=base64.b64encode(doc.platform_quote).decode("ascii"),
            master_sig_b64=base64.b64encode(doc.master_sig).decode("ascii"),
        )

    def to_doc(self) -> AttestationDoc:
        return AttestationDoc(
            provider_tag=self.provider_tag,
            master_vk=base64.b64decode(self.master_vk_b64),
            peer_nonce=base64.b64decode(self.peer_nonce_b64),
            issued_unix=self.issued_unix,
            deadline_unix=self.deadline_unix,
            field_witness_commitment=(
                base64.b64decode(self.field_witness_commitment_b64)
                if self.field_witness_commitment_b64 is not None
                else None
            ),
            platform_quote=base64.b64decode(self.platform_quote_b64),
            master_sig=base64.b64decode(self.master_sig_b64),
        )

    def to_wire_dict(self) -> Dict[str, object]:
        """Stable JSON shape. Compatible with the daemon's existing
        message envelope (``{"type": "...", "payload": {...}}``)."""
        return {
            "v": 1,  # wire-format version
            "provider_tag": self.provider_tag,
            "master_vk": self.master_vk_b64,
            "peer_nonce": self.peer_nonce_b64,
            "issued_unix": self.issued_unix,
            "deadline_unix": self.deadline_unix,
            "field_witness_commitment": self.field_witness_commitment_b64,
            "platform_quote": self.platform_quote_b64,
            "master_sig": self.master_sig_b64,
        }

    @classmethod
    def from_wire_dict(cls, d: Dict[str, object]) -> "AttestationWire":
        v = d.get("v")
        if v != 1:
            raise ValueError(f"unsupported attestation wire version: {v!r}")
        return cls(
            provider_tag=int(d["provider_tag"]),  # type: ignore[arg-type]
            master_vk_b64=str(d["master_vk"]),
            peer_nonce_b64=str(d["peer_nonce"]),
            issued_unix=int(d["issued_unix"]),  # type: ignore[arg-type]
            deadline_unix=int(d["deadline_unix"]),  # type: ignore[arg-type]
            field_witness_commitment_b64=(
                None
                if d.get("field_witness_commitment") is None
                else str(d["field_witness_commitment"])
            ),
            platform_quote_b64=str(d["platform_quote"]),
            master_sig_b64=str(d["master_sig"]),
        )
