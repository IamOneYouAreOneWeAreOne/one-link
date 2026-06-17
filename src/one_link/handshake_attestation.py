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

from one_link._coerce import to_int
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
    issuer_sdp_pubkey: bytes,
    field_witness: Optional[bytes] = None,
    now_unix: Optional[int] = None,
    freshness_window_secs: Optional[int] = None,
) -> AttestationDoc:
    """Issue an attestation doc binding ``sealed_master`` to the
    peer's challenge nonce AND to ``issuer_sdp_pubkey`` (the
    daemon's own 32-byte Ed25519 SDP-layer pubkey). The window
    defaults to ``ATTESTATION_FRESHNESS_WINDOW_SECS`` (30 s).

    Audit C1 (May 2026): the SDP-pubkey binding is mandatory and
    causes the peer's ``verify_doc`` to reject any doc whose
    embedded SDP pubkey does not match the channel identity.
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
        issuer_sdp_pubkey,
        field_witness,
    )


def verify_doc(
    doc: AttestationDoc,
    expected_peer_nonce: bytes,
    expected_issuer_sdp_pubkey: bytes,
    expected_field_witness: Optional[bytes] = None,
    now_unix: Optional[int] = None,
    min_tier: int = 1,
) -> None:
    """Verify a peer's attestation doc against our challenge.
    Raises ``ValueError`` on any failure (bad sig, expired,
    nonce mismatch, witness mismatch, tier below ``min_tier``,
    or SDP-pubkey mismatch).

    ``expected_issuer_sdp_pubkey`` (audit C1, May 2026) is the
    32-byte Ed25519 pubkey of the channel identity the verifier
    is actually talking to. The doc's embedded
    ``issuer_sdp_pubkey`` MUST match — closes the
    identity-confusion attack.

    ``min_tier`` defaults to ``TIER_SOFTWARE`` (accept any tier).
    """
    _require_native()
    if now_unix is None:
        now_unix = int(time.time())
    verify_attestation(
        doc,
        expected_peer_nonce,
        now_unix,
        expected_issuer_sdp_pubkey,
        expected_field_witness,
        min_tier,
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
    issuer_sdp_pubkey_b64: str
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
            issuer_sdp_pubkey_b64=base64.b64encode(doc.issuer_sdp_pubkey).decode(
                "ascii"
            ),
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
            issuer_sdp_pubkey=base64.b64decode(self.issuer_sdp_pubkey_b64),
            master_sig=base64.b64decode(self.master_sig_b64),
        )

    def to_wire_dict(self) -> Dict[str, object]:
        """Stable JSON shape. Compatible with the daemon's existing
        message envelope (``{"type": "...", "payload": {...}}``).

        Wire-format ``v: 2`` (audit C1, May 2026): added
        ``issuer_sdp_pubkey``. Old ``v: 1`` docs are rejected by
        ``from_wire_dict``; the underlying transcript-domain bump
        guarantees a ``v: 1`` doc cannot pass ``-v2`` master-sig
        verify anyway.
        """
        return {
            "v": 2,
            "provider_tag": self.provider_tag,
            "master_vk": self.master_vk_b64,
            "peer_nonce": self.peer_nonce_b64,
            "issued_unix": self.issued_unix,
            "deadline_unix": self.deadline_unix,
            "field_witness_commitment": self.field_witness_commitment_b64,
            "platform_quote": self.platform_quote_b64,
            "issuer_sdp_pubkey": self.issuer_sdp_pubkey_b64,
            "master_sig": self.master_sig_b64,
        }

    @classmethod
    def from_wire_dict(cls, d: Dict[str, object]) -> "AttestationWire":
        """Parse a JSON-wire-dict into an ``AttestationWire``.

        Audit M10 May 2026: strict-schema parse with per-field
        upper bounds applied BEFORE any base64 decode. Without
        these bounds an attacker could ship a 250 KB frame whose
        five base64 fields each maxed out the per-frame budget,
        forcing ~1 MB of allocations per frame even though native
        verify would reject afterward. Strict-schema rejection
        also denies attacker-supplied extra keys from surviving
        through to higher layers.
        """
        v = d.get("v")
        if v != 2:
            raise ValueError(f"unsupported attestation wire version: {v!r}")

        # Reject unknown / extra keys so the wire shape is closed
        # against attacker-supplied metadata that bypasses the
        # signed transcript.
        allowed = {
            "v",
            "provider_tag",
            "master_vk",
            "peer_nonce",
            "issued_unix",
            "deadline_unix",
            "field_witness_commitment",
            "platform_quote",
            "issuer_sdp_pubkey",
            "master_sig",
        }
        extras = set(d.keys()) - allowed
        if extras:
            raise ValueError(
                f"unexpected attestation wire keys: {sorted(extras)!r}"
            )
        # Required keys.
        required = {
            "v",
            "provider_tag",
            "master_vk",
            "peer_nonce",
            "issued_unix",
            "deadline_unix",
            "platform_quote",
            "issuer_sdp_pubkey",
            "master_sig",
        }
        missing = required - set(d.keys())
        if missing:
            raise ValueError(
                f"missing attestation wire keys: {sorted(missing)!r}"
            )

        def _b64str(key: str, max_len: int) -> str:
            raw = d[key]
            if not isinstance(raw, str):
                raise ValueError(
                    f"attestation wire field {key!r} must be a string, "
                    f"got {type(raw).__name__}"
                )
            if len(raw) > max_len:
                raise ValueError(
                    f"attestation wire field {key!r} length {len(raw)} "
                    f"exceeds max {max_len}"
                )
            return raw

        # Per-field byte caps. Derived from the native fixed sizes:
        # - master_vk: 1984 raw → 2648 base64 chars (round up)
        # - peer_nonce: 32 raw → 44 chars
        # - master_sig: 3357 raw → 4476 chars
        # - issuer_sdp_pubkey: 32 raw → 44 chars
        # - field_witness_commitment: 32 raw → 44 chars
        # - platform_quote: bounded to 64 KiB raw → ~87382 chars
        #   (TPM-quote upper bound)
        return cls(
            provider_tag=to_int(d["provider_tag"]),
            master_vk_b64=_b64str("master_vk", 2700),
            peer_nonce_b64=_b64str("peer_nonce", 60),
            issued_unix=to_int(d["issued_unix"]),
            deadline_unix=to_int(d["deadline_unix"]),
            field_witness_commitment_b64=(
                None
                if d.get("field_witness_commitment") is None
                else _b64str("field_witness_commitment", 60)
            ),
            platform_quote_b64=_b64str("platform_quote", 90_000),
            issuer_sdp_pubkey_b64=_b64str("issuer_sdp_pubkey", 60),
            master_sig_b64=_b64str("master_sig", 4600),
        )
