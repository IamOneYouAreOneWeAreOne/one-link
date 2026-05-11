"""Phase C-3 capability-layer migration shim (ADR-0021).

Translates the daemon's existing Ed25519-signed
:class:`one_link.caps_grants.CapabilityGrant` records to native
macaroon-style :class:`one_link_native.capability.Capability` tokens.

Per :doc:`../../docs/decisions/0021-capability-layer.md`, **Phase C
ships a translator, not a wholesale cutover**:

1. Existing Ed25519 grants stay valid until they expire. ``cap_store``
   (and the legacy ``verify_grant`` path) continue to accept them so
   no in-flight share breaks.
2. New shares mint native macaroon caps via :func:`mint_share_capability`
   (or :func:`grant_to_capability` to translate an in-hand grant).
3. After all live grants expire the legacy code paths can be removed.

The translation maps Ed25519 fields to macaroon caveats:

  ====================  ===========================================
  CapabilityGrant       Caveat
  ====================  ===========================================
  ``subject_pub``       :py:class:`PeerFingerprint` (32-byte BLAKE3
                        of the subject's Ed25519 pubkey)
  ``not_after_ms``      :py:class:`ExpiresAt`
  ``capabilities``      :py:class:`OperationIn` (set of operation
                        tags, e.g. ``["files:read", "chat:send"]``)
  ``scope``             :py:class:`PathPrefix` when scope decodes as
                        ASCII, otherwise the bytes are hex-encoded
                        and embedded under :py:class:`AuditTag`
  ``nonce``             :py:class:`AuditTag` ``"nonce:<hex>"`` for
                        chain provenance and replay tracking
  ``granter_pub``       Audit tag ``"granter:<hex>"`` so receivers
                        can resolve the originating issuer
  ====================  ===========================================

The macaroon's HMAC root key is derived from the granter's identity
(``BLAKE3(granter_priv_seed || "ol-cap-migration-root-v1")``), giving
each granter a stable per-identity root. Without the seed (parsing
foreign grants) a placeholder key is used and the resulting cap is
parse-only — the macaroon won't verify against the real root.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Iterable, Optional

from . import capability_native, caps_grants


CAP_MIGRATION_ROOT_CONTEXT = b"ol-cap-migration-root-v1"


def derive_root_key(granter_priv_seed: bytes) -> bytes:
    """Derive a stable per-granter root HMAC key. ``granter_priv_seed``
    is the same 32-byte Ed25519 seed the legacy grant code uses; we
    BLAKE3-keyed-hash it under a fixed migration context so a key
    leak doesn't compromise either system independently."""
    if len(granter_priv_seed) != 32:
        raise ValueError("granter_priv_seed must be 32 bytes")
    # Use BLAKE3 via the native helper since cryptography doesn't
    # ship it; fall back to SHA-256 if the native module isn't loaded.
    try:
        import blake3  # type: ignore[import-not-found]

        h = blake3.blake3(CAP_MIGRATION_ROOT_CONTEXT + granter_priv_seed)
        return h.digest()
    except ImportError:
        return hashlib.sha256(
            CAP_MIGRATION_ROOT_CONTEXT + granter_priv_seed
        ).digest()


def _peer_fingerprint(subject_pub: bytes) -> bytes:
    """Map an Ed25519 subject pubkey to a 32-byte peer fingerprint
    suitable for a :py:class:`PeerFingerprint` caveat. We
    BLAKE3-hash the subject pubkey so a leaked grant doesn't reveal
    the raw key in plaintext within the macaroon audit trail."""
    try:
        import blake3  # type: ignore[import-not-found]

        return blake3.blake3(subject_pub).digest()
    except ImportError:
        return hashlib.sha256(subject_pub).digest()


def _derive_cap_id(granter_pub: bytes, nonce: bytes) -> bytes:
    """Cap-id = BLAKE3(granter_pub || nonce). 32 bytes."""
    try:
        import blake3  # type: ignore[import-not-found]

        return blake3.blake3(granter_pub + nonce).digest()
    except ImportError:
        return hashlib.sha256(granter_pub + nonce).digest()


def mint_share_capability(
    *,
    granter_priv_seed: bytes,
    granter_pub: bytes,
    subject_pub: bytes,
    capabilities: Iterable[str],
    not_after_ms: int,
    scope: bytes = b"",
    nonce: Optional[bytes] = None,
):
    """Mint a fresh macaroon-style capability for a new share. Same
    shape as :func:`caps_grants.encode_grant` but emits a
    :class:`one_link_native.capability.Capability` instead of an
    Ed25519-signed grant blob.

    Returns the native ``Capability``; callers transmit
    ``cap.encode()`` on the wire and the receiver decodes + verifies
    with the granter's root key."""
    if len(granter_priv_seed) != 32:
        raise ValueError("granter_priv_seed must be 32 bytes")
    if len(granter_pub) != 32:
        raise ValueError("granter_pub must be 32 bytes")
    if len(subject_pub) != 32:
        raise ValueError("subject_pub must be 32 bytes")
    if nonce is None:
        nonce = os.urandom(16)
    elif len(nonce) != 16:
        raise ValueError("nonce must be 16 bytes")

    root_key = derive_root_key(granter_priv_seed)
    cap_id = _derive_cap_id(granter_pub, nonce)
    cap = capability_native.root_capability(cap_id, root_key)

    # Layer caveats in the canonical order: peer pin, expiry, op
    # allowlist, optional path scope, audit provenance.
    cap = cap.attenuate_peer(_peer_fingerprint(subject_pub))
    cap = cap.attenuate_expires_at(int(not_after_ms))
    caps_sorted = tuple(sorted({str(c) for c in capabilities}))
    if caps_sorted:
        cap = cap.attenuate_operation_in(list(caps_sorted))
    if scope:
        try:
            scope_str = scope.decode("ascii")
            cap = cap.attenuate_path_prefix(scope_str)
        except UnicodeDecodeError:
            cap = cap.attenuate_audit_tag("scope-hex:" + scope.hex())
    cap = cap.attenuate_audit_tag("granter:" + granter_pub.hex())
    cap = cap.attenuate_audit_tag("nonce:" + nonce.hex())
    return cap


def grant_to_capability(
    grant: caps_grants.CapabilityGrant,
    *,
    granter_priv_seed: Optional[bytes] = None,
):
    """Translate an existing Ed25519 :class:`CapabilityGrant` into a
    macaroon-style :class:`Capability` with equivalent caveats.

    If ``granter_priv_seed`` is provided, the resulting cap will
    ``verify`` against ``derive_root_key(seed)``. Without the seed
    we use a placeholder root key — the cap is parse-only (its
    caveats and structure are inspectable, but verification fails).
    This is how the legacy daemon can SHOW a grant as a macaroon
    in diagnostics without holding the issuer key."""
    seed = granter_priv_seed if granter_priv_seed is not None else b"\x00" * 32
    return mint_share_capability(
        granter_priv_seed=seed,
        granter_pub=grant.granter_pub,
        subject_pub=grant.subject_pub,
        capabilities=grant.capabilities,
        not_after_ms=grant.not_after_ms,
        scope=grant.scope,
        nonce=grant.nonce,
    )


@dataclass(frozen=True)
class TranslationReport:
    """Diagnostics about a grant→cap translation. Useful for the
    daemon UI to render a side-by-side view of legacy vs new."""

    n_caveats: int
    has_peer_pin: bool
    has_expiry: bool
    has_op_allowlist: bool
    has_path_prefix: bool


def describe_translation(grant: caps_grants.CapabilityGrant) -> TranslationReport:
    """Report which caveats a grant→cap translation would produce
    WITHOUT performing the translation. Pure inspection — does not
    need a private seed."""
    has_path = False
    if grant.scope:
        try:
            grant.scope.decode("ascii")
            has_path = True
        except UnicodeDecodeError:
            has_path = False
    n_caveats = (
        1  # peer pin
        + 1  # expiry
        + (1 if grant.capabilities else 0)
        + (1 if grant.scope else 0)
        + 2  # granter + nonce audit tags
    )
    return TranslationReport(
        n_caveats=n_caveats,
        has_peer_pin=True,
        has_expiry=True,
        has_op_allowlist=bool(grant.capabilities),
        has_path_prefix=has_path,
    )
