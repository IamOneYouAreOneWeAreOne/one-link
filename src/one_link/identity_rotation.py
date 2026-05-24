"""Identity key rotation - the cryptographic primitive.

What rotation is for
--------------------
A user's One Link identity is an Ed25519 keypair derived from the
master seed. Peers pin that public key. Two situations want a
rotation:

  - Compromise: the user believes the private key leaked (lost
    device, malware, "I'm being paranoid").
  - Scheduled: a high-security user rotates on a cadence so any
    silent compromise has a bounded window.

Without rotation, the only recovery on compromise is to re-pair
with every peer manually, which is a UX cliff: people give up.

Authorization model
-------------------
A rotation announcement must be cryptographically authorized by
the OLD key. Otherwise an attacker on the LAN could broadcast
"my new key is K" for any victim and steal the identity. The
authorization is a small certificate:

    canonical_json = {
        "v": 1,
        "old_fp":       hex(blake2b256(old_pubkey)),
        "new_fp":       hex(blake2b256(new_pubkey)),
        "new_pub_hex":  hex(new_pubkey),
        "ts_ms":        int (wall-clock, unix ms),
        "reason":       "compromise" | "scheduled" | "device_lost" | "other",
    }
    signature       = Ed25519(old_priv, canonical_json bytes)

The peer receives ``{cert: canonical_json, sig: bytes}``, looks
up its pinned ``old_pubkey`` for ``old_fp``, and runs
``Ed25519(old_pubkey).verify(sig, canonical_json bytes)``. If the
signature verifies, the peer is cryptographically certain the
holder of the OLD private key authorized this transition, and
atomically updates its peer record to bind the same trust state
(alias, mute, dm_ttl, pinned-trust) to ``new_pubkey``.

If verification fails (wrong signature, tampered cert, unknown
old_fp, malformed JSON, replay of an already-applied cert), the
cert is silently dropped and the existing v0.7.8 hostname-based
key-change DETECTION takes over - the peer sees the new pubkey
arriving and raises the manual-confirm warning banner.

Replay protection
-----------------
A rotation cert is a one-way transition: once applied, the peer's
pubkey IS the new pubkey, so a replayed cert for the same
(old_fp, new_fp) would be a no-op. We still record an
``applied_at_ms`` per (old_fp, new_fp) so the audit log shows the
moment the transition happened.

A more subtle replay is: attacker captures a valid rotation cert
from network observation, then later (after the legitimate user
has done a SECOND rotation) replays the FIRST cert to roll the
peer back to the intermediate key. The defense: applying a cert
chains forward only - if our pinned key is already past the
``new_fp`` in the cert, we drop. We track this via a chain of
applied cert IDs per peer.

Format
------
The wire format is canonical JSON + a separate signature blob so
the cert is human-inspectable (audit logs) without losing the
exact bytes the signature covers.
"""
from __future__ import annotations

import contextlib
import enum
import json
import time
from dataclasses import dataclass
from typing import Any, Optional

import blake3

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)


CERT_VERSION = 1
CERT_KEYS = ("v", "old_fp", "new_fp", "new_pub_hex", "ts_ms", "reason")


class RotationReason(str, enum.Enum):
    COMPROMISE = "compromise"
    SCHEDULED = "scheduled"
    DEVICE_LOST = "device_lost"
    OTHER = "other"


VALID_REASONS = frozenset(r.value for r in RotationReason)


@dataclass(frozen=True)
class RotationCertificate:
    """Decoded form of a rotation cert. The canonical_bytes field
    is the EXACT bytes the signature was computed over - keep it
    around so re-serialization round-trips byte-for-byte."""
    version: int
    old_fp: str
    new_fp: str
    new_pub_hex: str
    ts_ms: int
    reason: str
    canonical_bytes: bytes
    signature: bytes

    def to_wire_dict(self) -> dict[str, Any]:
        """The shape that goes on the wire OR into persistent state.
        Caller base64s the binary fields when transporting."""
        return {
            "cert_json": self.canonical_bytes.decode("ascii"),
            "sig_hex": self.signature.hex(),
        }

    @classmethod
    def from_wire_dict(cls, d: dict[str, Any]) -> "RotationCertificate":
        cert_raw = d.get("cert_json")
        sig_raw = d.get("sig_hex")
        if not isinstance(cert_raw, str) or not isinstance(sig_raw, str):
            raise ValueError("wire cert missing cert_json or sig_hex")
        try:
            sig = bytes.fromhex(sig_raw)
        except ValueError as e:
            raise ValueError(f"sig_hex not valid hex: {e}") from None
        if len(sig) != 64:
            raise ValueError(f"signature must be 64 bytes, got {len(sig)}")
        canonical = cert_raw.encode("ascii")
        body = _parse_canonical_cert(canonical)
        return cls(
            version=body["v"],
            old_fp=body["old_fp"],
            new_fp=body["new_fp"],
            new_pub_hex=body["new_pub_hex"],
            ts_ms=body["ts_ms"],
            reason=body["reason"],
            canonical_bytes=canonical,
            signature=sig,
        )


# Fingerprint format: BLAKE3(pubkey).hex(). Matches identity._fingerprint
# / fingerprint_of which the rest of the daemon (state.py, peer_rtc.py,
# the wire-handshake layer) uses to derive peer fingerprints from
# Ed25519 pubkeys. Using a different hash here would make the cert's
# old_fp + new_fp never line up with the peer's stored peers.fingerprint
# column - every rotation would silently fail the apply_certificate_to_peer
# old_fp == current_pinned_fp check. The two-daemon integration test
# (tests/test_rotation_integration_v021.py) catches this regression.
def fingerprint_for_pubkey(pubkey: bytes) -> str:
    if not isinstance(pubkey, (bytes, bytearray)) or len(pubkey) != 32:
        raise ValueError("pubkey must be 32 bytes")
    return blake3.blake3(bytes(pubkey)).hexdigest()


def _canonicalize_cert_body(body: dict[str, Any]) -> bytes:
    """Stable serialization for signing. Uses JSON with sorted keys
    and no whitespace so byte-equivalence holds across reproducers."""
    return json.dumps(
        {k: body[k] for k in CERT_KEYS if k in body},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def _parse_canonical_cert(canonical: bytes) -> dict[str, Any]:
    """Round-trip the JSON, validate the schema, return the body dict.
    Rejects unknown keys + missing keys + bad types."""
    try:
        obj = json.loads(canonical.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError(f"cert body is not ASCII JSON: {e}") from None
    if not isinstance(obj, dict):
        raise ValueError("cert body must be a JSON object")
    # Strict-schema: every known key must be present, no extras.
    extras = set(obj.keys()) - set(CERT_KEYS)
    if extras:
        raise ValueError(f"cert has unexpected keys: {sorted(extras)}")
    missing = set(CERT_KEYS) - set(obj.keys())
    if missing:
        raise ValueError(f"cert missing keys: {sorted(missing)}")
    if obj["v"] != CERT_VERSION:
        raise ValueError(f"unsupported cert version {obj['v']}")
    for k in ("old_fp", "new_fp", "new_pub_hex", "reason"):
        if not isinstance(obj[k], str):
            raise ValueError(f"cert.{k} must be a string")
    if not isinstance(obj["ts_ms"], int):
        raise ValueError("cert.ts_ms must be an int")
    if obj["reason"] not in VALID_REASONS:
        raise ValueError(
            f"cert.reason {obj['reason']!r} not in {sorted(VALID_REASONS)}"
        )
    # Fingerprints are SHA-256 hex; 64 lowercase hex chars.
    for k in ("old_fp", "new_fp"):
        v = obj[k]
        if len(v) != 64 or any(c not in "0123456789abcdef" for c in v):
            raise ValueError(f"cert.{k} must be 64 lowercase hex chars")
    # new_pub_hex is 32 bytes = 64 hex chars.
    pub_hex = obj["new_pub_hex"]
    if len(pub_hex) != 64 or any(c not in "0123456789abcdef" for c in pub_hex):
        raise ValueError("cert.new_pub_hex must be 64 lowercase hex chars")
    # Consistency: new_fp must equal sha256(new_pubkey).hex(). Otherwise
    # an attacker could craft a cert whose new_fp lies about the pubkey.
    try:
        derived_new_fp = fingerprint_for_pubkey(bytes.fromhex(pub_hex))
    except ValueError as e:
        raise ValueError(f"cert.new_pub_hex not parseable: {e}") from None
    if derived_new_fp != obj["new_fp"]:
        raise ValueError(
            "cert.new_fp does not match SHA-256(new_pub_hex); cert is "
            "internally inconsistent"
        )
    return obj


# ── mint ────────────────────────────────────────────────────────────


def mint_certificate(
    *,
    old_priv: Ed25519PrivateKey,
    new_pub: bytes,
    reason: str = RotationReason.SCHEDULED.value,
    ts_ms: Optional[int] = None,
) -> RotationCertificate:
    """Build + sign a rotation certificate.

    The OLD private key signs the canonical-JSON body that names the
    NEW public key as the rotation target. The signature is the only
    thing that makes the cert trustworthy to peers: if the OLD key
    is gone, no further rotations can be authorized (this is the
    sovereignty property - even we can't override it).

    ``ts_ms`` defaults to now. Set explicitly for reproducible tests.
    """
    if not isinstance(old_priv, Ed25519PrivateKey):
        raise TypeError("old_priv must be Ed25519PrivateKey")
    if not isinstance(new_pub, (bytes, bytearray)) or len(new_pub) != 32:
        raise ValueError("new_pub must be 32 bytes")
    if reason not in VALID_REASONS:
        raise ValueError(f"reason must be one of {sorted(VALID_REASONS)}")
    if ts_ms is None:
        ts_ms = int(time.time() * 1000)
    old_pub = old_priv.public_key().public_bytes_raw()
    body = {
        "v": CERT_VERSION,
        "old_fp": fingerprint_for_pubkey(old_pub),
        "new_fp": fingerprint_for_pubkey(bytes(new_pub)),
        "new_pub_hex": bytes(new_pub).hex(),
        "ts_ms": int(ts_ms),
        "reason": reason,
    }
    canonical = _canonicalize_cert_body(body)
    signature = old_priv.sign(canonical)
    return RotationCertificate(
        version=body["v"],
        old_fp=body["old_fp"],
        new_fp=body["new_fp"],
        new_pub_hex=body["new_pub_hex"],
        ts_ms=body["ts_ms"],
        reason=body["reason"],
        canonical_bytes=canonical,
        signature=signature,
    )


# ── verify ──────────────────────────────────────────────────────────


class CertVerifyError(Exception):
    """Raised when a certificate fails any verification check.

    The wrapping daemon-side handler treats every CertVerifyError as
    a silent drop + log (do NOT surface a user-visible 'someone tried
    to attack you' banner; it's noise). The v0.7.8 hostname-key
    detection layer still runs and will raise the manual-confirm
    warning for any legitimate key change that arrives without a
    valid cert.
    """


def verify_certificate(
    *,
    cert: RotationCertificate,
    expected_old_pubkey: bytes,
) -> None:
    """Verify a cert against a pinned old pubkey. Raises CertVerifyError
    if the cert is bogus; returns None on success.

    Callers should pass the pubkey they have pinned for old_fp - if the
    cert's old_fp doesn't match SHA-256(expected_old_pubkey), the cert
    is for a different peer and we refuse (defense against cert
    misrouting).
    """
    if not isinstance(expected_old_pubkey, (bytes, bytearray)) or len(expected_old_pubkey) != 32:
        raise CertVerifyError("expected_old_pubkey must be 32 bytes")
    derived_old_fp = fingerprint_for_pubkey(bytes(expected_old_pubkey))
    if cert.old_fp != derived_old_fp:
        raise CertVerifyError(
            f"cert.old_fp {cert.old_fp!r} does not match SHA-256(expected_old_pubkey) "
            f"{derived_old_fp!r}; cert is for a different identity"
        )
    # Re-parse the canonical bytes in case the caller built the cert
    # by hand (defense in depth - bad inputs hit the schema validator).
    # Surface schema errors as CertVerifyError so a single except
    # clause in the daemon handler catches every failure mode.
    try:
        _parse_canonical_cert(cert.canonical_bytes)
    except ValueError as e:
        raise CertVerifyError(f"cert body failed schema check: {e}") from None
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes(expected_old_pubkey))
        pub.verify(cert.signature, cert.canonical_bytes)
    except InvalidSignature as e:
        raise CertVerifyError(
            "cert signature does not verify against the pinned old pubkey"
        ) from e
    except Exception as e:
        raise CertVerifyError(f"signature verification failed: {e}") from None


# ── apply ───────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AppliedRotation:
    """What apply_certificate_to_peer returns to the daemon. The
    daemon uses this to update the peer's row + log an audit event +
    return an ack to the sender."""
    old_fp: str
    new_fp: str
    new_pubkey: bytes
    ts_ms: int
    reason: str


def apply_certificate_to_peer(
    *,
    cert: RotationCertificate,
    expected_old_pubkey: bytes,
    current_pinned_fp: Optional[str] = None,
) -> AppliedRotation:
    """Verify a cert and produce the transition data the daemon needs
    to update its peer record.

    ``current_pinned_fp`` is the fingerprint the daemon currently has
    pinned for this peer. We use it for replay/chain protection:

      - If current == cert.new_fp: the cert was already applied; this
        is a no-op replay. We raise CertVerifyError so the caller
        knows not to update or send an ack again. (Sender side WILL
        get an ack from the previous application that's still
        outstanding; that's the right re-sync mechanism.)
      - If current == cert.old_fp: the normal forward transition.
      - Otherwise: someone is trying to replay an OLD cert to roll
        the peer back to an intermediate key. Refuse.

    Returns AppliedRotation on success; raises CertVerifyError on
    any failure.
    """
    verify_certificate(cert=cert, expected_old_pubkey=expected_old_pubkey)
    if current_pinned_fp is not None:
        if current_pinned_fp == cert.new_fp:
            raise CertVerifyError(
                "cert already applied (current pinned fp matches cert.new_fp); "
                "replay no-op"
            )
        if current_pinned_fp != cert.old_fp:
            raise CertVerifyError(
                f"cert.old_fp {cert.old_fp!r} does not match current pinned fp "
                f"{current_pinned_fp!r}; refusing rollback attempt"
            )
    try:
        new_pubkey = bytes.fromhex(cert.new_pub_hex)
    except ValueError as e:
        raise CertVerifyError(f"cert.new_pub_hex not valid hex: {e}") from None
    return AppliedRotation(
        old_fp=cert.old_fp,
        new_fp=cert.new_fp,
        new_pubkey=new_pubkey,
        ts_ms=cert.ts_ms,
        reason=cert.reason,
    )


# ── local rotation orchestration ────────────────────────────────────


@dataclass(frozen=True)
class LocalRotationResult:
    """What perform_local_rotation returns to the HTTP handler. The
    handler ships ``new_phrase`` back to the UI for paper backup and
    sets ``restart_required=True`` in the response."""
    new_phrase: str
    cert: RotationCertificate
    queued_peer_count: int
    old_fp: str
    new_fp: str


def perform_local_rotation(
    *,
    data_dir,
    old_priv: Ed25519PrivateKey,
    pinned_peer_fingerprints: list[str],
    reason: str = RotationReason.SCHEDULED.value,
    state=None,
    ts_ms: Optional[int] = None,
) -> LocalRotationResult:
    """Run a complete local rotation:

      1. Generate a fresh master seed (32 bytes from os CSPRNG).
      2. Derive the new Ed25519 identity from that seed.
      3. Mint a rotation certificate signed by the OLD private key.
      4. Persist the new seed atomically (master_seed.store_seed).
      5. Clear identity.key + DRK so the daemon's NEXT start
         re-derives them from the new seed.
      6. Queue one row per pinned peer in
         pending_rotation_announcements (when ``state`` provided).
      7. Encode the new seed as a 24-word BIP-39 phrase and return
         it so the UI can prompt the user to back it up.

    The CALLER is responsible for telling the user to restart the
    daemon - we don't shut down here. We DO clear the old identity
    files because the new daemon must derive its identity from the
    seed; leaving stale identity.key would cause the next start to
    keep using the OLD identity (the file wins over the seed when
    both are present).

    Crypto property: the cert is signed by ``old_priv``, which is
    the identity the running daemon was loaded with. Once we return,
    the seed on disk no longer matches the in-memory identity; the
    handler MUST tell the user to restart and the running daemon
    must NOT use the old identity to sign anything else.
    """
    from pathlib import Path as _Path
    from one_link import master_seed, mnemonic
    from one_link import paths
    if not isinstance(old_priv, Ed25519PrivateKey):
        raise TypeError("old_priv must be Ed25519PrivateKey")
    if reason not in VALID_REASONS:
        raise ValueError(f"reason must be one of {sorted(VALID_REASONS)}")

    # Step 1+2: new seed + new identity.
    new_seed = mnemonic.generate_seed()
    new_identity = master_seed.derive_identity_priv(new_seed)
    new_pub = new_identity.public_key().public_bytes_raw()

    # Step 3: sign cert with OLD key, BEFORE replacing on-disk state.
    cert = mint_certificate(
        old_priv=old_priv, new_pub=new_pub, reason=reason, ts_ms=ts_ms,
    )

    # Step 4+5: persist new seed + clear identity.key + DRK.
    # store_seed is atomic (tmp + rename); persist BEFORE clearing
    # the old identity so a crash in the middle still leaves a
    # bootable daemon (either the old identity wins, or the new
    # seed wins; never both gone).
    master_seed.store_seed(_Path(data_dir), new_seed)
    for f in (paths.key_path(), _Path(data_dir) / "data-root-key.bin"):
        with contextlib.suppress(OSError):
            _Path(f).unlink()

    # Best-effort seed wipe in our reference; the on-disk copy is
    # the canonical source going forward.
    try:
        # Step 6: queue per-peer announcements.
        queued = 0
        if state is not None:
            wire = cert.to_wire_dict()
            for peer_fp in pinned_peer_fingerprints:
                with contextlib.suppress(Exception):
                    state.queue_rotation_announcement(
                        peer_fp=peer_fp,
                        old_fp=cert.old_fp,
                        new_fp=cert.new_fp,
                        cert_json=wire["cert_json"],
                        sig_hex=wire["sig_hex"],
                    )
                    queued += 1

        # Step 7: encode the phrase for the UI.
        new_phrase = mnemonic.encode(new_seed)
        return LocalRotationResult(
            new_phrase=new_phrase,
            cert=cert,
            queued_peer_count=queued,
            old_fp=cert.old_fp,
            new_fp=cert.new_fp,
        )
    finally:
        new_seed = b"\x00" * len(new_seed)
        del new_seed
