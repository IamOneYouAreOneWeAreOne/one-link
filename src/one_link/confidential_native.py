"""Adapter for the file-engine v2 native confidential-compute provider
(``ol_confidential`` via ``one_link_native``).

Row 10 of the Coherence Mesh. Provides the sealed-op surface
(seal_master / derive_child / sealed_sign / verifying_key / attest)
and remote-attestation verifier — backed by Rust's ``ol_confidential``
crate so the master key sealing + AEAD work happens in zeroize-clean
process memory, the hybrid sign uses ``ol_pqsig`` Ed25519+ML-DSA-65,
and attestation docs carry the canonical wire format.

Software baseline by default. Use the Windows TPM-rooted variant by
building ``one_link_native`` with ``--features windows-tpm`` and
invoking ``windows_hardened_provider`` (separate adapter — lands when
the daemon wants HardwareBound tier).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)

try:
    from one_link_native import confidential as _native  # type: ignore[import-not-found]

    HAS_NATIVE: bool = True
except ImportError as exc:
    HAS_NATIVE = False
    _native = None  # type: ignore[assignment]
    log.info(
        "one_link_native.confidential not installed (%s); Row 10 "
        "sealed-op surface unavailable. Build via "
        "`cd native && maturin develop --release`.",
        exc,
    )


# Provider tag wire-bytes (must match `ol_confidential::ProviderTag`).
PROVIDER_TAG_SOFTWARE = 1
PROVIDER_TAG_APPLE_SE = 2
PROVIDER_TAG_ANDROID_STRONGBOX = 3
PROVIDER_TAG_WINDOWS_TPM = 4
PROVIDER_TAG_INTEL_SGX = 5
PROVIDER_TAG_AMD_SEV_SNP = 6
PROVIDER_TAG_ARM_TRUSTZONE = 7

# Tier ordering: matches `ol_confidential::ConfidentialTier` discriminants.
TIER_SOFTWARE = 0
TIER_HARDWARE_BOUND = 1
TIER_HARDWARE_ATTESTED = 2


class ConfidentialNotInstalled(RuntimeError):
    """Raised when the daemon tries to use the native confidential
    surface but the ``one_link_native`` extension wasn't built."""


def _require_native() -> None:
    if not HAS_NATIVE:
        raise ConfidentialNotInstalled(
            "one_link_native.confidential is unavailable. "
            "Build with `cd native && maturin develop --release`."
        )


@dataclass(frozen=True)
class SealedKey:
    """Opaque sealed-key blob. Round-trip via the daemon's storage
    layer; never inspect ``bytes``.

    ``tag`` is one of the ``PROVIDER_TAG_*`` constants — written into
    the wire form so cross-provider unseal attempts fail at the tag
    check before the AEAD even runs.
    """

    bytes: bytes
    tag: int

    @property
    def is_software(self) -> bool:
        return self.tag == PROVIDER_TAG_SOFTWARE

    @property
    def is_hardware_bound(self) -> bool:
        return self.tag in (
            PROVIDER_TAG_APPLE_SE,
            PROVIDER_TAG_ANDROID_STRONGBOX,
            PROVIDER_TAG_WINDOWS_TPM,
            PROVIDER_TAG_INTEL_SGX,
            PROVIDER_TAG_AMD_SEV_SNP,
            PROVIDER_TAG_ARM_TRUSTZONE,
        )


@dataclass(frozen=True)
class AttestationDoc:
    """Wire envelope for a Row 10 remote attestation. The master sig
    transitively commits to every other field (including
    ``platform_quote`` and ``issuer_sdp_pubkey``).

    ``issuer_sdp_pubkey`` is the 32-byte Ed25519 verifying-key of the
    issuer's SDP-layer identity (the key that signs the WebRTC SDP
    envelope). The verifier checks this matches the channel identity
    they're actually talking to — defeats the identity-confusion
    attack where a peer attests with someone else's master_vk under
    their own SDP key (audit C1, ``-v2`` domain bump May 2026).
    """

    provider_tag: int
    master_vk: bytes
    peer_nonce: bytes
    issued_unix: int
    deadline_unix: int
    field_witness_commitment: Optional[bytes]
    platform_quote: bytes
    issuer_sdp_pubkey: bytes
    master_sig: bytes


class SoftwareProvider:
    """Thin Python wrapper over the native ``SoftwareProvider``.

    Lifecycle:
        provider = SoftwareProvider.fresh()
        sealed = provider.seal_master(master_seed_32_bytes)
        sig = provider.sealed_sign(sealed, transcript)
        vk = provider.verifying_key(sealed)
        doc = provider.attest(sealed, peer_nonce, issued_unix, deadline_unix)
    """

    __slots__ = ("_inner",)

    def __init__(self, inner) -> None:
        self._inner = inner

    @classmethod
    def fresh(cls) -> "SoftwareProvider":
        """CSPRNG-sourced ephemeral sealing key. Recommended for
        production daemon boot."""
        _require_native()
        return cls(_native.fresh_software_provider())  # type: ignore[union-attr]

    @classmethod
    def from_seed(cls, seed: bytes) -> "SoftwareProvider":
        """Deterministic. KAT-vector + incident-response replay only.
        DO NOT use a static seed in production.

        Audit M7 May 2026: this constructor is gated behind the
        Rust Cargo feature ``unstable-deterministic-provider`` which
        is OFF in production wheels. Calling this on a default
        ``maturin develop --release`` build will raise ``ValueError``
        from the native side. Test wheels can opt in via
        ``maturin develop --release --features
        unstable-deterministic-provider``.
        """
        _require_native()
        if len(seed) != 32:
            raise ValueError(
                f"SoftwareProvider seed must be 32 bytes, got {len(seed)}"
            )
        return cls(_native.software_provider_from_seed(seed))  # type: ignore[union-attr]

    @property
    def tier(self) -> int:
        """Returns the ``TIER_*`` discriminant for this provider."""
        return self._inner.tier_byte()

    @property
    def tag(self) -> int:
        """Returns the ``PROVIDER_TAG_*`` discriminant."""
        return self._inner.tag_byte()

    def seal_master(self, master_seed: bytes) -> SealedKey:
        """Seal a 32-byte master seed. The returned ``SealedKey`` can
        be persisted to disk safely (provider tag check + AEAD
        authenticator make tampering detectable)."""
        if len(master_seed) != 32:
            raise ValueError(
                f"master_seed must be 32 bytes, got {len(master_seed)}"
            )
        sealed_bytes, tag = self._inner.seal_master(master_seed)
        return SealedKey(bytes=sealed_bytes, tag=tag)

    def derive_child(self, sealed_master: SealedKey, context_tag: bytes) -> SealedKey:
        """Derive a child key from a sealed master + context tag.
        Output is itself a ``SealedKey``."""
        child_bytes, tag = self._inner.derive_child(
            sealed_master.bytes,
            sealed_master.tag,
            context_tag,
        )
        return SealedKey(bytes=child_bytes, tag=tag)

    def sealed_sign(self, sealed: SealedKey, transcript: bytes) -> bytes:
        """Sign ``transcript`` under the sealed master. Returns hybrid
        signature bytes (Ed25519 + ML-DSA-65 concatenated)."""
        return self._inner.sealed_sign(sealed.bytes, sealed.tag, transcript)

    def verifying_key(self, sealed: SealedKey) -> bytes:
        """Derive the 1984-byte hybrid verifying key from a sealed
        master. Publishable; the peer pins this for verification."""
        return self._inner.verifying_key(sealed.bytes, sealed.tag)

    def attest(
        self,
        sealed: SealedKey,
        peer_nonce: bytes,
        issued_unix: int,
        deadline_unix: int,
        issuer_sdp_pubkey: bytes,
        field_witness: Optional[bytes] = None,
    ) -> AttestationDoc:
        """Issue a fresh attestation doc bound to ``peer_nonce`` and
        ``issuer_sdp_pubkey``.

        ``issuer_sdp_pubkey`` MUST be the daemon's own 32-byte Ed25519
        SDP-layer pubkey (the one that signed the WebRTC offer/answer
        envelope on the channel where this attestation will be
        exchanged). The master signature binds to it so a verifier
        rejects any doc whose embedded SDP pubkey does not match the
        channel they're actually talking to (audit C1).

        The ``deadline_unix - issued_unix`` window must be ≤ 30s
        (``ATTESTATION_FRESHNESS_WINDOW_SECS``); peer rejects
        otherwise.
        """
        if len(issuer_sdp_pubkey) != 32:
            raise ValueError(
                f"issuer_sdp_pubkey must be 32 bytes, got {len(issuer_sdp_pubkey)}"
            )
        result = self._inner.attest(
            sealed.bytes,
            sealed.tag,
            peer_nonce,
            issued_unix,
            deadline_unix,
            issuer_sdp_pubkey,
            field_witness,
        )
        (
            tag,
            master_vk,
            nonce,
            iss,
            dl,
            cmt,
            quote,
            sdp,
            sig,
        ) = result
        return AttestationDoc(
            provider_tag=tag,
            master_vk=master_vk,
            peer_nonce=nonce,
            issued_unix=iss,
            deadline_unix=dl,
            field_witness_commitment=cmt,
            platform_quote=quote,
            issuer_sdp_pubkey=sdp,
            master_sig=sig,
        )


class WindowsHardenedProvider:
    """Audit M6 — TPM-rooted hardened provider on Windows.

    Wraps the native ``WindowsHardenedProvider`` (composition of
    ``SoftwareProvider`` for the seal/sign/verify primitives PLUS a
    TPM-resident ECDSA-P256 attestation key). The public surface is
    intentionally identical to :class:`SoftwareProvider` so callers
    can swap providers behind a feature gate without changing call
    sites. The TPM key root binds every attestation doc to this
    physical TPM via the ``platform_quote`` field — a peer who pins
    the master_vk also gets cross-host non-transferability.

    Available only when the native wheel is built with
    ``maturin develop --release --features windows-tpm`` on a Windows
    host with a functional TPM 2.0. On any other platform / wheel,
    :py:meth:`fresh` raises :class:`ConfidentialNotInstalled`.

    Lifecycle:
        provider = WindowsHardenedProvider.fresh("OL-daemon-attest-v1")
        sealed = provider.seal_master(master_seed_32_bytes)
        doc = provider.attest(sealed, peer_nonce, t_issue, t_deadline,
                              issuer_sdp_pubkey)
        # `doc.platform_quote` is the TPM-signed ECDSA-P256 commitment;
        # any cross-platform peer can verify via verify_attestation()
        # with min_tier=TIER_HARDWARE_BOUND.
    """

    __slots__ = ("_inner",)

    def __init__(self, inner) -> None:
        self._inner = inner

    @classmethod
    def fresh(cls, tpm_key_name: str) -> "WindowsHardenedProvider":
        """Acquire or create the TPM-resident attestation key under
        ``tpm_key_name``. Use a stable per-install identifier so the
        same TPM key survives daemon restarts.

        Raises :class:`ConfidentialNotInstalled` if the native wheel
        wasn't built with the ``windows-tpm`` feature, or
        ``ValueError`` if the TPM call fails (TPM 2.0 not present,
        ACL denial, etc.).
        """
        _require_native()
        if not isinstance(tpm_key_name, str) or not tpm_key_name:
            raise ValueError("tpm_key_name must be a non-empty string")
        if not has_windows_tpm_provider():
            raise ConfidentialNotInstalled(
                "WindowsHardenedProvider requires the native wheel "
                "to be built with `--features windows-tpm` "
                "(audit M6 May 2026). The current wheel was built "
                "WITHOUT that feature so the TPM surface is "
                "unavailable."
            )
        return cls(
            _native.fresh_windows_hardened_provider(tpm_key_name)  # type: ignore[union-attr]
        )

    @property
    def tier(self) -> int:
        """Returns ``TIER_HARDWARE_BOUND`` (= 2)."""
        return self._inner.tier_byte()

    @property
    def tag(self) -> int:
        """Returns ``PROVIDER_TAG_WINDOWS_TPM`` (= 4)."""
        return self._inner.tag_byte()

    def seal_master(self, master_seed: bytes) -> SealedKey:
        """Seal a 32-byte master seed; tag is bound to WindowsTpm."""
        if len(master_seed) != 32:
            raise ValueError(
                f"master_seed must be 32 bytes, got {len(master_seed)}"
            )
        sealed_bytes, tag = self._inner.seal_master(master_seed)
        return SealedKey(bytes=sealed_bytes, tag=tag)

    def derive_child(self, sealed_master: SealedKey, context_tag: bytes) -> SealedKey:
        child_bytes, tag = self._inner.derive_child(
            sealed_master.bytes,
            sealed_master.tag,
            context_tag,
        )
        return SealedKey(bytes=child_bytes, tag=tag)

    def sealed_sign(self, sealed: SealedKey, transcript: bytes) -> bytes:
        return self._inner.sealed_sign(sealed.bytes, sealed.tag, transcript)

    def verifying_key(self, sealed: SealedKey) -> bytes:
        return self._inner.verifying_key(sealed.bytes, sealed.tag)

    def attest(
        self,
        sealed: SealedKey,
        peer_nonce: bytes,
        issued_unix: int,
        deadline_unix: int,
        issuer_sdp_pubkey: bytes,
        field_witness: Optional[bytes] = None,
    ) -> AttestationDoc:
        """Issue a TPM-rooted attestation doc. Same shape as
        :py:meth:`SoftwareProvider.attest` but the resulting
        ``platform_quote`` carries the ECDSA-P256 signature produced
        by the TPM-resident attestation key — peers can cross-platform
        verify the TPM root via the pure-Rust verifier in
        ``ol_confidential::platform_quote``.
        """
        if len(issuer_sdp_pubkey) != 32:
            raise ValueError(
                f"issuer_sdp_pubkey must be 32 bytes, got {len(issuer_sdp_pubkey)}"
            )
        result = self._inner.attest(
            sealed.bytes,
            sealed.tag,
            peer_nonce,
            issued_unix,
            deadline_unix,
            issuer_sdp_pubkey,
            field_witness,
        )
        (tag, master_vk, nonce, iss, dl, cmt, quote, sdp, sig) = result
        return AttestationDoc(
            provider_tag=tag,
            master_vk=master_vk,
            peer_nonce=nonce,
            issued_unix=iss,
            deadline_unix=dl,
            field_witness_commitment=cmt,
            platform_quote=quote,
            issuer_sdp_pubkey=sdp,
            master_sig=sig,
        )


def has_windows_tpm_provider() -> bool:
    """Return True iff the native wheel was built with ``--features
    windows-tpm`` and the :class:`WindowsHardenedProvider` Python
    class is therefore usable. Callers should check this at daemon
    boot and fall back to :class:`SoftwareProvider` otherwise."""
    if not HAS_NATIVE:
        return False
    return bool(getattr(_native, "HAS_WINDOWS_TPM_PROVIDER", False))


def fresh_attestation_nonce() -> bytes:
    """Generate a fresh 32-byte attestation peer-challenge nonce."""
    _require_native()
    return _native.attestation_nonce()  # type: ignore[union-attr]


#: Provider-tier floor bytes — match Rust ``ConfidentialTier`` ordering.
#: ``Software`` accepts any tier; higher floors reject docs from
#: weaker providers (audit H4: enforced inside ``verify_attestation``
#: rather than left to callers).
TIER_SOFTWARE: int = 1
TIER_HARDWARE_BOUND: int = 2
TIER_HARDWARE_ATTESTED: int = 3


def verify_attestation(
    doc: AttestationDoc,
    expected_peer_nonce: bytes,
    now_unix: int,
    expected_issuer_sdp_pubkey: bytes,
    expected_field_witness: Optional[bytes] = None,
    min_tier: int = TIER_SOFTWARE,
) -> None:
    """Verify an attestation doc. Raises ``ValueError`` on any failure
    (bad master sig, expired, nonce mismatch, witness mismatch,
    freshness window too wide, provider tier below ``min_tier``,
    issuer-SDP-pubkey mismatch).

    ``expected_issuer_sdp_pubkey`` (audit C1, May 2026) is the 32-byte
    Ed25519 SDP-layer pubkey of the channel identity the verifier is
    actually talking to. The doc's embedded ``issuer_sdp_pubkey`` MUST
    byte-equal this — defeats the identity-confusion attack where a
    peer attests with another principal's master_vk under their own
    SDP key.

    ``min_tier`` defaults to ``TIER_SOFTWARE`` (accept any tier). Pass
    ``TIER_HARDWARE_BOUND`` to require the issuer to hold the master
    inside a hardware secure element (Apple Secure Enclave / Android
    StrongBox / Windows TPM / Intel SGX / AMD SEV-SNP / TrustZone) —
    closes the silent-TPM-downgrade vector after a peer was pinned at
    a hardware tier.
    """
    if len(expected_issuer_sdp_pubkey) != 32:
        raise ValueError(
            f"expected_issuer_sdp_pubkey must be 32 bytes, got {len(expected_issuer_sdp_pubkey)}"
        )
    _require_native()
    _native.verify(  # type: ignore[union-attr]
        doc.provider_tag,
        doc.master_vk,
        doc.peer_nonce,
        doc.issued_unix,
        doc.deadline_unix,
        doc.field_witness_commitment,
        doc.platform_quote,
        doc.issuer_sdp_pubkey,
        doc.master_sig,
        expected_peer_nonce,
        now_unix,
        expected_issuer_sdp_pubkey,
        expected_field_witness,
        min_tier,
    )


def attestation_freshness_window_secs() -> int:
    """The 30s default freshness window for attestation docs.
    Issuers MUST set ``deadline_unix - issued_unix ≤`` this."""
    _require_native()
    return int(_native.ATTESTATION_FRESHNESS_WINDOW_SECS)  # type: ignore[union-attr]


class SealedMasterIdentity:
    """High-level daemon-side wrapper holding a sealed master.

    Lifecycle:
        # Boot: read the at-rest seed (DPAPI on Windows, raw on POSIX
        # under `master_seed.load_or_create_seed`), seal it, then
        # wipe the plaintext from process memory.
        sealed = SealedMasterIdentity.from_seed_bytes(seed_bytes)
        seed_bytes = None  # caller should also `del` or bytearray-zero

        # Hot path: sign / attest / verifying_key all go through the
        # sealed handle. The 32-byte plaintext only re-materializes
        # briefly inside the Rust provider during each sign.
        sig = sealed.sign(b"transcript")
        vk = sealed.master_vk()
        doc = sealed.attest(peer_nonce, issued_unix, deadline_unix)

    Compared to holding the plaintext seed in a module-level variable
    for the daemon's lifetime, the sealed handle:

    - Keeps the master seed in plaintext for ~microseconds per sign
      instead of hours.
    - Re-zeroizes the unsealed buffer on every sign exit (Rust
      ``Zeroize`` impl on drop of the temporary buffer).
    - Refuses to expose the plaintext to Python at all — there's no
      ``.seed()`` accessor. Daemon code can sign / verify / attest
      but cannot leak the raw bytes back to a log line.

    NOT a replacement for the on-disk DPAPI / passphrase / hardware
    backup — those still gate WHO can construct this object at boot.
    This wrapper closes the *runtime* gap.
    """

    __slots__ = ("_provider", "_sealed")

    def __init__(
        self,
        provider: SoftwareProvider,
        sealed: SealedKey,
    ) -> None:
        self._provider = provider
        self._sealed = sealed

    @classmethod
    def from_seed_bytes(cls, seed: bytes) -> "SealedMasterIdentity":
        """Construct from a fresh 32-byte master seed. The caller is
        responsible for zeroizing the input buffer after this call —
        Python ``bytes`` are immutable so the buffer pattern is
        usually ``bytearray`` + ``bytes_view[:] = b"\\x00" * 32``.
        """
        if len(seed) != 32:
            raise ValueError(f"master seed must be 32 bytes, got {len(seed)}")
        provider = SoftwareProvider.fresh()
        sealed = provider.seal_master(bytes(seed))
        return cls(provider, sealed)

    @property
    def provider_tier(self) -> int:
        return self._provider.tier

    @property
    def provider_tag(self) -> int:
        return self._provider.tag

    def master_vk(self) -> bytes:
        """Return the 1984-byte hybrid verifying key for this master."""
        return self._provider.verifying_key(self._sealed)

    def sign(self, transcript: bytes) -> bytes:
        """Sign ``transcript`` under the sealed master."""
        return self._provider.sealed_sign(self._sealed, transcript)

    def derive_child(self, context_tag: bytes) -> "SealedMasterIdentity":
        """Derive a new ``SealedMasterIdentity`` under a context tag.
        Used for per-day / per-channel / per-purpose subkeys without
        exposing the master."""
        child = self._provider.derive_child(self._sealed, context_tag)
        return SealedMasterIdentity(self._provider, child)

    def attest(
        self,
        peer_nonce: bytes,
        issued_unix: int,
        deadline_unix: int,
        issuer_sdp_pubkey: bytes,
        field_witness: Optional[bytes] = None,
    ) -> AttestationDoc:
        """Issue an attestation doc binding this master to a peer
        challenge AND to the daemon's own SDP-layer Ed25519 pubkey
        (audit C1, May 2026)."""
        return self._provider.attest(
            self._sealed,
            peer_nonce,
            issued_unix,
            deadline_unix,
            issuer_sdp_pubkey,
            field_witness,
        )
