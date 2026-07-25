"""Adapter for the file-engine v2 native confidential-compute provider
(``ol_confidential`` via ``one_link_native``).

Row 10 of the Coherence Mesh. Provides the sealed-op surface
(seal_master / derive_child / sealed_sign / verifying_key / attest)
and an attestation-envelope verifier backed by Rust's ``ol_confidential``
crate. Temporary native plaintext buffers use ``Zeroize`` and the hybrid-sign
primitive uses ``ol_pqsig`` Ed25519+ML-DSA-65, but neither property makes the
Python/Rust process a confidential-computing enclave or protects it from
same-user malware able to inspect or inject into that process. The wire format
authenticates its fields under the selected provider; it is not by itself proof
of hardware origin or remote platform integrity.

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

# NOTE: the TIER_* tier-byte constants are defined ONCE, below, next to
# verify_attestation (values 1/2/3, matching the Rust pyo3 layer's
# min_tier_byte match + tier_byte(): 1=Software, 2=HardwareBound,
# 3=HardwareAttested). An earlier stale 0/1/2 copy lived here and was
# silently overwritten by that block — its values were WRONG (0 is
# rejected by Rust as an unknown tier byte, and 1 would mean Software
# where HardwareBound was intended), so it has been removed.


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
    check before the AEAD even runs. A tag is an encoded provider claim, not
    independent evidence that key operations happened in that hardware.
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
    """Wire envelope for a Row 10 attestation transcript. The master sig
    transitively commits to every other field (including
    ``platform_quote`` and ``issuer_sdp_pubkey``).

    ``issuer_sdp_pubkey`` is the 32-byte Ed25519 verifying-key of the
    issuer's SDP-layer identity (the key that signs the WebRTC SDP
    envelope). The verifier checks this matches the channel identity
    they're actually talking to. Within this verifier model that binding
    rejects substitution of someone else's master_vk under the caller's SDP
    key (audit C1, ``-v2`` domain bump May 2026); it is not a general remote-
    platform attestation proof.
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
        """Seal a 32-byte master seed for persistence.

        The provider tag and AEAD authenticator make accidental or malicious
        blob modification detectable under the provider key. Confidentiality
        still depends on that key and the host process; this does not make an
        untrusted same-user process safe.
        """
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
    """Audit M6 — Windows provider with a TPM-backed attestation-signing key.

    Wraps the native ``WindowsHardenedProvider`` (composition of
    ``SoftwareProvider`` for the seal/sign/verify primitives PLUS a
    TPM-backed ECDSA-P256 attestation key). The public surface is
    intentionally identical to :class:`SoftwareProvider` so callers
    can swap providers behind a feature gate without changing call
    sites. Master sealing/signing remains in ``SoftwareProvider`` process
    memory. The current ``platform_quote`` is a project-specific public-key
    blob plus ECDSA signature; verification proves possession/continuity for
    that key, but there is no EK/vendor certificate chain or standard TPM quote
    proving physical TPM origin to a remote peer. It therefore must not be used
    as proof that the master is hardware-resident or cross-host
    non-transferable.

    Available only when the native wheel is built with
    ``maturin develop --release --features windows-tpm`` on a Windows
    host with a functional TPM 2.0. On any other platform / wheel,
    :py:meth:`fresh` raises :class:`ConfidentialNotInstalled`.

    Lifecycle:
        provider = WindowsHardenedProvider.fresh("OL-daemon-attest-v1")
        sealed = provider.seal_master(master_seed_32_bytes)
        doc = provider.attest(sealed, peer_nonce, t_issue, t_deadline,
                              issuer_sdp_pubkey)
        # `doc.platform_quote` is the project-specific ECDSA-P256 possession
        # transcript; a peer can verify its signature/continuity but not a
        # vendor-certified physical TPM origin.
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
        """Seal a seed with the composed software provider and Windows tag.

        The tag participates in format/policy checks; it is not evidence that
        this master-sealing operation happened inside the TPM.
        """
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
        """Issue a Windows-provider attestation doc. Same shape as
        :py:meth:`SoftwareProvider.attest` but the resulting
        ``platform_quote`` carries the ECDSA-P256 signature produced
        through the configured TPM-backed key. Peers can verify the
        project-specific public-key/signature transcript via
        ``ol_confidential::platform_quote``; without an EK/vendor chain or
        standard quote they cannot remotely establish physical TPM origin.
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
    byte-equal this. That rejects the modeled cross-identity substitution; it
    does not prove the integrity of the issuer's process or platform.

    ``min_tier`` defaults to ``TIER_SOFTWARE`` (accept any tier). Pass
    ``TIER_HARDWARE_BOUND`` to require a document whose authenticated encoded
    provider tier meets that policy floor. This tier check is conditional on
    the provider's evidence model; a provider tag alone is self-asserted, and
    the current composed Windows provider does not prove that its master key is
    held inside a hardware secure element.
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

    Compared to intentionally holding the plaintext seed in a module-level
    variable for the daemon's lifetime, the software-sealed handle:

    - Reduces routine plaintext residency to the duration of an operation;
      scheduling, allocator copies, and compiler/runtime behavior prevent a
      precise universal duration guarantee.
    - Requests zeroization of the native temporary on operation exit (Rust
      ``Zeroize`` on drop), without proving every process-memory copy vanished.
    - Refuses to expose the plaintext to Python at all — there's no
      ``.seed()`` accessor. Daemon code can sign / verify / attest
      but ordinary wrapper calls cannot return it directly to a log line.

    NOT a replacement for the on-disk DPAPI / passphrase / hardware
    backup — those still gate WHO can construct this object at boot.
    It reduces accidental exposure; same-user process inspection/injection can
    still obtain plaintext or the provider key and is outside this boundary.
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
