"""Types for :mod:`one_link_native.confidential`."""

from typing import Protocol, TypeAlias, final, type_check_only

HAS_WINDOWS_TPM_PROVIDER: bool
ATTESTATION_NONCE_LEN: int
ATTESTATION_FRESHNESS_WINDOW_SECS: int
PROVIDER_TAG_SOFTWARE: int
PROVIDER_TAG_WINDOWS_TPM: int
PROVIDER_TAG_APPLE_SE: int
PROVIDER_TAG_ANDROID_STRONGBOX: int
PROVIDER_TAG_INTEL_SGX: int
PROVIDER_TAG_AMD_SEV_SNP: int
PROVIDER_TAG_ARM_TRUSTZONE: int

AttestationTuple: TypeAlias = tuple[
    int,
    bytes,
    bytes,
    int,
    int,
    bytes | None,
    bytes,
    bytes,
    bytes,
]

@type_check_only
class _Provider(Protocol):
    def tier_byte(self) -> int: ...
    def tag_byte(self) -> int: ...
    def seal_master(self, seed: bytes) -> tuple[bytes, int]: ...
    def derive_child(
        self, sealed_master_bytes: bytes, sealed_master_tag: int, context_tag: bytes
    ) -> tuple[bytes, int]: ...
    def sealed_sign(self, sealed_bytes: bytes, sealed_tag: int, transcript: bytes) -> bytes: ...
    def verifying_key(self, sealed_bytes: bytes, sealed_tag: int) -> bytes: ...
    def attest(
        self,
        sealed_bytes: bytes,
        sealed_tag: int,
        peer_nonce: bytes,
        issued_unix: int,
        deadline_unix: int,
        issuer_sdp_pubkey: bytes,
        field_witness: bytes | None = ...,
    ) -> AttestationTuple: ...

@final
class PySoftwareProvider:
    def tier_byte(self) -> int: ...
    def tag_byte(self) -> int: ...
    def seal_master(self, seed: bytes) -> tuple[bytes, int]: ...
    def derive_child(
        self, sealed_master_bytes: bytes, sealed_master_tag: int, context_tag: bytes
    ) -> tuple[bytes, int]: ...
    def sealed_sign(self, sealed_bytes: bytes, sealed_tag: int, transcript: bytes) -> bytes: ...
    def verifying_key(self, sealed_bytes: bytes, sealed_tag: int) -> bytes: ...
    def attest(
        self,
        sealed_bytes: bytes,
        sealed_tag: int,
        peer_nonce: bytes,
        issued_unix: int,
        deadline_unix: int,
        issuer_sdp_pubkey: bytes,
        field_witness: bytes | None = ...,
    ) -> AttestationTuple: ...

def fresh_software_provider() -> PySoftwareProvider: ...
def software_provider_from_seed(seed: bytes) -> PySoftwareProvider: ...
def fresh_windows_hardened_provider(_tpm_key_name: str) -> _Provider: ...
def attestation_nonce() -> bytes: ...
def verify(
    provider_tag: int,
    master_vk: bytes,
    peer_nonce: bytes,
    issued_unix: int,
    deadline_unix: int,
    field_witness_commitment: bytes | None,
    platform_quote: bytes,
    issuer_sdp_pubkey: bytes,
    master_sig: bytes,
    expected_peer_nonce: bytes,
    now_unix: int,
    expected_issuer_sdp_pubkey: bytes,
    expected_field_witness: bytes | None = ...,
    min_tier_byte: int = ...,
) -> None: ...
