//! Runtime confidential-compute tier and platform detection.

/// Claimed provider hardness tier.
///
/// Ordered: `Software < HardwareBound < HardwareAttested`. This enum is
/// policy metadata, not evidence: peers must verify the provider-specific
/// quote, trust root, measurements, and key-operation boundary before relying
/// on a hardware tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConfidentialTier {
    /// Software-only baseline. Master key sealed under a per-process
    /// ephemeral ChaCha20-Poly1305 key in the same process; best-effort
    /// cleanup on drop. Does not defeat malware able to inspect/inject into
    /// that process, root malware, or `/proc/mem` capture.
    Software,
    /// Local provider contract claims a key is held inside a hardware secure
    /// element (Apple Secure
    /// Enclave / Android `StrongBox` / Windows TPM / Intel SGX /
    /// AMD SEV-SNP). No vendor attestation chain. Cipher operations
    /// are intended to stay inside the element. A wire tag alone does not
    /// prove this to a peer; provider-specific verification is required.
    HardwareBound,
    /// Hardware-bound AND the peer verified a vendor-issued
    /// attestation chain (Apple App Attest / Android Play Integrity /
    /// Windows TPM EK / Intel quote service) and required measurements.
    HardwareAttested,
}

impl ConfidentialTier {
    /// True if the local tier meets or exceeds a peer-requested floor.
    #[must_use]
    pub const fn meets(self, required: Self) -> bool {
        (self as u8) >= (required as u8)
    }

    /// Map a [`crate::provider::ProviderTag`] (the byte that flows over
    /// the wire in [`crate::attestation::AttestationDoc`]) onto its
    /// claimed local tier. Used by `verify_attestation` to enforce the
    /// `min_tier` floor; callers must still run provider-specific quote/root
    /// verification before treating a tag as hardware evidence.
    #[must_use]
    pub const fn from_provider_tag(tag: crate::provider::ProviderTag) -> Self {
        use crate::provider::ProviderTag;
        match tag {
            ProviderTag::Software => Self::Software,
            ProviderTag::WindowsTpm
            | ProviderTag::AppleSecureEnclave
            | ProviderTag::AndroidStrongBox
            | ProviderTag::IntelSgx
            | ProviderTag::AmdSevSnp
            | ProviderTag::ArmTrustZone => Self::HardwareBound,
        }
    }
}

impl From<ol_hwkey::KeyGuarantee> for ConfidentialTier {
    fn from(value: ol_hwkey::KeyGuarantee) -> Self {
        match value {
            ol_hwkey::KeyGuarantee::TofuOnly => Self::Software,
            ol_hwkey::KeyGuarantee::HardwareBound => Self::HardwareBound,
            ol_hwkey::KeyGuarantee::HardwareAttested => Self::HardwareAttested,
        }
    }
}

/// Detect the strongest tier the local host supports.
///
/// Phase 1 always returns `Software`. Per-platform detection (SGX,
/// SEV-SNP, Secure Enclave, TPM, `TrustZone`) lands in Phase 2 commits
/// alongside the matching provider impl.
#[must_use]
pub fn detect_runtime_tier() -> ConfidentialTier {
    ConfidentialTier::Software
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_ordering() {
        assert!(ConfidentialTier::Software < ConfidentialTier::HardwareBound);
        assert!(ConfidentialTier::HardwareBound < ConfidentialTier::HardwareAttested);
    }

    #[test]
    fn meets_floor() {
        assert!(ConfidentialTier::HardwareAttested.meets(ConfidentialTier::Software));
        assert!(ConfidentialTier::HardwareBound.meets(ConfidentialTier::Software));
        assert!(!ConfidentialTier::Software.meets(ConfidentialTier::HardwareBound));
    }

    #[test]
    fn hwkey_guarantee_round_trip() {
        assert_eq!(
            ConfidentialTier::from(ol_hwkey::KeyGuarantee::TofuOnly),
            ConfidentialTier::Software
        );
        assert_eq!(
            ConfidentialTier::from(ol_hwkey::KeyGuarantee::HardwareBound),
            ConfidentialTier::HardwareBound
        );
        assert_eq!(
            ConfidentialTier::from(ol_hwkey::KeyGuarantee::HardwareAttested),
            ConfidentialTier::HardwareAttested
        );
    }

    #[test]
    fn detect_default_is_software() {
        assert_eq!(detect_runtime_tier(), ConfidentialTier::Software);
    }
}
