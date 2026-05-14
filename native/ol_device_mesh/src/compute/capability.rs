//! Device capability enumeration.
//!
//! Each tag is a stable byte string mixed into the
//! [`super::CapabilityAttestation`] transcript so adding a new
//! capability later is a wire-format change (deliberately).

/// Upper bound on how many capabilities one device can claim.
pub const MAX_CAPABILITIES_PER_DEVICE: usize = 32;

/// What a device can DO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DeviceCapability {
    /// Hardware-accelerated GPU (CUDA / Metal / `ROCm` / NPU).
    Gpu,
    /// Many-core CPU with adequate cooling (≥ 8 cores, mains
    /// power). Suitable for heavy CPU work like video transcoding.
    CpuHeavy,
    /// Microphone input (for voice capture / transcription input).
    Microphone,
    /// Camera input (for photo / video capture).
    Camera,
    /// Large persistent disk (≥ 500 GB free).
    LargeDisk,
    /// Low-latency wired network (Ethernet / fibre).
    LowLatencyNet,
    /// Mains-powered + no automatic sleep (typically desktop /
    /// server). Eligible for long-running tasks.
    AlwaysOn,
    /// User-facing display + input (typically laptop / desktop /
    /// tablet). Eligible for tasks that require user interaction.
    Display,
    /// GPS / geolocation services.
    GpsLocation,
    /// Hardware security module (TPM / Secure Enclave / `StrongBox` /
    /// `TrustZone`) capable of signing without exposing keys.
    HardwareSecurity,
    /// Trusted execution environment (Intel SGX / AMD SEV-SNP /
    /// Apple Secure Memory / ARM `TrustZone` — confidential compute).
    Tee,
}

impl DeviceCapability {
    /// Stable 8-byte tag mixed into the attestation transcript.
    #[must_use]
    pub const fn tag(self) -> [u8; 8] {
        match self {
            Self::Gpu => *b"OL-CP-GP",
            Self::CpuHeavy => *b"OL-CP-CH",
            Self::Microphone => *b"OL-CP-MC",
            Self::Camera => *b"OL-CP-CA",
            Self::LargeDisk => *b"OL-CP-LD",
            Self::LowLatencyNet => *b"OL-CP-LN",
            Self::AlwaysOn => *b"OL-CP-AO",
            Self::Display => *b"OL-CP-DP",
            Self::GpsLocation => *b"OL-CP-GS",
            Self::HardwareSecurity => *b"OL-CP-HS",
            Self::Tee => *b"OL-CP-TE",
        }
    }

    /// Parse a tag back into a capability. Returns `None` on
    /// unknown tag.
    #[must_use]
    pub const fn from_tag(tag: &[u8; 8]) -> Option<Self> {
        match tag {
            b"OL-CP-GP" => Some(Self::Gpu),
            b"OL-CP-CH" => Some(Self::CpuHeavy),
            b"OL-CP-MC" => Some(Self::Microphone),
            b"OL-CP-CA" => Some(Self::Camera),
            b"OL-CP-LD" => Some(Self::LargeDisk),
            b"OL-CP-LN" => Some(Self::LowLatencyNet),
            b"OL-CP-AO" => Some(Self::AlwaysOn),
            b"OL-CP-DP" => Some(Self::Display),
            b"OL-CP-GS" => Some(Self::GpsLocation),
            b"OL-CP-HS" => Some(Self::HardwareSecurity),
            b"OL-CP-TE" => Some(Self::Tee),
            _ => None,
        }
    }

    /// All known capabilities in declaration order.
    #[must_use]
    pub const fn all() -> [Self; 11] {
        [
            Self::Gpu,
            Self::CpuHeavy,
            Self::Microphone,
            Self::Camera,
            Self::LargeDisk,
            Self::LowLatencyNet,
            Self::AlwaysOn,
            Self::Display,
            Self::GpsLocation,
            Self::HardwareSecurity,
            Self::Tee,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_round_trip() {
        for c in DeviceCapability::all() {
            assert_eq!(DeviceCapability::from_tag(&c.tag()), Some(c));
        }
    }

    #[test]
    fn tags_distinct() {
        let mut seen = std::collections::HashSet::new();
        for c in DeviceCapability::all() {
            assert!(seen.insert(c.tag()), "tag collision on {c:?}");
        }
    }

    #[test]
    fn unknown_tag_rejected() {
        assert_eq!(DeviceCapability::from_tag(b"GARBAGE!"), None);
        assert_eq!(DeviceCapability::from_tag(b"OL-CP-XX"), None);
    }
}
