//! Device-class taxonomy.
//!
//! Drives Layer-2 policy decisions (which devices can grant new caps,
//! which can act as quorum members, which carry the audit log) and is
//! bound into the subkey derivation transcript so two devices of the
//! same class with different `device_id`s never produce the same key.

use zeroize::Zeroize;

/// Length of the canonical class tag mixed into the subkey-derivation
/// transcript.
pub const DEVICE_CLASS_TAG_LEN: usize = 8;

/// The set of device classes that the mesh recognises.
///
/// Adding a new class is a wire-format change; existing serialized
/// keys must keep their tag mapping forever. Tags are 8-byte ASCII.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeviceClass {
    /// Mobile phone (typically battery-constrained, NAT-traversed,
    /// frequent sleep/wake cycles).
    Phone,
    /// Laptop (occasionally connected, often battery, large disk).
    Laptop,
    /// Tablet (battery, often Wi-Fi only, big screen for previews).
    Tablet,
    /// Desktop (always-on, plugged in, big disk, often the courier).
    Desktop,
    /// Headless server or NAS (always-on, no UI, the durability tier).
    Server,
    /// Wearable (smartwatch / ring; tiny battery, intermittent BT).
    Wearable,
    /// Smart-home appliance (TV / hub / `IoT` bridge).
    Appliance,
    /// Generic — anything not better classified.
    Generic,
}

impl DeviceClass {
    /// Canonical 8-byte ASCII tag. Stable forever (wire format).
    ///
    /// ```
    /// use ol_device_mesh::DeviceClass;
    /// assert_eq!(&DeviceClass::Phone.tag(), b"OL-PHONE");
    /// ```
    #[must_use]
    pub const fn tag(self) -> [u8; DEVICE_CLASS_TAG_LEN] {
        match self {
            Self::Phone => *b"OL-PHONE",
            Self::Laptop => *b"OL-LAPTP",
            Self::Tablet => *b"OL-TABLT",
            Self::Desktop => *b"OL-DESKT",
            Self::Server => *b"OL-SERVR",
            Self::Wearable => *b"OL-WEARB",
            Self::Appliance => *b"OL-APPLI",
            Self::Generic => *b"OL-GENRC",
        }
    }

    /// Parse a tag back into a class. Returns `None` on unknown tag.
    #[must_use]
    pub const fn from_tag(tag: &[u8; DEVICE_CLASS_TAG_LEN]) -> Option<Self> {
        match tag {
            b"OL-PHONE" => Some(Self::Phone),
            b"OL-LAPTP" => Some(Self::Laptop),
            b"OL-TABLT" => Some(Self::Tablet),
            b"OL-DESKT" => Some(Self::Desktop),
            b"OL-SERVR" => Some(Self::Server),
            b"OL-WEARB" => Some(Self::Wearable),
            b"OL-APPLI" => Some(Self::Appliance),
            b"OL-GENRC" => Some(Self::Generic),
            _ => None,
        }
    }

    /// All known classes in declaration order. Used by KAT tests.
    #[must_use]
    pub const fn all() -> [Self; 8] {
        [
            Self::Phone,
            Self::Laptop,
            Self::Tablet,
            Self::Desktop,
            Self::Server,
            Self::Wearable,
            Self::Appliance,
            Self::Generic,
        ]
    }
}

// Sanity zeroize — DeviceClass is Copy, but the type contains no
// secrets so this is a no-op outside of trait-bound generic code.
impl Zeroize for DeviceClass {
    fn zeroize(&mut self) {
        *self = Self::Generic;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_round_trip() {
        for c in DeviceClass::all() {
            assert_eq!(DeviceClass::from_tag(&c.tag()), Some(c));
        }
    }

    #[test]
    fn all_tags_are_distinct() {
        let mut seen = std::collections::HashSet::new();
        for c in DeviceClass::all() {
            assert!(seen.insert(c.tag()), "tag collision: {c:?}");
        }
        assert_eq!(seen.len(), DeviceClass::all().len());
    }

    #[test]
    fn unknown_tag_rejected() {
        assert_eq!(DeviceClass::from_tag(b"GARBAGE!"), None);
        assert_eq!(DeviceClass::from_tag(b"OL-OTHER"), None);
        assert_eq!(DeviceClass::from_tag(&[0u8; DEVICE_CLASS_TAG_LEN]), None);
    }
}
