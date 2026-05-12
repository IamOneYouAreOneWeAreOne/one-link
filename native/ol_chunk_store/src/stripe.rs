//! Stripe descriptor for Reed-Solomon erasure coding per [ADR-0004].
//!
//! Phase A1 reserves the descriptor field in every chunk_log record so
//! Phase C's encoder/decoder can plug in without a format break. In A1,
//! every chunk has `role = NotStriped` and the other fields are zero.
//!
//! ```text
//! struct StripeDescriptor {
//!     stripe_id_lo64:  u64,
//!     stripe_role:     u8,
//!     stripe_index:    u8,
//!     stripe_k:        u8,
//!     stripe_m:        u8,
//!     cohort_id_lo64:  u64,
//!     reserved:        [u8; 4],   // Must be zero
//! }
//! ```
//!
//! Total: 24 bytes, all little-endian.
//!
//! [ADR-0004]: ../../../docs/decisions/0004-stripe-layout.md

use crate::error::ChunkStoreError;

/// On-disk length of a `StripeDescriptor` in bytes.
pub const STRIPE_DESCRIPTOR_LEN: usize = 24;

/// Role of this chunk within its stripe.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum StripeRole {
    /// Data shard (one of `stripe_k` per stripe).
    Data,
    /// Parity shard (one of `stripe_m` per stripe).
    Parity,
    /// Standalone chunk; not part of any RS stripe.
    NotStriped,
}

impl StripeRole {
    /// On-disk byte representation.
    #[inline]
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::Parity => 1,
            Self::NotStriped => 2,
        }
    }

    /// Decode from the on-disk byte. Returns `None` for unknown values.
    #[must_use]
    pub const fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Data),
            1 => Some(Self::Parity),
            2 => Some(Self::NotStriped),
            _ => None,
        }
    }
}

/// Stripe descriptor per [ADR-0004](../../../docs/decisions/0004-stripe-layout.md).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct StripeDescriptor {
    /// 64-bit prefix of the stripe identity (BLAKE3 of canonical stripe membership).
    pub stripe_id_lo64: u64,
    /// Data / Parity / NotStriped.
    pub stripe_role: StripeRole,
    /// Position within stripe (`0..k` for Data, `0..m` for Parity).
    pub stripe_index: u8,
    /// `k` data shards in the stripe.
    pub stripe_k: u8,
    /// `m` parity shards in the stripe.
    pub stripe_m: u8,
    /// 64-bit prefix of the cohort identity (mixes into parity derivation).
    pub cohort_id_lo64: u64,
}

impl StripeDescriptor {
    /// Standalone (non-striped) descriptor — what every Phase A1 chunk uses
    /// before the RS encoder ships in Phase C.
    pub const NONE: Self = Self {
        stripe_id_lo64: 0,
        stripe_role: StripeRole::NotStriped,
        stripe_index: 0,
        stripe_k: 0,
        stripe_m: 0,
        cohort_id_lo64: 0,
    };

    /// Encode into a 24-byte buffer.
    #[must_use]
    pub fn encode(&self) -> [u8; STRIPE_DESCRIPTOR_LEN] {
        let mut buf = [0u8; STRIPE_DESCRIPTOR_LEN];
        buf[0..8].copy_from_slice(&self.stripe_id_lo64.to_le_bytes());
        buf[8] = self.stripe_role.as_u8();
        buf[9] = self.stripe_index;
        buf[10] = self.stripe_k;
        buf[11] = self.stripe_m;
        buf[12..20].copy_from_slice(&self.cohort_id_lo64.to_le_bytes());
        // bytes 20..24 reserved-zero
        buf
    }

    /// Decode from a 24-byte buffer.
    ///
    /// # Errors
    ///
    /// - [`ChunkStoreError::InvalidStripeDescriptor`] if the role byte
    ///   is unrecognized or the reserved bytes are non-zero.
    pub fn decode(buf: &[u8; STRIPE_DESCRIPTOR_LEN]) -> Result<Self, ChunkStoreError> {
        let stripe_id_lo64 = u64::from_le_bytes(buf[0..8].try_into().expect("8 bytes"));
        let stripe_role = StripeRole::from_u8(buf[8]).ok_or(
            ChunkStoreError::InvalidStripeDescriptor("unknown role byte"),
        )?;
        let stripe_index = buf[9];
        let stripe_k = buf[10];
        let stripe_m = buf[11];
        let cohort_id_lo64 = u64::from_le_bytes(buf[12..20].try_into().expect("8 bytes"));
        if !buf[20..24].iter().all(|b| *b == 0) {
            return Err(ChunkStoreError::InvalidStripeDescriptor(
                "reserved bytes non-zero",
            ));
        }
        Ok(Self {
            stripe_id_lo64,
            stripe_role,
            stripe_index,
            stripe_k,
            stripe_m,
            cohort_id_lo64,
        })
    }

    /// True iff this descriptor represents a non-striped chunk (the
    /// Phase A1 default).
    #[inline]
    #[must_use]
    pub fn is_not_striped(&self) -> bool {
        self.stripe_role == StripeRole::NotStriped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_round_trip() {
        let buf = StripeDescriptor::NONE.encode();
        assert_eq!(buf.len(), STRIPE_DESCRIPTOR_LEN);
        let parsed = StripeDescriptor::decode(&buf).unwrap();
        assert_eq!(parsed, StripeDescriptor::NONE);
        assert!(parsed.is_not_striped());
    }

    #[test]
    fn striped_round_trip() {
        let desc = StripeDescriptor {
            stripe_id_lo64: 0x1234_5678_9ABC_DEF0,
            stripe_role: StripeRole::Data,
            stripe_index: 7,
            stripe_k: 10,
            stripe_m: 4,
            cohort_id_lo64: 0xCAFE_BABE_F00D_BAAD,
        };
        let buf = desc.encode();
        let parsed = StripeDescriptor::decode(&buf).unwrap();
        assert_eq!(parsed, desc);
    }

    #[test]
    fn parity_role_round_trip() {
        let desc = StripeDescriptor {
            stripe_id_lo64: 1,
            stripe_role: StripeRole::Parity,
            stripe_index: 2,
            stripe_k: 10,
            stripe_m: 4,
            cohort_id_lo64: 99,
        };
        let buf = desc.encode();
        let parsed = StripeDescriptor::decode(&buf).unwrap();
        assert_eq!(parsed.stripe_role, StripeRole::Parity);
        assert_eq!(parsed, desc);
    }

    #[test]
    fn rejects_unknown_role() {
        let mut buf = StripeDescriptor::NONE.encode();
        buf[8] = 99;
        let result = StripeDescriptor::decode(&buf);
        assert!(matches!(
            result,
            Err(ChunkStoreError::InvalidStripeDescriptor(_))
        ));
    }

    #[test]
    fn rejects_nonzero_reserved() {
        let mut buf = StripeDescriptor::NONE.encode();
        buf[20] = 0x42;
        let result = StripeDescriptor::decode(&buf);
        assert!(matches!(
            result,
            Err(ChunkStoreError::InvalidStripeDescriptor(_))
        ));
    }

    #[test]
    fn role_byte_canonical() {
        assert_eq!(StripeRole::Data.as_u8(), 0);
        assert_eq!(StripeRole::Parity.as_u8(), 1);
        assert_eq!(StripeRole::NotStriped.as_u8(), 2);
    }
}
