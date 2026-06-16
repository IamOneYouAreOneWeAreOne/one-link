//! Argon2id-derived duress key.
//!
//! User types a short code (e.g., a 6-digit number or a 4-word
//! passphrase) under stress. We need a serious work factor to defeat
//! offline brute force on a captured envelope; Argon2id with
//! memory-hard parameters is the standard tool.
//!
//! `m_cost = 19,456 KiB` and `t_cost = 2` are the OWASP-recommended
//! "balanced" Argon2id defaults that complete in about 50 ms on a
//! 2025 mobile `SoC`. The CPU+memory cost for an attacker is ~25 ×
//! that on commodity hardware — sufficient given that a 6-digit
//! duress code has only 1 M possibilities anyway (the user picks
//! something memorable). Daemons SHOULD enforce a minimum code
//! length + entropy at the entry surface.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::ZeroizeOnDrop;

use crate::errors::{DeviceMeshError, DeviceMeshResult};

/// Length of the derived key bytes.
pub const DURESS_KEY_LEN: usize = 32;

/// Memory cost for Argon2id (KiB).
pub const ARGON2_M_COST_KIB: u32 = 19_456;

/// Time cost (iterations).
pub const ARGON2_T_COST: u32 = 2;

/// Parallelism.
pub const ARGON2_P_COST: u32 = 1;

/// A 32-byte symmetric key derived from a duress code.
#[derive(ZeroizeOnDrop)]
pub struct DuressCode {
    key: [u8; DURESS_KEY_LEN],
}

impl DuressCode {
    /// Borrow the raw key bytes for AEAD use. Do NOT log.
    #[must_use]
    pub const fn key_bytes(&self) -> &[u8; DURESS_KEY_LEN] {
        &self.key
    }
}

impl std::fmt::Debug for DuressCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DuressCode").finish_non_exhaustive()
    }
}

/// Derive a [`DuressCode`] from the user-entered bytes + a per-
/// envelope salt via Argon2id.
pub fn derive_duress_key(user_code: &[u8], salt: &[u8]) -> DeviceMeshResult<DuressCode> {
    if user_code.is_empty() {
        return Err(DeviceMeshError::DuressCodeEmpty);
    }
    let params = Params::new(
        ARGON2_M_COST_KIB,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(DURESS_KEY_LEN),
    )
    .map_err(|e| DeviceMeshError::DuressArgon2Failed(format!("{e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; DURESS_KEY_LEN];
    argon
        .hash_password_into(user_code, salt, &mut key)
        .map_err(|e| DeviceMeshError::DuressArgon2Failed(format!("{e}")))?;
    Ok(DuressCode { key })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_codes_yield_distinct_keys() {
        let salt = b"01234567890123456789012345678901";
        let a = derive_duress_key(b"hunter22", salt).unwrap();
        let b = derive_duress_key(b"hunter23", salt).unwrap();
        assert_ne!(a.key_bytes(), b.key_bytes());
    }

    #[test]
    fn distinct_salts_yield_distinct_keys() {
        let a = derive_duress_key(b"hunter22", b"01234567890123456789012345678901").unwrap();
        let b = derive_duress_key(b"hunter22", b"abcdefghabcdefghabcdefghabcdefgh").unwrap();
        assert_ne!(a.key_bytes(), b.key_bytes());
    }

    #[test]
    fn same_code_same_salt_yields_same_key() {
        let salt = b"01234567890123456789012345678901";
        let a = derive_duress_key(b"hunter22", salt).unwrap();
        let b = derive_duress_key(b"hunter22", salt).unwrap();
        assert_eq!(a.key_bytes(), b.key_bytes());
    }

    #[test]
    fn empty_code_rejected() {
        let salt = b"01234567890123456789012345678901";
        let err = derive_duress_key(b"", salt).unwrap_err();
        assert!(matches!(err, DeviceMeshError::DuressCodeEmpty));
    }
}
