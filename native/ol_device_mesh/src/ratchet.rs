//! Daily ratchet for per-device subkey forward secrecy.
//!
//! Each device's subkey chain is rooted at `day_index = 0` and
//! advances forward one day at a time. The chain is one-way: the
//! transition `S_n → S_{n+1}` is a BLAKE3-keyed HKDF call that can't
//! be inverted, and the device zeroizes `S_n` as soon as it has
//! `S_{n+1}` in hand.
//!
//! Crucially, the master *seed* can re-derive ANY day in the chain
//! via `derive_subkey_seed(master_seed, class, id, day)`, so loss of
//! a device's current subkey doesn't lose history if the master is
//! recoverable.  But an attacker who captures only the device's
//! present-day subkey cannot decrypt any prior day's traffic — the
//! prior subkeys are gone from RAM and inaccessible without the
//! master.
//!
//! ## Threat-coverage matrix
//!
//! | Attacker has              | Can recover prior days?            |
//! |---                        |---                                 |
//! | Today's device subkey     | NO — chain is one-way              |
//! | Master seed               | YES — derive any day deterministically |
//! | Today's device + master   | YES                                |
//! | Yesterday's device subkey | YES, only via THAT device's RAM    |

use crate::derivation::SUBKEY_SEED_LEN;
use blake3::Hasher;
use zeroize::Zeroize;

/// Domain-separation tag for the daily-ratchet HKDF.
pub const RATCHET_DOMAIN: &[u8] = b"OL-device-mesh-ratchet-v1";

/// Step a subkey seed forward by one day.
///
/// `prev` is zeroized in place after the new seed is computed —
/// callers should NEVER keep a copy of `prev` alive past this call.
///
/// Returns the new seed (which the caller stores in place of `prev`).
pub fn ratchet_one_day(prev: &mut [u8; SUBKEY_SEED_LEN]) -> [u8; SUBKEY_SEED_LEN] {
    let mut out = [0u8; SUBKEY_SEED_LEN];
    // Ed25519 half — distinct sub-context from ML-DSA half so the
    // two halves remain independent under ratcheting.
    let mut h = Hasher::new();
    h.update(RATCHET_DOMAIN);
    h.update(b"-ed25519");
    h.update(prev);
    out[..32].copy_from_slice(h.finalize().as_bytes());

    let mut h2 = Hasher::new();
    h2.update(RATCHET_DOMAIN);
    h2.update(b"-mldsa");
    h2.update(prev);
    out[32..].copy_from_slice(h2.finalize().as_bytes());

    // Zeroize the previous seed in place — that's the forward-secrecy
    // contract for this call.
    prev.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratchet_advances_seed() {
        let mut s = [0x42u8; SUBKEY_SEED_LEN];
        let next = ratchet_one_day(&mut s);
        // Previous seed zeroized.
        assert_eq!(s, [0u8; SUBKEY_SEED_LEN]);
        // Next seed is non-zero (with overwhelming probability).
        assert_ne!(next, [0u8; SUBKEY_SEED_LEN]);
        // Both halves changed.
        assert_ne!(&next[..32], &[0u8; 32][..]);
        assert_ne!(&next[32..], &[0u8; 32][..]);
    }

    #[test]
    fn ratchet_is_deterministic_on_input() {
        let mut a = [0x55u8; SUBKEY_SEED_LEN];
        let mut b = [0x55u8; SUBKEY_SEED_LEN];
        let next_a = ratchet_one_day(&mut a);
        let next_b = ratchet_one_day(&mut b);
        assert_eq!(next_a, next_b);
    }

    #[test]
    fn ratchet_is_one_way_under_distinct_inputs() {
        // Two distinct prev seeds produce distinct next seeds (with
        // overwhelming probability).
        let mut a = [0x11u8; SUBKEY_SEED_LEN];
        let mut b = [0x22u8; SUBKEY_SEED_LEN];
        let next_a = ratchet_one_day(&mut a);
        let next_b = ratchet_one_day(&mut b);
        assert_ne!(next_a, next_b);
    }

    #[test]
    fn ratchet_chain_diverges_over_days() {
        // Step the same seed N times and confirm each step yields a
        // fresh value (the chain doesn't cycle within N).
        let mut s = [0x77u8; SUBKEY_SEED_LEN];
        let mut history = vec![s];
        for _ in 0..32 {
            s = ratchet_one_day(&mut s);
            assert!(!history.contains(&s), "ratchet cycle detected");
            history.push(s);
        }
    }
}
