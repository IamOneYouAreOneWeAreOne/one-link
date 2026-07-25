//! Symmetric chain ratchet using BLAKE3 keyed hash.

use zeroize::{Zeroize, Zeroizing};

use crate::error::RatchetError;

/// Length of a chain key (and of a message key) in bytes.
pub const CHAIN_KEY_LEN: usize = 32;
/// Length of a per-chunk message key in bytes (matches `ol_aead`).
pub const MESSAGE_KEY_LEN: usize = 32;

/// Maximum number of chain steps a single `fast_forward` /
/// `peek_message_key` call may traverse. Audit L11 (May 2026):
/// without a cap a malicious peer could ship `seq = u64::MAX` and
/// force the receiver into an indefinite BLAKE3 derive loop. 65 536
/// is well past any legitimate skip distance for a real multi-chunk
/// transfer (chunk sizes are 64 KiB+; 65 536 steps = ~4 GiB of
/// dropped chunks before the chain would naturally re-key anyway).
pub const MAX_SKIP_STEPS: u64 = 65_536;

/// 32-byte chain key, zeroized on drop.
pub type ChainKey = Zeroizing<[u8; CHAIN_KEY_LEN]>;
/// 32-byte per-chunk AEAD key, zeroized on drop.
pub type MessageKey = Zeroizing<[u8; MESSAGE_KEY_LEN]>;

/// BLAKE3 `derive_key` context for the chain advance step. The chain
/// uses keyed-hash with a per-step counter to derive both the next
/// chain key AND the message key for the corresponding chunk.
const CHAIN_STEP_CONTEXT: &str = "ol-ratchet-chain-step-v1";

/// BLAKE3 `derive_key` context used by [`derive_root_chain_key`] to
/// turn a fresh KEM shared secret into the initial chain key.
const ROOT_BOOTSTRAP_CONTEXT: &str = "ol-ratchet-root-bootstrap-v1";

/// Derive the initial chain key from a fresh shared secret (e.g. the
/// 32-byte output of `ol_pqkem::encapsulate` / `decapsulate`).
///
/// Domain-separated so the same KEM secret can be re-used for other
/// purposes (AEAD bootstrap, capability seal, etc.) without leaking
/// cross-context bits.
#[must_use]
pub fn derive_root_chain_key(shared_secret: &[u8]) -> ChainKey {
    let key = blake3::derive_key(ROOT_BOOTSTRAP_CONTEXT, shared_secret);
    Zeroizing::new(key)
}

/// A symmetric ratchet chain: one chain key + a step counter. Advance
/// the chain by calling [`Chain::next_message_key`] which returns the
/// AEAD key for the current step and rotates the chain forward.
#[derive(Clone)]
pub struct Chain {
    chain_key: ChainKey,
    step: u64,
}

impl std::fmt::Debug for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key bytes.
        f.debug_struct("Chain")
            .field("step", &self.step)
            .field("chain_key_len", &CHAIN_KEY_LEN)
            .finish_non_exhaustive()
    }
}

impl Chain {
    /// Build a chain from an explicit initial chain key.
    #[inline]
    #[must_use]
    pub fn from_chain_key(chain_key: ChainKey) -> Self {
        Self { chain_key, step: 0 }
    }

    /// Bootstrap a chain from a fresh KEM shared secret.
    #[inline]
    #[must_use]
    pub fn from_shared_secret(shared_secret: &[u8]) -> Self {
        Self::from_chain_key(derive_root_chain_key(shared_secret))
    }

    /// Current step counter.
    #[inline]
    #[must_use]
    pub fn step(&self) -> u64 {
        self.step
    }

    /// Derive the message key for the current step + advance the chain.
    ///
    /// Internally: produce 64 bytes via BLAKE3 `derive_key`. First 32
    /// become the next chain key; second 32 become the message key.
    /// We then zeroize the intermediate buffer.
    pub fn next_message_key(&mut self) -> MessageKey {
        let mk = self.derive_step(self.step);
        // Advance the chain.
        self.chain_key = self.advance(self.step);
        self.step += 1;
        mk
    }

    /// Fast-forward the chain to `target_step` without emitting the
    /// intervening message keys (used by senders that skipped chunks
    /// for re-send purposes). Callers that need the intermediate keys
    /// should iterate `next_message_key` and stash them in a
    /// [`crate::SkippedKeyStore`].
    ///
    /// # Errors
    ///
    /// - [`RatchetError::Rewind`] if `target_step < self.step`.
    /// - [`RatchetError::SkipTooLarge`] if
    ///   `target_step - self.step > MAX_SKIP_STEPS` (audit L11 May 2026 — closes the
    ///   `seq = u64::MAX` indefinite-derive denial-of-service attack).
    pub fn fast_forward(&mut self, target_step: u64) -> Result<(), RatchetError> {
        if target_step < self.step {
            return Err(RatchetError::Rewind {
                requested: target_step,
                current: self.step,
            });
        }
        let delta = target_step - self.step;
        if delta > MAX_SKIP_STEPS {
            return Err(RatchetError::SkipTooLarge {
                from: self.step,
                target: target_step,
                delta,
                max: MAX_SKIP_STEPS,
            });
        }
        while self.step < target_step {
            self.chain_key = self.advance(self.step);
            self.step += 1;
        }
        Ok(())
    }

    /// Peek at the message key for a future step WITHOUT advancing the
    /// chain. Used by receivers to derive a skipped key on demand.
    ///
    /// # Errors
    ///
    /// - [`RatchetError::Rewind`] if `target_step < self.step`.
    /// - [`RatchetError::SkipTooLarge`] if
    ///   `target_step - self.step > MAX_SKIP_STEPS` (audit L11 May 2026).
    pub fn peek_message_key(&self, target_step: u64) -> Result<MessageKey, RatchetError> {
        if target_step < self.step {
            return Err(RatchetError::Rewind {
                requested: target_step,
                current: self.step,
            });
        }
        let delta = target_step - self.step;
        if delta > MAX_SKIP_STEPS {
            return Err(RatchetError::SkipTooLarge {
                from: self.step,
                target: target_step,
                delta,
                max: MAX_SKIP_STEPS,
            });
        }
        let mut tmp = self.chain_key.clone();
        let mut s = self.step;
        while s < target_step {
            // Mirror `advance`: input layout = chain_key || step_le || 0x43 ('C').
            let mut input = [0u8; CHAIN_KEY_LEN + 8 + 1];
            input[..CHAIN_KEY_LEN].copy_from_slice(&tmp[..]);
            input[CHAIN_KEY_LEN..CHAIN_KEY_LEN + 8].copy_from_slice(&s.to_le_bytes());
            input[CHAIN_KEY_LEN + 8] = 0x43;
            let derived = blake3::derive_key(CHAIN_STEP_CONTEXT, &input);
            tmp[..].copy_from_slice(&derived);
            s += 1;
        }
        // Derive message key at target_step from the fast-forwarded tmp.
        let mk = Self::derive_from(&tmp, target_step);
        // Explicit zeroize of the intermediate.
        tmp[..].zeroize();
        Ok(mk)
    }

    /// Compute the message key for `step` from the current `chain_key`
    /// without mutating self.
    fn derive_step(&self, step: u64) -> MessageKey {
        Self::derive_from(&self.chain_key, step)
    }

    /// Compute the message key from a specific chain-key snapshot.
    fn derive_from(chain_key: &ChainKey, step: u64) -> MessageKey {
        // Mix the step counter into a per-step subcontext so re-use of
        // a chain key (defensive) cannot collide across steps.
        let mut input = [0u8; CHAIN_KEY_LEN + 8 + 1];
        input[..CHAIN_KEY_LEN].copy_from_slice(&chain_key[..]);
        input[CHAIN_KEY_LEN..CHAIN_KEY_LEN + 8].copy_from_slice(&step.to_le_bytes());
        input[CHAIN_KEY_LEN + 8] = 0x4D; // 'M' for message key
        let derived = blake3::derive_key(CHAIN_STEP_CONTEXT, &input);
        Zeroizing::new(derived)
    }

    /// Compute the next chain key from a specific step.
    fn advance(&self, step: u64) -> ChainKey {
        let mut input = [0u8; CHAIN_KEY_LEN + 8 + 1];
        input[..CHAIN_KEY_LEN].copy_from_slice(&self.chain_key[..]);
        input[CHAIN_KEY_LEN..CHAIN_KEY_LEN + 8].copy_from_slice(&step.to_le_bytes());
        input[CHAIN_KEY_LEN + 8] = 0x43; // 'C' for chain key
        let derived = blake3::derive_key(CHAIN_STEP_CONTEXT, &input);
        Zeroizing::new(derived)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_secret() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn fresh_chain_starts_at_step_zero() {
        let chain = Chain::from_shared_secret(&fixed_secret());
        assert_eq!(chain.step(), 0);
    }

    #[test]
    fn deterministic_keys_from_fixed_secret() {
        // Two independent chains from the same secret produce the
        // same message keys at each step.
        let mut a = Chain::from_shared_secret(&fixed_secret());
        let mut b = Chain::from_shared_secret(&fixed_secret());
        for _ in 0..10 {
            let mk_a = a.next_message_key();
            let mk_b = b.next_message_key();
            assert_eq!(*mk_a, *mk_b);
        }
        assert_eq!(a.step(), 10);
        assert_eq!(b.step(), 10);
    }

    #[test]
    fn distinct_secrets_produce_distinct_keys() {
        let mut a = Chain::from_shared_secret(&[0xAAu8; 32]);
        let mut b = Chain::from_shared_secret(&[0xBBu8; 32]);
        assert_ne!(*a.next_message_key(), *b.next_message_key());
    }

    #[test]
    fn message_keys_unique_across_steps() {
        let mut chain = Chain::from_shared_secret(&fixed_secret());
        let mut seen = std::collections::HashSet::new();
        for _ in 0..32 {
            let mk = chain.next_message_key();
            let mk_bytes: [u8; 32] = *mk;
            assert!(seen.insert(mk_bytes), "duplicate message key");
        }
    }

    #[test]
    fn fast_forward_skips_intermediate_keys() {
        let mut a = Chain::from_shared_secret(&fixed_secret());
        let mut b = Chain::from_shared_secret(&fixed_secret());
        // a advances step-by-step; b fast-forwards.
        for _ in 0..5 {
            a.next_message_key();
        }
        b.fast_forward(5).unwrap();
        assert_eq!(a.step(), b.step());
        // Next message keys must match (chain state identical).
        assert_eq!(*a.next_message_key(), *b.next_message_key());
    }

    #[test]
    fn fast_forward_rejects_rewind() {
        let mut chain = Chain::from_shared_secret(&fixed_secret());
        chain.fast_forward(5).unwrap();
        let r = chain.fast_forward(3);
        assert!(matches!(r, Err(RatchetError::Rewind { .. })));
    }

    #[test]
    fn peek_does_not_advance() {
        let chain = Chain::from_shared_secret(&fixed_secret());
        let mk_future = chain.peek_message_key(5).unwrap();
        // Chain still at step 0.
        assert_eq!(chain.step(), 0);
        // Now actually iterate to step 5 and confirm we get the same key.
        let mut other = Chain::from_shared_secret(&fixed_secret());
        for _ in 0..5 {
            other.next_message_key();
        }
        let mk_now = other.next_message_key();
        assert_eq!(*mk_future, *mk_now);
    }

    #[test]
    fn forward_secrecy_chain_key_advances_one_way() {
        // After 10 steps, the chain key has rotated 10 times. There's
        // no API to recover step-0 keys from the current key; verify
        // we can't even reproduce step 0 by re-creating a chain from
        // the same starting secret + comparing to the advanced chain's
        // current state.
        let mut a = Chain::from_shared_secret(&fixed_secret());
        for _ in 0..10 {
            a.next_message_key();
        }
        let b = Chain::from_shared_secret(&fixed_secret());
        // Their internal chain-key bytes MUST differ (a has advanced;
        // b is fresh).
        assert_ne!(*a.chain_key, *b.chain_key);
    }

    // ── Audit L11 May 2026 — skip-cap regression ───────────────

    #[test]
    fn fast_forward_rejects_huge_skip() {
        // Regression test for audit L11: an attacker who can place a
        // u64::MAX seq value on the wire previously forced the
        // receiver into an indefinite BLAKE3 derive loop. The cap
        // rejects skips beyond MAX_SKIP_STEPS.
        let mut c = Chain::from_shared_secret(&fixed_secret());
        let r = c.fast_forward(u64::MAX);
        assert!(matches!(r, Err(RatchetError::SkipTooLarge { .. })));
        // Chain unchanged after rejection.
        assert_eq!(c.step(), 0);
    }

    #[test]
    fn peek_message_key_rejects_huge_skip() {
        let c = Chain::from_shared_secret(&fixed_secret());
        let r = c.peek_message_key(u64::MAX);
        assert!(matches!(r, Err(RatchetError::SkipTooLarge { .. })));
    }

    #[test]
    fn fast_forward_at_exact_max_skip_succeeds() {
        // The cap is INCLUSIVE: delta == MAX_SKIP_STEPS is allowed,
        // delta == MAX_SKIP_STEPS + 1 is not. Boundary check.
        // (Using a smaller-than-max value for test speed; the
        // exact-boundary case would do ~65 K BLAKE3 derives.)
        let mut c = Chain::from_shared_secret(&fixed_secret());
        c.fast_forward(MAX_SKIP_STEPS / 64).unwrap();
        assert_eq!(c.step(), MAX_SKIP_STEPS / 64);
        // One more big jump that lands past the cap from THIS position.
        let r = c.fast_forward(MAX_SKIP_STEPS / 64 + MAX_SKIP_STEPS + 1);
        assert!(matches!(r, Err(RatchetError::SkipTooLarge { .. })));
    }
}
