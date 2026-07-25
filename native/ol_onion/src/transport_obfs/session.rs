//! Stateful per-direction Sealer/Opener over handshake-derived keys.
//!
//! A `Session` holds two `ChaCha20` keys: one for OUTBOUND traffic
//! (this side → peer) and one for INBOUND (peer → this side).
//! Both sides derive the same two keys, but their `outbound_key`
//! and `inbound_key` are swapped — so client.outbound ==
//! server.inbound and vice versa. Each direction uses
//! `derive_nonce(direction_tag, packet_counter)` to produce unique
//! per-packet `ChaCha20` nonces; (key, nonce) pairs never repeat.

use crate::transport_obfs::primitive::{deobfuscate, derive_nonce, obfuscate, OBFS_KEY_LEN};
use zeroize::Zeroize;

/// Length of a session key (= `ChaCha20` key length).
pub const SESSION_KEY_LEN: usize = OBFS_KEY_LEN;

/// Tag used by `derive_nonce`. Direction is captured by WHICH key
/// (`outbound_key` vs `inbound_key`) is used, so both directions can
/// use the same tag; (key, nonce) pairs never repeat because the
/// keys differ.
const OUTBOUND_DIRECTION_TAG: u32 = 0x4F4C_5458; // "OLTX"

/// Which direction a packet flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionDirection {
    /// This side → peer.
    Outbound,
    /// Peer → this side.
    Inbound,
}

/// A bidirectional obfuscation session derived from the handshake.
pub struct Session {
    outbound_key: [u8; SESSION_KEY_LEN],
    inbound_key: [u8; SESSION_KEY_LEN],
}

impl Session {
    /// Client-side constructor: client's outbound = `client_tx_key`,
    /// client's inbound = `server_tx_key`.
    pub fn new(client_tx_key: [u8; SESSION_KEY_LEN], server_tx_key: [u8; SESSION_KEY_LEN]) -> Self {
        Self {
            outbound_key: client_tx_key,
            inbound_key: server_tx_key,
        }
    }

    /// Server-side constructor: server's outbound = `server_tx_key`,
    /// server's inbound = `client_tx_key`. (Same two keys as
    /// `Session::new`, but mirrored.)
    pub fn for_server(
        client_tx_key: [u8; SESSION_KEY_LEN],
        server_tx_key: [u8; SESSION_KEY_LEN],
    ) -> Self {
        Self {
            outbound_key: server_tx_key,
            inbound_key: client_tx_key,
        }
    }

    /// Obfuscate an outbound packet with `counter` (must increase
    /// monotonically; daemon owns the counter state).
    pub fn seal_outbound(&self, plaintext: &[u8], counter: u64) -> Vec<u8> {
        let nonce = derive_nonce(OUTBOUND_DIRECTION_TAG, counter);
        obfuscate(&self.outbound_key, &nonce, plaintext)
    }

    /// Deobfuscate an inbound packet with the peer's `counter`.
    /// Returns the recovered bytes (this layer has no integrity —
    /// upper layer must MAC). The `Result` is unit-error on purpose:
    /// it mirrors `seal_outbound`'s shape and reserves a fallible
    /// surface for future integrity without leaking a failure reason.
    #[allow(clippy::result_unit_err)]
    pub fn open_inbound(&self, ciphertext: &[u8], counter: u64) -> Result<Vec<u8>, ()> {
        // Both directions derive the nonce with OUTBOUND_DIRECTION_TAG:
        // direction is captured by WHICH key is used (outbound_key vs
        // inbound_key), so the tag is fixed and both sides agree.
        let nonce = derive_nonce(OUTBOUND_DIRECTION_TAG, counter);
        Ok(deobfuscate(&self.inbound_key, &nonce, ciphertext))
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").finish_non_exhaustive()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.outbound_key.zeroize();
        self.inbound_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip_with_matching_keys() {
        let k1 = [0x11u8; SESSION_KEY_LEN];
        let k2 = [0x22u8; SESSION_KEY_LEN];
        let client = Session::new(k1, k2);
        let server = Session::for_server(k1, k2);

        let p = b"client->server message";
        let on_wire = client.seal_outbound(p, 1);
        let recovered = server.open_inbound(&on_wire, 1).unwrap();
        assert_eq!(recovered, p);

        let p2 = b"server->client reply";
        let on_wire2 = server.seal_outbound(p2, 1);
        let recovered2 = client.open_inbound(&on_wire2, 1).unwrap();
        assert_eq!(recovered2, p2);
    }

    #[test]
    fn different_counters_yield_different_ciphertext() {
        let k1 = [0x11u8; SESSION_KEY_LEN];
        let k2 = [0x22u8; SESSION_KEY_LEN];
        let s = Session::new(k1, k2);
        let c1 = s.seal_outbound(b"x", 1);
        let c2 = s.seal_outbound(b"x", 2);
        assert_ne!(c1, c2);
    }

    #[test]
    fn session_zeroizes_on_drop() {
        // Hard to observe directly; just confirm Drop runs without
        // panicking. Memory inspection would require unsafe.
        let s = Session::new([0xAA; SESSION_KEY_LEN], [0xBB; SESSION_KEY_LEN]);
        drop(s);
    }
}
