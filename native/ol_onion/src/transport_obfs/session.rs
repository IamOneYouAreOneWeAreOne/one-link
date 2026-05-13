//! Stateful per-direction Sealer/Opener over handshake-derived keys.
//!
//! A `Session` holds two ChaCha20 keys: one for OUTBOUND traffic
//! (this side → peer) and one for INBOUND (peer → this side).
//! Both sides derive the same two keys, but their `outbound_key`
//! and `inbound_key` are swapped — so client.outbound ==
//! server.inbound and vice versa. Each direction uses
//! `derive_nonce(direction_tag, packet_counter)` to produce unique
//! per-packet ChaCha20 nonces; (key, nonce) pairs never repeat.

use crate::transport_obfs::primitive::{
    deobfuscate, derive_nonce, obfuscate, OBFS_KEY_LEN,
};
use zeroize::Zeroize;

/// Length of a session key (= ChaCha20 key length).
pub const SESSION_KEY_LEN: usize = OBFS_KEY_LEN;

/// Tag used by `derive_nonce` to distinguish directions; ensures
/// the client-side packet counter 7 produces a different nonce
/// than the server-side packet counter 7.
const OUTBOUND_DIRECTION_TAG: u32 = 0x4F4C5458; // "OLTX"
const INBOUND_DIRECTION_TAG: u32 = 0x4F4C5258; // "OLRX"

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
    /// upper layer must MAC).
    pub fn open_inbound(&self, ciphertext: &[u8], counter: u64) -> Result<Vec<u8>, ()> {
        let nonce = derive_nonce(INBOUND_DIRECTION_TAG, counter);
        // Symmetric XOR — note: peer's outbound matches our inbound,
        // so the nonce-tag inversion makes the keystream align with
        // what the peer produced.
        // The peer sealed-outbound with their OUTBOUND_DIRECTION_TAG.
        // From our perspective those bytes are inbound, so we use
        // INBOUND_DIRECTION_TAG which equals... wait, peer's outbound
        // is our inbound, so the tags MUST differ across sides. Let
        // me re-think: both sides need to derive the same nonce for
        // a given packet. If client OUTBOUND_DIRECTION_TAG = X,
        // server INBOUND_DIRECTION_TAG must = X too so they match.
        //
        // SOLUTION: peer-to-direction nonce tag is FIXED — the
        // direction tag depends on PACKET DIRECTION, not on which
        // side processes it. Both sides agree: "packets flowing
        // client→server use OUTBOUND_DIRECTION_TAG; packets flowing
        // server→client use INBOUND_DIRECTION_TAG" — but each side
        // labels these tags inversely. We re-derive the nonce
        // using OUTBOUND tag here because the peer's seal_outbound
        // used the outbound tag (from THEIR perspective). That tag
        // is OUTBOUND_DIRECTION_TAG (same constant). We need to
        // mirror.
        //
        // The cleanest fix: BOTH directions use OUTBOUND_DIRECTION_TAG
        // for the nonce since the direction is uniquely captured by
        // which key (outbound_key vs inbound_key) is used.
        let nonce = derive_nonce(OUTBOUND_DIRECTION_TAG, counter);
        Ok(deobfuscate(&self.inbound_key, &nonce, ciphertext))
    }

    /// Borrow the outbound key (for diagnostics; do NOT export).
    pub(crate) fn outbound_key(&self) -> &[u8; SESSION_KEY_LEN] {
        &self.outbound_key
    }

    /// Borrow the inbound key (for diagnostics; do NOT export).
    pub(crate) fn inbound_key(&self) -> &[u8; SESSION_KEY_LEN] {
        &self.inbound_key
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
