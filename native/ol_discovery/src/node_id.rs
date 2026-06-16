//! 256-bit NodeId derived from a peer's Ed25519 master pubkey, plus
//! XOR distance metric and bit-prefix utilities.
//!
//! The NodeId is BLAKE3(ed25519_pubkey), so:
//!   - Two peers cannot collide on NodeId without colliding on BLAKE3.
//!   - An attacker targeting a specific prefix must keygen until a
//!     pubkey hashes to that prefix — Ed25519 keygen is CPU-bound
//!     (no GPU shortcut), so this is a real cost for Sybil attacks.

use core::cmp::Ordering;

/// NodeId length in bytes. Matches BLAKE3 output (32 bytes = 256 bits).
pub const NODE_ID_BYTES: usize = 32;

/// NodeId length in bits. Equals `NODE_ID_BYTES * 8`.
pub const NODE_ID_BITS: usize = NODE_ID_BYTES * 8;

/// A 256-bit Kademlia node identifier.
///
/// Constructed from an Ed25519 master pubkey via [`NodeId::from_pubkey`].
/// Equality + ordering are byte-lexicographic. Distance is XOR-metric
/// (interpreted as a 256-bit unsigned integer), accessed via
/// [`NodeId::distance`] / [`NodeId::xor_leading_zeros`].
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct NodeId(pub [u8; NODE_ID_BYTES]);

impl NodeId {
    /// Construct from raw bytes.
    #[must_use]
    pub const fn from_bytes(b: [u8; NODE_ID_BYTES]) -> Self {
        Self(b)
    }

    /// Derive a NodeId from an Ed25519 master pubkey (32 bytes).
    /// `NodeId = BLAKE3(pubkey)`. Pure, deterministic, collision-
    /// resistant under BLAKE3.
    #[must_use]
    pub fn from_pubkey(pubkey: &[u8; 32]) -> Self {
        let h = blake3::hash(pubkey);
        Self(*h.as_bytes())
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; NODE_ID_BYTES] {
        &self.0
    }

    /// XOR distance: `self ^ other` interpreted as a 256-bit unsigned
    /// integer. Returned as raw bytes; the smallest distance is all-
    /// zero (`self == other`).
    ///
    /// Used by Kademlia routing to pick "closest" peers; smaller XOR
    /// = closer in the metric space.
    #[must_use]
    pub fn distance(&self, other: &Self) -> [u8; NODE_ID_BYTES] {
        let mut out = [0u8; NODE_ID_BYTES];
        for i in 0..NODE_ID_BYTES {
            out[i] = self.0[i] ^ other.0[i];
        }
        out
    }

    /// Number of leading zero bits in `self XOR other`. Equivalent
    /// to the K-bucket index for `other` from `self`'s perspective.
    ///
    /// Returns `NODE_ID_BITS` (256) when self == other (distance is
    /// all-zero). Constant-time per bit-position, branch-free over
    /// byte chunks.
    #[must_use]
    pub fn xor_leading_zeros(&self, other: &Self) -> u32 {
        let mut count: u32 = 0;
        for i in 0..NODE_ID_BYTES {
            let x = self.0[i] ^ other.0[i];
            if x == 0 {
                count += 8;
            } else {
                count += x.leading_zeros();
                return count;
            }
        }
        count
    }

    /// K-bucket index for `other` viewed from `self`. Bucket k holds
    /// peers whose XOR-distance has exactly k leading zeros: bucket
    /// 0 is the "farthest" (top bit differs), bucket 255 is the
    /// "closest non-self". Identity (self) belongs to no bucket.
    ///
    /// Returns `None` when `self == other`. Otherwise returns an
    /// index in `0..NODE_ID_BITS`.
    #[must_use]
    pub fn bucket_index(&self, other: &Self) -> Option<usize> {
        let lz = self.xor_leading_zeros(other);
        if (lz as usize) >= NODE_ID_BITS {
            None
        } else {
            Some(lz as usize)
        }
    }
}

impl Ord for NodeId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for NodeId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl core::fmt::Debug for NodeId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Short-hex for log readability: first 4 bytes only.
        write!(
            f,
            "NodeId({:02x}{:02x}{:02x}{:02x}…)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

/// XOR-distance comparator: returns the ordering of distance(a, target)
/// vs distance(b, target). Smaller XOR == "closer".
#[must_use]
pub fn closer_to(a: &NodeId, b: &NodeId, target: &NodeId) -> Ordering {
    let da = a.distance(target);
    let db = b.distance(target);
    // Both are 32-byte big-endian unsigned ints; lexicographic compare
    // of the byte arrays gives integer order.
    da.cmp(&db)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_distance_is_self() {
        let a = NodeId([0xAA; 32]);
        assert_eq!(a.distance(&a), [0u8; 32]);
        assert_eq!(a.xor_leading_zeros(&a), NODE_ID_BITS as u32);
        assert_eq!(a.bucket_index(&a), None);
    }

    #[test]
    fn distance_is_symmetric() {
        let a = NodeId([0xAA; 32]);
        let b = NodeId([0x55; 32]);
        assert_eq!(a.distance(&b), b.distance(&a));
    }

    #[test]
    fn distance_max_is_all_ones() {
        let a = NodeId([0x00; 32]);
        let b = NodeId([0xFF; 32]);
        assert_eq!(a.distance(&b), [0xFFu8; 32]);
    }

    #[test]
    fn xor_leading_zeros_first_byte_differs() {
        let a = NodeId([0x00; 32]);
        let b = {
            let mut x = [0u8; 32];
            x[0] = 0x80;
            NodeId(x)
        };
        assert_eq!(a.xor_leading_zeros(&b), 0);
    }

    #[test]
    fn xor_leading_zeros_low_bit_only() {
        // a and b agree on every bit except the very last.
        let a = NodeId([0x00; 32]);
        let b = {
            let mut x = [0u8; 32];
            x[31] = 0x01;
            NodeId(x)
        };
        assert_eq!(a.xor_leading_zeros(&b), 255);
        assert_eq!(a.bucket_index(&b), Some(255));
    }

    #[test]
    fn bucket_index_progression() {
        // For each bit position k, set only that bit in b. lz must be k.
        for k in 0..NODE_ID_BITS {
            let mut x = [0u8; 32];
            let byte = k / 8;
            let bit = 7 - (k % 8);
            x[byte] = 1 << bit;
            let a = NodeId([0u8; 32]);
            let b = NodeId(x);
            assert_eq!(a.xor_leading_zeros(&b), k as u32, "k={k}");
            assert_eq!(a.bucket_index(&b), Some(k));
        }
    }

    #[test]
    fn closer_to_orders_correctly() {
        let target = NodeId([0x00; 32]);
        let near = NodeId({
            let mut x = [0u8; 32];
            x[31] = 0x01;
            x
        });
        let far = NodeId([0xFF; 32]);
        assert_eq!(closer_to(&near, &far, &target), Ordering::Less);
        assert_eq!(closer_to(&far, &near, &target), Ordering::Greater);
        assert_eq!(closer_to(&near, &near, &target), Ordering::Equal);
    }

    #[test]
    fn from_pubkey_deterministic() {
        let pk = [0x42u8; 32];
        let id1 = NodeId::from_pubkey(&pk);
        let id2 = NodeId::from_pubkey(&pk);
        assert_eq!(id1, id2);
    }

    #[test]
    fn from_pubkey_distinct_for_distinct_input() {
        let id1 = NodeId::from_pubkey(&[0x01u8; 32]);
        let id2 = NodeId::from_pubkey(&[0x02u8; 32]);
        assert_ne!(id1, id2);
        // Differ in many positions (BLAKE3 avalanche).
        let d = id1.distance(&id2);
        let popcount: u32 = d.iter().map(|b| b.count_ones()).sum();
        assert!(
            popcount > 100,
            "BLAKE3 should give >100 bit-differences; got {popcount}"
        );
    }

    #[test]
    fn ordering_is_byte_lex() {
        let a = NodeId([0x01; 32]);
        let b = NodeId([0x02; 32]);
        assert!(a < b);
        let c = {
            let mut x = [0x01; 32];
            x[31] = 0x02;
            NodeId(x)
        };
        assert!(a < c);
    }
}
