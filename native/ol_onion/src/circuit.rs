//! [`Circuit`] — an ordered list of hops + the final destination.
//!
//! Convention: `circuit.hops[0]` is the FIRST relay the sender
//! dispatches the packet to. `circuit.hops[n-1]` is the final
//! destination. For a 1-hop "pinned-contact" circuit, `hops` has
//! length 2 (one relay + destination). For 3-hop "paranoid mode",
//! `hops` has length 4 (3 relays + destination).
//!
//! The crate does NOT distinguish "relay" vs "destination" in the
//! type — every hop is just a hop. The last one happens to be the
//! peer that consumes the payload; this is the canonical Tor / Sphinx
//! convention and simplifies the peel logic.

use crate::errors::{OnionError, OnionResult};
use crate::hop::HopDescriptor;
use crate::packet::MAX_HOPS;

/// Ordered list of [`HopDescriptor`]s along the path the sender
/// chose. Constructed via [`Circuit::new`] which enforces the hop
/// count bound.
#[derive(Debug, Clone)]
pub struct Circuit {
    hops: Vec<HopDescriptor>,
}

impl Circuit {
    /// Build a circuit from a vector of hops. Refuses empty and
    /// over-long circuits.
    pub fn new(hops: Vec<HopDescriptor>) -> OnionResult<Self> {
        if hops.is_empty() {
            return Err(OnionError::EmptyCircuit);
        }
        if hops.len() > MAX_HOPS {
            return Err(OnionError::TooManyHops {
                got: hops.len(),
                max: MAX_HOPS,
            });
        }
        Ok(Self { hops })
    }

    /// Number of hops including the destination.
    pub fn len(&self) -> usize {
        self.hops.len()
    }

    /// True iff the circuit has no hops (never possible via the
    /// public constructor — included for completeness).
    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }

    /// Borrow the hop sequence.
    pub fn hops(&self) -> &[HopDescriptor] {
        &self.hops
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hop::{HopDescriptor, HopId};
    use x25519_dalek::{PublicKey, StaticSecret};

    fn fake_hop(i: u8) -> HopDescriptor {
        let sk = StaticSecret::from([i; 32]);
        HopDescriptor {
            id: HopId::from_bytes([i; 32]),
            pubkey: PublicKey::from(&sk),
        }
    }

    #[test]
    fn one_hop_circuit_constructs() {
        let c = Circuit::new(vec![fake_hop(1)]).unwrap();
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn three_hop_circuit_constructs() {
        let c = Circuit::new(vec![fake_hop(1), fake_hop(2), fake_hop(3), fake_hop(4)]).unwrap();
        assert_eq!(c.len(), 4);
    }

    #[test]
    fn empty_circuit_rejected() {
        let err = Circuit::new(vec![]).unwrap_err();
        assert_eq!(err, OnionError::EmptyCircuit);
    }

    #[test]
    fn too_many_hops_rejected() {
        let many: Vec<HopDescriptor> = (0..=MAX_HOPS)
            .map(|index| fake_hop(u8::try_from(index).unwrap()))
            .collect();
        let err = Circuit::new(many).unwrap_err();
        assert!(matches!(err, OnionError::TooManyHops { .. }));
    }
}
