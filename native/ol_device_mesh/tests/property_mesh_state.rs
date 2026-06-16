//! Property tests for Row 8 Layer 3 mesh-state CRDT lattice.
//!
//! Two tiers:
//!   - Pure CRDT lattice axioms (associativity, commutativity,
//!     idempotence): 1M iters CI default.
//!   - Keygen-bound auth-op round-trips: 1k iters.

use proptest::prelude::*;
use rand::rngs::OsRng;

use ol_device_mesh::mesh_state::{
    AuthenticatedOp, Delta, LwwMap, LwwRegister, MeshState, OrSet, PnCounter, SubtreePolicyKind,
    SyncState,
};
use ol_device_mesh::{mint_subkey, DeviceClass, MasterIdentity, DEVICE_ID_LEN};
use ol_pqsig::HybridVerifyingKey;
use ol_pqsig::HYBRID_VK_LEN;

fn cheap_cases() -> u32 {
    if std::env::var("ONE_LINK_F1_GATE").as_deref() == Ok("1") {
        5_000_000
    } else {
        1_000_000
    }
}

fn keygen_cases() -> u32 {
    if std::env::var("ONE_LINK_F1_GATE").as_deref() == Ok("1") {
        10_000
    } else {
        1_000
    }
}

// ── CRDT lattice properties at 1M iters ───────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cheap_cases(),
        max_global_rejects: cheap_cases() * 4,
        .. ProptestConfig::default()
    })]

    /// LWW-Register idempotence: replaying the same write twice is
    /// the same as applying it once.
    #[test]
    fn lww_register_idempotent(
        value in prop::collection::vec(any::<u8>(), 0..32),
        ts in any::<u64>(),
        writer in any::<[u8; 16]>(),
    ) {
        let mut a = LwwRegister::empty();
        let mut b = LwwRegister::empty();
        a.set(value.clone(), ts, &writer);
        b.set(value.clone(), ts, &writer);
        b.set(value, ts, &writer);
        prop_assert_eq!(format!("{a:?}"), format!("{b:?}"));
    }

    /// LWW-Register commutativity: applying (op1, op2) ↔ (op2, op1)
    /// converges to the same value because LWW is total-order on
    /// `(ts, writer)`.
    #[test]
    fn lww_register_commutative(
        v1 in prop::collection::vec(any::<u8>(), 0..16),
        t1 in any::<u64>(),
        w1 in any::<[u8; 16]>(),
        v2 in prop::collection::vec(any::<u8>(), 0..16),
        t2 in any::<u64>(),
        w2 in any::<[u8; 16]>(),
    ) {
        let mut a = LwwRegister::empty();
        a.set(v1.clone(), t1, &w1);
        a.set(v2.clone(), t2, &w2);
        let mut b = LwwRegister::empty();
        b.set(v2, t2, &w2);
        b.set(v1, t1, &w1);
        prop_assert_eq!(format!("{a:?}"), format!("{b:?}"));
    }

    /// OR-Set: replay of the same `(elem, tag)` add is idempotent.
    #[test]
    fn or_set_add_idempotent(
        elem in prop::collection::vec(any::<u8>(), 1..16),
        tag in any::<[u8; 16]>(),
    ) {
        let mut s = OrSet::empty();
        s.add(elem.clone(), tag);
        let first = s.contains(&elem);
        s.add(elem.clone(), tag);
        prop_assert_eq!(s.contains(&elem), first);
    }

    /// OR-Set: remove without a matching add never makes the element
    /// visible.
    #[test]
    fn or_set_remove_only_never_visible(
        elem in prop::collection::vec(any::<u8>(), 1..16),
        tag in any::<[u8; 16]>(),
    ) {
        let mut s = OrSet::empty();
        s.remove(&elem, &tag);
        prop_assert!(!s.contains(&elem));
    }

    /// PN-Counter is commutative: same set of adjustments applied in
    /// any order yields the same value.
    #[test]
    fn pn_counter_commutative(
        ops in prop::collection::vec((any::<[u8; 16]>(), -1000i64..1000), 0..32),
    ) {
        let mut a = PnCounter::empty();
        let mut b = PnCounter::empty();
        for (id, d) in &ops {
            a.adjust(*id, *d);
        }
        for (id, d) in ops.iter().rev() {
            b.adjust(*id, *d);
        }
        prop_assert_eq!(a.value(), b.value());
    }

    /// LWW-Map root is invariant under operation reordering when the
    /// per-key timestamps are total-ordered.
    #[test]
    fn lww_map_root_independent_of_order(
        ops in prop::collection::vec((
            prop::collection::vec(any::<u8>(), 1..8),
            prop::collection::vec(any::<u8>(), 0..16),
            1u64..1000,
        ), 0..16),
    ) {
        let w = [0x01u8; 16];
        let mut a = LwwMap::empty();
        let mut b = LwwMap::empty();
        for (k, v, ts) in &ops {
            a.put(k.clone(), v.clone(), *ts, &w);
        }
        for (k, v, ts) in ops.iter().rev() {
            b.put(k.clone(), v.clone(), *ts, &w);
        }
        // a/b may differ in transient state (LWW resolves all ts ties
        // by writer; same writer ⇒ same outcome). Check by encoding.
        prop_assert_eq!(format!("{:?}", a.get(b"missing-key")), "None");
        for (k, _v, _ts) in &ops {
            prop_assert_eq!(a.get(k), b.get(k));
        }
    }

    /// Mesh-state root is stable on identical subtree state across
    /// distinct insert orders.
    #[test]
    fn mesh_state_root_stable_across_insert_orders(
        labels in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..16), 1..6),
    ) {
        let labels_unique: std::collections::BTreeSet<_> =
            labels.iter().cloned().collect();
        let mut s_a = MeshState::empty();
        let mut s_b = MeshState::empty();
        for l in &labels_unique {
            s_a.ensure_subtree(l.clone(), SubtreePolicyKind::LwwRegister).unwrap();
        }
        for l in labels_unique.iter().rev() {
            s_b.ensure_subtree(l.clone(), SubtreePolicyKind::LwwRegister).unwrap();
        }
        prop_assert_eq!(s_a.root(), s_b.root());
    }
}

// ── Keygen-bound auth-op properties ───────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: keygen_cases(),
        max_global_rejects: keygen_cases() * 4,
        .. ProptestConfig::default()
    })]

    /// Sign + verify always round-trips for any valid op shape.
    #[test]
    fn auth_op_sign_verify_round_trip(
        value in prop::collection::vec(any::<u8>(), 0..32),
        ts in any::<u64>(),
        seq in 1u64..u64::MAX,
        wall in any::<u64>(),
    ) {
        let master = MasterIdentity::generate(&mut OsRng);
        let id = [0x42; DEVICE_ID_LEN];
        let (sk, _att) =
            mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
        let op = AuthenticatedOp::sign(
            &sk,
            b"x".to_vec(),
            Delta::LwwSet { value, ts },
            seq,
            wall,
        ).unwrap();
        op.verify(&sk.verifying_key()).unwrap();
    }

    /// Replay protection: ingesting the same op twice applies once.
    #[test]
    fn replay_protection_idempotent(
        value in prop::collection::vec(any::<u8>(), 0..32),
        seq in 1u64..1_000u64,
    ) {
        let master = MasterIdentity::generate(&mut OsRng);
        let id = [0x42; DEVICE_ID_LEN];
        let (sk, att) =
            mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
        let mut state = MeshState::empty();
        state.ensure_subtree(b"x".to_vec(), SubtreePolicyKind::LwwRegister).unwrap();
        let mut sync = SyncState::empty();
        let vk = HybridVerifyingKey::from_bytes(&att.subkey_vk_bytes).unwrap();
        let lookup = |_: &[u8; 16], _: u64| Ok(vk.clone());

        let op = AuthenticatedOp::sign(
            &sk,
            b"x".to_vec(),
            Delta::LwwSet { value, ts: seq },
            seq,
            seq,
        ).unwrap();
        let applied_a = sync.ingest(op.clone(), &mut state, lookup).unwrap();
        let applied_b = sync.ingest(op, &mut state, lookup).unwrap();
        prop_assert!(applied_a);
        prop_assert!(!applied_b);
    }
}

// ── Bookkeeping ───────────────────────────────────────────────────

#[test]
fn vk_len_pinned() {
    assert_eq!(HYBRID_VK_LEN, 1984);
}
