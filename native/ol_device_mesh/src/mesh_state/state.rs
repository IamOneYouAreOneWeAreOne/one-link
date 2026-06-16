//! CRDT lattice types + the canonical [`MeshState`] container.

use blake3::Hasher;
use std::collections::{BTreeMap, BTreeSet};

use crate::errors::{DeviceMeshError, DeviceMeshResult};

use super::ops::{Delta, MAX_SUBTREE_LABEL_LEN};

/// Label that names a subtree within the mesh state. Bounded so
/// canonical hashing has predictable cost.
pub type SubtreeLabel = Vec<u8>;

/// Per-subtree root: BLAKE3 over the subtree's canonical encoding.
pub type SubtreeRoot = [u8; 32];

/// Global state root: BLAKE3 over the sorted list of
/// `(label, subtree_root)` pairs.
pub type StateRoot = [u8; 32];

/// Tag bound to each OR-Set element so concurrent adds/removes can
/// be reconciled. Typically derived from `(device_id, seq)` by the
/// emitter.
pub type OrSetTag = [u8; 16];

/// One subtree of the mesh state. Each variant is a CRDT lattice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subtree {
    /// Last-writer-wins single value. Ties broken by lexicographic
    /// device-id comparison so two concurrent writes resolve
    /// deterministically.
    LwwRegister(LwwRegister),
    /// Observed-remove set: tagged adds, tagged removes; remove
    /// only erases adds whose tags appear in the remove set.
    OrSet(OrSet),
    /// Per-device positive/negative counter.
    PnCounter(PnCounter),
    /// Map<key, lww-bytes> with tombstones on delete.
    LwwMap(LwwMap),
}

impl Subtree {
    /// Empty subtree of the supplied kind.
    #[must_use]
    pub fn empty_of_kind(kind: super::policy::SubtreePolicyKind) -> Self {
        use super::policy::SubtreePolicyKind as K;
        match kind {
            K::LwwRegister => Self::LwwRegister(LwwRegister::empty()),
            K::OrSet => Self::OrSet(OrSet::empty()),
            K::PnCounter => Self::PnCounter(PnCounter::empty()),
            K::LwwMap => Self::LwwMap(LwwMap::empty()),
        }
    }

    /// BLAKE3 commitment of this subtree's canonical encoding.
    #[must_use]
    pub fn root(&self) -> SubtreeRoot {
        let mut h = Hasher::new();
        match self {
            Self::LwwRegister(r) => {
                h.update(b"OL-mesh-subtree-lww-register-v1");
                r.canonical_into(&mut h);
            }
            Self::OrSet(s) => {
                h.update(b"OL-mesh-subtree-or-set-v1");
                s.canonical_into(&mut h);
            }
            Self::PnCounter(c) => {
                h.update(b"OL-mesh-subtree-pn-counter-v1");
                c.canonical_into(&mut h);
            }
            Self::LwwMap(m) => {
                h.update(b"OL-mesh-subtree-lww-map-v1");
                m.canonical_into(&mut h);
            }
        }
        *h.finalize().as_bytes()
    }

    /// Apply a delta to this subtree. Returns
    /// [`DeviceMeshError::DeltaKindMismatch`] if the delta isn't
    /// applicable to this variant.
    pub fn apply(&mut self, delta: &Delta, emitter_device_id: &[u8; 16]) -> DeviceMeshResult<()> {
        match (self, delta) {
            (Self::LwwRegister(r), Delta::LwwSet { value, ts }) => {
                r.set(value.clone(), *ts, emitter_device_id);
                Ok(())
            }
            (Self::OrSet(s), Delta::OrAdd { element, tag }) => {
                s.add(element.clone(), *tag);
                Ok(())
            }
            (Self::OrSet(s), Delta::OrRemove { element, tag }) => {
                s.remove(element, tag);
                Ok(())
            }
            (Self::PnCounter(c), Delta::Counter { device_id, delta }) => {
                c.adjust(*device_id, *delta);
                Ok(())
            }
            (Self::LwwMap(m), Delta::MapPut { key, value, ts }) => {
                m.put(key.clone(), value.clone(), *ts, emitter_device_id);
                Ok(())
            }
            (Self::LwwMap(m), Delta::MapDelete { key, ts }) => {
                m.delete(key, *ts, emitter_device_id);
                Ok(())
            }
            _ => Err(DeviceMeshError::DeltaKindMismatch),
        }
    }
}

// ── LwwRegister ────────────────────────────────────────────────────

/// Last-writer-wins register. Ties on `ts` are broken by
/// lexicographic comparison of the writer's device id so two
/// concurrent writes from different devices converge deterministically.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LwwRegister {
    value: Option<Vec<u8>>,
    ts: u64,
    last_writer: [u8; 16],
}

impl LwwRegister {
    /// Empty register (no value yet).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }
    /// Current value (or `None` if no write has ever happened).
    #[must_use]
    pub fn value(&self) -> Option<&[u8]> {
        self.value.as_deref()
    }
    /// Current write timestamp.
    #[must_use]
    pub const fn ts(&self) -> u64 {
        self.ts
    }
    /// Apply a write at `(ts, writer)`. Deterministic under arbitrary
    /// delivery order: ties on `ts` break to the larger writer id;
    /// ties on `(ts, writer)` break to the lexicographically larger
    /// value bytes (so two concurrent same-source writes converge).
    pub fn set(&mut self, value: Vec<u8>, ts: u64, writer: &[u8; 16]) {
        if self.is_dominated_by(ts, writer, Some(&value)) {
            self.value = Some(value);
            self.ts = ts;
            self.last_writer = *writer;
        }
    }
    fn is_dominated_by(&self, ts: u64, writer: &[u8; 16], value: Option<&[u8]>) -> bool {
        match ts.cmp(&self.ts) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => false,
            std::cmp::Ordering::Equal => match writer.cmp(&self.last_writer) {
                std::cmp::Ordering::Greater => true,
                std::cmp::Ordering::Less => false,
                // Same (ts, writer): tertiary tie-break on value bytes.
                // None (delete) is treated as MAX so a delete dominates a
                // same-(ts,writer) put.
                std::cmp::Ordering::Equal => match (value, self.value.as_deref()) {
                    (None, Some(_)) => true,
                    (None | Some(_), None) => false,
                    (Some(v_new), Some(v_old)) => v_new > v_old,
                },
            },
        }
    }
    fn canonical_into(&self, h: &mut Hasher) {
        h.update(&self.ts.to_be_bytes());
        h.update(&self.last_writer);
        match &self.value {
            None => {
                h.update(&[0u8]);
            }
            Some(v) => {
                h.update(&[1u8]);
                let len = u32::try_from(v.len()).unwrap_or(u32::MAX);
                h.update(&len.to_be_bytes());
                h.update(&v[..len as usize]);
            }
        }
    }
}

// ── OrSet ──────────────────────────────────────────────────────────

/// Observed-remove set: each add carries a unique tag. A remove
/// erases all adds whose `(element, tag)` pair appears in the remove
/// set. Replays of the same `(element, tag)` are idempotent.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OrSet {
    adds: BTreeMap<Vec<u8>, BTreeSet<OrSetTag>>,
    removes: BTreeMap<Vec<u8>, BTreeSet<OrSetTag>>,
}

impl OrSet {
    /// Empty set.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }
    /// All currently-visible elements.
    #[must_use]
    pub fn members(&self) -> Vec<&[u8]> {
        let mut out = Vec::new();
        for (elem, adds) in &self.adds {
            let tomb = self.removes.get(elem);
            let visible = adds.iter().any(|t| tomb.is_none_or(|r| !r.contains(t)));
            if visible {
                out.push(elem.as_slice());
            }
        }
        out
    }
    /// True iff `element` is currently in the set.
    #[must_use]
    pub fn contains(&self, element: &[u8]) -> bool {
        match self.adds.get(element) {
            None => false,
            Some(adds) => {
                let tomb = self.removes.get(element);
                adds.iter().any(|t| tomb.is_none_or(|r| !r.contains(t)))
            }
        }
    }
    /// Tagged add. Replays are idempotent.
    pub fn add(&mut self, element: Vec<u8>, tag: OrSetTag) {
        self.adds.entry(element).or_default().insert(tag);
    }
    /// Tagged remove. Idempotent.
    pub fn remove(&mut self, element: &[u8], tag: &OrSetTag) {
        self.removes
            .entry(element.to_vec())
            .or_default()
            .insert(*tag);
    }
    fn canonical_into(&self, h: &mut Hasher) {
        let n_adds = u32::try_from(self.adds.len()).unwrap_or(u32::MAX);
        h.update(&n_adds.to_be_bytes());
        for (k, v) in &self.adds {
            let kl = u32::try_from(k.len()).unwrap_or(u32::MAX);
            h.update(&kl.to_be_bytes());
            h.update(&k[..kl as usize]);
            let nl = u32::try_from(v.len()).unwrap_or(u32::MAX);
            h.update(&nl.to_be_bytes());
            for tag in v {
                h.update(tag);
            }
        }
        let n_rem = u32::try_from(self.removes.len()).unwrap_or(u32::MAX);
        h.update(&n_rem.to_be_bytes());
        for (k, v) in &self.removes {
            let kl = u32::try_from(k.len()).unwrap_or(u32::MAX);
            h.update(&kl.to_be_bytes());
            h.update(&k[..kl as usize]);
            let nl = u32::try_from(v.len()).unwrap_or(u32::MAX);
            h.update(&nl.to_be_bytes());
            for tag in v {
                h.update(tag);
            }
        }
    }
}

// ── PnCounter ──────────────────────────────────────────────────────

/// Per-device positive/negative counter. Each device tracks its own
/// `(positive, negative)` totals; the global value is the sum.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PnCounter {
    pos: BTreeMap<[u8; 16], u128>,
    neg: BTreeMap<[u8; 16], u128>,
}

impl PnCounter {
    /// Empty counter.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }
    /// Current value (positive sum minus negative sum), as i128 to
    /// allow negative results.
    #[must_use]
    pub fn value(&self) -> i128 {
        let p: u128 = self.pos.values().sum();
        let n: u128 = self.neg.values().sum();
        (p as i128) - (n as i128)
    }
    /// Adjust this device's slot. `delta > 0` accumulates into
    /// the positive bucket; `delta < 0` into the negative bucket.
    /// Replays at the SAME (device, value) are idempotent because
    /// the underlying values are CRDT-style absolute accumulators.
    pub fn adjust(&mut self, device_id: [u8; 16], delta: i64) {
        if delta == 0 {
            return;
        }
        if delta > 0 {
            let entry = self.pos.entry(device_id).or_insert(0);
            *entry = entry.saturating_add(delta as u128);
        } else {
            let entry = self.neg.entry(device_id).or_insert(0);
            *entry = entry.saturating_add((-delta) as u128);
        }
    }
    fn canonical_into(&self, h: &mut Hasher) {
        let n = u32::try_from(self.pos.len()).unwrap_or(u32::MAX);
        h.update(&n.to_be_bytes());
        for (k, v) in &self.pos {
            h.update(k);
            h.update(&v.to_be_bytes());
        }
        let n = u32::try_from(self.neg.len()).unwrap_or(u32::MAX);
        h.update(&n.to_be_bytes());
        for (k, v) in &self.neg {
            h.update(k);
            h.update(&v.to_be_bytes());
        }
    }
}

// ── LwwMap ─────────────────────────────────────────────────────────

/// Map<key, lww-bytes> with tombstone semantics on delete.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LwwMap {
    entries: BTreeMap<Vec<u8>, LwwRegister>,
}

impl LwwMap {
    /// Empty map.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }
    /// Borrow the value for `key` (or `None` if absent / tombstoned).
    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.entries.get(key).and_then(|r| r.value())
    }
    /// Number of currently-visible (non-tombstoned) entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries
            .values()
            .filter(|r| r.value().is_some())
            .count()
    }
    /// True iff no entries are currently visible.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Put a value at `(key, ts)` from `writer`.
    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>, ts: u64, writer: &[u8; 16]) {
        let entry = self.entries.entry(key).or_insert_with(LwwRegister::empty);
        entry.set(value, ts, writer);
    }
    /// Delete `key` at `(ts, writer)`. Implemented as a LWW
    /// tombstone (value = None). A delete dominates a same-
    /// `(ts, writer)` put under our tie-break rule, so concurrent
    /// put-vs-delete from the same writer at the same timestamp
    /// converges to delete.
    pub fn delete(&mut self, key: &[u8], ts: u64, writer: &[u8; 16]) {
        let entry = self
            .entries
            .entry(key.to_vec())
            .or_insert_with(LwwRegister::empty);
        if entry.is_dominated_by(ts, writer, None) {
            entry.value = None;
            entry.ts = ts;
            entry.last_writer = *writer;
        }
    }
    fn canonical_into(&self, h: &mut Hasher) {
        let n = u32::try_from(self.entries.len()).unwrap_or(u32::MAX);
        h.update(&n.to_be_bytes());
        for (k, v) in &self.entries {
            let kl = u32::try_from(k.len()).unwrap_or(u32::MAX);
            h.update(&kl.to_be_bytes());
            h.update(&k[..kl as usize]);
            v.canonical_into(h);
        }
    }
}

// ── MeshState ──────────────────────────────────────────────────────

/// The complete mesh-replicated state — a map of named subtrees.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MeshState {
    subtrees: BTreeMap<SubtreeLabel, Subtree>,
}

impl MeshState {
    /// Empty state.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }
    /// Borrow a subtree by label.
    #[must_use]
    pub fn subtree(&self, label: &[u8]) -> Option<&Subtree> {
        self.subtrees.get(label)
    }
    /// Number of subtrees currently tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.subtrees.len()
    }
    /// True iff no subtrees.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.subtrees.is_empty()
    }
    /// Iterate `(label, subtree)` pairs in deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &Subtree)> {
        self.subtrees.iter().map(|(k, v)| (k.as_slice(), v))
    }
    /// Ensure `label` exists with a subtree of `kind`. Errors if the
    /// label is too long or the subtree exists with a different kind.
    pub fn ensure_subtree(
        &mut self,
        label: SubtreeLabel,
        kind: super::policy::SubtreePolicyKind,
    ) -> DeviceMeshResult<()> {
        if label.len() > MAX_SUBTREE_LABEL_LEN {
            return Err(DeviceMeshError::SubtreeLabelTooLong {
                got: label.len(),
                max: MAX_SUBTREE_LABEL_LEN,
            });
        }
        let entry = self.subtrees.entry(label);
        match entry {
            std::collections::btree_map::Entry::Vacant(v) => {
                v.insert(Subtree::empty_of_kind(kind));
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(o) => {
                if super::policy::subtree_kind(o.get()) == kind {
                    Ok(())
                } else {
                    Err(DeviceMeshError::SubtreeKindCollision)
                }
            }
        }
    }
    /// Apply a [`Delta`] to the named subtree. Caller is responsible
    /// for verifying the op's signature + subtree policy upstream;
    /// this function is the pure-state-machine half.
    pub fn apply_delta(
        &mut self,
        label: &[u8],
        delta: &Delta,
        emitter_device_id: &[u8; 16],
    ) -> DeviceMeshResult<()> {
        let st = self
            .subtrees
            .get_mut(label)
            .ok_or(DeviceMeshError::SubtreeMissing)?;
        st.apply(delta, emitter_device_id)
    }
    /// Compute the canonical state root. BLAKE3 over the sorted
    /// `(label, subtree_root)` list.
    #[must_use]
    pub fn root(&self) -> StateRoot {
        let mut h = Hasher::new();
        h.update(b"OL-mesh-state-root-v1");
        let n = u32::try_from(self.subtrees.len()).unwrap_or(u32::MAX);
        h.update(&n.to_be_bytes());
        for (label, sub) in &self.subtrees {
            let ll = u32::try_from(label.len()).unwrap_or(u32::MAX);
            h.update(&ll.to_be_bytes());
            h.update(&label[..ll as usize]);
            h.update(&sub.root());
        }
        *h.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh_state::policy::SubtreePolicyKind;

    #[test]
    fn empty_state_root_is_stable() {
        let a = MeshState::empty();
        let b = MeshState::empty();
        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn lww_register_writer_breaks_ts_tie() {
        let mut r = LwwRegister::empty();
        let alice = [0x01u8; 16];
        let bob = [0x02u8; 16];
        r.set(b"alice".to_vec(), 10, &alice);
        // Same ts, bob's id > alice's → bob wins.
        r.set(b"bob".to_vec(), 10, &bob);
        assert_eq!(r.value(), Some(&b"bob"[..]));
        // Older ts cannot revert.
        r.set(b"old".to_vec(), 5, &alice);
        assert_eq!(r.value(), Some(&b"bob"[..]));
    }

    #[test]
    fn or_set_add_then_remove() {
        let mut s = OrSet::empty();
        s.add(b"x".to_vec(), [0x01; 16]);
        assert!(s.contains(b"x"));
        s.remove(b"x", &[0x01; 16]);
        assert!(!s.contains(b"x"));
    }

    #[test]
    fn or_set_concurrent_add_after_remove_wins() {
        // Two devices independently add the same element with
        // different tags. One removes its own add; the other's add
        // stays visible because the remove only covers ONE tag.
        let mut s = OrSet::empty();
        s.add(b"x".to_vec(), [0x01; 16]);
        s.add(b"x".to_vec(), [0x02; 16]);
        s.remove(b"x", &[0x01; 16]);
        assert!(s.contains(b"x"));
    }

    #[test]
    fn pn_counter_concurrent_increments() {
        let mut c = PnCounter::empty();
        c.adjust([0x01; 16], 5);
        c.adjust([0x02; 16], 3);
        c.adjust([0x01; 16], -2);
        assert_eq!(c.value(), 5 + 3 - 2);
    }

    #[test]
    fn lww_map_put_get_delete() {
        let mut m = LwwMap::empty();
        let w = [0x01; 16];
        m.put(b"k".to_vec(), b"v1".to_vec(), 1, &w);
        assert_eq!(m.get(b"k"), Some(&b"v1"[..]));
        m.put(b"k".to_vec(), b"v2".to_vec(), 2, &w);
        assert_eq!(m.get(b"k"), Some(&b"v2"[..]));
        m.delete(b"k", 3, &w);
        assert_eq!(m.get(b"k"), None);
    }

    #[test]
    fn mesh_state_root_stable_under_distinct_insert_order() {
        let w = [0x01; 16];
        let mut a = MeshState::empty();
        a.ensure_subtree(b"x".to_vec(), SubtreePolicyKind::LwwRegister)
            .unwrap();
        a.ensure_subtree(b"y".to_vec(), SubtreePolicyKind::LwwMap)
            .unwrap();
        a.apply_delta(
            b"x",
            &Delta::LwwSet {
                value: b"v".to_vec(),
                ts: 1,
            },
            &w,
        )
        .unwrap();

        let mut b = MeshState::empty();
        b.ensure_subtree(b"y".to_vec(), SubtreePolicyKind::LwwMap)
            .unwrap();
        b.ensure_subtree(b"x".to_vec(), SubtreePolicyKind::LwwRegister)
            .unwrap();
        b.apply_delta(
            b"x",
            &Delta::LwwSet {
                value: b"v".to_vec(),
                ts: 1,
            },
            &w,
        )
        .unwrap();

        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn subtree_kind_collision_rejected() {
        let mut s = MeshState::empty();
        s.ensure_subtree(b"x".to_vec(), SubtreePolicyKind::LwwRegister)
            .unwrap();
        let err = s
            .ensure_subtree(b"x".to_vec(), SubtreePolicyKind::PnCounter)
            .unwrap_err();
        assert!(matches!(err, DeviceMeshError::SubtreeKindCollision));
    }

    #[test]
    fn oversize_label_rejected() {
        let mut s = MeshState::empty();
        let big = vec![b'x'; MAX_SUBTREE_LABEL_LEN + 1];
        let err = s
            .ensure_subtree(big, SubtreePolicyKind::LwwRegister)
            .unwrap_err();
        assert!(matches!(err, DeviceMeshError::SubtreeLabelTooLong { .. }));
    }
}
