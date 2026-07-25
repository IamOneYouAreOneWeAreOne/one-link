//! Observed-Remove Set (OR-set).
//!
//! Each add stamps the element with a unique tag (here: a 16-byte
//! BLAKE3-derived id keyed on the replica + counter). Remove tombstones
//! the *tags currently observed*. Concurrent (add, remove) of the same
//! element resolves as add-wins: the concurrent add has a fresh tag that
//! the remove never saw.
//!
//! Bounded-storage variant: we keep the set of tombstoned tags. For long-
//! lived folders a periodic `prune_synced(vc)` pass garbage-collects
//! tombstones causally dominated by every replica's clock. This crate
//! doesn't enforce sync state — callers wire pruning to their gossip
//! layer.

use std::collections::BTreeSet;

use crate::Lattice;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tag(pub [u8; 16]);

/// Generic OR-set keyed on any orderable element type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrSet<E: Ord + Clone> {
    /// (element, tag) tuples that have been added.
    pub(crate) added: BTreeSet<(E, Tag)>,
    /// Tags whose add has been remove-tombstoned.
    pub(crate) removed: BTreeSet<Tag>,
}

impl<E: Ord + Clone> Default for OrSet<E> {
    fn default() -> Self {
        Self {
            added: BTreeSet::new(),
            removed: BTreeSet::new(),
        }
    }
}

impl<E: Ord + Clone> OrSet<E> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `element` with the caller-supplied tag. Tags must be unique
    /// per add — callers derive them from (replica id || vector clock
    /// counter) hashed via BLAKE3, truncated to 16 bytes.
    pub fn add(&mut self, element: E, tag: Tag) {
        self.added.insert((element, tag));
    }

    /// Remove every currently-observed (element, tag) pair for this
    /// element value. Future adds with a fresh tag survive — the
    /// add-wins property.
    pub fn remove(&mut self, element: &E) {
        for (e, tag) in &self.added {
            if e == element && !self.removed.contains(tag) {
                self.removed.insert(tag.clone());
            }
        }
    }

    /// True if `element` is currently in the set (has at least one
    /// non-tombstoned tag).
    pub fn contains(&self, element: &E) -> bool {
        self.added
            .iter()
            .any(|(e, tag)| e == element && !self.removed.contains(tag))
    }

    pub fn iter(&self) -> impl Iterator<Item = &E> {
        let mut emitted: BTreeSet<&E> = BTreeSet::new();
        for (e, tag) in &self.added {
            if !self.removed.contains(tag) {
                emitted.insert(e);
            }
        }
        emitted.into_iter()
    }

    pub fn len(&self) -> usize {
        self.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate the underlying (element, tag) add log in deterministic
    /// order. Used by the structural-hash function in the lattice-law
    /// acceptance gate.
    pub fn iter_added(&self) -> impl Iterator<Item = &(E, Tag)> {
        self.added.iter()
    }

    /// Iterate the tombstone set in deterministic order.
    pub fn iter_removed(&self) -> impl Iterator<Item = &Tag> {
        self.removed.iter()
    }
}

impl<E: Ord + Clone> Lattice for OrSet<E> {
    fn merge(&mut self, other: &Self) {
        self.added.extend(other.added.iter().cloned());
        self.removed.extend(other.removed.iter().cloned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag(b: u8) -> Tag {
        Tag([b; 16])
    }

    #[test]
    fn add_makes_element_present() {
        let mut s: OrSet<String> = OrSet::new();
        s.add("a".into(), tag(1));
        assert!(s.contains(&"a".to_string()));
    }

    #[test]
    fn remove_then_add_wins() {
        let mut s: OrSet<String> = OrSet::new();
        s.add("a".into(), tag(1));
        s.remove(&"a".to_string());
        assert!(!s.contains(&"a".to_string()));
        s.add("a".into(), tag(2));
        assert!(s.contains(&"a".to_string()));
    }

    #[test]
    fn concurrent_add_survives_remove() {
        // Replica A adds with tag 1; replica B does (add with tag 2,
        // remove). When merged, the tag-2 remove tombstones tag 2 but
        // tag 1 is still alive.
        let mut a: OrSet<String> = OrSet::new();
        a.add("a".into(), tag(1));

        let mut b: OrSet<String> = OrSet::new();
        b.add("a".into(), tag(2));
        b.remove(&"a".to_string());

        a.merge(&b);
        // tag 1 still observed, tag 2 tombstoned → still present.
        assert!(a.contains(&"a".to_string()));
    }

    #[test]
    fn merge_is_idempotent() {
        let mut a: OrSet<u32> = OrSet::new();
        a.add(1, tag(1));
        a.add(2, tag(2));
        a.remove(&2);
        let snapshot = a.clone();
        a.merge(&snapshot);
        assert_eq!(a, snapshot);
    }
}
