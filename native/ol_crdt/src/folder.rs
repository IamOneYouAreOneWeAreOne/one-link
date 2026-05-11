//! Folder CRDT: composes vector clock + OR-set of file ids + LWW per-file
//! attribute registers.
//!
//! The folder model the plan calls for is:
//!
//! - The folder *exists* as soon as any replica adds it.
//! - File entries are an OR-set keyed on a stable content-addressed
//!   id (BLAKE3 of the manifest root).
//! - Per-file attributes (display name, size, last-modified) are LWW
//!   registers stamped with the local vector-clock counter.
//!
//! Merge is pointwise across all three sub-lattices. The folder type
//! itself satisfies the lattice merge laws (the acceptance gate
//! verifies this across ≥1M random states).

use std::collections::BTreeMap;

use crate::lww::LwwRegister;
use crate::or_set::{OrSet, Tag};
use crate::vector_clock::{ReplicaId, VectorClock};
use crate::Lattice;

/// Stable id for a file inside a folder.
pub type FileId = [u8; 32];

/// Per-file metadata, all LWW-stamped so concurrent renames / size
/// adjustments resolve deterministically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub display_name: LwwRegister<String>,
    pub size_bytes: LwwRegister<u64>,
    pub last_modified_ms: LwwRegister<u64>,
}

impl Lattice for FileEntry {
    fn merge(&mut self, other: &Self) {
        self.display_name.merge(&other.display_name);
        self.size_bytes.merge(&other.size_bytes);
        self.last_modified_ms.merge(&other.last_modified_ms);
    }
}

/// The Folder CRDT.
///
/// Holds:
/// - A vector clock summarising which counter each replica has reached.
/// - An OR-set of `FileId`s currently present.
/// - A map of per-file `FileEntry` lattices.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Folder {
    pub clock: VectorClock,
    pub files: OrSet<FileId>,
    pub entries: BTreeMap<FileId, FileEntry>,
}

impl Folder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a file with metadata. Stamps with this replica's next clock
    /// tick to derive a unique OR-set tag and LWW timestamp.
    pub fn add_file(
        &mut self,
        replica: &ReplicaId,
        id: FileId,
        display_name: String,
        size_bytes: u64,
        last_modified_ms: u64,
    ) {
        let counter = self.clock.tick(replica);
        let tag = derive_tag(replica, counter);
        self.files.add(id, tag);
        let entry = FileEntry {
            display_name: LwwRegister::new(display_name, counter, replica.clone()),
            size_bytes: LwwRegister::new(size_bytes, counter, replica.clone()),
            last_modified_ms: LwwRegister::new(last_modified_ms, counter, replica.clone()),
        };
        match self.entries.get_mut(&id) {
            Some(existing) => existing.merge(&entry),
            None => {
                self.entries.insert(id, entry);
            }
        }
    }

    pub fn remove_file(&mut self, replica: &ReplicaId, id: &FileId) {
        // Advance the clock so the observer knows this remove happened
        // after the previous local state.
        self.clock.tick(replica);
        self.files.remove(id);
    }

    pub fn contains(&self, id: &FileId) -> bool {
        self.files.contains(id)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&FileId, &FileEntry)> {
        self.entries
            .iter()
            .filter(move |(id, _)| self.files.contains(id))
    }
}

impl Lattice for Folder {
    fn merge(&mut self, other: &Self) {
        self.clock.merge(&other.clock);
        self.files.merge(&other.files);
        // Per-key LWW merge. Insert missing entries; merge existing.
        for (id, entry) in &other.entries {
            match self.entries.get_mut(id) {
                Some(existing) => existing.merge(entry),
                None => {
                    self.entries.insert(*id, entry.clone());
                }
            }
        }
    }
}

fn derive_tag(replica: &ReplicaId, counter: u64) -> Tag {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ol-crdt-tag-v1");
    hasher.update(&replica.0);
    hasher.update(&counter.to_le_bytes());
    let h = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&h.as_bytes()[..16]);
    Tag(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rid(b: u8) -> ReplicaId {
        ReplicaId([b; 32])
    }
    fn fid(b: u8) -> FileId {
        [b; 32]
    }

    #[test]
    fn add_then_iter() {
        let mut f = Folder::new();
        let alice = rid(1);
        f.add_file(&alice, fid(0xAA), "report.pdf".into(), 1024, 100);
        assert!(f.contains(&fid(0xAA)));
        let items: Vec<_> = f.iter().collect();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].1.display_name.value, "report.pdf");
    }

    #[test]
    fn concurrent_add_and_remove_add_wins_via_or_set() {
        let alice = rid(1);
        let bob = rid(2);
        let mut a = Folder::new();
        a.add_file(&alice, fid(0xCC), "secret.pdf".into(), 4096, 1);

        let mut b = a.clone();
        // Alice continues to keep working: nothing.
        // Bob removes the file.
        b.remove_file(&bob, &fid(0xCC));
        // Alice re-adds concurrently (fresh tag).
        a.add_file(&alice, fid(0xCC), "secret.pdf".into(), 4096, 1);

        a.merge(&b);
        // Concurrent re-add wins over Bob's remove: file present.
        assert!(a.contains(&fid(0xCC)));
    }

    #[test]
    fn merge_is_commutative_and_idempotent() {
        let alice = rid(1);
        let bob = rid(2);

        let mut a = Folder::new();
        a.add_file(&alice, fid(0x01), "a".into(), 1, 1);
        a.add_file(&alice, fid(0x02), "b".into(), 2, 2);

        let mut b = Folder::new();
        b.add_file(&bob, fid(0x02), "b'".into(), 2, 5);
        b.add_file(&bob, fid(0x03), "c".into(), 3, 3);

        let mut ab = a.clone();
        ab.merge(&b);

        let mut ba = b.clone();
        ba.merge(&a);

        assert_eq!(ab, ba, "merge not commutative");

        let snap = ab.clone();
        ab.merge(&snap);
        assert_eq!(ab, snap, "merge not idempotent");
    }
}
