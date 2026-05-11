//! Phase C acceptance gate for `ol_crdt` (FILE_ENGINE_V2_PLAN.md line 289):
//!
//!     "lattice merge laws" property tests.
//!
//! Property-tests commutativity, associativity, and idempotency of
//! `Folder::merge` across ≥1M random (a, b, c) triples. The randomized
//! folder generator covers four state-shape buckets:
//!
//! 1. Pure adds.
//! 2. Adds + removes.
//! 3. Adds + concurrent re-adds (add-wins regression coverage).
//! 4. LWW-attribute battles (concurrent renames of the same FileId).
//!
//! Iteration count is configurable via `OL_CRDT_GATE_ITERS` env var
//! (default: 10_000 for CI; the acceptance gate run sets it to 1_000_000).
//! At default iter count this test runs in ≤500 ms; at gate count it
//! runs in ≤45 s on a tuned x86 host.

use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;

use ol_crdt::{FileEntry, Folder, Lattice, LwwRegister, ReplicaId};

fn next_rng(state: &mut u64) -> u64 {
    // SplitMix64. Tiny, fast, deterministic — we want reproducibility,
    // not cryptographic quality.
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn random_id(state: &mut u64, namespace: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for chunk in bytes.chunks_mut(8) {
        let v = next_rng(state).to_le_bytes();
        chunk.copy_from_slice(&v);
    }
    bytes[0] = namespace;
    bytes
}

fn random_folder(state: &mut u64, bucket: u8) -> Folder {
    let mut f = Folder::new();
    let replicas: Vec<ReplicaId> = (0..3)
        .map(|i| ReplicaId(random_id(state, i as u8)))
        .collect();
    let file_ids: Vec<[u8; 32]> = (0..6)
        .map(|i| random_id(state, 0x80 | i as u8))
        .collect();

    let n_ops = (next_rng(state) % 8) + 1;
    for _ in 0..n_ops {
        let r = &replicas[(next_rng(state) as usize) % replicas.len()];
        let fid = file_ids[(next_rng(state) as usize) % file_ids.len()];
        let action = match bucket {
            0 => 0, // pure adds
            1 => next_rng(state) % 2, // add or remove
            2 => next_rng(state) % 3, // add / remove / re-add
            _ => next_rng(state) % 4, // also rename battles
        };
        match action {
            0 | 2 => {
                let name = format!("file_{}.bin", next_rng(state) % 100);
                let size = next_rng(state) % 65536;
                let mtime = next_rng(state) % 1_000_000;
                f.add_file(r, fid, name, size, mtime);
            }
            1 => {
                f.remove_file(r, &fid);
            }
            _ => {
                // Direct LWW attribute battle: overwrite display_name via
                // a freshly-stamped entry.
                let counter = f.clock.tick(r);
                let entry = FileEntry {
                    display_name: LwwRegister::new(
                        format!("rename_{}.bin", next_rng(state) % 100),
                        counter,
                        r.clone(),
                    ),
                    size_bytes: LwwRegister::new(0, counter, r.clone()),
                    last_modified_ms: LwwRegister::new(counter, counter, r.clone()),
                };
                if let Some(existing) = f.entries.get_mut(&fid) {
                    existing.merge(&entry);
                } else {
                    f.entries.insert(fid, entry);
                }
            }
        }
    }
    f
}

fn folder_hash(f: &Folder) -> u64 {
    // Stable structural hash: hash the deterministic serialization of
    // sub-lattices. Used to compare merge outputs across paths.
    let mut h = DefaultHasher::new();
    // Vector clock
    for (rid, c) in f.clock.iter() {
        h.write(&rid.0);
        h.write_u64(*c);
    }
    h.write(b"|");
    // OR-set added
    for (e, tag) in f.files.iter_added() {
        h.write(e);
        h.write(&tag.0);
    }
    h.write(b"|");
    // OR-set removed
    for tag in f.files.iter_removed() {
        h.write(&tag.0);
    }
    h.write(b"|");
    // Entry map
    for (fid, entry) in &f.entries {
        h.write(fid);
        h.write(entry.display_name.value.as_bytes());
        h.write_u64(entry.display_name.timestamp);
        h.write(&entry.display_name.replica.0);
        h.write_u64(entry.size_bytes.value);
        h.write_u64(entry.size_bytes.timestamp);
        h.write(&entry.size_bytes.replica.0);
        h.write_u64(entry.last_modified_ms.value);
        h.write_u64(entry.last_modified_ms.timestamp);
        h.write(&entry.last_modified_ms.replica.0);
    }
    h.finish()
}

#[test]
fn folder_merge_laws() {
    let iters: u64 = std::env::var("OL_CRDT_GATE_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);

    let mut state: u64 = 0xCAFE_F00D_DEAD_BEEF;
    let mut comm_fail = 0u64;
    let mut assoc_fail = 0u64;
    let mut idem_fail = 0u64;

    for i in 0..iters {
        let bucket = (i % 4) as u8;
        let a = random_folder(&mut state, bucket);
        let b = random_folder(&mut state, bucket);
        let c = random_folder(&mut state, bucket);

        // Commutativity: a ⊔ b == b ⊔ a
        let mut ab = a.clone();
        ab.merge(&b);
        let mut ba = b.clone();
        ba.merge(&a);
        if folder_hash(&ab) != folder_hash(&ba) {
            comm_fail += 1;
        }

        // Associativity: (a ⊔ b) ⊔ c == a ⊔ (b ⊔ c)
        let mut left = ab.clone();
        left.merge(&c);
        let mut bc = b.clone();
        bc.merge(&c);
        let mut right = a.clone();
        right.merge(&bc);
        if folder_hash(&left) != folder_hash(&right) {
            assoc_fail += 1;
        }

        // Idempotency: a ⊔ a == a
        let mut aa = a.clone();
        aa.merge(&a);
        if folder_hash(&aa) != folder_hash(&a) {
            idem_fail += 1;
        }
    }

    assert_eq!(
        comm_fail, 0,
        "commutativity violations across {iters} iters"
    );
    assert_eq!(
        assoc_fail, 0,
        "associativity violations across {iters} iters"
    );
    assert_eq!(
        idem_fail, 0,
        "idempotency violations across {iters} iters"
    );
}
