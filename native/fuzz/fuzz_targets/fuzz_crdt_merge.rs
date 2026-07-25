#![no_main]
//! Fuzz the Folder CRDT merge. Build two folders A and B from fuzz
//! input, then assert the lattice merge laws (commutativity,
//! idempotency) hold for the produced folder states.

use libfuzzer_sys::fuzz_target;
use ol_crdt::{Folder, Lattice, ReplicaId};

fn take_array<const N: usize>(input: &mut &[u8]) -> Option<[u8; N]> {
    if input.len() < N {
        return None;
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&input[..N]);
    *input = &input[N..];
    Some(out)
}

fn take_byte(input: &mut &[u8]) -> Option<u8> {
    let b = *input.first()?;
    *input = &input[1..];
    Some(b)
}

fn take_u32(input: &mut &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = take_array(input)?;
    Some(u32::from_le_bytes(bytes))
}

fn take_u64(input: &mut &[u8]) -> Option<u64> {
    let bytes: [u8; 8] = take_array(input)?;
    Some(u64::from_le_bytes(bytes))
}

fn structural_eq(a: &Folder, b: &Folder) -> bool {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::Hasher;
    let hash_one = |f: &Folder| -> u64 {
        let mut h = DefaultHasher::new();
        for (rid, c) in f.clock.iter() {
            h.write(&rid.0);
            h.write_u64(*c);
        }
        h.write(b"|");
        for (e, tag) in f.files.iter_added() {
            h.write(e);
            h.write(&tag.0);
        }
        h.write(b"|");
        for tag in f.files.iter_removed() {
            h.write(&tag.0);
        }
        h.finish()
    };
    hash_one(a) == hash_one(b)
}

fn build_folder(input: &mut &[u8]) -> Folder {
    let mut f = Folder::new();
    let Some(n_ops) = take_byte(input) else {
        return f;
    };
    for _ in 0..(n_ops % 16) {
        let Some(op) = take_byte(input) else { break };
        let Some(rb) = take_byte(input) else { break };
        let Some(fid_lo) = take_u32(input) else { break };
        let mut fid = [0u8; 32];
        fid[..4].copy_from_slice(&fid_lo.to_le_bytes());
        let r = ReplicaId([rb; 32]);
        if op % 2 == 0 {
            let size = take_u64(input).unwrap_or(0);
            let mtime = take_u64(input).unwrap_or(0);
            f.add_file(&r, fid, format!("f{fid_lo}"), size, mtime);
        } else {
            f.remove_file(&r, &fid);
        }
    }
    f
}

fuzz_target!(|data: &[u8]| {
    let mut input = data;
    let a = build_folder(&mut input);
    let b = build_folder(&mut input);

    // Commutativity: a⊔b == b⊔a
    let mut ab = a.clone();
    ab.merge(&b);
    let mut ba = b.clone();
    ba.merge(&a);
    assert!(structural_eq(&ab, &ba), "merge not commutative");

    // Idempotency: a⊔a == a
    let mut aa = a.clone();
    aa.merge(&a);
    assert!(structural_eq(&aa, &a), "merge not idempotent");
});
