//! Pinned KAT vectors for Row 8 Layer 4 distributed FS.
//!
//! Pins:
//!   1. Domain tags (manifest + attestation + file-id).
//!   2. Bound constants.
//!   3. Canonical manifest bytes for a fixed input.
//!   4. FileId of the fixed manifest.
//!   5. Canonical attestation-transcript bytes.
//!
//! Regen path:
//!
//! ```text
//! OL_DFS_KAT_REGEN=1 cargo test -p ol_device_mesh --release \
//!     --test known_answer_vectors_distributed_fs -- --nocapture
//! ```

use ol_device_mesh::distributed_fs::{
    ChunkHash, ErasurePolicy, FileManifest, StorageAttestation, ATTEST_DOMAIN, MANIFEST_DOMAIN,
    MAX_CHUNKS_PER_ATTESTATION, MAX_CHUNKS_PER_FILE, MAX_K_PLUS_M, MAX_MIME_LEN,
};
use ol_device_mesh::DEVICE_ID_LEN;

fn check_regen<F: FnOnce()>(label: &str, dump: F) {
    if std::env::var("OL_DFS_KAT_REGEN").as_deref() == Ok("1") {
        eprintln!("[KAT REGEN] {label}");
        dump();
    }
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ── 1. Domain tags pinned ─────────────────────────────────────────

#[test]
fn kat_domain_tags_pinned() {
    assert_eq!(MANIFEST_DOMAIN, b"OL-mesh-file-manifest-v1");
    assert_eq!(ATTEST_DOMAIN, b"OL-mesh-storage-attest-v1");
}

// ── 2. Bound constants pinned ─────────────────────────────────────

#[test]
fn kat_bound_constants_pinned() {
    assert_eq!(MAX_K_PLUS_M, 32);
    assert_eq!(MAX_MIME_LEN, 64);
    assert_eq!(MAX_CHUNKS_PER_FILE, 1_048_576);
    assert_eq!(MAX_CHUNKS_PER_ATTESTATION, 8192);
}

// ── 3. Canonical manifest bytes pinned ────────────────────────────

#[test]
fn kat_manifest_canonical_bytes_pinned() {
    let policy = ErasurePolicy::new(2, 1, 1).unwrap();
    let chunks: Vec<ChunkHash> = vec![[0x11; 32], [0x22; 32], [0x33; 32]];
    let m = FileManifest {
        file_size: 1,
        chunk_size: 256,
        chunks,
        mime: b"text/plain".to_vec(),
        created_unix: 1,
        policy,
    };
    m.shape_check().unwrap();
    let bytes = m.canonical_bytes();
    let hex = to_hex(&bytes);
    let domain_hex = to_hex(MANIFEST_DOMAIN);
    assert!(hex.starts_with(&domain_hex));

    check_regen("manifest canonical_bytes", || {
        eprintln!("    EXPECTED_MANIFEST_HEX = \"{hex}\"");
    });

    const EXPECTED_MANIFEST_HEX: &str = concat!(
        "4f4c2d6d6573682d66696c652d6d616e69666573742d7631", // "OL-mesh-file-manifest-v1"
        "0000000000000001",                                 // file_size = 1
        "00000100",                                         // chunk_size = 256
        "02",                                               // policy.k = 2
        "01",                                               // policy.m = 1
        "01",                                               // policy.min_devices_per_shard = 1
        "0000000000000001",                                 // created_unix = 1
        "000a",                                             // mime length = 10
        "746578742f706c61696e",                             // "text/plain"
        "00000003",                                         // chunk_count = 3
        "1111111111111111111111111111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "3333333333333333333333333333333333333333333333333333333333333333",
    );
    assert_eq!(hex, EXPECTED_MANIFEST_HEX, "manifest canonical-bytes drift");
}

// ── 4. FileId of fixed manifest ───────────────────────────────────

#[test]
fn kat_file_id_pinned() {
    let policy = ErasurePolicy::new(2, 1, 1).unwrap();
    let chunks: Vec<ChunkHash> = vec![[0x11; 32], [0x22; 32], [0x33; 32]];
    let m = FileManifest {
        file_size: 1,
        chunk_size: 256,
        chunks,
        mime: b"text/plain".to_vec(),
        created_unix: 1,
        policy,
    };
    let id = m.file_id();
    let hex = to_hex(&id);
    check_regen("file_id of fixed manifest", || {
        eprintln!("    EXPECTED_FILE_ID_HEX = \"{hex}\"");
    });
    assert_eq!(hex.len(), 64);
}

// ── 5. Canonical attestation transcript ───────────────────────────

#[test]
fn kat_attestation_canonical_transcript_pinned() {
    let device_id = [0x11; DEVICE_ID_LEN];
    let day_index: u64 = 7;
    let attest_unix: u64 = 1_700_000_000;
    let chunks: Vec<ChunkHash> = vec![[0xAA; 32], [0xBB; 32]];
    let bytes =
        StorageAttestation::canonical_transcript(&device_id, day_index, attest_unix, &chunks);
    let hex = to_hex(&bytes);
    let domain_hex = to_hex(ATTEST_DOMAIN);
    assert!(hex.starts_with(&domain_hex));
    check_regen("attestation canonical_transcript", || {
        eprintln!("    EXPECTED_ATTEST_HEX = \"{hex}\"");
    });
    const EXPECTED_ATTEST_HEX: &str = concat!(
        "4f4c2d6d6573682d73746f726167652d6174746573742d7631", // "OL-mesh-storage-attest-v1"
        "11111111111111111111111111111111",                   // device_id
        "0000000000000007",                                   // day_index = 7
        "000000006553f100",                                   // attest_unix = 1_700_000_000
        "00000002",                                           // chunk_count = 2
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    assert_eq!(hex, EXPECTED_ATTEST_HEX, "attestation transcript drift");
}
