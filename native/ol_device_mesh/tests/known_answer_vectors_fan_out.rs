//! Pinned KAT vectors for Row 8 Layer 5 fan-out.

use ol_device_mesh::distributed_fs::{ChunkHash, FILE_ID_LEN};
use ol_device_mesh::fan_out::{
    ChunkAck, FetchRequest, ACK_DOMAIN, FETCH_NONCE_LEN, FETCH_REQUEST_DOMAIN,
    MAX_CHUNKS_PER_FETCH,
};
use ol_device_mesh::DEVICE_ID_LEN;

fn check_regen<F: FnOnce()>(label: &str, dump: F) {
    if std::env::var("OL_FAN_OUT_KAT_REGEN").as_deref() == Ok("1") {
        eprintln!("[KAT REGEN] {label}");
        dump();
    }
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn kat_domain_tags_pinned() {
    assert_eq!(FETCH_REQUEST_DOMAIN, b"OL-mesh-fetch-request-v1");
    assert_eq!(ACK_DOMAIN, b"OL-mesh-chunk-ack-v1");
}

#[test]
fn kat_bound_constants_pinned() {
    assert_eq!(MAX_CHUNKS_PER_FETCH, 8192);
    assert_eq!(FETCH_NONCE_LEN, 16);
}

#[test]
fn kat_fetch_request_canonical_transcript_pinned() {
    let bytes = FetchRequest::canonical_transcript(
        &[0xCC; FILE_ID_LEN],
        &[0xAA; DEVICE_ID_LEN],
        &[0xBB; DEVICE_ID_LEN],
        &[[0x11; 32], [0x22; 32]],
        1_000_000,
        1_700_003_600,
        &[0xDA; FETCH_NONCE_LEN],
        7,
        1_700_000_000,
    );
    let hex = to_hex(&bytes);
    let domain_hex = to_hex(FETCH_REQUEST_DOMAIN);
    assert!(hex.starts_with(&domain_hex));
    check_regen("fetch request canonical_transcript", || {
        eprintln!("    EXPECTED_FETCH_REQ_HEX = \"{hex}\"");
    });
    const EXPECTED_FETCH_REQ_HEX: &str = concat!(
        "4f4c2d6d6573682d66657463682d726571756573742d7631", // "OL-mesh-fetch-request-v1"
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",  // file_id
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  // receiver
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",  // source
        "00000002",                          // chunk_count
        "1111111111111111111111111111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "00000000000f4240",                  // max_byte_budget = 1_000_000
        "000000006553ff10",                  // deadline_unix
        "dadadadadadadadadadadadadadadada",  // nonce
        "0000000000000007",                  // receiver_day_index = 7
        "000000006553f100",                  // issued_unix = 1_700_000_000
    );
    assert_eq!(hex, EXPECTED_FETCH_REQ_HEX, "fetch req transcript drift");
}

#[test]
fn kat_chunk_ack_canonical_transcript_pinned() {
    let bytes = ChunkAck::canonical_transcript(
        &[0xCC; FILE_ID_LEN],
        &[0xDD; 32],
        &[0xAA; DEVICE_ID_LEN],
        &[0xBB; DEVICE_ID_LEN],
        3,
        1_700_000_000,
        8192,
    );
    let hex = to_hex(&bytes);
    let domain_hex = to_hex(ACK_DOMAIN);
    assert!(hex.starts_with(&domain_hex));
    check_regen("chunk-ack canonical_transcript", || {
        eprintln!("    EXPECTED_ACK_HEX = \"{hex}\"");
    });
    const EXPECTED_ACK_HEX: &str = concat!(
        "4f4c2d6d6573682d6368756e6b2d61636b2d7631",                   // "OL-mesh-chunk-ack-v1"
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",  // file_id
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",  // chunk_hash
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  // source
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",  // receiver
        "0000000000000003",                  // source_day_index = 3
        "000000006553f100",                  // delivered_unix
        "00002000",                          // byte_size = 8192
    );
    assert_eq!(hex, EXPECTED_ACK_HEX, "chunk-ack transcript drift");
}

#[test]
fn kat_chunk_hash_length_in_transcript() {
    // Sanity: a 32-byte ChunkHash contributes 64 hex chars per chunk
    // in the canonical transcript.
    let bytes = FetchRequest::canonical_transcript(
        &[0; FILE_ID_LEN],
        &[0; DEVICE_ID_LEN],
        &[0; DEVICE_ID_LEN],
        &[[0u8; 32]],
        0,
        1,
        &[0; FETCH_NONCE_LEN],
        0,
        0,
    );
    // domain(24) + file_id(32) + 2*device_id(16) + count(4) +
    // 1 chunk(32) + budget(8) + deadline(8) + nonce(16) +
    // day_index(8) + issued(8) = 172 bytes
    assert_eq!(bytes.len(), 172);
}
