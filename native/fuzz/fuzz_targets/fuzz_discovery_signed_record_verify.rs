#![no_main]
//! Fuzz SignedRecord::verify against arbitrary inputs. Verifier
//! must NEVER panic — malformed pubkey/signature/canonical-bytes
//! all return RecordError cleanly.

use libfuzzer_sys::fuzz_target;
use ol_discovery::record::{PeerRecord, SignedRecord};

fuzz_target!(|data: &[u8]| {
    // Need at least 32 (pubkey) + 16 (publish + ttl) + 2 (n_eps)
    // + 64 (signature) = 114 bytes to even attempt.
    if data.len() < 128 {
        return;
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&data[..32]);
    let publish = u64::from_be_bytes(<[u8; 8]>::try_from(&data[32..40]).unwrap());
    let ttl = u64::from_be_bytes(<[u8; 8]>::try_from(&data[40..48]).unwrap());
    // Take remaining bytes as the (possibly malformed) endpoints
    // sequence. We construct a record with one endpoint and feed
    // its canonical bytes through; verify must not panic.
    let ep_bytes = &data[48..data.len() - 64];
    // Bound endpoint length to avoid the shape-check rejecting
    // before verify gets called.
    let ep = String::from_utf8_lossy(&ep_bytes[..ep_bytes.len().min(120)]).to_string();
    let rec = PeerRecord {
        publisher_pubkey: pubkey,
        endpoints: vec![ep],
        publish_time_unix: publish,
        ttl_secs: ttl,
    };
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[data.len() - 64..]);
    let signed = SignedRecord {
        record: rec,
        signature,
    };
    // Must not panic. Most inputs will return BadSignature or
    // MalformedPubkey; that's fine.
    let _ = signed.verify();
});
