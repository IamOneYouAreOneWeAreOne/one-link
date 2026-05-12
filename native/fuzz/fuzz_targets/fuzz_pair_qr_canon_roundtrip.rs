#![no_main]
//! Fuzz ol_pair_qr canon Reader. Walk a sequence of primitive reads
//! against an arbitrary byte buffer; must never panic regardless of
//! cursor position or truncation.

use libfuzzer_sys::fuzz_target;
use ol_pair_qr::canon::Reader;

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    // Try a sequence of reads that includes every primitive path.
    let _ = r.read_u8();
    let _ = r.read_u16();
    let _ = r.read_u32();
    let _ = r.read_u64();
    let _ = r.read_var();
    let _ = r.read_fixed(16);
    let _ = r.read_fixed(64);
    let _ = r.read_u8();
});
