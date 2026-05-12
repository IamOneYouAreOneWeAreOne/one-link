#![no_main]
//! Fuzz ol_pair_qr PairConfirm::decode_raw +
//! PairConfirm::decode_and_verify. Must never panic.

use libfuzzer_sys::fuzz_target;
use ol_pair_qr::confirm::PairConfirm;
use ol_pair_qr::transcript::TranscriptHash;

fuzz_target!(|data: &[u8]| {
    let _ = PairConfirm::decode_raw(data);
    // decode_and_verify needs an expected pubkey + expected transcript;
    // supply arbitrary fixed values — we're proving panic-freedom.
    let pubkey = [0u8; 32];
    let t = TranscriptHash::from_bytes([0u8; 32]);
    let _ = PairConfirm::decode_and_verify(data, &pubkey, &t);
});
