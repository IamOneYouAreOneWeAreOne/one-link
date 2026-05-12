#![no_main]
//! Fuzz ol_pair_qr PairResponse::decode_raw +
//! PairResponse::decode_and_verify. Must never panic.

use libfuzzer_sys::fuzz_target;
use ol_pair_qr::response::PairResponse;

fuzz_target!(|data: &[u8]| {
    let _ = PairResponse::decode_raw(data);
    // decode_and_verify needs a transcript_bind; supply a fixed
    // garbage one — we're proving the verifier is panic-free across
    // arbitrary frames.
    let bind: &[u8] = b"fuzz-bind-vector-do-not-trust";
    let _ = PairResponse::decode_and_verify(data, bind);
});
