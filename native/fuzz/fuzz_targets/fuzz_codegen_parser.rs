#![no_main]
//! Fuzz the codegen parser. Arbitrary UTF-8 input must never panic
//! the parser — it should return Ok or Err deterministically.

use libfuzzer_sys::fuzz_target;
use ol_codegen::parse_struct;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let _ = parse_struct(s);
});
