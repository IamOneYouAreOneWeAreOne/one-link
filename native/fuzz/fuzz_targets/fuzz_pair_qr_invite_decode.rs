#![no_main]
//! Fuzz ol_pair_qr Invite::decode_raw + Invite::decode_and_verify
//! with arbitrary byte payloads. Must never panic.

use libfuzzer_sys::fuzz_target;
use ol_pair_qr::invite::Invite;

fuzz_target!(|data: &[u8]| {
    // decode_raw is the parser-only path — must NEVER panic regardless
    // of input. The result (Ok/Err) is informational.
    let _ = Invite::decode_raw(data);
    // decode_and_verify is the verifying path — must NEVER panic
    // regardless of input. May return BadSignature, BadTag,
    // Truncated, Oversize, UnsupportedVersion, etc.
    let _ = Invite::decode_and_verify(data);
});
