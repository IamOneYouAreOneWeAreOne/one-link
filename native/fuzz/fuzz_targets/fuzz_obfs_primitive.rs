#![no_main]
//! Fuzz the obfuscate / deobfuscate primitive round-trip on arbitrary
//! bytes. Must never panic; output must always be the same length as
//! input; deobfuscate(obfuscate(x)) == x always.

use libfuzzer_sys::fuzz_target;
use ol_onion::transport_obfs::primitive::{deobfuscate, obfuscate, OBFS_KEY_LEN, OBFS_NONCE_LEN};

fuzz_target!(|data: &[u8]| {
    // Use first OBFS_KEY_LEN bytes as key (zero-padded if short),
    // next OBFS_NONCE_LEN bytes as nonce, rest as plaintext.
    let key_src = if data.len() >= OBFS_KEY_LEN { &data[..OBFS_KEY_LEN] } else { data };
    let mut key = [0u8; OBFS_KEY_LEN];
    key[..key_src.len()].copy_from_slice(key_src);

    let nonce_src = if data.len() >= OBFS_KEY_LEN + OBFS_NONCE_LEN {
        &data[OBFS_KEY_LEN..OBFS_KEY_LEN + OBFS_NONCE_LEN]
    } else {
        &[]
    };
    let mut nonce = [0u8; OBFS_NONCE_LEN];
    nonce[..nonce_src.len()].copy_from_slice(nonce_src);

    let plain_src = if data.len() >= OBFS_KEY_LEN + OBFS_NONCE_LEN {
        &data[OBFS_KEY_LEN + OBFS_NONCE_LEN..]
    } else {
        &[]
    };

    let cipher = obfuscate(&key, &nonce, plain_src);
    assert_eq!(cipher.len(), plain_src.len());
    let recovered = deobfuscate(&key, &nonce, &cipher);
    assert_eq!(recovered, plain_src);
});
