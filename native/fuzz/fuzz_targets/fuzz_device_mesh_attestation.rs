#![no_main]
//! Fuzz the device-mesh `SubkeyAttestation::verify` path. Arbitrary
//! attestation bytes must never panic; verify returns a typed error.

use libfuzzer_sys::fuzz_target;
use ol_device_mesh::{
    mint_subkey, DeviceClass, MasterIdentity, SubkeyAttestation,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fuzz_target!(|data: &[u8]| {
    // Deterministic master so fuzz runs are reproducible.
    let mut rng = ChaCha20Rng::from_seed([0xA1u8; 32]);
    let master = MasterIdentity::generate(&mut rng);
    let (_sk, mut att) =
        mint_subkey(&master, DeviceClass::Phone, [0x55; 16], 0, 365).unwrap();

    // Mutate the attestation with the fuzz input.
    if !data.is_empty() {
        // First byte selects which field to corrupt.
        let pick = data[0] % 5;
        let body = &data[1..];
        match pick {
            0 => {
                // Replace master_sig with body (length-aware).
                let n = body.len().min(att.master_sig.len());
                att.master_sig[..n].copy_from_slice(&body[..n]);
            }
            1 => {
                // Replace subkey_vk_bytes prefix.
                let n = body.len().min(att.subkey_vk_bytes.len());
                att.subkey_vk_bytes[..n].copy_from_slice(&body[..n]);
            }
            2 if body.len() >= 8 => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&body[..8]);
                att.mint_day_index = u64::from_be_bytes(buf);
            }
            3 if body.len() >= 8 => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&body[..8]);
                att.expiry_day_index = u64::from_be_bytes(buf);
            }
            _ if !body.is_empty() => {
                let n = body.len().min(att.device_id.len());
                att.device_id[..n].copy_from_slice(&body[..n]);
            }
            _ => {}
        }
    }
    let _ = att.verify(&master.verifying_key());
    // Also stress canonical_transcript with the mutated parts.
    let _ = SubkeyAttestation::canonical_transcript(
        att.class,
        &att.device_id,
        att.mint_day_index,
        att.expiry_day_index,
        &att.subkey_vk_bytes,
    );
});
