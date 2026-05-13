#![no_main]
//! Fuzz the Layer 10 duress surface.

use libfuzzer_sys::fuzz_target;
use ol_device_mesh::duress::{
    create_duress_envelope, sign_duress_alert, unlock_duress_envelope,
    verify_pairing_cross_channel, PairingChannel, PairingCommitment,
};
use ol_device_mesh::{
    mint_subkey, DeviceClass, MasterIdentity, DEVICE_ID_LEN,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fuzz_target!(|data: &[u8]| {
    let mut rng = ChaCha20Rng::from_seed([0xAAu8; 32]);

    // 1. Pairing-commitment cross-channel: build commitments derived
    //    from fuzz bytes, attempt verify.
    let secret_bytes: Vec<u8> = data.iter().take(16).copied().collect();
    if !secret_bytes.is_empty() {
        let qr = PairingCommitment::build(
            PairingChannel::Qr,
            &secret_bytes,
            [data.get(16).copied().unwrap_or(0); 16],
            u64::from(data.get(17).copied().unwrap_or(0)),
        );
        let audio = PairingCommitment::build(
            PairingChannel::Audio,
            &secret_bytes,
            [data.get(18).copied().unwrap_or(0); 16],
            u64::from(data.get(19).copied().unwrap_or(0)),
        );
        let motion = PairingCommitment::build(
            PairingChannel::Motion,
            &secret_bytes,
            [data.get(20).copied().unwrap_or(0); 16],
            u64::from(data.get(21).copied().unwrap_or(0)),
        );
        let _ =
            verify_pairing_cross_channel(&[qr, audio, motion], &secret_bytes, 1_000_000);
    }

    // 2. DuressAlert sign + tamper.
    let master = MasterIdentity::generate(&mut rng);
    let (sk, _) = mint_subkey(
        &master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365,
    )
    .unwrap();
    let mut nonce = [0u8; 16];
    for (i, b) in data.iter().take(16).enumerate() {
        nonce[i] = *b;
    }
    if let Ok(mut alert) = sign_duress_alert(&sk, 1, nonce) {
        if let Some(&b) = data.first() {
            if !alert.subkey_sig.is_empty() {
                alert.subkey_sig[0] ^= b;
            }
        }
        let _ = alert.verify(&sk.verifying_key());
    }

    // 3. DuressEnvelope (small plaintext to keep Argon2 cost bounded).
    let witness = [data.first().copied().unwrap_or(0); 32];
    if data.len() > 4 {
        let real_pt = &data[..data.len().min(16)];
        let decoy_pt = &data[data.len().min(16).min(data.len())..data.len().min(32).max(data.len().min(16) + 1)];
        let real_code = &data[..1.min(data.len())];
        let decoy_code: &[u8] = b"decoy-fuzz-code-9";
        if !real_pt.is_empty() && !decoy_pt.is_empty() && !real_code.is_empty()
            && real_code != decoy_code
        {
            if let Ok(env) = create_duress_envelope(
                real_pt, decoy_pt, real_code, decoy_code, &witness, &mut rng,
            ) {
                let _ = unlock_duress_envelope(&env, real_code, Some(&witness));
                let _ = unlock_duress_envelope(&env, decoy_code, None);
            }
        }
    }
});
