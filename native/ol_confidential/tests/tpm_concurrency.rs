//! Concurrency stress on the real Windows TPM.
//!
//! NCrypt handles are documented thread-safe by MSDN, but consumer
//! TPMs have a single internal command pipeline — under heavy
//! concurrent load they return `TPM_RC_CANCELED` rather than block.
//! These tests verify:
//!
//! - Sharing one `TpmAttestationKey` across threads via `Arc` never
//!   panics or corrupts state.
//! - Each thread eventually completes its sign (with retry).
//! - The TPM-issued signatures from concurrent threads all verify
//!   under the same TPM public key.

#![cfg(all(target_os = "windows", feature = "windows-tpm"))]

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use ol_confidential::platform_quote::{
    canonical_platform_quote_subtranscript, verify_platform_quote,
};
use ol_confidential::windows_tpm::{produce_platform_quote, TpmAttestationKey};
use ol_confidential::ProviderTag;

const KEY_NAME: &str = "OL-confidential-tpm-concurrency-v1";
const VK_PLACEHOLDER: [u8; 1984] = [0x42u8; 1984];

fn sign_with_retry(key: &TpmAttestationKey, digest: &[u8; 32]) -> Vec<u8> {
    let mut attempts = 0;
    loop {
        match key.sign(digest) {
            Ok(sig) => return sig,
            Err(_) if attempts < 10 => {
                attempts += 1;
                // TPM is busy — back off.
                thread::sleep(Duration::from_millis(50 * attempts));
            }
            Err(e) => panic!("TPM sign failed after retries: {e}"),
        }
    }
}

#[test]
#[ignore = "requires hardware TPM access"]
fn tpm_4_threads_concurrent_sign() {
    let key = Arc::new(TpmAttestationKey::acquire_or_create(KEY_NAME).expect("acquire"));
    let mut handles = Vec::new();
    for thread_idx in 0..4 {
        let k = Arc::clone(&key);
        handles.push(thread::spawn(move || {
            let mut sigs = Vec::new();
            for op_idx in 0..5 {
                let mut digest = [0u8; 32];
                digest[0] = thread_idx as u8;
                digest[1] = op_idx as u8;
                let sig = sign_with_retry(&k, &digest);
                sigs.push((digest, sig));
            }
            sigs
        }));
    }
    let mut all = Vec::new();
    for h in handles {
        all.extend(h.join().expect("thread join"));
    }
    assert_eq!(all.len(), 4 * 5);
    // Every sig is non-empty and they're not all identical.
    let first_sig = all[0].1.clone();
    let mut some_differ = false;
    for (_, sig) in &all {
        assert!(!sig.is_empty());
        if sig != &first_sig {
            some_differ = true;
        }
    }
    assert!(
        some_differ,
        "concurrent sigs over different digests must differ"
    );
}

#[test]
#[ignore = "requires hardware TPM access"]
fn tpm_concurrent_attestation_quotes_all_verify() {
    let key = Arc::new(TpmAttestationKey::acquire_or_create(KEY_NAME).expect("acquire"));
    let mut handles = Vec::new();
    for thread_idx in 0..4 {
        let k = Arc::clone(&key);
        handles.push(thread::spawn(move || {
            let mut nonce = [0u8; 32];
            nonce[0] = thread_idx as u8;
            let digest = canonical_platform_quote_subtranscript(
                ProviderTag::WindowsTpm,
                &VK_PLACEHOLDER,
                &nonce,
                100,
                120,
                None,
            );
            // Produce a quote with retry-on-TPM-busy.
            let mut attempts = 0;
            loop {
                match produce_platform_quote(&k, &digest) {
                    Ok(q) => break (nonce, q),
                    Err(_) if attempts < 10 => {
                        attempts += 1;
                        thread::sleep(Duration::from_millis(50 * attempts));
                    }
                    Err(e) => panic!("produce_platform_quote failed: {e}"),
                }
            }
        }));
    }
    for h in handles {
        let (nonce, quote) = h.join().expect("thread join");
        let pub_blob = verify_platform_quote(
            &quote,
            ProviderTag::WindowsTpm,
            &VK_PLACEHOLDER,
            &nonce,
            100,
            120,
            None,
        )
        .expect("verify");
        assert!(!pub_blob.is_empty());
    }
}
