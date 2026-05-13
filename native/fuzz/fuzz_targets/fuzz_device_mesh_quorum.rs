#![no_main]
//! Fuzz the quorum certificate verify path with arbitrary mutations.
//! Must never panic; verify always returns a typed error or Ok.

use libfuzzer_sys::fuzz_target;
use ol_device_mesh::quorum::{
    mint_policy, propose_operation, sign_approval, QuorumCertificate,
};
use ol_device_mesh::{
    mint_subkey, DeviceClass, MasterIdentity,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fuzz_target!(|data: &[u8]| {
    let mut rng = ChaCha20Rng::from_seed([0xA2u8; 32]);
    let master = MasterIdentity::generate(&mut rng);
    let id1 = [0x11u8; 16];
    let id2 = [0x22u8; 16];
    let id3 = [0x33u8; 16];
    let (sk1, a1) =
        mint_subkey(&master, DeviceClass::Phone, id1, 0, 365).unwrap();
    let (sk2, a2) =
        mint_subkey(&master, DeviceClass::Laptop, id2, 0, 365).unwrap();
    let (sk3, a3) =
        mint_subkey(&master, DeviceClass::Desktop, id3, 0, 365).unwrap();
    let policy =
        mint_policy(&master, [0x42; 16], b"fuzz", 2, vec![id1, id2, id3]).unwrap();
    let now: u64 = 1_700_000_000;
    let proposal = propose_operation(
        &sk1, &policy, [0xEE; 32], [0xDA; 16], now, now + 3600,
    )
    .unwrap();
    let ap2 = sign_approval(&sk2, &proposal, now + 1).unwrap();
    let ap3 = sign_approval(&sk3, &proposal, now + 2).unwrap();
    let mut cert = QuorumCertificate {
        proposal,
        approvals: vec![ap2, ap3],
        policy,
        subkey_attestations: vec![a1, a2, a3],
    };

    // Mutate one field of the cert based on the first fuzz byte.
    if !data.is_empty() {
        let pick = data[0] % 5;
        let body = &data[1..];
        match pick {
            0 if !body.is_empty() => {
                let n = body.len().min(cert.proposal.issuer_sig.len());
                cert.proposal.issuer_sig[..n].copy_from_slice(&body[..n]);
            }
            1 if !body.is_empty() && !cert.approvals.is_empty() => {
                let n = body.len().min(cert.approvals[0].approver_sig.len());
                cert.approvals[0].approver_sig[..n].copy_from_slice(&body[..n]);
            }
            2 if !body.is_empty() => {
                let n = body.len().min(cert.policy.master_sig.len());
                cert.policy.master_sig[..n].copy_from_slice(&body[..n]);
            }
            3 if body.len() >= 8 => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&body[..8]);
                cert.proposal.deadline_unix = u64::from_be_bytes(buf);
            }
            4 if !cert.approvals.is_empty() => {
                cert.approvals.push(cert.approvals[0].clone());
            }
            _ => {}
        }
    }
    let _ = cert.verify(&master.verifying_key(), now + 100);
});
