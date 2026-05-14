#![no_main]
//! Fuzz the mesh-state auth-op verify + ingest paths with arbitrary
//! mutations. Must never panic.

use libfuzzer_sys::fuzz_target;
use ol_device_mesh::mesh_state::{
    AuthenticatedOp, Delta, MeshState, SubtreePolicyKind, SyncState,
};
use ol_device_mesh::{
    mint_subkey, DeviceClass, MasterIdentity,
};
use ol_pqsig::HybridVerifyingKey;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fuzz_target!(|data: &[u8]| {
    let mut rng = ChaCha20Rng::from_seed([0xA3u8; 32]);
    let master = MasterIdentity::generate(&mut rng);
    let (sk, att) =
        mint_subkey(&master, DeviceClass::Phone, [0x55; 16], 0, 365).unwrap();
    let vk = HybridVerifyingKey::from_bytes(&att.subkey_vk_bytes).unwrap();
    let mut state = MeshState::empty();
    let _ = state.ensure_subtree(b"x".to_vec(), SubtreePolicyKind::LwwRegister);
    let mut sync = SyncState::empty();

    // Build a baseline op, then mutate one field based on the first byte.
    let mut op = AuthenticatedOp::sign(
        &sk,
        b"x".to_vec(),
        Delta::LwwSet { value: b"baseline".to_vec(), ts: 1 },
        1,
        1,
    )
    .unwrap();

    if !data.is_empty() {
        let pick = data[0] % 5;
        let body = &data[1..];
        match pick {
            0 if !body.is_empty() => {
                let n = body.len().min(op.subkey_sig.len());
                op.subkey_sig[..n].copy_from_slice(&body[..n]);
            }
            1 if !body.is_empty() => {
                let n = body.len().min(op.subtree.len());
                op.subtree[..n].copy_from_slice(&body[..n]);
            }
            2 if body.len() >= 8 => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&body[..8]);
                op.seq = u64::from_be_bytes(buf);
            }
            3 if body.len() >= 8 => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&body[..8]);
                op.wall_unix = u64::from_be_bytes(buf);
            }
            _ if !body.is_empty() => {
                op.device_id[0] = body[0];
            }
            _ => {}
        }
    }
    // Verify path: must not panic.
    let _ = op.verify(&vk);
    // Ingest path: must not panic. We deliberately use a lookup that
    // always returns the real VK, even if the op claims a different
    // device — exercising the signature-mismatch branch.
    let _ = sync.ingest(op, &mut state, |_, _| Ok(vk.clone()));
});
