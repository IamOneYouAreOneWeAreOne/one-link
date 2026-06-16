//! Cross-layer integration tests for Row 8.
//!
//! Each test exercises 3+ layers together to flush out
//! layer-interaction bugs (wrong byte alignments, wrong key
//! material flowing between layers, wrong types where a callee
//! expects something subtly different). Per-layer unit tests
//! catch ~95% of bugs; cross-layer tests catch the rest.

use rand::rngs::OsRng;
use std::collections::{BTreeMap, BTreeSet};

use ol_device_mesh::active_routing::{
    pick_device_for_context, CohortPrior, RoutingContext, RoutingHistory,
};
use ol_device_mesh::compute::task::TASK_NONCE_LEN;
use ol_device_mesh::compute::{
    pick_executor, sign_capability_attestation, sign_task_request, CapabilityRegistry,
    DeviceCapability, TaskClass,
};
use ol_device_mesh::distributed_fs::{
    ChunkHash, ChunkPlacement, ErasurePolicy, FileManifest, FILE_ID_LEN,
};
use ol_device_mesh::fan_out::{
    fan_out_plan, sign_chunk_ack, sign_fetch_request, SourceCapacity, FETCH_NONCE_LEN,
};
use ol_device_mesh::mesh_state::{AuthenticatedOp, Delta, MeshState, SubtreePolicyKind, SyncState};
use ol_device_mesh::quorum::{mint_policy, propose_operation, sign_approval, QuorumCertificate};
use ol_device_mesh::self_routing::{
    pick_best_route, sign_route_announcement, PeerLink, RouteTable,
};
use ol_device_mesh::subkey::{fresh_device_id, mint_subkey, SubkeyAttestation};
use ol_device_mesh::{DeviceClass, MasterIdentity, DEVICE_ID_LEN};
use ol_pqsig::{HybridVerifyingKey, HYBRID_VK_LEN};

/// 3-device mesh fixture: master + phone + laptop + desktop
/// subkeys, all attested.
struct ThreeDeviceMesh {
    master: MasterIdentity,
    device_ids: [[u8; DEVICE_ID_LEN]; 3],
    subkeys: Vec<ol_device_mesh::subkey::DeviceSubkey>,
    attestations: Vec<SubkeyAttestation>,
}

impl ThreeDeviceMesh {
    fn new() -> Self {
        let master = MasterIdentity::generate(&mut OsRng);
        let mut device_ids = [[0u8; DEVICE_ID_LEN]; 3];
        let mut subkeys = Vec::new();
        let mut attestations = Vec::new();
        let classes = [
            DeviceClass::Phone,
            DeviceClass::Laptop,
            DeviceClass::Desktop,
        ];
        for (i, class) in classes.into_iter().enumerate() {
            let id = fresh_device_id(&mut OsRng);
            device_ids[i] = id;
            let (sk, att) = mint_subkey(&master, class, id, 0, 365).unwrap();
            subkeys.push(sk);
            attestations.push(att);
        }
        Self {
            master,
            device_ids,
            subkeys,
            attestations,
        }
    }
    fn vk_for(&self, idx: usize) -> HybridVerifyingKey {
        assert_eq!(self.attestations[idx].subkey_vk_bytes.len(), HYBRID_VK_LEN);
        HybridVerifyingKey::from_bytes(&self.attestations[idx].subkey_vk_bytes).unwrap()
    }
}

#[test]
fn layer1_to_layer2_quorum_certificate_round_trips() {
    // Layer 1 mints 3 device subkeys.
    // Layer 2 builds a 2-of-3 quorum cert that verifies end-to-end
    // under the original master.
    let mesh = ThreeDeviceMesh::new();
    let policy = mint_policy(
        &mesh.master,
        [0x11; 16],
        b"shared-folder-policy",
        2,
        mesh.device_ids.to_vec(),
    )
    .unwrap();
    let proposal =
        propose_operation(&mesh.subkeys[0], &policy, [0xAA; 32], [0x33; 16], 100, 2000).unwrap();
    let approval_b = sign_approval(&mesh.subkeys[1], &proposal, 110).unwrap();
    let approval_c = sign_approval(&mesh.subkeys[2], &proposal, 120).unwrap();
    let cert = QuorumCertificate {
        policy,
        proposal,
        approvals: vec![approval_b, approval_c],
        subkey_attestations: mesh.attestations.clone(),
    };
    cert.verify(&mesh.master.verifying_key(), 150).unwrap();
}

#[test]
fn layer3_mesh_state_ingest_with_layer1_subkey() {
    // Layer 1: mint a phone subkey.
    // Layer 3: ingest a signed LWW write into MeshState; confirm the
    // verify-by-subkey path resolves correctly.
    let mesh = ThreeDeviceMesh::new();
    let mut state = MeshState::empty();
    state
        .ensure_subtree(b"folder.alpha".to_vec(), SubtreePolicyKind::LwwRegister)
        .unwrap();
    let mut sync = SyncState::empty();
    let op = AuthenticatedOp::sign(
        &mesh.subkeys[0],
        b"folder.alpha".to_vec(),
        Delta::LwwSet {
            value: b"hello mesh".to_vec(),
            ts: 100,
        },
        1,
        1,
    )
    .unwrap();
    let phone_vk = mesh.vk_for(0);
    let phone_id = mesh.device_ids[0];
    let phone_vk_for_lookup = phone_vk.clone();
    let applied = sync
        .ingest(op, &mut state, |id, _day| {
            assert_eq!(id, &phone_id, "ingest should resolve VK for emitter id");
            Ok(phone_vk_for_lookup.clone())
        })
        .unwrap();
    assert!(applied);
    // Verify the value landed in the subtree.
    let subtree = state.subtree(b"folder.alpha").unwrap();
    let bytes = subtree.root();
    assert!(bytes.iter().any(|b| *b != 0));
}

#[test]
fn layer4_to_layer5_manifest_drives_fan_out_plan() {
    // Layer 4: build a 6-chunk manifest with 2+1 erasure (3 shards
    // per stripe → 6 chunks total covers 2 stripes).
    // Layer 5: fan-out plan distributes chunks across 2 source devices.
    let mesh = ThreeDeviceMesh::new();
    let policy = ErasurePolicy::new(2, 1, 1).unwrap();
    let chunks: Vec<ChunkHash> = (0..6u8).map(|i| [i; 32]).collect();
    let manifest = FileManifest {
        file_size: 6 * 1024,
        chunk_size: 1024,
        chunks: chunks.clone(),
        mime: b"text/plain".to_vec(),
        created_unix: 1_700_000_000,
        policy,
    };
    manifest.shape_check().unwrap();
    let file_id = manifest.file_id();
    assert_eq!(file_id.len(), FILE_ID_LEN);

    let placements: Vec<ChunkPlacement> = chunks
        .iter()
        .map(|c| {
            let mut set = BTreeSet::new();
            set.insert(mesh.device_ids[0]);
            set.insert(mesh.device_ids[1]);
            ChunkPlacement {
                chunk_hash: *c,
                device_ids: set,
                last_attest_unix: 100,
            }
        })
        .collect();

    let sources = vec![
        SourceCapacity {
            device_id: mesh.device_ids[0],
            estimated_bps: 5_000_000,
            current_load_bytes: 0,
        },
        SourceCapacity {
            device_id: mesh.device_ids[1],
            estimated_bps: 5_000_000,
            current_load_bytes: 0,
        },
    ];
    let plan = fan_out_plan(&manifest, &placements, &sources, 1.0).unwrap();
    let counts: BTreeMap<_, _> = plan
        .assignments
        .iter()
        .map(|a| (a.source_device_id, a.chunk_hashes.len()))
        .collect();
    // Two stripes of (k=2, m=1) = 3 shards each; only k=2 per stripe
    // needs fetching → 4 chunks total assigned across the 2 sources.
    let total: usize = counts.values().sum();
    assert_eq!(
        total, 4,
        "expected 4 (k=2 per stripe × 2 stripes), got {total}"
    );
    // Both sources should get some work given equal capacity.
    assert!(
        counts.values().all(|&n| n > 0),
        "expected both sources assigned chunks: {counts:?}"
    );
}

#[test]
fn layer5_fetch_request_signed_by_layer1_subkey() {
    // Layer 1 receiver subkey → Layer 5 fetch_request transcript →
    // verify under the receiver's attested VK.
    let mesh = ThreeDeviceMesh::new();
    let receiver = &mesh.subkeys[0];
    let receiver_vk = mesh.vk_for(0);
    let req = sign_fetch_request(
        receiver,
        mesh.device_ids[1],
        [0xAB; FILE_ID_LEN],
        vec![[0x01; 32], [0x02; 32], [0x03; 32]],
        1024 * 1024,
        100,
        2000,
        [0x42; FETCH_NONCE_LEN],
    )
    .unwrap();
    req.verify(&receiver_vk).unwrap();
}

#[test]
fn layer6_self_routing_then_layer9_records_observation() {
    // Layer 1 mints 3 subkeys → Layer 6 device A announces a 2-link
    // table → Layer 9 records routing observations under a context
    // and picks via Beta-posterior Thompson sampling.
    let mesh = ThreeDeviceMesh::new();
    let a = &mesh.subkeys[0];
    let a_id = mesh.device_ids[0];
    let b_id = mesh.device_ids[1];
    let c_id = mesh.device_ids[2];

    // A announces direct links A→B (τ=50) and A→C (τ=100).
    let ann = sign_route_announcement(
        a,
        100,
        vec![
            PeerLink {
                peer_device_id: b_id,
                tau_score: 50,
                last_seen_unix: 100,
                direct: true,
            },
            PeerLink {
                peer_device_id: c_id,
                tau_score: 100,
                last_seen_unix: 100,
                direct: true,
            },
        ],
    )
    .unwrap();
    let a_vk = mesh.vk_for(0);
    let mut table = RouteTable::empty();
    table.ingest(ann, &a_vk).unwrap();
    let route = pick_best_route(&table, &a_id, &c_id).unwrap();
    assert_eq!(route.hops, vec![a_id, c_id]);

    // Layer 9 observation + picker.
    let ctx = RoutingContext {
        contact_pin: [1; 32],
        hour_bucket: 9,
        day_of_week: 2,
        message_class: *b"DM  ",
        urgency: 1,
    };
    let ctx_hash = ctx.canonical_hash();
    let mut history = RoutingHistory::empty();
    for _ in 0..40 {
        history.observe(ctx_hash, c_id, true, 1, 1, 1);
    }
    let candidates = vec![(b_id, DeviceClass::Laptop), (c_id, DeviceClass::Desktop)];
    let cohort = CohortPrior::uniform();
    let mut c_count = 0;
    for _ in 0..200 {
        if let Some(pick) =
            pick_device_for_context(&ctx, &candidates, &history, &cohort, &mut OsRng)
        {
            if pick == c_id {
                c_count += 1;
            }
        }
    }
    assert!(c_count >= 150, "C won only {c_count}/200; expected ≥150");
}

#[test]
fn layer8_capability_attestation_then_executor_pick() {
    // Layer 1 mints 3 subkeys → Layer 8 each device gets a
    // master-signed capability attestation → pick_executor must
    // select the device that holds the required caps AND has the
    // best capacity/load score.
    let mesh = ThreeDeviceMesh::new();
    let mut reg = CapabilityRegistry::empty();
    let master_vk = mesh.master.verifying_key();
    reg.ingest(
        sign_capability_attestation(
            &mesh.master,
            mesh.device_ids[0],
            vec![DeviceCapability::Microphone, DeviceCapability::Camera],
            0,
            365,
        )
        .unwrap(),
        &master_vk,
    )
    .unwrap();
    reg.ingest(
        sign_capability_attestation(
            &mesh.master,
            mesh.device_ids[1],
            vec![DeviceCapability::CpuHeavy, DeviceCapability::Display],
            0,
            365,
        )
        .unwrap(),
        &master_vk,
    )
    .unwrap();
    reg.ingest(
        sign_capability_attestation(
            &mesh.master,
            mesh.device_ids[2],
            vec![
                DeviceCapability::Gpu,
                DeviceCapability::CpuHeavy,
                DeviceCapability::LargeDisk,
            ],
            0,
            365,
        )
        .unwrap(),
        &master_vk,
    )
    .unwrap();

    let caps = vec![
        SourceCapacity {
            device_id: mesh.device_ids[0],
            estimated_bps: 1_000,
            current_load_bytes: 0,
        },
        SourceCapacity {
            device_id: mesh.device_ids[1],
            estimated_bps: 100_000,
            current_load_bytes: 0,
        },
        SourceCapacity {
            device_id: mesh.device_ids[2],
            estimated_bps: 1_000_000_000,
            current_load_bytes: 0,
        },
    ];

    let pick = pick_executor(&[DeviceCapability::Gpu], &reg, &caps, 100);
    assert_eq!(pick, Some(mesh.device_ids[2]));
    let pick = pick_executor(&[DeviceCapability::CpuHeavy], &reg, &caps, 100);
    assert_eq!(pick, Some(mesh.device_ids[2]));

    // Sign a TaskRequest and verify it.
    let req = sign_task_request(
        &mesh.subkeys[0],
        TaskClass::new(b"transcribe-audio").unwrap(),
        [0xCD; FILE_ID_LEN],
        vec![DeviceCapability::Gpu],
        300,
        10_000_000,
        100,
        2000,
        [0x77; TASK_NONCE_LEN],
    )
    .unwrap();
    req.verify(&mesh.vk_for(0)).unwrap();
}

#[test]
fn fan_out_then_chunk_ack_signed_by_source() {
    // Source signs a ChunkAck binding chunk hash + receiver id;
    // tampering must break verify.
    let mesh = ThreeDeviceMesh::new();
    let source = &mesh.subkeys[1];
    let source_vk = mesh.vk_for(1);
    let chunk = [0xAA; 32];
    let receiver_id = mesh.device_ids[0];

    let ack = sign_chunk_ack(source, [0xFE; FILE_ID_LEN], chunk, receiver_id, 500, 1024).unwrap();
    ack.verify(&source_vk).unwrap();
    let mut tampered = ack.clone();
    tampered.receiver_device_id = mesh.device_ids[2];
    assert!(tampered.verify(&source_vk).is_err());
}
