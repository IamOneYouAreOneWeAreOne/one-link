//! Microbenchmarks for Row 8 Layer 1.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;

use ol_device_mesh::derivation::derive_field_bound_subkey_seed;
use ol_device_mesh::distributed_fs::{
    repair_plan, sign_storage_attestation, ChunkHash, ChunkPlacement, ErasurePolicy, FileManifest,
    FILE_ID_LEN,
};
use ol_device_mesh::fan_out::{
    fan_out_plan, sign_chunk_ack, sign_fetch_request, SourceCapacity, FETCH_NONCE_LEN,
};
use ol_device_mesh::mesh_state::{AuthenticatedOp, Delta, MeshState, SubtreePolicyKind, SyncState};
use ol_device_mesh::quorum::{mint_policy, propose_operation, sign_approval, QuorumCertificate};
use ol_device_mesh::{
    derive_subkey_seed, master_pin_handle, mint_subkey, ratchet_one_day, sibling_witness,
    state_root, verify_liveness, DeviceClass, HardwareWrapper, LivenessProof, MasterIdentity,
    SoftwareWrapper, DEFAULT_LIVENESS_SKEW_SECS, DEVICE_ID_LEN, MASTER_SEED_LEN, SUBKEY_SEED_LEN,
};
use ol_pqsig::HybridVerifyingKey;
use std::collections::BTreeSet;

fn bench_derive_subkey_seed(c: &mut Criterion) {
    let master = [0x42; MASTER_SEED_LEN];
    let id = [0x55; DEVICE_ID_LEN];
    c.bench_function("device_mesh::derive_subkey_seed", |b| {
        b.iter(|| {
            let s = derive_subkey_seed(
                black_box(&master),
                black_box(DeviceClass::Phone),
                black_box(&id),
                black_box(0),
            );
            black_box(s);
        });
    });
}

fn bench_field_bound_seed(c: &mut Criterion) {
    let master = [0x42; MASTER_SEED_LEN];
    let id = [0x55; DEVICE_ID_LEN];
    let witness = [0xCC; 32];
    c.bench_function("device_mesh::derive_field_bound_subkey_seed", |b| {
        b.iter(|| {
            let s = derive_field_bound_subkey_seed(
                black_box(&master),
                black_box(DeviceClass::Phone),
                black_box(&id),
                black_box(0),
                black_box(&witness),
            );
            black_box(s);
        });
    });
}

fn bench_ratchet(c: &mut Criterion) {
    c.bench_function("device_mesh::ratchet_one_day", |b| {
        b.iter_with_setup(
            || [0x77u8; SUBKEY_SEED_LEN],
            |mut s| {
                let next = ratchet_one_day(&mut s);
                black_box(next);
            },
        );
    });
}

fn bench_mint_subkey(c: &mut Criterion) {
    let master = MasterIdentity::generate(&mut OsRng);
    c.bench_function("device_mesh::mint_subkey", |b| {
        b.iter(|| {
            let (sk, att) = mint_subkey(
                black_box(&master),
                black_box(DeviceClass::Phone),
                black_box([0x99; DEVICE_ID_LEN]),
                black_box(0),
                black_box(365),
            )
            .unwrap();
            black_box((sk, att));
        });
    });
}

fn bench_liveness_issue(c: &mut Criterion) {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk, _att) =
        mint_subkey(&master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365).unwrap();
    let now = 1_700_000_000u64;
    let sr = state_root(b"bench state");
    c.bench_function("device_mesh::liveness_proof_issue", |b| {
        b.iter(|| {
            let p = LivenessProof::issue(black_box(&sk), black_box(now), black_box(sr)).unwrap();
            black_box(p);
        });
    });
}

fn bench_liveness_verify(c: &mut Criterion) {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk, _att) =
        mint_subkey(&master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365).unwrap();
    let now = 1_700_000_000u64;
    let sr = state_root(b"bench state");
    let proof = LivenessProof::issue(&sk, now, sr).unwrap();
    let witness = sibling_witness(sk.verifying_key(), DEFAULT_LIVENESS_SKEW_SECS);
    c.bench_function("device_mesh::liveness_proof_verify", |b| {
        b.iter(|| {
            verify_liveness(black_box(&proof), black_box(&witness), now).unwrap();
        });
    });
}

fn bench_hardware_wrap(c: &mut Criterion) {
    let w = SoftwareWrapper::new([0xAB; 32]);
    let seed = [0x42; SUBKEY_SEED_LEN];
    c.bench_function("device_mesh::software_wrapper_wrap_64", |b| {
        b.iter(|| {
            let ct = w.wrap(black_box(&seed)).unwrap();
            black_box(ct);
        });
    });
    let ct = w.wrap(&seed).unwrap();
    c.bench_function("device_mesh::software_wrapper_unwrap_64", |b| {
        b.iter(|| {
            let pt = w.unwrap(black_box(&ct)).unwrap();
            black_box(pt);
        });
    });
}

fn bench_master_pin_handle(c: &mut Criterion) {
    let m = MasterIdentity::generate(&mut OsRng);
    let vk = m.verifying_key();
    c.bench_function("device_mesh::master_pin_handle", |b| {
        b.iter(|| {
            let h = master_pin_handle(black_box(&vk));
            black_box(h);
        });
    });
}

fn bench_quorum_mint_policy(c: &mut Criterion) {
    let master = MasterIdentity::generate(&mut OsRng);
    let devices: Vec<[u8; DEVICE_ID_LEN]> = (0..5).map(|i| [i as u8; DEVICE_ID_LEN]).collect();
    c.bench_function("device_mesh::quorum_mint_policy_3_of_5", |b| {
        b.iter(|| {
            let p = mint_policy(
                black_box(&master),
                black_box([0x42; 16]),
                black_box(b"bench-policy"),
                black_box(3),
                black_box(devices.clone()),
            )
            .unwrap();
            black_box(p);
        });
    });
}

fn bench_quorum_propose_and_approve(c: &mut Criterion) {
    let master = MasterIdentity::generate(&mut OsRng);
    let id1 = [0x11; DEVICE_ID_LEN];
    let id2 = [0x22; DEVICE_ID_LEN];
    let (sk1, _a1) = mint_subkey(&master, DeviceClass::Phone, id1, 0, 365).unwrap();
    let (sk2, _a2) = mint_subkey(&master, DeviceClass::Laptop, id2, 0, 365).unwrap();
    let policy = mint_policy(&master, [0x42; 16], b"p", 2, vec![id1, id2]).unwrap();
    let now: u64 = 1_700_000_000;
    c.bench_function("device_mesh::quorum_propose_operation", |b| {
        b.iter(|| {
            let p = propose_operation(
                black_box(&sk1),
                black_box(&policy),
                black_box([0xEE; 32]),
                black_box([0xDA; 16]),
                now,
                now + 3600,
            )
            .unwrap();
            black_box(p);
        });
    });
    let proposal =
        propose_operation(&sk1, &policy, [0xEE; 32], [0xDA; 16], now, now + 3600).unwrap();
    c.bench_function("device_mesh::quorum_sign_approval", |b| {
        b.iter(|| {
            let a = sign_approval(black_box(&sk2), black_box(&proposal), now + 1).unwrap();
            black_box(a);
        });
    });
}

fn bench_quorum_certificate_verify_2_of_3(c: &mut Criterion) {
    let master = MasterIdentity::generate(&mut OsRng);
    let id1 = [0x11; DEVICE_ID_LEN];
    let id2 = [0x22; DEVICE_ID_LEN];
    let id3 = [0x33; DEVICE_ID_LEN];
    let (sk1, a1) = mint_subkey(&master, DeviceClass::Phone, id1, 0, 365).unwrap();
    let (sk2, a2) = mint_subkey(&master, DeviceClass::Laptop, id2, 0, 365).unwrap();
    let (sk3, a3) = mint_subkey(&master, DeviceClass::Desktop, id3, 0, 365).unwrap();
    let policy = mint_policy(&master, [0x42; 16], b"p", 2, vec![id1, id2, id3]).unwrap();
    let now: u64 = 1_700_000_000;
    let proposal =
        propose_operation(&sk1, &policy, [0xEE; 32], [0xDA; 16], now, now + 3600).unwrap();
    let ap2 = sign_approval(&sk2, &proposal, now + 1).unwrap();
    let ap3 = sign_approval(&sk3, &proposal, now + 2).unwrap();
    let cert = QuorumCertificate {
        proposal,
        approvals: vec![ap2, ap3],
        policy,
        subkey_attestations: vec![a1, a2, a3],
    };
    let vk = master.verifying_key();
    c.bench_function("device_mesh::quorum_certificate_verify_2_of_3", |b| {
        b.iter(|| {
            cert.verify(black_box(&vk), now + 100).unwrap();
        });
    });
}

fn bench_mesh_state_auth_op_sign(c: &mut Criterion) {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk, _att) =
        mint_subkey(&master, DeviceClass::Phone, [0x55; DEVICE_ID_LEN], 0, 365).unwrap();
    c.bench_function("device_mesh::mesh_state_auth_op_sign", |b| {
        b.iter(|| {
            let op = AuthenticatedOp::sign(
                black_box(&sk),
                black_box(b"contacts".to_vec()),
                black_box(Delta::OrAdd {
                    element: b"alice".to_vec(),
                    tag: [0x77; 16],
                }),
                1,
                1,
            )
            .unwrap();
            black_box(op);
        });
    });
}

fn bench_mesh_state_auth_op_verify(c: &mut Criterion) {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk, att) =
        mint_subkey(&master, DeviceClass::Phone, [0x55; DEVICE_ID_LEN], 0, 365).unwrap();
    let vk = HybridVerifyingKey::from_bytes(&att.subkey_vk_bytes).unwrap();
    let op = AuthenticatedOp::sign(
        &sk,
        b"contacts".to_vec(),
        Delta::OrAdd {
            element: b"alice".to_vec(),
            tag: [0x77; 16],
        },
        1,
        1,
    )
    .unwrap();
    c.bench_function("device_mesh::mesh_state_auth_op_verify", |b| {
        b.iter(|| {
            op.verify(black_box(&vk)).unwrap();
        });
    });
}

fn bench_mesh_state_root(c: &mut Criterion) {
    let w = [0x42u8; DEVICE_ID_LEN];
    let mut state = MeshState::empty();
    for i in 0..16u8 {
        let label = vec![b's', i];
        state
            .ensure_subtree(label.clone(), SubtreePolicyKind::LwwMap)
            .unwrap();
        for k in 0..8u8 {
            state
                .apply_delta(
                    &label,
                    &Delta::MapPut {
                        key: vec![k],
                        value: vec![k, k],
                        ts: u64::from(k),
                    },
                    &w,
                )
                .unwrap();
        }
    }
    c.bench_function("device_mesh::mesh_state_root_16_subtrees_8_keys", |b| {
        b.iter(|| {
            let r = state.root();
            black_box(r);
        });
    });
}

fn bench_mesh_state_sync_ingest(c: &mut Criterion) {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk, att) =
        mint_subkey(&master, DeviceClass::Phone, [0x55; DEVICE_ID_LEN], 0, 365).unwrap();
    let vk = HybridVerifyingKey::from_bytes(&att.subkey_vk_bytes).unwrap();
    c.bench_function("device_mesh::mesh_state_ingest_single_op", |b| {
        b.iter_with_setup(
            || {
                let mut state = MeshState::empty();
                state
                    .ensure_subtree(b"x".to_vec(), SubtreePolicyKind::LwwRegister)
                    .unwrap();
                let sync = SyncState::empty();
                (state, sync)
            },
            |(mut state, mut sync)| {
                let op = AuthenticatedOp::sign(
                    &sk,
                    b"x".to_vec(),
                    Delta::LwwSet {
                        value: b"v".to_vec(),
                        ts: 1,
                    },
                    1,
                    1,
                )
                .unwrap();
                let _ = sync.ingest(op, &mut state, |_, _| Ok(vk.clone())).unwrap();
                (state, sync)
            },
        );
    });
}

fn bench_dfs_manifest_canonical_bytes(c: &mut Criterion) {
    let policy = ErasurePolicy::new(10, 4, 2).unwrap();
    let chunks: Vec<ChunkHash> = (0..140u8)
        .map(|i| {
            let mut h = [0u8; 32];
            h[0] = i;
            h
        })
        .collect();
    let m = FileManifest {
        file_size: 1_000_000,
        chunk_size: 8192,
        chunks,
        mime: b"application/octet-stream".to_vec(),
        created_unix: 1_700_000_000,
        policy,
    };
    c.bench_function("device_mesh::dfs_manifest_canonical_bytes_140", |b| {
        b.iter(|| {
            let v = m.canonical_bytes();
            black_box(v);
        });
    });
    c.bench_function("device_mesh::dfs_file_id_140", |b| {
        b.iter(|| {
            let id = m.file_id();
            black_box(id);
        });
    });
}

fn bench_dfs_storage_attest_sign(c: &mut Criterion) {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk, _att) =
        mint_subkey(&master, DeviceClass::Phone, [0x55; DEVICE_ID_LEN], 0, 365).unwrap();
    let chunks: Vec<ChunkHash> = (0..256u32)
        .map(|i| {
            let mut h = [0u8; 32];
            h[..4].copy_from_slice(&i.to_be_bytes());
            h
        })
        .collect();
    c.bench_function("device_mesh::dfs_storage_attest_sign_256", |b| {
        b.iter(|| {
            let att =
                sign_storage_attestation(black_box(&sk), 1, black_box(chunks.clone())).unwrap();
            black_box(att);
        });
    });
}

fn bench_dfs_storage_attest_verify(c: &mut Criterion) {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk, att_l1) =
        mint_subkey(&master, DeviceClass::Phone, [0x55; DEVICE_ID_LEN], 0, 365).unwrap();
    let vk = HybridVerifyingKey::from_bytes(&att_l1.subkey_vk_bytes).unwrap();
    let chunks: Vec<ChunkHash> = (0..256u32)
        .map(|i| {
            let mut h = [0u8; 32];
            h[..4].copy_from_slice(&i.to_be_bytes());
            h
        })
        .collect();
    let att = sign_storage_attestation(&sk, 1, chunks).unwrap();
    c.bench_function("device_mesh::dfs_storage_attest_verify_256", |b| {
        b.iter(|| {
            att.verify(black_box(&vk)).unwrap();
        });
    });
}

fn bench_dfs_repair_plan(c: &mut Criterion) {
    let policy = ErasurePolicy::new(10, 4, 2).unwrap();
    let mesh: BTreeSet<[u8; DEVICE_ID_LEN]> = (1u8..=4).map(|i| [i; DEVICE_ID_LEN]).collect();
    let placements: Vec<ChunkPlacement> = (0u8..64)
        .map(|i| {
            let mut h = [0u8; 32];
            h[0] = i;
            ChunkPlacement::empty(h)
        })
        .collect();
    c.bench_function("device_mesh::dfs_repair_plan_64_chunks_4_devices", |b| {
        b.iter(|| {
            let plan = repair_plan(placements.iter(), black_box(&mesh), &policy);
            black_box(plan);
        });
    });
}

fn bench_fan_out_plan(c: &mut Criterion) {
    let policy = ErasurePolicy::new(10, 4, 1).unwrap();
    let n_stripes = 8usize;
    let stripe = policy.total_shards() as usize;
    let chunks: Vec<ChunkHash> = (0..(n_stripes * stripe))
        .map(|i| {
            let mut h = [0u8; 32];
            h[..2].copy_from_slice(&(i as u16).to_be_bytes());
            h
        })
        .collect();
    let m = FileManifest {
        file_size: chunks.len() as u64,
        chunk_size: 8192,
        chunks: chunks.clone(),
        mime: b"x".to_vec(),
        created_unix: 0,
        policy,
    };
    let placements: Vec<ChunkPlacement> = chunks
        .iter()
        .map(|c| {
            let mut p = ChunkPlacement::empty(*c);
            for i in 1u8..=4 {
                p.add_holder([i; DEVICE_ID_LEN], 1);
            }
            p
        })
        .collect();
    let sources: Vec<SourceCapacity> = (1u8..=4)
        .map(|i| SourceCapacity {
            device_id: [i; DEVICE_ID_LEN],
            estimated_bps: 100_000_000 * u64::from(i),
            current_load_bytes: 0,
        })
        .collect();
    c.bench_function("device_mesh::fan_out_plan_112_chunks_4_sources", |b| {
        b.iter(|| {
            let plan = fan_out_plan(&m, &placements, &sources, 1.0).unwrap();
            black_box(plan);
        });
    });
}

fn bench_fan_out_fetch_request(c: &mut Criterion) {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk, _) = mint_subkey(&master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365).unwrap();
    c.bench_function("device_mesh::fan_out_fetch_request_sign_8", |b| {
        b.iter(|| {
            let req = sign_fetch_request(
                black_box(&sk),
                [0xBB; DEVICE_ID_LEN],
                [0xCC; FILE_ID_LEN],
                vec![
                    [1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32], [7; 32], [8; 32],
                ],
                1_000_000,
                1,
                10,
                [0xDA; FETCH_NONCE_LEN],
            )
            .unwrap();
            black_box(req);
        });
    });
}

fn bench_fan_out_chunk_ack(c: &mut Criterion) {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk, _) = mint_subkey(&master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365).unwrap();
    c.bench_function("device_mesh::fan_out_chunk_ack_sign", |b| {
        b.iter(|| {
            let ack = sign_chunk_ack(
                black_box(&sk),
                [0xCC; FILE_ID_LEN],
                [0xDD; 32],
                [0xEE; DEVICE_ID_LEN],
                1_700_000_000,
                8192,
            )
            .unwrap();
            black_box(ack);
        });
    });
}

fn bench_self_routing_announcement_sign(c: &mut Criterion) {
    use ol_device_mesh::self_routing::{sign_route_announcement, PeerLink};
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk, _) = mint_subkey(&master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365).unwrap();
    let links: Vec<PeerLink> = (1u8..=8)
        .map(|i| PeerLink {
            peer_device_id: [i; DEVICE_ID_LEN],
            tau_score: u32::from(i) * 10,
            last_seen_unix: u64::from(i),
            direct: true,
        })
        .collect();
    c.bench_function("device_mesh::self_routing_announcement_sign_8", |b| {
        b.iter(|| {
            let ann =
                sign_route_announcement(black_box(&sk), 1_700_000_000, black_box(links.clone()))
                    .unwrap();
            black_box(ann);
        });
    });
}

fn bench_self_routing_pick_best_route(c: &mut Criterion) {
    use ol_device_mesh::self_routing::{
        pick_best_route, sign_route_announcement, PeerLink, RouteTable,
    };
    let master = MasterIdentity::generate(&mut OsRng);
    let mut ids = Vec::new();
    let mut sks = Vec::new();
    let mut atts = Vec::new();
    for i in 1u8..=6 {
        let id = [i; DEVICE_ID_LEN];
        let (sk, a) = mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
        ids.push(id);
        sks.push(sk);
        atts.push(a);
    }
    let mut table = RouteTable::empty();
    for i in 0..ids.len() {
        let links: Vec<PeerLink> = (0..ids.len())
            .filter(|j| *j != i)
            .map(|j| PeerLink {
                peer_device_id: ids[j],
                tau_score: (((i + j) as u32) * 13) % 200 + 1,
                last_seen_unix: 1,
                direct: true,
            })
            .collect();
        let ann = sign_route_announcement(&sks[i], 1, links).unwrap();
        let vk = HybridVerifyingKey::from_bytes(&atts[i].subkey_vk_bytes).unwrap();
        table.ingest(ann, &vk).unwrap();
    }
    let src = ids[0];
    let dst = ids[ids.len() - 1];
    c.bench_function(
        "device_mesh::self_routing_pick_best_route_6_node_clique",
        |b| {
            b.iter(|| {
                let r = pick_best_route(black_box(&table), black_box(&src), black_box(&dst));
                black_box(r);
            });
        },
    );
}

fn bench_self_onion_derive_identity(c: &mut Criterion) {
    use ol_device_mesh::self_onion::derive_onion_identity;
    let master = MasterIdentity::generate(&mut OsRng);
    let id = [0xAA; DEVICE_ID_LEN];
    c.bench_function("device_mesh::self_onion_derive_identity", |b| {
        b.iter(|| {
            let identity = derive_onion_identity(black_box(&master), black_box(&id));
            black_box(identity);
        });
    });
}

fn bench_self_onion_build_2_hop(c: &mut Criterion) {
    use ol_device_mesh::self_onion::{
        build_self_onion_circuit, derive_onion_identity, sign_onion_attestation, OnionKeyRegistry,
    };
    use ol_device_mesh::self_routing::Route;
    let master = MasterIdentity::generate(&mut OsRng);
    let src = [0x11; DEVICE_ID_LEN];
    let dst = [0x22; DEVICE_ID_LEN];
    let mut reg = OnionKeyRegistry::empty();
    for id in &[src, dst] {
        let identity = derive_onion_identity(&master, id);
        let att = sign_onion_attestation(&master, *id, identity.public_bytes(), 0, 365).unwrap();
        reg.ingest(att, &master.verifying_key()).unwrap();
    }
    let route = Route {
        hops: vec![src, dst],
        bottleneck_tau: 100,
        min_last_seen_unix: 1,
    };
    c.bench_function("device_mesh::self_onion_build_circuit_2_hop", |b| {
        b.iter(|| {
            let packet = build_self_onion_circuit(
                black_box(&route),
                black_box(&reg),
                0,
                b"bench payload",
                &mut OsRng,
            )
            .unwrap();
            black_box(packet);
        });
    });
}

fn bench_self_onion_peel(c: &mut Criterion) {
    use ol_device_mesh::self_onion::{
        build_self_onion_circuit, derive_onion_identity, peel_self_onion_layer,
        sign_onion_attestation, OnionKeyRegistry,
    };
    use ol_device_mesh::self_routing::Route;
    let master = MasterIdentity::generate(&mut OsRng);
    let src = [0x11; DEVICE_ID_LEN];
    let dst = [0x22; DEVICE_ID_LEN];
    let dst_identity = derive_onion_identity(&master, &dst);
    let mut reg = OnionKeyRegistry::empty();
    for id in &[src, dst] {
        let identity = derive_onion_identity(&master, id);
        let att = sign_onion_attestation(&master, *id, identity.public_bytes(), 0, 365).unwrap();
        reg.ingest(att, &master.verifying_key()).unwrap();
    }
    let route = Route {
        hops: vec![src, dst],
        bottleneck_tau: 100,
        min_last_seen_unix: 1,
    };
    let packet = build_self_onion_circuit(&route, &reg, 0, b"bench payload", &mut OsRng).unwrap();
    c.bench_function("device_mesh::self_onion_peel_layer", |b| {
        b.iter(|| {
            let outcome =
                peel_self_onion_layer(black_box(&dst_identity), black_box(&packet)).unwrap();
            black_box(outcome);
        });
    });
}

fn bench_duress_envelope_create(c: &mut Criterion) {
    use ol_device_mesh::duress::create_duress_envelope;
    let witness = [0x42; 32];
    c.bench_function("device_mesh::duress_envelope_create", |b| {
        b.iter(|| {
            let env = create_duress_envelope(
                black_box(b"real plaintext"),
                black_box(b"decoy plaintext"),
                black_box(b"real-pass"),
                black_box(b"duress-code"),
                black_box(&witness),
                &mut OsRng,
            )
            .unwrap();
            black_box(env);
        });
    });
}

fn bench_duress_envelope_unlock_real(c: &mut Criterion) {
    use ol_device_mesh::duress::{create_duress_envelope, unlock_duress_envelope};
    let witness = [0x42; 32];
    let env = create_duress_envelope(
        b"real plaintext",
        b"decoy plaintext",
        b"real-pass",
        b"duress-code",
        &witness,
        &mut OsRng,
    )
    .unwrap();
    c.bench_function("device_mesh::duress_envelope_unlock_real", |b| {
        b.iter(|| {
            let outcome = unlock_duress_envelope(
                black_box(&env),
                black_box(b"real-pass"),
                Some(black_box(&witness)),
            )
            .unwrap();
            black_box(outcome);
        });
    });
}

fn bench_duress_pair_commitment(c: &mut Criterion) {
    use ol_device_mesh::duress::{PairingChannel, PairingCommitment};
    let secret = b"shared-pair-secret";
    c.bench_function("device_mesh::duress_pair_commitment_build", |b| {
        b.iter(|| {
            let pc = PairingCommitment::build(
                black_box(PairingChannel::Qr),
                black_box(secret),
                black_box([0; 16]),
                black_box(0),
            );
            black_box(pc);
        });
    });
}

fn bench_compute_capability_attestation_sign(c: &mut Criterion) {
    use ol_device_mesh::compute::{sign_capability_attestation, DeviceCapability};
    let master = MasterIdentity::generate(&mut OsRng);
    c.bench_function("device_mesh::compute_cap_attestation_sign", |b| {
        b.iter(|| {
            let att = sign_capability_attestation(
                black_box(&master),
                [0xAA; DEVICE_ID_LEN],
                vec![
                    DeviceCapability::Gpu,
                    DeviceCapability::CpuHeavy,
                    DeviceCapability::AlwaysOn,
                ],
                0,
                365,
            )
            .unwrap();
            black_box(att);
        });
    });
}

fn bench_compute_task_request_sign(c: &mut Criterion) {
    use ol_device_mesh::compute::{sign_task_request, DeviceCapability, TaskClass};
    use ol_device_mesh::distributed_fs::FILE_ID_LEN;
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk, _) = mint_subkey(&master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365).unwrap();
    c.bench_function("device_mesh::compute_task_request_sign", |b| {
        b.iter(|| {
            let req = sign_task_request(
                black_box(&sk),
                TaskClass::new(b"transcribe-audio").unwrap(),
                [0xCC; FILE_ID_LEN],
                vec![DeviceCapability::Microphone],
                300,
                10_000,
                1,
                10_000,
                [0xDA; 16],
            )
            .unwrap();
            black_box(req);
        });
    });
}

fn bench_compute_pick_executor(c: &mut Criterion) {
    use ol_device_mesh::compute::{
        pick_executor, sign_capability_attestation, CapabilityRegistry, DeviceCapability,
    };
    use ol_device_mesh::fan_out::SourceCapacity;
    let master = MasterIdentity::generate(&mut OsRng);
    let mut reg = CapabilityRegistry::empty();
    for i in 1u8..=8 {
        let id = [i; DEVICE_ID_LEN];
        reg.ingest(
            sign_capability_attestation(
                &master,
                id,
                vec![DeviceCapability::CpuHeavy, DeviceCapability::AlwaysOn],
                0,
                365,
            )
            .unwrap(),
            &master.verifying_key(),
        )
        .unwrap();
    }
    let caps: Vec<SourceCapacity> = (1u8..=8)
        .map(|i| SourceCapacity {
            device_id: [i; DEVICE_ID_LEN],
            estimated_bps: u64::from(i) * 10_000_000,
            current_load_bytes: 0,
        })
        .collect();
    c.bench_function("device_mesh::compute_pick_executor_8_devices", |b| {
        b.iter(|| {
            let pick = pick_executor(
                black_box(&[DeviceCapability::CpuHeavy]),
                black_box(&reg),
                black_box(&caps),
                100,
            );
            black_box(pick);
        });
    });
}

fn bench_active_routing_context_hash(c: &mut Criterion) {
    use ol_device_mesh::active_routing::RoutingContext;
    let ctx = RoutingContext {
        contact_pin: [0x42; 32],
        hour_bucket: 14,
        day_of_week: 2,
        message_class: *b"DM  ",
        urgency: 1,
    };
    c.bench_function("device_mesh::active_routing_context_hash", |b| {
        b.iter(|| {
            let h = black_box(&ctx).canonical_hash();
            black_box(h);
        });
    });
}

fn bench_active_routing_pick_device(c: &mut Criterion) {
    use ol_device_mesh::active_routing::{
        pick_device_for_context, CohortPrior, RoutingContext, RoutingHistory,
    };
    use ol_device_mesh::DeviceClass;
    let ctx = RoutingContext {
        contact_pin: [0x42; 32],
        hour_bucket: 14,
        day_of_week: 2,
        message_class: *b"DM  ",
        urgency: 1,
    };
    let candidates: Vec<([u8; DEVICE_ID_LEN], DeviceClass)> = (1u8..=4)
        .map(|i| ([i; DEVICE_ID_LEN], DeviceClass::Phone))
        .collect();
    // Pre-seed history with realistic observations.
    let mut history = RoutingHistory::empty();
    let ctx_hash = ctx.canonical_hash();
    for _ in 0..50 {
        history.observe(ctx_hash, [0x01; DEVICE_ID_LEN], true, 1, 1, 1);
        history.observe(ctx_hash, [0x02; DEVICE_ID_LEN], false, 1, 1, 1);
    }
    let cohort = CohortPrior::uniform();
    c.bench_function("device_mesh::active_routing_pick_device_4", |b| {
        b.iter(|| {
            let pick = pick_device_for_context(
                black_box(&ctx),
                black_box(&candidates),
                black_box(&history),
                black_box(&cohort),
                &mut OsRng,
            );
            black_box(pick);
        });
    });
}

fn bench_active_routing_observe(c: &mut Criterion) {
    use ol_device_mesh::active_routing::{RoutingContext, RoutingHistory};
    let ctx = RoutingContext {
        contact_pin: [0x42; 32],
        hour_bucket: 14,
        day_of_week: 2,
        message_class: *b"DM  ",
        urgency: 1,
    };
    let ctx_hash = ctx.canonical_hash();
    c.bench_function("device_mesh::active_routing_observe", |b| {
        b.iter_with_setup(RoutingHistory::empty, |mut h| {
            h.observe(
                black_box(ctx_hash),
                black_box([0x01; DEVICE_ID_LEN]),
                true,
                1,
                1,
                1,
            );
            h
        });
    });
}

criterion_group!(
    benches,
    bench_derive_subkey_seed,
    bench_field_bound_seed,
    bench_ratchet,
    bench_mint_subkey,
    bench_liveness_issue,
    bench_liveness_verify,
    bench_hardware_wrap,
    bench_master_pin_handle,
    bench_quorum_mint_policy,
    bench_quorum_propose_and_approve,
    bench_quorum_certificate_verify_2_of_3,
    bench_mesh_state_auth_op_sign,
    bench_mesh_state_auth_op_verify,
    bench_mesh_state_root,
    bench_mesh_state_sync_ingest,
    bench_dfs_manifest_canonical_bytes,
    bench_dfs_storage_attest_sign,
    bench_dfs_storage_attest_verify,
    bench_dfs_repair_plan,
    bench_fan_out_plan,
    bench_fan_out_fetch_request,
    bench_fan_out_chunk_ack,
    bench_self_routing_announcement_sign,
    bench_self_routing_pick_best_route,
    bench_self_onion_derive_identity,
    bench_self_onion_build_2_hop,
    bench_self_onion_peel,
    bench_duress_envelope_create,
    bench_duress_envelope_unlock_real,
    bench_duress_pair_commitment,
    bench_compute_capability_attestation_sign,
    bench_compute_task_request_sign,
    bench_compute_pick_executor,
    bench_active_routing_context_hash,
    bench_active_routing_pick_device,
    bench_active_routing_observe,
);
criterion_main!(benches);
