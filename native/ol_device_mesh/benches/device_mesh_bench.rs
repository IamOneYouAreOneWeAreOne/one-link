//! Microbenchmarks for Row 8 Layer 1.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;

use ol_device_mesh::derivation::derive_field_bound_subkey_seed;
use ol_device_mesh::{
    derive_subkey_seed, master_pin_handle, mint_subkey, ratchet_one_day,
    sibling_witness, state_root, verify_liveness, DeviceClass, HardwareWrapper,
    LivenessProof, MasterIdentity, SoftwareWrapper, DEFAULT_LIVENESS_SKEW_SECS,
    DEVICE_ID_LEN, MASTER_SEED_LEN, SUBKEY_SEED_LEN,
};

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
    let (sk, _att) = mint_subkey(
        &master,
        DeviceClass::Phone,
        [0xAA; DEVICE_ID_LEN],
        0,
        365,
    )
    .unwrap();
    let now = 1_700_000_000u64;
    let sr = state_root(b"bench state");
    c.bench_function("device_mesh::liveness_proof_issue", |b| {
        b.iter(|| {
            let p = LivenessProof::issue(black_box(&sk), black_box(now), black_box(sr))
                .unwrap();
            black_box(p);
        });
    });
}

fn bench_liveness_verify(c: &mut Criterion) {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk, _att) = mint_subkey(
        &master,
        DeviceClass::Phone,
        [0xAA; DEVICE_ID_LEN],
        0,
        365,
    )
    .unwrap();
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
);
criterion_main!(benches);
