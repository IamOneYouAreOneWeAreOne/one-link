//! Microbenchmarks for the Row 7 transport_obfs primitive + handshake.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;

use ol_onion::transport_obfs::handshake::{
    BridgeKeypair, ClientHandshake, ServerHandshake, BRIDGE_PUBKEY_LEN,
};
use ol_onion::transport_obfs::primitive::{
    deobfuscate, derive_nonce, obfuscate, OBFS_KEY_LEN, OBFS_NONCE_LEN,
};
use ol_onion::transport_obfs::session::{Session, SESSION_KEY_LEN};

fn bench_obfuscate(c: &mut Criterion) {
    let key = [0x42u8; OBFS_KEY_LEN];
    let nonce = [0x99u8; OBFS_NONCE_LEN];
    for &sz in &[64usize, 512, 1500, 8192, 65_536] {
        let plain = vec![0xABu8; sz];
        let label = format!("obfs::obfuscate_{sz}");
        c.bench_function(&label, |b| {
            b.iter(|| {
                let out = obfuscate(black_box(&key), black_box(&nonce), black_box(&plain));
                black_box(out);
            });
        });
    }
}

fn bench_deobfuscate(c: &mut Criterion) {
    let key = [0x42u8; OBFS_KEY_LEN];
    let nonce = [0x99u8; OBFS_NONCE_LEN];
    let plain = vec![0xABu8; 1500];
    let cipher = obfuscate(&key, &nonce, &plain);
    c.bench_function("obfs::deobfuscate_1500", |b| {
        b.iter(|| {
            let out = deobfuscate(black_box(&key), black_box(&nonce), black_box(&cipher));
            black_box(out);
        });
    });
}

fn bench_derive_nonce(c: &mut Criterion) {
    c.bench_function("obfs::derive_nonce", |b| {
        b.iter(|| {
            let n = derive_nonce(black_box(0xDEADBEEF), black_box(0x123456789ABCDEF0));
            black_box(n);
        });
    });
}

fn bench_handshake_start(c: &mut Criterion) {
    let bridge = BridgeKeypair::generate(&mut OsRng);
    let bridge_pk: [u8; BRIDGE_PUBKEY_LEN] = *bridge.public.as_bytes();
    c.bench_function("obfs::handshake_client_start", |b| {
        b.iter(|| {
            let h = ClientHandshake::start(
                &mut OsRng,
                black_box(&bridge_pk),
                black_box(&bridge.id),
                1_700_000_000,
            );
            black_box(h);
        });
    });
}

fn bench_handshake_accept(c: &mut Criterion) {
    let bridge = BridgeKeypair::generate(&mut OsRng);
    let bridge_pk: [u8; BRIDGE_PUBKEY_LEN] = *bridge.public.as_bytes();
    let now = 1_700_000_000u64;
    let client = ClientHandshake::start(&mut OsRng, &bridge_pk, &bridge.id, now);
    let first = *client.first_message();
    c.bench_function("obfs::handshake_server_accept", |b| {
        b.iter(|| {
            let r = ServerHandshake::accept(&mut OsRng, black_box(&bridge), black_box(&first), now);
            black_box(r.ok());
        });
    });
}

fn bench_handshake_full_round_trip(c: &mut Criterion) {
    let bridge = BridgeKeypair::generate(&mut OsRng);
    let bridge_pk: [u8; BRIDGE_PUBKEY_LEN] = *bridge.public.as_bytes();
    let now = 1_700_000_000u64;
    c.bench_function("obfs::handshake_full_round_trip", |b| {
        b.iter(|| {
            let client = ClientHandshake::start(&mut OsRng, &bridge_pk, &bridge.id, now);
            let (reply, server_session) =
                ServerHandshake::accept(&mut OsRng, &bridge, client.first_message(), now).unwrap();
            let client_session = client.finish(&reply).unwrap();
            black_box((client_session, server_session));
        });
    });
}

fn bench_session_seal(c: &mut Criterion) {
    let s = Session::new([0x11; SESSION_KEY_LEN], [0x22; SESSION_KEY_LEN]);
    let p = vec![0xCDu8; 1500];
    c.bench_function("obfs::session_seal_outbound_1500", |b| {
        b.iter(|| {
            let out = s.seal_outbound(black_box(&p), 1);
            black_box(out);
        });
    });
}

criterion_group!(
    benches,
    bench_obfuscate,
    bench_deobfuscate,
    bench_derive_nonce,
    bench_handshake_start,
    bench_handshake_accept,
    bench_handshake_full_round_trip,
    bench_session_seal,
);
criterion_main!(benches);
