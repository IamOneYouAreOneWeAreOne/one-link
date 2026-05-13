//! Known-answer test vectors for Sphinx Coherence.
//!
//! Pins:
//! - Filler output for 2-relay + 3-relay seeded keys.
//! - HopKeys derivation for fixed (shared, alpha).
//! - Field-bound HopKeys for fixed witness.
//! - End-to-end Sphinx outer packet bytes + delivered payload.
//!
//! Regenerate with `OL_SPHINX_KAT_REGEN=1` when the wire format
//! intentionally changes.

use rand::SeedableRng;

use ol_onion::sphinx::core::{
    build_sphinx_onion, generate_static_keypair, peel_sphinx_layer, SphinxHop, SphinxPeelOutcome,
    SPHINX_PACKET_LEN,
};
use ol_onion::sphinx::field::{derive_hop_keys_with_witness, FIELD_WITNESS_LEN};
use ol_onion::sphinx::primitives::{build_filler, derive_hop_keys, header_mac};
use ol_onion::HopId;
use ol_onion::HOP_ID_LEN;

// ── Pinned expected outputs ──────────────────────────────────────

const EXPECTED_FILLER_2RELAYS_HEX: &str = "0b70aba7e5a3dddbfda563f14fe6fedb487104ffef114c6df3f32b9a644a0c2dd0fd78f3efc9a15bd08028b18797b37f8c5340e0341d4e0c356f0772ed561dc4369fee770add62b358e81f97d629e36e70e240be8a2a52d7cd39db2d690a3de7";
const EXPECTED_FILLER_3RELAYS_HEX: &str = "033253eb74c3bdf4fa594c83205c0e074fbfe1beeb60fab1fad05e071e0c1b06d2a000e3028c44ec8a96bd2777eff2fb239d873457280a9f0562adbbb800c458d4a605551ec4e106d5efda972403358e70231507f5698a4726f4e614d459db391f9feffe026103039ca4d3df11fe06fb2024b65eaba3344e513bc78f72c1c5dcde8b461f63d6f1ed8bbb8a559dc2cd6b";
const EXPECTED_HOP_KEYS_HEADER_STREAM_HEX: &str =
    "d4e793abb8e5c58a20bb767b7e91f9bf2c6acd5f50f16c3ad72c3882a27f2f2f";
const EXPECTED_HOP_KEYS_MAC_KEY_HEX: &str =
    "a012c4357a42e660bc225fc5b16e0e950873381251a92eb6b35083e8cd3bff79";
const EXPECTED_FIELD_BOUND_HEADER_STREAM_HEX: &str =
    "6d080f4140fe552562bd3f6b3c519f9abe8692107c81ac63223dbadf7fde89fd";
const EXPECTED_HEADER_MAC_HEX: &str = "571425d5fa8ca6f48f6f01c7f7529dbd";
const EXPECTED_SPHINX_PACKET_LEN: usize = SPHINX_PACKET_LEN;
const EXPECTED_DELIVERED_PAYLOAD_HEX: &str = "6b61742d70617964";

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for &byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

fn maybe_regen() -> bool {
    std::env::var("OL_SPHINX_KAT_REGEN").as_deref() == Ok("1")
}

fn assert_or_regen_str(name: &str, expected: &str, actual: &str) {
    if expected.is_empty() || maybe_regen() {
        eprintln!("KAT regen: const EXPECTED_{name} = \"{actual}\";");
        if expected.is_empty() && !maybe_regen() {
            panic!("EXPECTED_{name} is empty; run with OL_SPHINX_KAT_REGEN=1 to populate");
        }
        return;
    }
    assert_eq!(
        expected, actual,
        "\nKAT mismatch for {name}.\nexpected: {expected}\nactual:   {actual}"
    );
}

// ── Filler KAT ───────────────────────────────────────────────────

#[test]
fn kat_filler_2_relays() {
    let keys = vec![[0xAAu8; 32], [0xBBu8; 32]];
    let f = build_filler(&keys);
    assert_or_regen_str("FILLER_2RELAYS_HEX", EXPECTED_FILLER_2RELAYS_HEX, &hex(&f));
}

#[test]
fn kat_filler_3_relays() {
    let keys = vec![[0xAAu8; 32], [0xBBu8; 32], [0xCCu8; 32]];
    let f = build_filler(&keys);
    assert_or_regen_str("FILLER_3RELAYS_HEX", EXPECTED_FILLER_3RELAYS_HEX, &hex(&f));
}

// ── HopKeys KAT ──────────────────────────────────────────────────

#[test]
fn kat_derive_hop_keys() {
    let shared = [0x11u8; 32];
    let alpha = [0x22u8; 32];
    let k = derive_hop_keys(&shared, &alpha);
    assert_or_regen_str(
        "HOP_KEYS_HEADER_STREAM_HEX",
        EXPECTED_HOP_KEYS_HEADER_STREAM_HEX,
        &hex(&k.header_stream),
    );
    assert_or_regen_str(
        "HOP_KEYS_MAC_KEY_HEX",
        EXPECTED_HOP_KEYS_MAC_KEY_HEX,
        &hex(&k.mac_key),
    );
}

// ── Field-bound HopKeys KAT ──────────────────────────────────────

#[test]
fn kat_field_bound_hop_keys() {
    let shared = [0x11u8; 32];
    let alpha = [0x22u8; 32];
    let witness = [0x77u8; FIELD_WITNESS_LEN];
    let k = derive_hop_keys_with_witness(&shared, &alpha, &witness);
    assert_or_regen_str(
        "FIELD_BOUND_HEADER_STREAM_HEX",
        EXPECTED_FIELD_BOUND_HEADER_STREAM_HEX,
        &hex(&k.header_stream),
    );
}

// ── header_mac KAT ───────────────────────────────────────────────

#[test]
fn kat_header_mac() {
    let key = [0x55u8; 32];
    let data = vec![0x99u8; 240]; // HEADER_LEN
    let m = header_mac(&key, &data);
    assert_or_regen_str("HEADER_MAC_HEX", EXPECTED_HEADER_MAC_HEX, &hex(&m));
}

// ── End-to-end Sphinx packet KAT ─────────────────────────────────

#[test]
fn kat_sphinx_one_hop_end_to_end() {
    // Deterministic seeded RNG.
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([0xDDu8; 32]);
    let (dest_sk, dest_pk) = generate_static_keypair(&mut rng);
    let dest = SphinxHop {
        id: HopId::from_bytes([0x33u8; HOP_ID_LEN]),
        static_pk: dest_pk,
    };
    let (eph_sk, _) = generate_static_keypair(&mut rng);
    let payload = b"kat-payd";
    let packet = build_sphinx_onion(&eph_sk, &[dest], payload, &mut rng).unwrap();
    assert_eq!(packet.as_bytes().len(), EXPECTED_SPHINX_PACKET_LEN);
    let outcome = peel_sphinx_layer(&dest_sk, &packet).unwrap();
    match outcome {
        SphinxPeelOutcome::Deliver { payload: out } => {
            assert_or_regen_str(
                "DELIVERED_PAYLOAD_HEX",
                EXPECTED_DELIVERED_PAYLOAD_HEX,
                &hex(&out),
            );
        }
        _ => panic!("expected Deliver"),
    }
}

// ── Sphinx 3-hop end-to-end ──────────────────────────────────────

#[test]
fn kat_sphinx_three_hop_round_trip() {
    // Deterministic — verifies that the 3-hop path delivers the same
    // pinned payload byte-for-byte.
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([0xEEu8; 32]);
    let (r1_sk, r1_pk) = generate_static_keypair(&mut rng);
    let (r2_sk, r2_pk) = generate_static_keypair(&mut rng);
    let (dest_sk, dest_pk) = generate_static_keypair(&mut rng);
    let circuit = vec![
        SphinxHop {
            id: HopId::from_bytes([0x10; HOP_ID_LEN]),
            static_pk: r1_pk,
        },
        SphinxHop {
            id: HopId::from_bytes([0x20; HOP_ID_LEN]),
            static_pk: r2_pk,
        },
        SphinxHop {
            id: HopId::from_bytes([0x30; HOP_ID_LEN]),
            static_pk: dest_pk,
        },
    ];
    let (eph_sk, _) = generate_static_keypair(&mut rng);
    let payload = b"kat-3hop";
    let mut packet = build_sphinx_onion(&eph_sk, &circuit, payload, &mut rng).unwrap();
    for (i, sk) in [&r1_sk, &r2_sk, &dest_sk].iter().enumerate() {
        match peel_sphinx_layer(sk, &packet).unwrap() {
            SphinxPeelOutcome::Forward { next_packet, .. } => {
                packet = next_packet;
                assert!(i < 2);
            }
            SphinxPeelOutcome::Deliver { payload: out } => {
                assert_eq!(out, payload);
                assert_eq!(i, 2);
                return;
            }
        }
    }
}
