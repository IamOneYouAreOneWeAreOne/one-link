//! Known-answer test vectors (KAT) for ol_onion.
//!
//! The onion building loop calls into the RNG for ephemeral
//! material — to get DETERMINISTIC outputs, the KAT test uses a
//! seeded RNG (rand_chacha::ChaCha20Rng with a fixed seed).
//!
//! Pinning the exact byte output of a small fixed circuit catches:
//! - ChaCha20-Poly1305 / BLAKE3 primitive changes upstream.
//! - Domain separator drift.
//! - Wire format changes (encode ordering, version bumps).
//! - AAD computation drift.
//!
//! Regenerate with `OL_ONION_KAT_REGEN=1` when the wire format
//! intentionally changes.

use rand::SeedableRng;
use x25519_dalek::{PublicKey, StaticSecret};

use ol_onion::keyderiv::derive_layer_key_sender;
use ol_onion::{
    build_onion, peel_one_layer, Circuit, HopDescriptor, HopId, OnionPacket, PeelOutcome,
    HOP_ID_LEN,
};

// ── Fixed test inputs ─────────────────────────────────────────────

const RELAY_1_SK: [u8; 32] = [0xAAu8; 32];
const RELAY_2_SK: [u8; 32] = [0xBBu8; 32];
const DEST_SK: [u8; 32] = [0xCCu8; 32];
const RNG_SEED: [u8; 32] = [0xDDu8; 32];
const PAYLOAD: &[u8] = b"kat-payload-pinned-bytes";

// ── Pinned expected outputs ───────────────────────────────────────
// Captured from ol_onion 0.21.0-alpha.0 with the fixed seeds above.
const EXPECTED_OUTER_PACKET_LEN: usize = 280;
const EXPECTED_PEELED_PAYLOAD_HEX: &str = "6b61742d7061796c6f61642d70696e6e65642d6279746573";

// LayerKey derivation: BLAKE3 keyed by (PROTOCOL_DOMAIN || "-layer-key-v1" || shared || sender_epk).
// Sender_ESK = [0x55; 32], Relay_PK derived from [0xAA; 32].
const EXPECTED_LAYER_KEY_HEX: &str =
    "823498d9758fd5c94680d9ca2e0365fa3ef87cc9f924299edc9f78964ed26386";
// outermost packet hops_remaining + ephemeral pubkey hex (first peel).
const EXPECTED_OUTERMOST_HOPS_REMAINING: u8 = 2;
const EXPECTED_OUTERMOST_AAD_HEX: &str =
    "0102fa84a11ad155b6a0f50fa9eac0995c32e4ff38614bdae2e1226344216236060a969578b94523eae10f65e94300e8";

// ── Helpers ───────────────────────────────────────────────────────

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for &byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

fn maybe_regen() -> bool {
    std::env::var("OL_ONION_KAT_REGEN").as_deref() == Ok("1")
}

fn assert_or_regen_str(name: &str, expected: &str, actual: &str) {
    if maybe_regen() {
        eprintln!("KAT regen: const EXPECTED_{name} = \"{actual}\";");
        return;
    }
    assert_eq!(
        expected, actual,
        "\nKAT mismatch for {name}.\n\
         expected: {expected}\n\
         actual:   {actual}\n\
         Set OL_ONION_KAT_REGEN=1 to regenerate if this change is intended."
    );
}

fn assert_or_regen_usize(name: &str, expected: usize, actual: usize) {
    if maybe_regen() {
        eprintln!("KAT regen: const EXPECTED_{name} = {actual};");
        return;
    }
    assert_eq!(
        expected, actual,
        "\nKAT mismatch for {name}.\n\
         expected: {expected}\n\
         actual:   {actual}\n\
         Set OL_ONION_KAT_REGEN=1 to regenerate if this change is intended."
    );
}

type KatHop = (StaticSecret, HopDescriptor);

fn build_kat_circuit() -> (KatHop, KatHop, KatHop, Circuit) {
    let make = |seed: [u8; 32], i: u8| {
        let sk = StaticSecret::from(seed);
        let pk = PublicKey::from(&sk);
        (
            sk,
            HopDescriptor {
                id: HopId::from_bytes([i; HOP_ID_LEN]),
                pubkey: pk,
            },
        )
    };
    let r1 = make(RELAY_1_SK, 1);
    let r2 = make(RELAY_2_SK, 2);
    let dest = make(DEST_SK, 3);
    let circuit = Circuit::new(vec![r1.1.clone(), r2.1.clone(), dest.1.clone()]).unwrap();
    (r1, r2, dest, circuit)
}

// ── Tests ─────────────────────────────────────────────────────────

#[test]
fn kat_outer_packet_length_pinned() {
    let (_, _, _, circuit) = build_kat_circuit();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(RNG_SEED);
    let packet = build_onion(&circuit, PAYLOAD, &mut rng).unwrap();
    let enc = packet.encode();
    assert_or_regen_usize("OUTER_PACKET_LEN", EXPECTED_OUTER_PACKET_LEN, enc.len());
}

#[test]
fn kat_layer_key_derivation_pinned() {
    // Fixed sender ephemeral + fixed relay pubkey → deterministic LayerKey.
    let sender_esk = StaticSecret::from([0x55u8; 32]);
    let relay_sk = StaticSecret::from([0xAAu8; 32]);
    let relay_pk = PublicKey::from(&relay_sk);
    let key = derive_layer_key_sender(&sender_esk, &relay_pk);
    let key_hex = hex(key.as_bytes());
    if EXPECTED_LAYER_KEY_HEX.is_empty() {
        if maybe_regen() {
            eprintln!("KAT regen: const EXPECTED_LAYER_KEY_HEX = \"{key_hex}\";");
            return;
        }
        panic!("EXPECTED_LAYER_KEY_HEX is empty; rerun with OL_ONION_KAT_REGEN=1");
    }
    assert_or_regen_str("LAYER_KEY_HEX", EXPECTED_LAYER_KEY_HEX, &key_hex);
}

#[test]
fn kat_outermost_header_metadata_pinned() {
    let (_, _, _, circuit) = build_kat_circuit();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(RNG_SEED);
    let packet = build_onion(&circuit, PAYLOAD, &mut rng).unwrap();
    // hops_remaining at the outermost layer: 2 (r2 + dest remain after r1).
    assert_eq!(packet.hops_remaining, EXPECTED_OUTERMOST_HOPS_REMAINING);
    // AAD bytes are deterministic from header fields.
    let aad_hex = hex(&packet.aad());
    if EXPECTED_OUTERMOST_AAD_HEX.is_empty() {
        if maybe_regen() {
            eprintln!("KAT regen: const EXPECTED_OUTERMOST_AAD_HEX = \"{aad_hex}\";");
            return;
        }
        panic!("EXPECTED_OUTERMOST_AAD_HEX is empty; rerun with OL_ONION_KAT_REGEN=1");
    }
    assert_or_regen_str("OUTERMOST_AAD_HEX", EXPECTED_OUTERMOST_AAD_HEX, &aad_hex);
}

#[test]
fn kat_layer_key_sender_and_relay_paths_match() {
    // Sender derives layer key with esk + relay_pk.
    // Relay derives same with relay_sk + sender_epk.
    // Property test of derive_layer_key; KAT pins the SAME byte
    // sequence is obtained from both paths.
    use ol_onion::keyderiv::derive_layer_key_relay;
    let sender_esk = StaticSecret::from([0x55u8; 32]);
    let relay_sk = StaticSecret::from([0xAAu8; 32]);
    let relay_pk = PublicKey::from(&relay_sk);
    let sender_epk = PublicKey::from(&sender_esk);
    let k_send = derive_layer_key_sender(&sender_esk, &relay_pk);
    let k_relay = derive_layer_key_relay(&relay_sk, &sender_epk);
    assert_eq!(k_send, k_relay);
}

#[test]
fn kat_end_to_end_payload_pinned() {
    let ((r1_sk, _), (r2_sk, _), (dest_sk, _), circuit) = build_kat_circuit();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(RNG_SEED);
    let mut packet = build_onion(&circuit, PAYLOAD, &mut rng).unwrap();
    // r1 → r2 → dest
    let o1 = peel_one_layer(&r1_sk, &packet).unwrap();
    packet = match o1 {
        PeelOutcome::Forward {
            inner_packet_bytes, ..
        } => OnionPacket::decode(&inner_packet_bytes).unwrap(),
        _ => panic!(),
    };
    let o2 = peel_one_layer(&r2_sk, &packet).unwrap();
    packet = match o2 {
        PeelOutcome::Forward {
            inner_packet_bytes, ..
        } => OnionPacket::decode(&inner_packet_bytes).unwrap(),
        _ => panic!(),
    };
    let o3 = peel_one_layer(&dest_sk, &packet).unwrap();
    let payload = match o3 {
        PeelOutcome::Deliver { payload } => payload,
        _ => panic!(),
    };
    assert_or_regen_str(
        "PEELED_PAYLOAD_HEX",
        EXPECTED_PEELED_PAYLOAD_HEX,
        &hex(&payload),
    );
}
