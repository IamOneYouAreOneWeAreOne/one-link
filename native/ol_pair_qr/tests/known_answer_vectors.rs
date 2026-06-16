//! Known-answer test vectors (KAT) for the pair-by-QR wire surface.
//!
//! Pins the exact byte output of Invite / PairResponse / PairConfirm
//! / transcript / SAS / chain-key derivation for deterministic seed
//! inputs. A future refactor that silently changes the encoder, the
//! domain-separation tags, the BLAKE3 derivation order, or any of
//! the cryptographic primitive choices produces a failure here —
//! catching the kind of regression that property-tests-on-random-
//! inputs can miss because both the "test generator" and the
//! "implementation" walk the same broken path.
//!
//! ## Determinism
//!
//! - Ed25519 signing is deterministic per RFC 8032 (SHA-512 of secret
//!   ‖ message). Same SigningKey + same body = byte-identical
//!   signature, every platform, every build.
//! - X25519 ECDH is deterministic over its inputs.
//! - BLAKE3 is deterministic.
//!
//! ## Regenerating the vectors
//!
//! If a vector intentionally needs to change (e.g. wire format bump
//! to v2), set `OL_PAIR_QR_KAT_REGEN=1` and re-run; the test dumps
//! the new values to stderr, copy them into this file, commit the
//! diff along with the version bump.

use ed25519_dalek::SigningKey;
use x25519_dalek::{PublicKey, StaticSecret};

use ol_pair_qr::chain_key::derive_chain_key;
use ol_pair_qr::confirm::PairConfirm;
use ol_pair_qr::invite::{CapabilityScope, Invite, INVITE_NONCE_LEN};
use ol_pair_qr::response::{PairResponse, RESPONSE_NONCE_LEN};
use ol_pair_qr::sas::Sas;
use ol_pair_qr::transcript::transcript_hash;

// ── Fixed test inputs ─────────────────────────────────────────────

// Inviter identity seed: 32 bytes of value 0xA1.
const INVITER_ID_SEED: [u8; 32] = [0xA1u8; 32];
// Inviter ephemeral X25519 secret seed.
const INVITER_EPHEM_SEED: [u8; 32] = [0xB2u8; 32];
// Invite nonce.
const INVITE_NONCE: [u8; INVITE_NONCE_LEN] = [0xC3u8; INVITE_NONCE_LEN];
// Invite expiry.
const INVITE_EXPIRY: u64 = 1_900_000_000;
// Capability scope.
const SCOPE: &[u8] = b"contact:kat";

// Scanner identity seed.
const SCANNER_ID_SEED: [u8; 32] = [0xD4u8; 32];
// Scanner ephemeral X25519 secret seed.
const SCANNER_EPHEM_SEED: [u8; 32] = [0xE5u8; 32];
// Response nonce.
const RESPONSE_NONCE: [u8; RESPONSE_NONCE_LEN] = [0xF6u8; RESPONSE_NONCE_LEN];

// ── Pinned expected outputs (hex-encoded for readability) ─────────
//
// These values were captured from a stable build of ol_pair_qr at
// crate version 0.21.0-alpha.0 / wire format INVITE_VERSION = 1.
// A divergence here is either an intentional wire format change
// (bump INVITE_VERSION + regenerate) or a regression.

const EXPECTED_INVITE_HEX: &str = "0101bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a5db48257e1237976a74ad8cfedca00213408fe89ac6251f1b930245f242b5c31ac3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c300000000713fb300000b636f6e746163743a6b6174a948cb76e7d122caeb9e8f7285dd20a80555c465b8c681d049f800712c8a55670d18ab2d006e8312445981fa6311a93e2cd91eae2e9ba3ba2196b42081f29f07";
const EXPECTED_RESPONSE_HEX: &str = "0102ed3234b276d4ceda57d59bad14fbaf5a773c0f318c999de3a60d53c5a5b34c05e606d7ea293b0ce5dd7a32714e7de10fb8a01d6f23a6a93c1e32b06b12d8b319f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f61c86c95dcdb68b648323be98b9a13de6fb5fd80905d055ad08b2db601386e62b34a56b6936b63414ae03f227cf53b0ed09636eec1b07ef892646a157698ec205";
const EXPECTED_TRANSCRIPT_HEX: &str =
    "7713ba7ab21d6b1af3763f7b59be61e21114138484a47e4f98b0f7fc78a64fdf";
const EXPECTED_SAS_WORDS: &str = "brick flame decoy brick hover";
const EXPECTED_CHAIN_KEY_HEX: &str =
    "df937e57624b161414f8f0a47cd5e12efc312ed1a6c8c99175f7fe21a3080d2f";
const EXPECTED_CONFIRM_HEX: &str = "0103bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a57713ba7ab21d6b1af3763f7b59be61e21114138484a47e4f98b0f7fc78a64fdf518c461eaf2f214f59d38fb0362534a1b2a3ea7db17453f8c0076508d27b2533562f56f0a3ea50335f83fd955401b4171cfd52f2096c5b740e47d042ee3a020a";

// ── Helpers ───────────────────────────────────────────────────────

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for &byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

fn maybe_regen() -> bool {
    std::env::var("OL_PAIR_QR_KAT_REGEN").as_deref() == Ok("1")
}

fn assert_or_regen(name: &str, expected: &str, actual: &str) {
    if maybe_regen() {
        eprintln!("KAT regen: const EXPECTED_{name} = \"{actual}\";");
        return;
    }
    assert_eq!(
        expected, actual,
        "\nKAT mismatch for {name}.\n\
         expected: {expected}\n\
         actual:   {actual}\n\
         Set OL_PAIR_QR_KAT_REGEN=1 to regenerate if this change is intended."
    );
}

fn build_kat_pair() -> (Invite, PairResponse, PairConfirm) {
    let inviter_sk = SigningKey::from_bytes(&INVITER_ID_SEED);
    let inviter_esk = StaticSecret::from(INVITER_EPHEM_SEED);
    let inviter_epk = PublicKey::from(&inviter_esk).to_bytes();

    let invite = Invite::sign(
        &inviter_sk,
        inviter_epk,
        INVITE_NONCE,
        INVITE_EXPIRY,
        CapabilityScope::from_bytes(SCOPE).unwrap(),
    );

    let scanner_sk = SigningKey::from_bytes(&SCANNER_ID_SEED);
    let scanner_esk = StaticSecret::from(SCANNER_EPHEM_SEED);
    let scanner_epk = PublicKey::from(&scanner_esk).to_bytes();

    let response = PairResponse::sign_for_transcript(
        &scanner_sk,
        scanner_epk,
        RESPONSE_NONCE,
        &invite.body_bytes(),
    );

    let t = transcript_hash(&invite, &response);
    let confirm = PairConfirm::sign(&inviter_sk, t);
    (invite, response, confirm)
}

// ── Tests ─────────────────────────────────────────────────────────

#[test]
fn kat_invite_bytes_pinned() {
    let (invite, _, _) = build_kat_pair();
    assert_or_regen("INVITE_HEX", EXPECTED_INVITE_HEX, &hex(&invite.encode()));
}

#[test]
fn kat_response_bytes_pinned() {
    let (_, response, _) = build_kat_pair();
    assert_or_regen(
        "RESPONSE_HEX",
        EXPECTED_RESPONSE_HEX,
        &hex(&response.encode()),
    );
}

#[test]
fn kat_transcript_hash_pinned() {
    let (invite, response, _) = build_kat_pair();
    let t = transcript_hash(&invite, &response);
    assert_or_regen(
        "TRANSCRIPT_HEX",
        EXPECTED_TRANSCRIPT_HEX,
        &hex(t.as_bytes()),
    );
}

#[test]
fn kat_sas_words_pinned() {
    let (invite, response, _) = build_kat_pair();
    let t = transcript_hash(&invite, &response);
    let sas = Sas::derive(&t);
    assert_or_regen("SAS_WORDS", EXPECTED_SAS_WORDS, &sas.display());
}

#[test]
fn kat_chain_key_pinned() {
    let (invite, response, _) = build_kat_pair();
    let inviter_esk = StaticSecret::from(INVITER_EPHEM_SEED);
    // Note: scanner-side ECDH (esk_scanner.diffie_hellman(&epk_inviter))
    // produces the same shared secret as inviter-side
    // (esk_inviter.diffie_hellman(&epk_scanner)) — that's the X25519
    // symmetric property. Pin the inviter-side computation.
    let scanner_epk = PublicKey::from(&StaticSecret::from(SCANNER_EPHEM_SEED));
    let ss = inviter_esk.diffie_hellman(&scanner_epk);
    let ss_bytes: [u8; 32] = ss.to_bytes();
    let t = transcript_hash(&invite, &response);
    let chain_key = derive_chain_key(&t, &ss_bytes);
    assert_or_regen(
        "CHAIN_KEY_HEX",
        EXPECTED_CHAIN_KEY_HEX,
        &hex(chain_key.as_bytes()),
    );
}

#[test]
fn kat_confirm_bytes_pinned() {
    let (_, _, confirm) = build_kat_pair();
    assert_or_regen("CONFIRM_HEX", EXPECTED_CONFIRM_HEX, &hex(&confirm.encode()));
}

#[test]
fn kat_full_roundtrip_decodes_and_verifies() {
    let (invite, response, confirm) = build_kat_pair();
    // Invite roundtrip
    let decoded = Invite::decode_and_verify(&invite.encode()).unwrap();
    assert_eq!(decoded, invite);
    // Response roundtrip
    let decoded =
        PairResponse::decode_and_verify(&response.encode(), &invite.body_bytes()).unwrap();
    assert_eq!(decoded, response);
    // Confirm roundtrip
    let t = transcript_hash(&invite, &response);
    let decoded = PairConfirm::decode_and_verify(&confirm.encode(), &invite.id_pubkey, &t).unwrap();
    assert_eq!(decoded, confirm);
}
