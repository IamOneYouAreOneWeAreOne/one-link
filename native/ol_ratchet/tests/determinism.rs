//! Cross-platform determinism vector for `ol_ratchet`.
//!
//! The per-step message keys MUST be byte-identical across platforms
//! given a fixed shared secret — otherwise sender and receiver would
//! derive different AEAD keys and the engine breaks.

use ol_ratchet::Chain;

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

#[test]
fn cross_platform_first_three_message_keys_pinned() {
    // Fixed shared secret: 0x42 repeated.
    let mut chain = Chain::from_shared_secret(&[0x42u8; 32]);
    let mk0_bytes: [u8; 32] = *chain.next_message_key();
    let mk1_bytes: [u8; 32] = *chain.next_message_key();
    let mk2_bytes: [u8; 32] = *chain.next_message_key();

    let mk0 = hex_lower(&mk0_bytes);
    let mk1 = hex_lower(&mk1_bytes);
    let mk2 = hex_lower(&mk2_bytes);

    if mk0 != PINNED_MK0 || mk1 != PINNED_MK1 || mk2 != PINNED_MK2 {
        eprintln!("PINNED_MK0 = \"{mk0}\"");
        eprintln!("PINNED_MK1 = \"{mk1}\"");
        eprintln!("PINNED_MK2 = \"{mk2}\"");
    }
    assert_eq!(mk0, PINNED_MK0, "MK0 diverged");
    assert_eq!(mk1, PINNED_MK1, "MK1 diverged");
    assert_eq!(mk2, PINNED_MK2, "MK2 diverged");
}

const PINNED_MK0: &str = "c8c5d3af981a7377b8ff185f03374594edd10d5cb428744f537bbc31bc781d0e";
const PINNED_MK1: &str = "e61b19efb755ce38fae328c9ed27f0e95ba7a0b461a196ed77d552f9681b4b76";
const PINNED_MK2: &str = "177d7568b7354fa5d66560c39b17ba4aeff283dbbe8df3c0c51db04b4e23b601";
