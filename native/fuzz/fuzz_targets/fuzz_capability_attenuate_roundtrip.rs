#![no_main]
//! Fuzz attenuation + wire round trip. Build a capability from fuzz
//! input (root key, cap id, sequence of caveats), encode, decode, and
//! assert structural equality. Any panic or round-trip divergence is
//! a bug.

use libfuzzer_sys::fuzz_target;
use ol_capability::{Capability, Caveat};
use zeroize::Zeroizing;

fn take_array<const N: usize>(input: &mut &[u8]) -> Option<[u8; N]> {
    if input.len() < N {
        return None;
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&input[..N]);
    *input = &input[N..];
    Some(out)
}

fn take_byte(input: &mut &[u8]) -> Option<u8> {
    let b = *input.first()?;
    *input = &input[1..];
    Some(b)
}

fn take_u32(input: &mut &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = take_array(input)?;
    Some(u32::from_le_bytes(bytes))
}

fn take_u64(input: &mut &[u8]) -> Option<u64> {
    let bytes: [u8; 8] = take_array(input)?;
    Some(u64::from_le_bytes(bytes))
}

fn take_string(input: &mut &[u8], max_len: usize) -> Option<String> {
    let len = take_byte(input)? as usize % max_len.max(1);
    if input.len() < len {
        return None;
    }
    let s = String::from_utf8_lossy(&input[..len]).into_owned();
    *input = &input[len..];
    Some(s)
}

fn take_caveat(input: &mut &[u8]) -> Option<Caveat> {
    match take_byte(input)? % 5 {
        0 => Some(Caveat::ExpiresAt(take_u64(input)?)),
        1 => Some(Caveat::PeerFingerprint(take_array(input)?)),
        2 => Some(Caveat::PathPrefix(take_string(input, 32)?)),
        3 => {
            let n = (take_byte(input)? % 4) as usize + 1;
            let mut ops = Vec::with_capacity(n);
            for _ in 0..n {
                ops.push(take_string(input, 16)?);
            }
            Some(Caveat::OperationIn(ops))
        }
        _ => Some(Caveat::AuditTag(take_string(input, 32)?)),
    }
}

fuzz_target!(|data: &[u8]| {
    let mut input = data;
    let Some(root_arr) = take_array::<32>(&mut input) else { return };
    let Some(id) = take_array::<32>(&mut input) else { return };
    let root = Zeroizing::new(root_arr);
    let mut cap = Capability::root(id, &root);

    let n_caveats = (take_u32(&mut input).unwrap_or(0) % 8) as usize;
    for _ in 0..n_caveats {
        let Some(cav) = take_caveat(&mut input) else { return };
        cap = cap.attenuate(cav);
    }

    let wire = cap.encode();
    let decoded = Capability::decode(&wire).expect("encode→decode round trip must succeed");
    assert_eq!(decoded, cap, "wire round trip not structurally equal");
});
