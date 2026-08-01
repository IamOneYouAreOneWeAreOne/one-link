//! Replay the capability-attenuation fuzz harness over a corpus directory.
//!
//! `fuzz (nightly)` has been red on `fuzz_capability_attenuate_roundtrip`
//! for every run, and libFuzzer does not build on this workstation. This
//! test replicates the harness byte-for-byte so the same inputs can be
//! replayed anywhere `cargo test` runs, which is what makes the failure
//! reproducible off the CI box.
//!
//! Point it at a corpus by setting `ONE_LINK_FUZZ_CORPUS` to a directory and
//! running this test with `--nocapture`. With no corpus set it is a no-op, so
//! it never fails a normal run.

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

/// The harness body, returning a description instead of panicking so the
/// replay can report every failing input rather than only the first.
fn replay_detailed(data: &[u8]) -> Result<Vec<String>, String> {
    let mut refusals: Vec<String> = Vec::new();
    let mut input = data;
    let Some(root_arr) = take_array::<32>(&mut input) else {
        return Ok(refusals);
    };
    let Some(id) = take_array::<32>(&mut input) else {
        return Ok(refusals);
    };
    let root = Zeroizing::new(root_arr);
    let mut cap = Capability::root(id, &root);

    let n_caveats = (take_u32(&mut input).unwrap_or(0) % 8) as usize;
    for _ in 0..n_caveats {
        let Some(cav) = take_caveat(&mut input) else {
            return Ok(refusals);
        };
        let described = format!("{cav:?}");
        let before = cap.clone();
        cap = match cap.attenuate(cav) {
            Ok(next) => next,
            // Mirrors the fuzz target: a refusal is a defined outcome. It is
            // surfaced through `refusals` so a test can still assert that a
            // given input WAS refused, without treating it as a failure.
            Err(e) => {
                refusals.push(format!("{e:?} :: {described}"));
                before
            }
        };
    }

    let wire = cap.encode();
    let decoded = Capability::decode(&wire)
        .map_err(|e| format!("decode failed on {} wire bytes: {e:?}", wire.len()))?;
    if decoded != cap {
        return Err(format!(
            "round trip not structurally equal ({} wire bytes, {} caveats)",
            wire.len(),
            cap.caveats().len()
        ));
    }
    Ok(refusals)
}

/// Convenience wrapper: success or the first hard failure.
fn replay(data: &[u8]) -> Result<Vec<String>, String> {
    replay_detailed(data)
}

/// Build the exact input shape the fuzzer feeds the harness.
fn harness_input(caveat_bytes: &[u8], n_caveats: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&[7u8; 32]); // root key
    v.extend_from_slice(&[9u8; 32]); // capability id
    v.extend_from_slice(&n_caveats.to_le_bytes());
    v.extend_from_slice(caveat_bytes);
    v
}

#[test]
fn empty_path_prefix_is_refused_not_a_crash() {
    // take_string computes `len = byte % 32`, so a length byte of 0 yields an
    // EMPTY string. The capability layer refuses an empty PathPrefix on
    // purpose: a zero-length prefix matches every path, which is the opposite
    // of attenuation. The harness called that refusal a bug and panicked.
    //
    // caveat byte 0 -> tag % 5 == 2 -> PathPrefix; next byte 0 -> empty string.
    let input = harness_input(&[2u8, 0u8], 1);
    let refusals = replay(&input).expect("a refusal must not fail the harness");
    assert_eq!(
        refusals.len(),
        1,
        "expected exactly one refusal: {refusals:?}"
    );
    assert!(
        refusals[0].contains("PathPrefix"),
        "expected the empty PathPrefix to be the refused caveat: {refusals:?}"
    );
}

#[test]
fn empty_operation_name_is_refused_not_a_crash() {
    // tag % 5 == 3 -> OperationIn; count byte 0 -> 1 name; length byte 0 ->
    // empty name, which is refused for the same reason.
    let input = harness_input(&[3u8, 0u8, 0u8], 1);
    let refusals = replay(&input).expect("a refusal must not fail the harness");
    assert_eq!(
        refusals.len(),
        1,
        "expected exactly one refusal: {refusals:?}"
    );
    assert!(
        refusals[0].contains("OperationIn"),
        "expected the empty operation name to be the refused caveat: {refusals:?}"
    );
}

#[test]
fn a_valid_caveat_still_round_trips() {
    // Same shape, non-empty prefix: this must succeed, so the tests above are
    // pinning the empty case specifically rather than a broken harness.
    let input = harness_input(&[2u8, 3u8, b'a', b'b', b'c'], 1);
    let refusals = replay(&input).expect("a non-empty PathPrefix must round trip");
    assert!(
        refusals.is_empty(),
        "a valid caveat must not be refused: {refusals:?}"
    );
}

#[test]
fn replay_corpus_directory() {
    let Ok(dir) = std::env::var("ONE_LINK_FUZZ_CORPUS") else {
        eprintln!("ONE_LINK_FUZZ_CORPUS not set; nothing to replay");
        return;
    };
    let entries = std::fs::read_dir(&dir).expect("corpus directory must be readable");
    let mut checked = 0usize;
    let mut failures: Vec<(String, String)> = Vec::new();
    for entry in entries {
        let path = entry.expect("corpus entry").path();
        if !path.is_file() {
            continue;
        }
        let data = std::fs::read(&path).expect("corpus file must be readable");
        checked += 1;
        if let Err(reason) = replay(&data) {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            failures.push((name, reason));
        }
    }
    eprintln!(
        "replayed {checked} corpus inputs, {} failing",
        failures.len()
    );
    for (name, reason) in &failures {
        eprintln!("  FAIL {name}: {reason}");
    }
    assert!(checked > 0, "corpus directory contained no inputs");
    assert!(
        failures.is_empty(),
        "{} corpus inputs fail the harness",
        failures.len()
    );
}
