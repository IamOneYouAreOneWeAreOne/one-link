//! Byte-equivalence gate for `ol_canon`. Per the plan: 1M random
//! structured inputs MUST produce byte-identical output across runs.
//!
//! Configurable via ``OL_CANON_GATE_ITERS`` (default 100k for
//! everyday `cargo test`; CI nightly sets 1_000_000 to meet the
//! plan's Phase A1 acceptance number).

use ol_canon::{CanonDecoder, CanonEncoder};

/// SplitMix64 — deterministic, fast, ample quality for round-trip
/// fuzzing. Same constants as the rest of the workspace's randomized
/// gates so seeds are interchangeable.
fn next_rng(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[derive(Debug, PartialEq)]
enum Value {
    Null,
    Bool(bool),
    U64(u64),
    I64(i64),
    F64(f64),
    String(String),
    Bytes(Vec<u8>),
}

fn random_value(state: &mut u64) -> Value {
    match next_rng(state) % 7 {
        0 => Value::Null,
        1 => Value::Bool(next_rng(state) & 1 == 0),
        2 => Value::U64(next_rng(state)),
        3 => Value::I64(next_rng(state) as i64),
        4 => {
            // Reject NaN/Inf so the round-trip equality holds at the
            // bit level. Canonicalisation is tested separately.
            let bits = next_rng(state);
            let f = f64::from_bits(bits);
            if f.is_nan() || f.is_infinite() {
                Value::F64(0.0)
            } else {
                Value::F64(f)
            }
        }
        5 => {
            let len = (next_rng(state) % 16) as usize;
            let mut s = String::with_capacity(len);
            for _ in 0..len {
                // ASCII printable so we don't need full UTF-8 generators
                let c = b'a' + (next_rng(state) % 26) as u8;
                s.push(c as char);
            }
            Value::String(s)
        }
        _ => {
            let len = (next_rng(state) % 32) as usize;
            let bytes: Vec<u8> = (0..len).map(|_| (next_rng(state) & 0xFF) as u8).collect();
            Value::Bytes(bytes)
        }
    }
}

fn encode(value: &Value) -> Vec<u8> {
    let mut e = CanonEncoder::new();
    match value {
        Value::Null => e.encode_null().unwrap(),
        Value::Bool(v) => e.encode_bool(*v).unwrap(),
        Value::U64(v) => e.encode_u64(*v).unwrap(),
        Value::I64(v) => e.encode_i64(*v).unwrap(),
        Value::F64(v) => e.encode_f64(*v).unwrap(),
        Value::String(v) => e.encode_string(v).unwrap(),
        Value::Bytes(v) => e.encode_bytes(v).unwrap(),
    }
    e.finish()
}

fn decode(bytes: &[u8]) -> Value {
    let mut d = CanonDecoder::new(bytes);
    let tag = d.peek_tag().unwrap();
    match tag {
        ol_canon::TypeTag::Null => {
            d.decode_null().unwrap();
            Value::Null
        }
        ol_canon::TypeTag::True | ol_canon::TypeTag::False => Value::Bool(d.decode_bool().unwrap()),
        ol_canon::TypeTag::UInt => Value::U64(d.decode_u64().unwrap()),
        ol_canon::TypeTag::Int => Value::I64(d.decode_i64().unwrap()),
        ol_canon::TypeTag::Float64 => Value::F64(d.decode_f64().unwrap()),
        ol_canon::TypeTag::String => Value::String(d.decode_string().unwrap()),
        ol_canon::TypeTag::Bytes => Value::Bytes(d.decode_bytes().unwrap()),
        other => panic!("unexpected tag: {:?}", other),
    }
}

#[test]
fn property_random_values_round_trip_and_are_deterministic() {
    let iters: u64 = std::env::var("OL_CANON_GATE_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000);
    let mut state: u64 = 0xC0DE_C0DE_C0DE_C0DE;
    let mut fail = 0u64;
    for _ in 0..iters {
        let value = random_value(&mut state);
        let bytes_a = encode(&value);
        let bytes_b = encode(&value);
        if bytes_a != bytes_b {
            eprintln!("non-deterministic encode for {:?}", value);
            fail += 1;
            continue;
        }
        let decoded = decode(&bytes_a);
        // Float bit-equality: NaN/Inf were filtered above.
        if let (Value::F64(a), Value::F64(b)) = (&value, &decoded) {
            if a.to_bits() != b.to_bits() {
                eprintln!("f64 round-trip mismatch: {} vs {}", a, b);
                fail += 1;
                continue;
            }
        } else if value != decoded {
            eprintln!("round-trip mismatch: {:?} → {:?}", value, decoded);
            fail += 1;
        }
    }
    assert_eq!(
        fail, 0,
        "byte-equivalence gate: {fail} / {iters} round-trips failed"
    );
}
