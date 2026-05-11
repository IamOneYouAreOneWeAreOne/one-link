//! Property-based tests for `ol_codegen`.

use ol_codegen::{emit_rust_struct, parse_struct, EmitOptions};
use proptest::prelude::*;

proptest! {
    /// parse_struct never panics on arbitrary UTF-8 input.
    /// (Deterministic Err for invalid input is the expected outcome.)
    #[test]
    fn parser_never_panics_on_arbitrary_input(s in "[a-zA-Z0-9_{},:; \\n\\[\\]]{0,200}") {
        let _ = parse_struct(&s);
    }

    /// emit_rust_struct produces a non-empty result for any successfully
    /// parsed struct.
    #[test]
    fn emit_non_empty_after_successful_parse(
        name in "[a-z][a-z0-9_]{0,8}",
        n_fields in 1usize..6,
        seeds in proptest::collection::vec(0u8..6, 1..6),
    ) {
        let types = ["u8", "u16", "u32", "u64", "[u8; 32]", "String"];
        let mut cl = format!("struct {} {{\n", name);
        for (i, seed) in seeds.iter().take(n_fields).enumerate() {
            cl.push_str(&format!("    field_{}: {},\n", i, types[*seed as usize]));
        }
        cl.push('}');
        let parsed = parse_struct(&cl).expect("constructed CL is valid");
        let rust = emit_rust_struct(&parsed, &EmitOptions::default()).unwrap();
        prop_assert!(!rust.is_empty());
        let needle = format!("pub struct {}", name);
        prop_assert!(rust.contains(&needle));
        prop_assert!(rust.contains("pub fn encode(&self)"));
    }

    /// Emitting twice on the same parsed struct produces identical output
    /// (determinism — codegen must be idempotent for stable build hashes).
    #[test]
    fn emit_is_deterministic(
        cl in r"struct [a-z][a-z0-9_]{0,4} \{\s*a: u8\s*,\s*\}",
    ) {
        if let Ok(parsed) = parse_struct(&cl) {
            let a = emit_rust_struct(&parsed, &EmitOptions::default()).unwrap();
            let b = emit_rust_struct(&parsed, &EmitOptions::default()).unwrap();
            prop_assert_eq!(a, b);
        }
    }
}
