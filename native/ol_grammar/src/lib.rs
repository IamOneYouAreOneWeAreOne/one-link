//! `ol_grammar` — Re-Pair grammar compression for the secondary chunk
//! index.
//!
//! Per `FILE_ENGINE_V2_PLAN.md` Phase D item #5:
//!
//! > Grammar compression secondary index — Re-Pair on structural-
//! > token streams of recognized formats. Layered on CDC, not
//! > replacing it. Rust port of forge_shootouts/hardened_grammar_
//! > compression.py.
//!
//! ## Algorithm
//!
//! Re-Pair: iteratively find the most-frequent pair of adjacent
//! symbols in the input sequence, replace every occurrence with a
//! fresh non-terminal symbol, and record the production rule. Stop
//! when no pair repeats. The output is a context-free grammar that
//! generates the original sequence; its compressed representation is
//! the rule table + the residual top-level sequence.
//!
//! For One Link's secondary index, the goal is NOT line-rate stream
//! compression — that's primary AEAD chunks' job. The grammar's
//! value is **structural fingerprinting**: two chunks that share
//! repeated substructures produce overlapping rule sets, exposing
//! dedup opportunities the raw BLAKE3 address can't see (e.g. two
//! Premiere project files that differ only in metadata at the
//! header).
//!
//! Complexity: O(N²) on naive implementation; sufficient for the
//! KB-scale chunks the index runs on. Production-scale (MB+)
//! callers should use the heap-based variant (out of scope for this
//! port).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod repair;

pub use repair::{
    compress, compression_ratio, decompress, Grammar, GrammarError, Rule,
};

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
