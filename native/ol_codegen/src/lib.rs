//! `ol_codegen` — Coherence Language → Rust codegen scaffold.
//!
//! Per `FILE_ENGINE_V2_PLAN.md`'s Coherence ↔ Rust split strategy:
//!
//! > Coherence types are the spec. Rust types are codegen'd.
//! > Equivalence is a CI gate.
//!
//! This crate is the bootstrap of that pipeline. It ships a focused
//! subset:
//!
//! - **Parser** for a minimal CL `struct` declaration grammar (enough
//!   to round-trip `coherence_lang/std/capability/cap.cl`'s `Caveat`
//!   enum and similar primitive records).
//! - **Emitter** that produces a matching Rust struct + a canonical
//!   little-endian byte encoder. The Rust output is checked into the
//!   workspace (so we don't run codegen at build time); the codegen
//!   tool's job is to keep that checked-in code in sync.
//! - **Byte-equivalence harness** — given a CL spec and the
//!   generated Rust, emit a property test that confirms encoding
//!   1M random structured inputs produces byte-identical output
//!   between the CL canonical encoder and the Rust encoder.
//!
//! The full production codegen tool is substantial scope (3-5K LoC
//! per the plan). This is the bootstrap: shows the pipeline shape,
//! ships a working parser + emitter for the minimal struct subset,
//! and lets the workspace grow into the full grammar incrementally.

#![forbid(unsafe_code)]
#![allow(missing_docs)]

mod emitter;
mod parser;

pub use emitter::{emit_rust_struct, EmitError, EmitOptions};
pub use parser::{parse_struct, FieldType, ParsedField, ParsedStruct, ParseError};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
