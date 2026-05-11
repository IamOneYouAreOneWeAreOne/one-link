//! Minimal CL declaration parser. Recognizes both `struct` and
//! tagged-union (`enum`) shapes:
//!
//! ```text
//! struct Foo {
//!     bar: u32,
//!     baz: [u8; 32],
//!     name: String,
//! }
//!
//! enum Caveat {
//!     NotAfter(u64),
//!     Scope(String),
//!     Audit([u8; 32]),
//!     Sentinel,                // unit variant — no payload
//! }
//! ```
//!
//! That's enough to round-trip the primitive records and tagged
//! unions the daemon actually uses across the FFI boundary
//! (capability id, caveat discriminants, vector-clock entry tuples).
//! The full CL grammar (multi-field variants, traits, lifetimes,
//! generics) is out of scope for this bootstrap; the parser refuses
//! anything outside its grammar with a typed `ParseError`.

use thiserror::Error;

/// Errors the parser can return. The `Error::source` chain conveys
/// the structural reason; variants exist for `UnexpectedToken`,
/// `UnexpectedEof`, `UnknownType`, `InvalidArrayLength`, and
/// `UnknownDecl`.
#[allow(missing_docs)]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("expected token {expected}, found {found} at offset {offset}")]
    UnexpectedToken {
        expected: &'static str,
        found: String,
        offset: usize,
    },
    #[error("unexpected end of input")]
    UnexpectedEof,
    #[error("unknown field type: {0}")]
    UnknownType(String),
    #[error("invalid byte-array length: {0}")]
    InvalidArrayLength(String),
    #[error("unknown declaration kind: {0} (expected `struct` or `enum`)")]
    UnknownDecl(String),
}

/// CL spec field types this minimal grammar recognizes. Maps 1:1 to
/// Rust types in the emitter (`u8`, `u16`, `u32`, `u64`,
/// `[u8; N]`, `String`).
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldType {
    U8,
    U16,
    U32,
    U64,
    /// Fixed-length byte array.
    ByteArray(usize),
    /// Length-prefixed UTF-8 string.
    String,
}

/// A parsed `name: type` pair inside a struct body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedField {
    /// Field name in the CL source.
    pub name: String,
    /// Field type per the spec.
    pub ty: FieldType,
}

/// A parsed `struct Foo { ... }` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedStruct {
    /// Struct name (becomes the Rust struct identifier).
    pub name: String,
    /// Field declarations in source order.
    pub fields: Vec<ParsedField>,
}

/// A single enum variant. `payload = None` is a unit variant, e.g.
/// `Sentinel`. `payload = Some(ty)` is a single-payload tuple-variant,
/// e.g. `Scope(String)`. The discriminant is the variant's source-order
/// index (0-based, u8) — matches the canonical CL tag layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedVariant {
    /// Variant name as written in the CL source.
    pub name: String,
    /// Optional single-typed payload; `None` for unit variants.
    pub payload: Option<FieldType>,
}

/// A parsed `enum Foo { Variant(..), ... }` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedEnum {
    /// Enum name (becomes the Rust enum identifier).
    pub name: String,
    /// Variants in source order — the index into this vector is the
    /// canonical u8 discriminant byte.
    pub variants: Vec<ParsedVariant>,
}

/// Top-level CL declaration the parser recognizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedDecl {
    /// A struct declaration.
    Struct(ParsedStruct),
    /// An enum / tagged-union declaration.
    Enum(ParsedEnum),
}

/// Parse a `struct Foo { ... }` declaration. Returns the parsed
/// struct on success. Whitespace + line comments (`// ...`) are
/// skipped.
pub fn parse_struct(input: &str) -> Result<ParsedStruct, ParseError> {
    let mut cursor = Cursor::new(input);
    cursor.skip_trivia();
    cursor.expect_keyword("struct")?;
    parse_struct_body(&mut cursor)
}

/// Parse an `enum Foo { Variant(Type), ... }` declaration. Returns
/// the parsed enum. Trailing commas + unit variants are accepted.
pub fn parse_enum(input: &str) -> Result<ParsedEnum, ParseError> {
    let mut cursor = Cursor::new(input);
    cursor.skip_trivia();
    cursor.expect_keyword("enum")?;
    parse_enum_body(&mut cursor)
}

/// Parse any top-level declaration this grammar supports. Auto-routes
/// based on the leading keyword (`struct` or `enum`).
pub fn parse_decl(input: &str) -> Result<ParsedDecl, ParseError> {
    let mut cursor = Cursor::new(input);
    cursor.skip_trivia();
    let kw = cursor.parse_ident()?;
    match kw.as_str() {
        "struct" => parse_struct_body(&mut cursor).map(ParsedDecl::Struct),
        "enum" => parse_enum_body(&mut cursor).map(ParsedDecl::Enum),
        other => Err(ParseError::UnknownDecl(other.to_string())),
    }
}

fn parse_struct_body(cursor: &mut Cursor<'_>) -> Result<ParsedStruct, ParseError> {
    cursor.skip_trivia();
    let name = cursor.parse_ident()?;
    cursor.skip_trivia();
    cursor.expect_char('{')?;
    let mut fields = Vec::new();
    loop {
        cursor.skip_trivia();
        if cursor.peek() == Some('}') {
            cursor.advance(1);
            break;
        }
        let field_name = cursor.parse_ident()?;
        cursor.skip_trivia();
        cursor.expect_char(':')?;
        cursor.skip_trivia();
        let ty = parse_field_type(cursor)?;
        cursor.skip_trivia();
        if cursor.peek() == Some(',') {
            cursor.advance(1);
        }
        fields.push(ParsedField { name: field_name, ty });
    }
    Ok(ParsedStruct { name, fields })
}

fn parse_enum_body(cursor: &mut Cursor<'_>) -> Result<ParsedEnum, ParseError> {
    cursor.skip_trivia();
    let name = cursor.parse_ident()?;
    cursor.skip_trivia();
    cursor.expect_char('{')?;
    let mut variants = Vec::new();
    loop {
        cursor.skip_trivia();
        if cursor.peek() == Some('}') {
            cursor.advance(1);
            break;
        }
        let variant_name = cursor.parse_ident()?;
        cursor.skip_trivia();
        let payload = if cursor.peek() == Some('(') {
            cursor.advance(1);
            cursor.skip_trivia();
            let ty = parse_field_type(cursor)?;
            cursor.skip_trivia();
            cursor.expect_char(')')?;
            Some(ty)
        } else {
            None
        };
        cursor.skip_trivia();
        if cursor.peek() == Some(',') {
            cursor.advance(1);
        }
        variants.push(ParsedVariant { name: variant_name, payload });
    }
    Ok(ParsedEnum { name, variants })
}

fn parse_field_type(cursor: &mut Cursor<'_>) -> Result<FieldType, ParseError> {
    // Either an identifier (u8, u16, u32, u64, String) or [u8; N].
    if cursor.peek() == Some('[') {
        cursor.advance(1);
        cursor.skip_trivia();
        let inner = cursor.parse_ident()?;
        if inner != "u8" {
            return Err(ParseError::UnknownType(inner));
        }
        cursor.skip_trivia();
        cursor.expect_char(';')?;
        cursor.skip_trivia();
        let len_str = cursor.parse_number()?;
        let len: usize = len_str
            .parse()
            .map_err(|_| ParseError::InvalidArrayLength(len_str.clone()))?;
        cursor.skip_trivia();
        cursor.expect_char(']')?;
        return Ok(FieldType::ByteArray(len));
    }
    let ident = cursor.parse_ident()?;
    match ident.as_str() {
        "u8" => Ok(FieldType::U8),
        "u16" => Ok(FieldType::U16),
        "u32" => Ok(FieldType::U32),
        "u64" => Ok(FieldType::U64),
        "String" => Ok(FieldType::String),
        other => Err(ParseError::UnknownType(other.to_string())),
    }
}

struct Cursor<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(src: &'a str) -> Self {
        Self { src: src.as_bytes(), pos: 0 }
    }

    fn peek(&self) -> Option<char> {
        self.src.get(self.pos).map(|&b| b as char)
    }

    fn advance(&mut self, n: usize) {
        self.pos += n;
    }

    fn skip_trivia(&mut self) {
        while self.pos < self.src.len() {
            let c = self.src[self.pos] as char;
            if c.is_whitespace() {
                self.pos += 1;
            } else if c == '/' && self.src.get(self.pos + 1).copied() == Some(b'/') {
                while self.pos < self.src.len() && self.src[self.pos] != b'\n' {
                    self.pos += 1;
                }
            } else {
                break;
            }
        }
    }

    fn expect_char(&mut self, expected: char) -> Result<(), ParseError> {
        if self.peek() == Some(expected) {
            self.advance(1);
            Ok(())
        } else {
            Err(ParseError::UnexpectedToken {
                expected: "char",
                found: format!("{:?}", self.peek()),
                offset: self.pos,
            })
        }
    }

    fn expect_keyword(&mut self, kw: &'static str) -> Result<(), ParseError> {
        let ident = self.parse_ident()?;
        if ident == kw {
            Ok(())
        } else {
            Err(ParseError::UnexpectedToken {
                expected: kw,
                found: ident,
                offset: self.pos,
            })
        }
    }

    fn parse_ident(&mut self) -> Result<String, ParseError> {
        let start = self.pos;
        while self.pos < self.src.len() {
            let c = self.src[self.pos] as char;
            if c.is_alphanumeric() || c == '_' {
                self.pos += 1;
            } else {
                break;
            }
        }
        if start == self.pos {
            return Err(ParseError::UnexpectedEof);
        }
        Ok(std::str::from_utf8(&self.src[start..self.pos])
            .map_err(|_| ParseError::UnexpectedEof)?
            .to_string())
    }

    fn parse_number(&mut self) -> Result<String, ParseError> {
        let start = self.pos;
        while self.pos < self.src.len() {
            let c = self.src[self.pos] as char;
            if c.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
        if start == self.pos {
            return Err(ParseError::UnexpectedEof);
        }
        Ok(std::str::from_utf8(&self.src[start..self.pos])
            .map_err(|_| ParseError::UnexpectedEof)?
            .to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_struct() {
        let cl = "struct Foo { a: u32, b: u8 }";
        let p = parse_struct(cl).unwrap();
        assert_eq!(p.name, "Foo");
        assert_eq!(p.fields.len(), 2);
        assert_eq!(p.fields[0].name, "a");
        assert_eq!(p.fields[0].ty, FieldType::U32);
        assert_eq!(p.fields[1].name, "b");
        assert_eq!(p.fields[1].ty, FieldType::U8);
    }

    #[test]
    fn parse_byte_array_field() {
        let cl = "struct Cap { id: [u8; 32], not_after: u64 }";
        let p = parse_struct(cl).unwrap();
        assert_eq!(p.fields[0].ty, FieldType::ByteArray(32));
        assert_eq!(p.fields[1].ty, FieldType::U64);
    }

    #[test]
    fn parse_with_comments_and_whitespace() {
        let cl = "
            // This is the capability id record.
            struct CapId {
                // 32-byte BLAKE3
                bytes: [u8; 32],
                seq: u64
            }
        ";
        let p = parse_struct(cl).unwrap();
        assert_eq!(p.name, "CapId");
        assert_eq!(p.fields.len(), 2);
    }

    #[test]
    fn parse_string_field() {
        let cl = "struct Tag { name: String }";
        let p = parse_struct(cl).unwrap();
        assert_eq!(p.fields[0].ty, FieldType::String);
    }

    #[test]
    fn parse_rejects_unknown_type() {
        let cl = "struct X { v: Unknown }";
        assert!(matches!(parse_struct(cl), Err(ParseError::UnknownType(_))));
    }

    #[test]
    fn parse_rejects_missing_brace() {
        let cl = "struct X v: u8 }";
        assert!(parse_struct(cl).is_err());
    }

    #[test]
    fn parse_simple_enum_with_payloads() {
        let cl = "enum Caveat { NotAfter(u64), Scope(String), Audit([u8; 32]) }";
        let p = parse_enum(cl).unwrap();
        assert_eq!(p.name, "Caveat");
        assert_eq!(p.variants.len(), 3);
        assert_eq!(p.variants[0].name, "NotAfter");
        assert_eq!(p.variants[0].payload, Some(FieldType::U64));
        assert_eq!(p.variants[1].payload, Some(FieldType::String));
        assert_eq!(p.variants[2].payload, Some(FieldType::ByteArray(32)));
    }

    #[test]
    fn parse_enum_with_unit_variant() {
        let cl = "enum Tag { Sentinel, Numbered(u32) }";
        let p = parse_enum(cl).unwrap();
        assert_eq!(p.variants.len(), 2);
        assert_eq!(p.variants[0].name, "Sentinel");
        assert_eq!(p.variants[0].payload, None);
        assert_eq!(p.variants[1].payload, Some(FieldType::U32));
    }

    #[test]
    fn parse_enum_trailing_comma_ok() {
        let cl = "enum E { A, B, }";
        let p = parse_enum(cl).unwrap();
        assert_eq!(p.variants.len(), 2);
    }

    #[test]
    fn parse_decl_routes_by_keyword() {
        match parse_decl("struct X { a: u8 }").unwrap() {
            ParsedDecl::Struct(s) => assert_eq!(s.name, "X"),
            ParsedDecl::Enum(_) => panic!("expected struct"),
        }
        match parse_decl("enum E { A }").unwrap() {
            ParsedDecl::Enum(e) => assert_eq!(e.name, "E"),
            ParsedDecl::Struct(_) => panic!("expected enum"),
        }
    }

    #[test]
    fn parse_decl_rejects_unknown_keyword() {
        assert!(matches!(
            parse_decl("trait X {}"),
            Err(ParseError::UnknownDecl(_))
        ));
    }
}
