//! Minimal CL `struct` parser. Recognizes:
//!
//! ```text
//! struct Foo {
//!     bar: u32,
//!     baz: [u8; 32],
//!     name: String,
//! }
//! ```
//!
//! That's enough to round-trip the primitive records the daemon
//! actually uses across the FFI boundary (capability id, caveat
//! discriminants, vector-clock entry tuples, etc.). The full CL
//! grammar (algebraic data types, traits, lifetimes) is out of
//! scope for this bootstrap.

use thiserror::Error;

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
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedField {
    pub name: String,
    pub ty: FieldType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedStruct {
    pub name: String,
    pub fields: Vec<ParsedField>,
}

/// Parse a `struct Foo { ... }` declaration. Returns the parsed
/// struct on success. Whitespace + line comments (`// ...`) are
/// skipped.
pub fn parse_struct(input: &str) -> Result<ParsedStruct, ParseError> {
    let mut cursor = Cursor::new(input);
    cursor.skip_trivia();
    cursor.expect_keyword("struct")?;
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
        let ty = parse_field_type(&mut cursor)?;
        cursor.skip_trivia();
        // Optional comma.
        if cursor.peek() == Some(',') {
            cursor.advance(1);
        }
        fields.push(ParsedField { name: field_name, ty });
    }
    Ok(ParsedStruct { name, fields })
}

fn parse_field_type(cursor: &mut Cursor<'_>) -> Result<FieldType, ParseError> {
    // Either an identifier (u8, u16, u32, u64, String) or [u8; N].
    if cursor.peek() == Some('[') {
        cursor.advance(1);
        cursor.skip_trivia();
        // expect "u8"
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
                // Line comment.
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
}
