//! Wire encoding for Kademlia RPC envelopes.
//!
//! Compact, hand-rolled, no external serialization dep. Format:
//!
//! ```text
//! +--------+---------+----------+-----------+----------------+
//! | magic  | version | kind tag | sender id | nonce          |
//! | "OLD1" | 1 byte  | 1 byte   | 32 bytes  | 16 bytes       |
//! +--------+---------+----------+-----------+----------------+
//! | timestamp_unix (8 bytes BE) | body (kind-specific)        |
//! +----------------------------+-----------------------------+
//! ```
//!
//! Kind tags:
//!   0x01 Ping       0x81 Pong
//!   0x02 Store      0x82 StoreResult
//!   0x04 FindNode   0x84 FindNodeResult
//!   0x08 FindValue  0x88 FindValueResult
//!
//! Bodies:
//!   - Ping / Pong: empty
//!   - Store: SignedRecord encoding (4-byte u32 length + record
//!     canonical_bytes + 64-byte signature)
//!   - StoreResult: 1 byte outcome code
//!   - FindNode / FindValue: 32-byte target
//!   - FindNodeResult: 1-byte count + N × 32-byte NodeIds
//!   - FindValueResult:
//!     - `0x01 + signed-record-bytes` (Found)
//!     - `0x02 + 1-byte count + N×32` (Closer)

use thiserror::Error;

use crate::node_id::NodeId;
use crate::record::{PeerRecord, SignedRecord};
use crate::rpc::{
    FindValueOutcome, Header, Nonce, Request, Response, RpcEnvelope, StoreOutcome, MAX_FIND_RESULTS,
};

/// Wire-format magic. Disambiguates from other UDP traffic on the
/// same port and forms the first bytes of every envelope.
pub const WIRE_MAGIC: [u8; 4] = *b"OLD1";

/// Wire protocol version. Increment on any breaking format change.
pub const WIRE_VERSION: u8 = 1;

const TAG_PING: u8 = 0x01;
const TAG_PONG: u8 = 0x81;
const TAG_STORE: u8 = 0x02;
const TAG_STORE_RESULT: u8 = 0x82;
const TAG_FIND_NODE: u8 = 0x04;
const TAG_FIND_NODE_RESULT: u8 = 0x84;
const TAG_FIND_VALUE: u8 = 0x08;
const TAG_FIND_VALUE_RESULT: u8 = 0x88;

const STORE_RESULT_ACCEPTED: u8 = 0x00;
const STORE_RESULT_BAD_SIGNATURE: u8 = 0x01;
const STORE_RESULT_EXPIRED: u8 = 0x02;
const STORE_RESULT_PUBLISHER_MISMATCH: u8 = 0x03;
const STORE_RESULT_RATE_LIMITED: u8 = 0x04;

const FIND_VALUE_FOUND: u8 = 0x01;
const FIND_VALUE_CLOSER: u8 = 0x02;

/// Sanity cap to defeat DoS via huge payloads. UDP datagrams are
/// typically ≤1500 bytes anyway; we allow a bit more for IPv6
/// jumbograms but reject anything wildly out of profile.
pub const MAX_WIRE_BYTES: usize = 4096;

/// Wire encode / decode errors.
#[derive(Debug, Error, PartialEq)]
pub enum WireError {
    /// Encoded payload exceeds [`MAX_WIRE_BYTES`].
    #[error("encoded payload exceeds {MAX_WIRE_BYTES} bytes (was {got})")]
    TooLarge {
        /// Encoded length.
        got: usize,
    },
    /// Buffer too short to decode the expected structure.
    #[error("truncated: need {need} more bytes")]
    Truncated {
        /// How many bytes the decoder needed.
        need: usize,
    },
    /// Wire magic doesn't match [`WIRE_MAGIC`].
    #[error("wire magic mismatch")]
    BadMagic,
    /// Version not supported by this binary.
    #[error("unsupported wire version: {got}")]
    BadVersion {
        /// Version byte.
        got: u8,
    },
    /// Unknown kind tag.
    #[error("unknown kind tag: 0x{got:02x}")]
    BadTag {
        /// The tag we saw.
        got: u8,
    },
    /// List count exceeds [`MAX_FIND_RESULTS`].
    #[error("response list too long: {got} (max {max})")]
    ListTooLong {
        /// Actual.
        got: usize,
        /// Max permitted.
        max: usize,
    },
}

/// Encode a request envelope to a UDP-ready byte buffer.
///
/// # Errors
/// [`WireError::TooLarge`] if the encoded result exceeds [`MAX_WIRE_BYTES`].
pub fn encode_request(env: &RpcEnvelope<Request>) -> Result<Vec<u8>, WireError> {
    let mut out = Vec::with_capacity(64);
    write_header(&mut out, &env.header, request_tag(&env.body));
    encode_request_body(&mut out, &env.body);
    bounds_check(&out)?;
    Ok(out)
}

/// Encode a response envelope to a UDP-ready byte buffer.
///
/// # Errors
/// [`WireError::TooLarge`] / [`WireError::ListTooLong`].
pub fn encode_response(env: &RpcEnvelope<Response>) -> Result<Vec<u8>, WireError> {
    let mut out = Vec::with_capacity(64);
    write_header(&mut out, &env.header, response_tag(&env.body));
    encode_response_body(&mut out, &env.body)?;
    bounds_check(&out)?;
    Ok(out)
}

/// Decode either kind of envelope from raw bytes. Returns the parsed
/// header + a kind-tagged body so callers can dispatch on the type.
///
/// # Errors
/// Any [`WireError`] variant.
pub fn decode(bytes: &[u8]) -> Result<DecodedEnvelope, WireError> {
    let mut c = Cursor::new(bytes);
    let magic = c.take(4)?;
    if magic != WIRE_MAGIC {
        return Err(WireError::BadMagic);
    }
    let version = c.take_byte()?;
    if version != WIRE_VERSION {
        return Err(WireError::BadVersion { got: version });
    }
    let tag = c.take_byte()?;
    let sender = NodeId::from_bytes(<[u8; 32]>::try_from(c.take(32)?).expect("32"));
    let mut nonce: Nonce = [0u8; 16];
    nonce.copy_from_slice(c.take(16)?);
    let ts_bytes: [u8; 8] = c.take(8)?.try_into().expect("8");
    let timestamp_unix = u64::from_be_bytes(ts_bytes);
    let header = Header {
        sender,
        nonce,
        timestamp_unix,
    };
    match tag {
        TAG_PING => Ok(DecodedEnvelope::Request(RpcEnvelope {
            header,
            body: Request::Ping,
        })),
        TAG_PONG => Ok(DecodedEnvelope::Response(RpcEnvelope {
            header,
            body: Response::Pong,
        })),
        TAG_FIND_NODE => {
            let target = NodeId::from_bytes(<[u8; 32]>::try_from(c.take(32)?).expect("32"));
            Ok(DecodedEnvelope::Request(RpcEnvelope {
                header,
                body: Request::FindNode { target },
            }))
        }
        TAG_FIND_VALUE => {
            let target = NodeId::from_bytes(<[u8; 32]>::try_from(c.take(32)?).expect("32"));
            Ok(DecodedEnvelope::Request(RpcEnvelope {
                header,
                body: Request::FindValue { target },
            }))
        }
        TAG_FIND_NODE_RESULT => {
            let closest = decode_id_list(&mut c)?;
            Ok(DecodedEnvelope::Response(RpcEnvelope {
                header,
                body: Response::FindNodeResult { closest },
            }))
        }
        TAG_FIND_VALUE_RESULT => {
            let sub = c.take_byte()?;
            match sub {
                FIND_VALUE_FOUND => {
                    let rec = decode_signed_record(&mut c)?;
                    Ok(DecodedEnvelope::Response(RpcEnvelope {
                        header,
                        body: Response::FindValueResult(FindValueOutcome::Found(rec)),
                    }))
                }
                FIND_VALUE_CLOSER => {
                    let closer = decode_id_list(&mut c)?;
                    Ok(DecodedEnvelope::Response(RpcEnvelope {
                        header,
                        body: Response::FindValueResult(FindValueOutcome::Closer(closer)),
                    }))
                }
                other => Err(WireError::BadTag { got: other }),
            }
        }
        TAG_STORE => {
            let rec = decode_signed_record(&mut c)?;
            Ok(DecodedEnvelope::Request(RpcEnvelope {
                header,
                body: Request::Store(rec),
            }))
        }
        TAG_STORE_RESULT => {
            let code = c.take_byte()?;
            let outcome = match code {
                STORE_RESULT_ACCEPTED => StoreOutcome::Accepted,
                STORE_RESULT_BAD_SIGNATURE => StoreOutcome::BadSignature,
                STORE_RESULT_EXPIRED => StoreOutcome::Expired,
                STORE_RESULT_PUBLISHER_MISMATCH => StoreOutcome::PublisherMismatch,
                STORE_RESULT_RATE_LIMITED => StoreOutcome::RateLimited,
                other => return Err(WireError::BadTag { got: other }),
            };
            Ok(DecodedEnvelope::Response(RpcEnvelope {
                header,
                body: Response::StoreResult(outcome),
            }))
        }
        other => Err(WireError::BadTag { got: other }),
    }
}

/// Decoded envelope — caller dispatches based on whether body is a
/// Request or a Response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodedEnvelope {
    /// Inbound request.
    Request(RpcEnvelope<Request>),
    /// Inbound response (to a pending request).
    Response(RpcEnvelope<Response>),
}

// ── encoding helpers ─────────────────────────────────────────────

fn write_header(out: &mut Vec<u8>, h: &Header, tag: u8) {
    out.extend_from_slice(&WIRE_MAGIC);
    out.push(WIRE_VERSION);
    out.push(tag);
    out.extend_from_slice(h.sender.as_bytes());
    out.extend_from_slice(&h.nonce);
    out.extend_from_slice(&h.timestamp_unix.to_be_bytes());
}

fn encode_request_body(out: &mut Vec<u8>, body: &Request) {
    match body {
        Request::Ping => {}
        Request::Store(rec) => encode_signed_record(out, rec),
        Request::FindNode { target } | Request::FindValue { target } => {
            out.extend_from_slice(target.as_bytes());
        }
    }
}

fn encode_response_body(out: &mut Vec<u8>, body: &Response) -> Result<(), WireError> {
    match body {
        Response::Pong => {}
        Response::StoreResult(outcome) => {
            let code = match outcome {
                StoreOutcome::Accepted => STORE_RESULT_ACCEPTED,
                StoreOutcome::BadSignature => STORE_RESULT_BAD_SIGNATURE,
                StoreOutcome::Expired => STORE_RESULT_EXPIRED,
                StoreOutcome::PublisherMismatch => STORE_RESULT_PUBLISHER_MISMATCH,
                StoreOutcome::RateLimited => STORE_RESULT_RATE_LIMITED,
            };
            out.push(code);
        }
        Response::FindNodeResult { closest } => {
            encode_id_list(out, closest)?;
        }
        Response::FindValueResult(FindValueOutcome::Found(rec)) => {
            out.push(FIND_VALUE_FOUND);
            encode_signed_record(out, rec);
        }
        Response::FindValueResult(FindValueOutcome::Closer(closer)) => {
            out.push(FIND_VALUE_CLOSER);
            encode_id_list(out, closer)?;
        }
    }
    Ok(())
}

fn encode_signed_record(out: &mut Vec<u8>, rec: &SignedRecord) {
    let body_bytes = rec.record.canonical_bytes();
    let len = body_bytes.len() as u32;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&body_bytes);
    out.extend_from_slice(&rec.signature);
}

fn encode_id_list(out: &mut Vec<u8>, ids: &[NodeId]) -> Result<(), WireError> {
    if ids.len() > MAX_FIND_RESULTS {
        return Err(WireError::ListTooLong {
            got: ids.len(),
            max: MAX_FIND_RESULTS,
        });
    }
    out.push(ids.len() as u8);
    for id in ids {
        out.extend_from_slice(id.as_bytes());
    }
    Ok(())
}

fn decode_id_list(c: &mut Cursor) -> Result<Vec<NodeId>, WireError> {
    let count = c.take_byte()?;
    let count = count as usize;
    if count > MAX_FIND_RESULTS {
        return Err(WireError::ListTooLong {
            got: count,
            max: MAX_FIND_RESULTS,
        });
    }
    let mut ids = Vec::with_capacity(count);
    for _ in 0..count {
        let id_bytes: [u8; 32] = c.take(32)?.try_into().expect("32");
        ids.push(NodeId::from_bytes(id_bytes));
    }
    Ok(ids)
}

fn decode_signed_record(c: &mut Cursor) -> Result<SignedRecord, WireError> {
    let len_bytes: [u8; 4] = c.take(4)?.try_into().expect("4");
    let body_len = u32::from_be_bytes(len_bytes) as usize;
    let body_bytes = c.take(body_len)?.to_vec();
    let sig_bytes: [u8; 64] = c.take(64)?.try_into().expect("64");
    let record = parse_canonical_record(&body_bytes)?;
    Ok(SignedRecord {
        record,
        signature: sig_bytes,
    })
}

fn parse_canonical_record(bytes: &[u8]) -> Result<PeerRecord, WireError> {
    // Mirror PeerRecord::canonical_bytes encoding:
    //   "OLR1" + 32B pubkey + 8B publish + 8B ttl + 2B n_eps + endpoints
    let mut c = Cursor::new(bytes);
    let magic = c.take(4)?;
    if magic != b"OLR1" {
        return Err(WireError::BadMagic);
    }
    let pk: [u8; 32] = c.take(32)?.try_into().expect("32");
    let publish_bytes: [u8; 8] = c.take(8)?.try_into().expect("8");
    let ttl_bytes: [u8; 8] = c.take(8)?.try_into().expect("8");
    let n_eps_bytes: [u8; 2] = c.take(2)?.try_into().expect("2");
    let n_eps = u16::from_be_bytes(n_eps_bytes) as usize;
    let mut endpoints = Vec::with_capacity(n_eps);
    for _ in 0..n_eps {
        let len_bytes: [u8; 2] = c.take(2)?.try_into().expect("2");
        let ep_len = u16::from_be_bytes(len_bytes) as usize;
        let ep_bytes = c.take(ep_len)?;
        endpoints.push(
            String::from_utf8(ep_bytes.to_vec()).map_err(|_| WireError::BadTag { got: 0xFF })?,
        );
    }
    Ok(PeerRecord {
        publisher_pubkey: pk,
        endpoints,
        publish_time_unix: u64::from_be_bytes(publish_bytes),
        ttl_secs: u64::from_be_bytes(ttl_bytes),
    })
}

fn request_tag(body: &Request) -> u8 {
    match body {
        Request::Ping => TAG_PING,
        Request::Store(_) => TAG_STORE,
        Request::FindNode { .. } => TAG_FIND_NODE,
        Request::FindValue { .. } => TAG_FIND_VALUE,
    }
}

fn response_tag(body: &Response) -> u8 {
    match body {
        Response::Pong => TAG_PONG,
        Response::StoreResult(_) => TAG_STORE_RESULT,
        Response::FindNodeResult { .. } => TAG_FIND_NODE_RESULT,
        Response::FindValueResult(_) => TAG_FIND_VALUE_RESULT,
    }
}

fn bounds_check(buf: &[u8]) -> Result<(), WireError> {
    if buf.len() > MAX_WIRE_BYTES {
        Err(WireError::TooLarge { got: buf.len() })
    } else {
        Ok(())
    }
}

// ── tiny cursor (avoids pulling bytes / nom) ──────────────────────

struct Cursor<'a> {
    buf: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.buf.len() < n {
            return Err(WireError::Truncated {
                need: n - self.buf.len(),
            });
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }
    fn take_byte(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> NodeId {
        NodeId([b; 32])
    }

    fn hdr() -> Header {
        Header::new(id(0xAA), [0x42; 16], 1_700_000_000)
    }

    #[test]
    fn ping_roundtrip() {
        let env = RpcEnvelope {
            header: hdr(),
            body: Request::Ping,
        };
        let bytes = encode_request(&env).unwrap();
        let dec = decode(&bytes).unwrap();
        match dec {
            DecodedEnvelope::Request(r) => assert_eq!(r, env),
            DecodedEnvelope::Response(_) => panic!("wrong type"),
        }
    }

    #[test]
    fn pong_roundtrip() {
        let env = RpcEnvelope {
            header: hdr(),
            body: Response::Pong,
        };
        let bytes = encode_response(&env).unwrap();
        let dec = decode(&bytes).unwrap();
        match dec {
            DecodedEnvelope::Response(r) => assert_eq!(r, env),
            DecodedEnvelope::Request(_) => panic!("wrong type"),
        }
    }

    #[test]
    fn find_node_roundtrip() {
        let env = RpcEnvelope {
            header: hdr(),
            body: Request::FindNode { target: id(0x99) },
        };
        let bytes = encode_request(&env).unwrap();
        let dec = decode(&bytes).unwrap();
        match dec {
            DecodedEnvelope::Request(r) => assert_eq!(r, env),
            _ => panic!(),
        }
    }

    #[test]
    fn find_node_result_roundtrip() {
        let env = RpcEnvelope {
            header: hdr(),
            body: Response::FindNodeResult {
                closest: vec![id(1), id(2), id(3)],
            },
        };
        let bytes = encode_response(&env).unwrap();
        let dec = decode(&bytes).unwrap();
        match dec {
            DecodedEnvelope::Response(r) => assert_eq!(r, env),
            _ => panic!(),
        }
    }

    #[test]
    fn find_value_closer_roundtrip() {
        let env = RpcEnvelope {
            header: hdr(),
            body: Response::FindValueResult(FindValueOutcome::Closer(vec![id(7), id(8)])),
        };
        let bytes = encode_response(&env).unwrap();
        let dec = decode(&bytes).unwrap();
        match dec {
            DecodedEnvelope::Response(r) => assert_eq!(r, env),
            _ => panic!(),
        }
    }

    #[test]
    fn store_result_roundtrip_all_outcomes() {
        for outcome in [
            StoreOutcome::Accepted,
            StoreOutcome::BadSignature,
            StoreOutcome::Expired,
            StoreOutcome::PublisherMismatch,
            StoreOutcome::RateLimited,
        ] {
            let env = RpcEnvelope {
                header: hdr(),
                body: Response::StoreResult(outcome.clone()),
            };
            let bytes = encode_response(&env).unwrap();
            let dec = decode(&bytes).unwrap();
            match dec {
                DecodedEnvelope::Response(r) => assert_eq!(r, env),
                _ => panic!(),
            }
        }
    }

    #[test]
    fn bad_magic_rejected() {
        let mut bytes = vec![0u8; 64];
        bytes[0..4].copy_from_slice(b"XXXX");
        assert_eq!(decode(&bytes).unwrap_err(), WireError::BadMagic);
    }

    #[test]
    fn truncated_rejected() {
        let env = RpcEnvelope {
            header: hdr(),
            body: Request::FindNode { target: id(0x99) },
        };
        let bytes = encode_request(&env).unwrap();
        // Slice off the target.
        let trunc = &bytes[..bytes.len() - 16];
        let err = decode(trunc).unwrap_err();
        assert!(matches!(err, WireError::Truncated { .. }));
    }

    #[test]
    fn unknown_tag_rejected() {
        let mut bytes = vec![0u8; 64];
        bytes[0..4].copy_from_slice(&WIRE_MAGIC);
        bytes[4] = WIRE_VERSION;
        bytes[5] = 0x7F; // unknown tag
        assert!(matches!(
            decode(&bytes).unwrap_err(),
            WireError::BadTag { .. }
        ));
    }

    #[test]
    fn oversized_list_rejected_at_encode() {
        let env = RpcEnvelope {
            header: hdr(),
            body: Response::FindNodeResult {
                closest: vec![id(0); MAX_FIND_RESULTS + 1],
            },
        };
        let err = encode_response(&env).unwrap_err();
        assert!(matches!(err, WireError::ListTooLong { .. }));
    }

    #[test]
    fn signed_record_roundtrip() {
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let rec = PeerRecord {
            publisher_pubkey: sk.verifying_key().to_bytes(),
            endpoints: vec!["udp://1.2.3.4:5".into(), "quic://x:9".into()],
            publish_time_unix: 1_700_000_000,
            ttl_secs: 86_400,
        };
        let signed = SignedRecord::sign(rec, &sk).unwrap();
        let env = RpcEnvelope {
            header: hdr(),
            body: Request::Store(signed.clone()),
        };
        let bytes = encode_request(&env).unwrap();
        let dec = decode(&bytes).unwrap();
        match dec {
            DecodedEnvelope::Request(r) => {
                if let Request::Store(decoded_signed) = r.body {
                    // Round-tripped record verifies (signature preserved).
                    decoded_signed.verify().unwrap();
                    assert_eq!(decoded_signed, signed);
                } else {
                    panic!();
                }
            }
            _ => panic!(),
        }
    }
}
