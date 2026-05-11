//! Caveats — typed predicates on the runtime context.

use crate::context::Context;
use crate::error::CapError;

/// Tag bytes for the wire encoding of each caveat kind. Stable; new
/// kinds get new tags (don't reuse).
mod tag {
    pub const EXPIRES_AT: u8 = 0x01;
    pub const PEER_FINGERPRINT: u8 = 0x02;
    pub const PATH_PREFIX: u8 = 0x03;
    pub const OPERATION_IN: u8 = 0x04;
    pub const AUDIT_TAG: u8 = 0x05;
}

/// A single caveat. Caveats compose: a capability's permission is the
/// AND of all its caveats.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum Caveat {
    /// Cap is valid until this absolute Unix-ms timestamp.
    ExpiresAt(u64),
    /// Cap is bound to a specific peer fingerprint.
    PeerFingerprint([u8; 32]),
    /// Cap restricts operations to paths starting with this prefix.
    PathPrefix(String),
    /// Operation must be one of these names.
    OperationIn(Vec<String>),
    /// Audit tag — doesn't restrict; logged on every use to identify
    /// the delegation chain.
    AuditTag(String),
}

impl Caveat {
    /// Wire encoding: `[tag: u8][len: u32 LE][bytes]`.
    pub(crate) fn encode(&self) -> Vec<u8> {
        match self {
            Self::ExpiresAt(ms) => {
                let mut out = Vec::with_capacity(1 + 4 + 8);
                out.push(tag::EXPIRES_AT);
                out.extend_from_slice(&8u32.to_le_bytes());
                out.extend_from_slice(&ms.to_le_bytes());
                out
            }
            Self::PeerFingerprint(fp) => {
                let mut out = Vec::with_capacity(1 + 4 + 32);
                out.push(tag::PEER_FINGERPRINT);
                out.extend_from_slice(&32u32.to_le_bytes());
                out.extend_from_slice(fp);
                out
            }
            Self::PathPrefix(p) => {
                let b = p.as_bytes();
                let mut out = Vec::with_capacity(1 + 4 + b.len());
                out.push(tag::PATH_PREFIX);
                out.extend_from_slice(&(b.len() as u32).to_le_bytes());
                out.extend_from_slice(b);
                out
            }
            Self::OperationIn(ops) => {
                // Encoded as: count u32 LE, then each op as len u32 + bytes.
                let mut body = Vec::new();
                body.extend_from_slice(&(ops.len() as u32).to_le_bytes());
                for op in ops {
                    let b = op.as_bytes();
                    body.extend_from_slice(&(b.len() as u32).to_le_bytes());
                    body.extend_from_slice(b);
                }
                let mut out = Vec::with_capacity(1 + 4 + body.len());
                out.push(tag::OPERATION_IN);
                out.extend_from_slice(&(body.len() as u32).to_le_bytes());
                out.extend_from_slice(&body);
                out
            }
            Self::AuditTag(t) => {
                let b = t.as_bytes();
                let mut out = Vec::with_capacity(1 + 4 + b.len());
                out.push(tag::AUDIT_TAG);
                out.extend_from_slice(&(b.len() as u32).to_le_bytes());
                out.extend_from_slice(b);
                out
            }
        }
    }

    /// Decode a single caveat from `buf`. Returns the caveat + the
    /// number of bytes consumed.
    pub(crate) fn decode(buf: &[u8]) -> Result<(Self, usize), CapError> {
        if buf.len() < 5 {
            return Err(CapError::Malformed {
                reason: "caveat header < 5 bytes",
            });
        }
        let tag_byte = buf[0];
        let len = u32::from_le_bytes(buf[1..5].try_into().expect("4 bytes")) as usize;
        if buf.len() < 5 + len {
            return Err(CapError::Malformed {
                reason: "caveat truncated",
            });
        }
        let body = &buf[5..5 + len];
        let caveat = match tag_byte {
            tag::EXPIRES_AT => {
                if body.len() != 8 {
                    return Err(CapError::Malformed {
                        reason: "ExpiresAt body != 8 bytes",
                    });
                }
                let ms = u64::from_le_bytes(body.try_into().expect("8 bytes"));
                Self::ExpiresAt(ms)
            }
            tag::PEER_FINGERPRINT => {
                if body.len() != 32 {
                    return Err(CapError::Malformed {
                        reason: "PeerFingerprint body != 32 bytes",
                    });
                }
                let mut fp = [0u8; 32];
                fp.copy_from_slice(body);
                Self::PeerFingerprint(fp)
            }
            tag::PATH_PREFIX => {
                let s = std::str::from_utf8(body).map_err(|_| CapError::Malformed {
                    reason: "PathPrefix body not UTF-8",
                })?;
                Self::PathPrefix(s.to_string())
            }
            tag::OPERATION_IN => {
                if body.len() < 4 {
                    return Err(CapError::Malformed {
                        reason: "OperationIn header < 4 bytes",
                    });
                }
                let count = u32::from_le_bytes(body[..4].try_into().expect("4 bytes")) as usize;
                let mut ops = Vec::with_capacity(count);
                let mut cursor = 4usize;
                for _ in 0..count {
                    if body.len() < cursor + 4 {
                        return Err(CapError::Malformed {
                            reason: "OperationIn entry truncated",
                        });
                    }
                    let l =
                        u32::from_le_bytes(body[cursor..cursor + 4].try_into().expect("4 bytes"))
                            as usize;
                    cursor += 4;
                    if body.len() < cursor + l {
                        return Err(CapError::Malformed {
                            reason: "OperationIn entry body truncated",
                        });
                    }
                    let s = std::str::from_utf8(&body[cursor..cursor + l]).map_err(|_| {
                        CapError::Malformed {
                            reason: "OperationIn entry not UTF-8",
                        }
                    })?;
                    ops.push(s.to_string());
                    cursor += l;
                }
                Self::OperationIn(ops)
            }
            tag::AUDIT_TAG => {
                let s = std::str::from_utf8(body).map_err(|_| CapError::Malformed {
                    reason: "AuditTag body not UTF-8",
                })?;
                Self::AuditTag(s.to_string())
            }
            other => return Err(CapError::UnknownCaveat { tag: other }),
        };
        Ok((caveat, 5 + len))
    }

    /// Evaluate this caveat against `ctx`. Returns `Ok(())` if the
    /// caveat permits the context; `Err` with a static reason otherwise.
    pub(crate) fn check(&self, ctx: &Context) -> Result<(), &'static str> {
        match self {
            Self::ExpiresAt(ms) => {
                if let Some(now) = ctx.now_unix_ms {
                    if now > *ms {
                        return Err("ExpiresAt: cap expired");
                    }
                } else {
                    return Err("ExpiresAt: ctx.now_unix_ms not provided");
                }
            }
            Self::PeerFingerprint(fp) => {
                if let Some(peer) = ctx.peer {
                    if &peer != fp {
                        return Err("PeerFingerprint: peer mismatch");
                    }
                } else {
                    return Err("PeerFingerprint: ctx.peer not provided");
                }
            }
            Self::PathPrefix(p) => {
                if let Some(path) = ctx.path {
                    if !path.starts_with(p.as_str()) {
                        return Err("PathPrefix: path not under prefix");
                    }
                } else {
                    return Err("PathPrefix: ctx.path not provided");
                }
            }
            Self::OperationIn(ops) => {
                if let Some(op) = ctx.operation {
                    if !ops.iter().any(|allowed| allowed == op) {
                        return Err("OperationIn: operation not in allow list");
                    }
                } else {
                    return Err("OperationIn: ctx.operation not provided");
                }
            }
            Self::AuditTag(_) => {
                // AuditTag never rejects. It's informational/logged.
            }
        }
        Ok(())
    }
}
