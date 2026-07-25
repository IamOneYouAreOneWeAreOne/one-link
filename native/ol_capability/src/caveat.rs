//! Caveats — typed predicates on the runtime context.

use crate::context::Context;
use crate::error::CapError;

/// Maximum number of operation names accepted in one `OperationIn` caveat.
///
/// A capability's entire wire representation is already capped at 8 KiB, but
/// the nested count is attacker controlled.  Keeping an explicit semantic
/// bound prevents a compact payload containing empty operation names from
/// amplifying into thousands of heap allocations during decode.
pub const MAX_OPERATION_NAMES: usize = 256;

/// Tag bytes for the wire encoding of each caveat kind. Stable; new
/// kinds get new tags (don't reuse).
mod tag {
    pub(super) const EXPIRES_AT: u8 = 0x01;
    pub(super) const PEER_FINGERPRINT: u8 = 0x02;
    pub(super) const PATH_PREFIX: u8 = 0x03;
    pub(super) const OPERATION_IN: u8 = 0x04;
    pub(super) const AUDIT_TAG: u8 = 0x05;
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
    /// Validate locally constructed caveat data before it can influence an
    /// allocation or enter a capability signature chain.
    pub(crate) fn validate_for_wire(&self) -> Result<(), CapError> {
        let body_len = match self {
            Self::ExpiresAt(_) => 8,
            Self::PeerFingerprint(_) => 32,
            Self::PathPrefix(prefix) => {
                if prefix.is_empty() {
                    return Err(CapError::ResourceLimit {
                        reason: "PathPrefix must not be empty",
                    });
                }
                prefix.len()
            }
            Self::OperationIn(ops) => {
                if ops.len() > MAX_OPERATION_NAMES {
                    return Err(CapError::ResourceLimit {
                        reason: "OperationIn count exceeds MAX_OPERATION_NAMES",
                    });
                }
                let mut len = 4usize;
                for op in ops {
                    if op.is_empty() {
                        return Err(CapError::ResourceLimit {
                            reason: "OperationIn names must not be empty",
                        });
                    }
                    len = len
                        .checked_add(4)
                        .and_then(|n| n.checked_add(op.len()))
                        .ok_or(CapError::ResourceLimit {
                            reason: "OperationIn encoded length overflow",
                        })?;
                }
                len
            }
            Self::AuditTag(tag) => tag.len(),
        };
        if u32::try_from(body_len).is_err() {
            return Err(CapError::ResourceLimit {
                reason: "caveat body exceeds u32 wire length",
            });
        }
        Ok(())
    }

    pub(crate) fn encoded_len(&self) -> Result<usize, CapError> {
        self.validate_for_wire()?;
        let body_len = match self {
            Self::ExpiresAt(_) => 8,
            Self::PeerFingerprint(_) => 32,
            Self::PathPrefix(prefix) | Self::AuditTag(prefix) => prefix.len(),
            Self::OperationIn(ops) => ops.iter().try_fold(4usize, |len, op| {
                len.checked_add(4)
                    .and_then(|n| n.checked_add(op.len()))
                    .ok_or(CapError::ResourceLimit {
                        reason: "OperationIn encoded length overflow",
                    })
            })?,
        };
        5usize.checked_add(body_len).ok_or(CapError::ResourceLimit {
            reason: "caveat encoded length overflow",
        })
    }

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
                out.extend_from_slice(&u32::try_from(b.len()).unwrap_or(u32::MAX).to_le_bytes());
                out.extend_from_slice(b);
                out
            }
            Self::OperationIn(ops) => {
                // Encoded as: count u32 LE, then each op as len u32 + bytes.
                let mut body = Vec::new();
                body.extend_from_slice(&u32::try_from(ops.len()).unwrap_or(u32::MAX).to_le_bytes());
                for op in ops {
                    let b = op.as_bytes();
                    body.extend_from_slice(
                        &u32::try_from(b.len()).unwrap_or(u32::MAX).to_le_bytes(),
                    );
                    body.extend_from_slice(b);
                }
                let mut out = Vec::with_capacity(1 + 4 + body.len());
                out.push(tag::OPERATION_IN);
                out.extend_from_slice(&u32::try_from(body.len()).unwrap_or(u32::MAX).to_le_bytes());
                out.extend_from_slice(&body);
                out
            }
            Self::AuditTag(t) => {
                let b = t.as_bytes();
                let mut out = Vec::with_capacity(1 + 4 + b.len());
                out.push(tag::AUDIT_TAG);
                out.extend_from_slice(&u32::try_from(b.len()).unwrap_or(u32::MAX).to_le_bytes());
                out.extend_from_slice(b);
                out
            }
        }
    }

    /// Decode a single caveat from `buf`. Returns the caveat + the
    /// number of bytes consumed.
    #[allow(clippy::too_many_lines)] // One bounded, linear parser keeps cursor invariants local.
    pub(crate) fn decode(buf: &[u8]) -> Result<(Self, usize), CapError> {
        if buf.len() < 5 {
            return Err(CapError::Malformed {
                reason: "caveat header < 5 bytes",
            });
        }
        let tag_byte = buf[0];
        // External audit 2026-05-18 ES-31: each `.expect("4 bytes")` here
        // was unreachable given the bounds checks above, but a remote
        // decoder must NEVER panic — a panic in this path converts to
        // a measurable latency spike under flood (and on some runtimes
        // a worker-thread crash). `?`-propagated Malformed errors are
        // uniform with the rest of this decoder.
        let len_bytes: [u8; 4] = buf[1..5].try_into().map_err(|_| CapError::Malformed {
            reason: "caveat length field not 4 bytes",
        })?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        let body_end = 5usize.checked_add(len).ok_or(CapError::Malformed {
            reason: "caveat length overflows address space",
        })?;
        if buf.len() < body_end {
            return Err(CapError::Malformed {
                reason: "caveat truncated",
            });
        }
        let body = &buf[5..body_end];
        let caveat = match tag_byte {
            tag::EXPIRES_AT => {
                if body.len() != 8 {
                    return Err(CapError::Malformed {
                        reason: "ExpiresAt body != 8 bytes",
                    });
                }
                let ms_bytes: [u8; 8] = body.try_into().map_err(|_| CapError::Malformed {
                    reason: "ExpiresAt body not 8 bytes (bounds invariant violated)",
                })?;
                Self::ExpiresAt(u64::from_le_bytes(ms_bytes))
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
                let count_bytes: [u8; 4] =
                    body[..4].try_into().map_err(|_| CapError::Malformed {
                        reason: "OperationIn count field not 4 bytes",
                    })?;
                let count = u32::from_le_bytes(count_bytes) as usize;
                // Every encoded entry needs at least its four-byte length
                // field.  Prove the declared count can fit in this body
                // *before* using it as a Vec capacity.  This ordering is a
                // security invariant: a 137-byte fuzz input previously made
                // Vec::with_capacity attempt an allocation of about 100 GiB.
                let structurally_possible = (body.len() - 4) / 4;
                if count > structurally_possible {
                    return Err(CapError::Malformed {
                        reason: "OperationIn count exceeds encoded body",
                    });
                }
                if count > MAX_OPERATION_NAMES {
                    return Err(CapError::Malformed {
                        reason: "OperationIn count exceeds MAX_OPERATION_NAMES",
                    });
                }
                let mut ops = Vec::with_capacity(count);
                let mut cursor = 4usize;
                for _ in 0..count {
                    let length_end = cursor.checked_add(4).ok_or(CapError::Malformed {
                        reason: "OperationIn entry length overflows address space",
                    })?;
                    if body.len() < length_end {
                        return Err(CapError::Malformed {
                            reason: "OperationIn entry truncated",
                        });
                    }
                    let entry_len_bytes: [u8; 4] =
                        body[cursor..length_end]
                            .try_into()
                            .map_err(|_| CapError::Malformed {
                                reason: "OperationIn entry length not 4 bytes",
                            })?;
                    let l = u32::from_le_bytes(entry_len_bytes) as usize;
                    cursor = length_end;
                    let entry_end = cursor.checked_add(l).ok_or(CapError::Malformed {
                        reason: "OperationIn entry body length overflows address space",
                    })?;
                    if body.len() < entry_end {
                        return Err(CapError::Malformed {
                            reason: "OperationIn entry body truncated",
                        });
                    }
                    let s = std::str::from_utf8(&body[cursor..entry_end]).map_err(|_| {
                        CapError::Malformed {
                            reason: "OperationIn entry not UTF-8",
                        }
                    })?;
                    ops.push(s.to_string());
                    cursor = entry_end;
                }
                if cursor != body.len() {
                    return Err(CapError::Malformed {
                        reason: "OperationIn body has trailing bytes",
                    });
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
        Ok((caveat, body_end))
    }

    /// Evaluate this caveat against `ctx`. Returns `Ok(())` if the
    /// caveat permits the context; `Err` with a static reason otherwise.
    pub(crate) fn check(&self, ctx: &Context) -> Result<(), &'static str> {
        match self {
            Self::ExpiresAt(ms) => {
                if let Some(now) = ctx.now_unix_ms {
                    // Audit L9 May 2026: tightened to `>=`. A cap with
                    // `not_after_ms == now` was previously still
                    // valid for the exact millisecond it expired;
                    // inconsistent with `not_before_ms`'s strict `<`
                    // and with caps_grants.py's `>= not_after_ms`
                    // semantics. Symmetric strict-boundary handling
                    // is least-surprise.
                    if now >= *ms {
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
                    if !path_is_within_prefix(path, p) {
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

/// Segment-aware lexical prefix check.  Callers should still provide
/// canonical resource paths, but this layer fails closed on dot-segments and
/// prevents `/safe` from authorizing `/safety` or `/safe/../escape`.
fn path_is_within_prefix(path: &str, prefix: &str) -> bool {
    if prefix.is_empty()
        || path
            .split(['/', '\\'])
            .any(|segment| matches!(segment, "." | ".."))
        || prefix
            .split(['/', '\\'])
            .any(|segment| matches!(segment, "." | ".."))
    {
        return false;
    }
    if path == prefix {
        return true;
    }
    let Some(rest) = path.strip_prefix(prefix) else {
        return false;
    };
    prefix.ends_with(['/', '\\']) || rest.starts_with(['/', '\\'])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation_in_body(body: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(5 + body.len());
        encoded.push(tag::OPERATION_IN);
        encoded.extend_from_slice(&u32::try_from(body.len()).unwrap_or(u32::MAX).to_le_bytes());
        encoded.extend_from_slice(body);
        encoded
    }

    #[test]
    fn operation_count_must_fit_before_allocation() {
        // Regression for nightly fuzz crash 2d52b3564a26e2971f552534b63e5b130d048643:
        // an attacker-controlled count used to flow directly into
        // Vec::with_capacity and request an allocation of roughly 100 GiB.
        let encoded = operation_in_body(&u32::MAX.to_le_bytes());
        assert!(matches!(
            Caveat::decode(&encoded),
            Err(CapError::Malformed {
                reason: "OperationIn count exceeds encoded body"
            })
        ));
    }

    #[test]
    fn operation_count_has_a_semantic_resource_bound() {
        let count = MAX_OPERATION_NAMES + 1;
        let mut body = Vec::with_capacity(4 + count * 4);
        body.extend_from_slice(&u32::try_from(count).unwrap_or(u32::MAX).to_le_bytes());
        for _ in 0..count {
            body.extend_from_slice(&0u32.to_le_bytes());
        }
        let encoded = operation_in_body(&body);
        assert!(matches!(
            Caveat::decode(&encoded),
            Err(CapError::Malformed {
                reason: "OperationIn count exceeds MAX_OPERATION_NAMES"
            })
        ));
    }

    #[test]
    fn operation_body_must_be_canonical() {
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.push(0xAA);
        let encoded = operation_in_body(&body);
        assert!(matches!(
            Caveat::decode(&encoded),
            Err(CapError::Malformed {
                reason: "OperationIn body has trailing bytes"
            })
        ));
    }

    #[test]
    fn path_prefix_is_segment_aware_and_traversal_safe() {
        let caveat = Caveat::PathPrefix("/safe".to_string());
        assert!(caveat
            .check(&Context::new().with_path("/safe/file"))
            .is_ok());
        assert!(caveat.check(&Context::new().with_path("/safe")).is_ok());
        assert!(caveat
            .check(&Context::new().with_path("/safety/file"))
            .is_err());
        assert!(caveat
            .check(&Context::new().with_path("/safe/../escape"))
            .is_err());
    }
}
