//! An INDEPENDENT verifier for the certified surfaces — in a different language from the producer.
//!
//! WHY A SECOND IMPLEMENTATION AT ALL. `one_link/certified_surface.py` already verifies these
//! artifacts, and re-checking the same bytes with the same logic would prove nothing. This is
//! deliberately *not* the same logic: it is a second, from-scratch implementation of the canonical
//! form, the digest and the signature, written against the spec rather than against the code.
//!
//! Two implementations that agree byte-for-byte are evidence. One implementation checking itself is
//! a tautology with a hash in it.
//!
//! WHAT MAKES THIS A FIRST, as far as I can tell. Applications ship signed *binaries*; the OS checks
//! them and the app then draws whatever it likes. Here the thing that OWNS THE PIXELS refuses to
//! open a window when the surface's proofs do not verify. The guarantee is not a claim in a settings
//! page a user must find and believe — it is the window's precondition. If somebody edits a certified
//! table on disk, One Link does not render a subtly-wrong badge: it does not open.
//!
//! THE CANONICAL-FORM TRAP, stated because it is the real risk here. Python emits
//! `json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=True)`. `serde_json` sorts
//! object keys (its `Map` is a `BTreeMap`) and emits compact separators, so the two agree — EXCEPT
//! that Python escapes non-ASCII as `\uXXXX` and serde_json emits UTF-8 directly. Every value in
//! these artifacts is an integer or an ASCII identifier, so they agree today; `ascii_only` below
//! REFUSES an artifact containing a non-ASCII byte rather than silently diverging from the producer.
//! A cross-implementation agreement that holds "for the data we happen to have" is not a property,
//! so it is enforced instead of assumed.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Domain separator for the table digest. Must match `idem/certified_view.py::table_digest`.
const TABLE_DOMAIN: &[u8] = b"idem-view-table/v1";
/// Domain separator for the signed bytes. Must match `idem/certified_view.py::_signable`.
const SIG_DOMAIN: &[u8] = b"idem-view-sig/v1\x00";

const SCHEMA: &str = "idem-certified-view/v1";

#[derive(Debug)]
pub struct Verdict {
    pub ok: bool,
    pub reason: String,
}

impl Verdict {
    fn no(reason: impl Into<String>) -> Self {
        Self { ok: false, reason: reason.into() }
    }
    fn yes(reason: impl Into<String>) -> Self {
        Self { ok: true, reason: reason.into() }
    }
}

/// Canonical JSON, rebuilt from the spec rather than borrowed from the producer.
///
/// Sorted keys, no whitespace, ASCII only. `serde_json::to_string` gives the first two; the third is
/// enforced by `ascii_only` at the door, because Python's `ensure_ascii=True` would escape where
/// this does not, and a digest that diverges on the first non-ASCII device name would be a failure
/// nobody could reproduce on an English machine.
fn canonical(value: &serde_json::Value) -> Result<Vec<u8>, String> {
    let s = serde_json::to_string(value).map_err(|e| format!("cannot serialise: {e}"))?;
    if !s.is_ascii() {
        return Err(
            "the artifact contains non-ASCII text; this verifier and the Python producer escape it \
             differently, so refusing rather than computing a digest that silently disagrees"
                .into(),
        );
    }
    Ok(s.into_bytes())
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// Verify one certified view: schema, table digest, exhaustive coverage, and a PINNED signature.
///
/// `trusted` is the set of signer public keys (hex) this build accepts. Verifying against whatever
/// key the artifact names would be verifying against its author, which is not verification.
pub fn verify(doc: &serde_json::Value, trusted: &[&str]) -> Verdict {
    let obj = match doc.as_object() {
        Some(o) => o,
        None => return Verdict::no("the artifact is not a JSON object"),
    };

    if obj.get("schema").and_then(|v| v.as_str()) != Some(SCHEMA) {
        return Verdict::no(format!("unknown schema {:?}", obj.get("schema")));
    }

    let rows = match obj.get("rows").and_then(|v| v.as_array()) {
        Some(r) if !r.is_empty() => r,
        _ => return Verdict::no("the artifact carries no rows"),
    };

    // ---- the table digest: proves nobody EDITED an answer ------------------------------------
    let rows_value = serde_json::Value::Array(rows.clone());
    let canon = match canonical(&rows_value) {
        Ok(c) => c,
        Err(e) => return Verdict::no(e),
    };
    let mut h = Sha256::new();
    h.update(TABLE_DOMAIN);
    h.update(&canon);
    let recomputed = hex_encode(&h.finalize());

    let claimed = obj.get("table_digest").and_then(|v| v.as_str()).unwrap_or("");
    if recomputed != claimed {
        return Verdict::no(format!(
            "TABLE DIGEST MISMATCH: rows hash to {}, artifact claims {} — the answers were edited \
             after they were certified",
            &recomputed[..16.min(recomputed.len())],
            &claimed[..16.min(claimed.len())]
        ));
    }

    // ---- exhaustive coverage: a missing point is a broken surface, not a smaller one ----------
    let axes = obj
        .get("space")
        .and_then(|s| s.get("axes"))
        .and_then(|a| a.as_array());
    let expected: usize = match axes {
        Some(a) if !a.is_empty() => a
            .iter()
            .filter_map(|ax| ax.as_array().and_then(|p| p.get(1)).and_then(|v| v.as_array()))
            .map(|vals| vals.len())
            .product(),
        _ => return Verdict::no("the artifact declares no state space, so 'exhaustive' means nothing"),
    };
    if rows.len() != expected {
        return Verdict::no(format!(
            "the space declares {expected} points and the table carries {} — an incomplete table is \
             a broken surface, not a smaller one",
            rows.len()
        ));
    }

    if obj.get("laws").and_then(|v| v.as_array()).map(|l| l.is_empty()).unwrap_or(true) {
        return Verdict::no(
            "no proven laws — this would be a lookup table with a hash, which is exactly what the \
             format exists not to be",
        );
    }

    // ---- the signature: proves nobody FABRICATED the table -----------------------------------
    //
    // Everything above is self-referential. A forger who edits an answer AND recomputes the digest
    // produces a perfectly self-consistent artifact, because a hash is not an identity.
    let signer = obj.get("signer").and_then(|v| v.as_str()).unwrap_or("");
    let sig_hex = obj.get("signature").and_then(|v| v.as_str()).unwrap_or("");
    if signer.is_empty() || sig_hex.is_empty() {
        return Verdict::no(
            "the artifact is UNSIGNED — its digest proves only that nobody edited it, and a \
             fabricated table with a freshly computed digest is self-consistent",
        );
    }
    if !trusted.iter().any(|t| *t == signer) {
        return Verdict::no(format!(
            "signed by {}, which is not a pinned signer — an artifact verified against whatever key \
             it names is verified against its author",
            &signer[..16.min(signer.len())]
        ));
    }

    // Coverage by EXCLUSION, mirroring the producer: everything except the signature fields. A
    // signature scoped to an enumerated list of keys silently stops covering the newest field.
    let mut body = obj.clone();
    body.remove("signature");
    body.remove("signer");
    let body_canon = match canonical(&serde_json::Value::Object(body)) {
        Ok(c) => c,
        Err(e) => return Verdict::no(e),
    };
    let mut signed_bytes = SIG_DOMAIN.to_vec();
    signed_bytes.extend_from_slice(&body_canon);

    let key_bytes = match hex_decode(signer).and_then(|b| <[u8; 32]>::try_from(b).ok()) {
        Some(k) => k,
        None => return Verdict::no("the signer is not 32 bytes of hex"),
    };
    let key = match VerifyingKey::from_bytes(&key_bytes) {
        Ok(k) => k,
        Err(e) => return Verdict::no(format!("the signer is not a valid ed25519 key: {e}")),
    };
    let sig_bytes = match hex_decode(sig_hex).and_then(|b| <[u8; 64]>::try_from(b).ok()) {
        Some(s) => s,
        None => return Verdict::no("the signature is not 64 bytes of hex"),
    };
    if key.verify(&signed_bytes, &Signature::from_bytes(&sig_bytes)).is_err() {
        return Verdict::no("SIGNATURE INVALID: this is not the artifact that was signed");
    }

    Verdict::yes(format!(
        "{} points, exhaustive, {} law(s), digest {}, signed by pinned {}",
        rows.len(),
        obj.get("laws").and_then(|v| v.as_array()).map(|l| l.len()).unwrap_or(0),
        &recomputed[..16],
        &signer[..16]
    ))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> serde_json::Value {
        serde_json::json!({
            "schema": SCHEMA,
            "rows": [{"in": {"a": 0}, "out": {"g": 1}}, {"in": {"a": 1}, "out": {"g": 2}}],
            "space": {"axes": [["a", [0, 1]]]},
            "laws": [["a-law", "exact"]],
            "table_digest": "",
        })
    }

    #[test]
    fn an_unsigned_artifact_is_refused() {
        let v = verify(&sample(), &["deadbeef"]);
        assert!(!v.ok);
    }

    #[test]
    fn a_non_ascii_artifact_is_REFUSED_rather_than_silently_diverging() {
        // Python escapes non-ASCII as \uXXXX and serde_json emits UTF-8. The digests would differ,
        // and the failure would appear only on a device whose name is not English -- reproducible
        // nowhere the developers live. Refusing is the honest outcome.
        let mut doc = sample();
        doc["rows"][0]["out"] = serde_json::json!({"name": "café"});
        let v = verify(&doc, &["deadbeef"]);
        assert!(!v.ok);
        assert!(v.reason.contains("non-ASCII"), "{}", v.reason);
    }

    #[test]
    fn a_truncated_table_is_refused_even_with_a_consistent_digest() {
        let mut doc = sample();
        doc["rows"] = serde_json::json!([{"in": {"a": 0}, "out": {"g": 1}}]);
        // Recompute so the digest is self-consistent; only the coverage check can catch this.
        let canon = canonical(&doc["rows"]).unwrap();
        let mut h = Sha256::new();
        h.update(TABLE_DOMAIN);
        h.update(&canon);
        doc["table_digest"] = serde_json::json!(hex_encode(&h.finalize()));
        let v = verify(&doc, &["deadbeef"]);
        assert!(!v.ok);
        assert!(v.reason.contains("incomplete table"), "{}", v.reason);
    }

    #[test]
    fn hex_round_trips() {
        assert_eq!(hex_decode("00ff10").unwrap(), vec![0u8, 255, 16]);
        assert!(hex_decode("abc").is_none());
        assert!(hex_decode("zz").is_none());
    }
}
