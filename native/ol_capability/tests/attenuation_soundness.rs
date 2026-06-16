//! Phase C acceptance gate for `ol_capability` (FILE_ENGINE_V2_PLAN.md:289):
//!
//!     "Macaroon attenuation: property test that no derived cap exceeds
//!      parent rights across ≥1M random delegation chains."
//!
//! Soundness invariant under test:
//!
//!     For all (parent, child, ctx) where child is a strict attenuation
//!     of parent: child.accepts(ctx) ⇒ parent.accepts(ctx).
//!
//! In English: an attenuated cap can never accept a context that the
//! parent would reject. Attenuation can only **shrink** the set of
//! accepted contexts.
//!
//! Iteration count is configurable via `OL_CAPABILITY_GATE_ITERS`
//! (default 10_000 for CI; gate run sets it to 1_000_000).

use ol_capability::{Capability, Caveat, Context, CAP_ID_LEN, ROOT_KEY_LEN};
use zeroize::Zeroizing;

// SplitMix64 — same deterministic PRNG used by the ol_crdt gate.
fn next_rng(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn random_bytes<const N: usize>(state: &mut u64) -> [u8; N] {
    let mut out = [0u8; N];
    for chunk in out.chunks_mut(8) {
        let v = next_rng(state).to_le_bytes();
        let n = chunk.len().min(8);
        chunk[..n].copy_from_slice(&v[..n]);
    }
    out
}

fn random_string(state: &mut u64, max_len: usize) -> String {
    let len = (next_rng(state) as usize) % max_len.max(1);
    (0..len)
        .map(|_| {
            // ASCII letter range so caveats render and parse cleanly.
            let v = (next_rng(state) % 26) as u8;
            (b'a' + v) as char
        })
        .collect()
}

fn random_caveat(state: &mut u64) -> Caveat {
    match next_rng(state) % 5 {
        0 => Caveat::ExpiresAt(next_rng(state) % 1_000_000_000),
        1 => Caveat::PeerFingerprint(random_bytes::<32>(state)),
        2 => Caveat::PathPrefix(format!("/{}", random_string(state, 8))),
        3 => {
            let n = (next_rng(state) as usize) % 4 + 1;
            let ops: Vec<String> = (0..n)
                .map(|_| match next_rng(state) % 4 {
                    0 => "read".to_string(),
                    1 => "write".to_string(),
                    2 => "list".to_string(),
                    _ => "delete".to_string(),
                })
                .collect();
            Caveat::OperationIn(ops)
        }
        _ => Caveat::AuditTag(random_string(state, 12)),
    }
}

fn random_context(state: &mut u64) -> OwnedContext {
    OwnedContext {
        now_unix_ms: if !next_rng(state).is_multiple_of(4) {
            Some(next_rng(state) % 2_000_000_000)
        } else {
            None
        },
        peer: if !next_rng(state).is_multiple_of(3) {
            Some(random_bytes::<32>(state))
        } else {
            None
        },
        path: if !next_rng(state).is_multiple_of(3) {
            Some(format!(
                "/{}/{}",
                random_string(state, 8),
                random_string(state, 8),
            ))
        } else {
            None
        },
        operation: if !next_rng(state).is_multiple_of(3) {
            Some(
                match next_rng(state) % 5 {
                    0 => "read",
                    1 => "write",
                    2 => "list",
                    3 => "delete",
                    _ => "rename",
                }
                .to_string(),
            )
        } else {
            None
        },
    }
}

/// Owned variant so we can hold the string fields across iterations
/// without lifetime gymnastics. We build a borrowed `Context` from this
/// at use sites.
struct OwnedContext {
    now_unix_ms: Option<u64>,
    peer: Option<[u8; 32]>,
    path: Option<String>,
    operation: Option<String>,
}

impl OwnedContext {
    fn as_ctx<'a>(&'a self) -> Context<'a> {
        let mut c = Context::new();
        if let Some(ms) = self.now_unix_ms {
            c = c.with_now(ms);
        }
        if let Some(peer) = self.peer {
            c = c.with_peer(peer);
        }
        if let Some(ref p) = self.path {
            c = c.with_path(p.as_str());
        }
        if let Some(ref op) = self.operation {
            c = c.with_operation(op.as_str());
        }
        c
    }
}

#[test]
fn child_never_exceeds_parent_rights() {
    let iters: u64 = std::env::var("OL_CAPABILITY_GATE_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);

    let mut state: u64 = 0xCA9C_0DE0_F00D_FACE_u64.swap_bytes();
    let mut soundness_fail = 0u64;
    let mut child_accepts = 0u64;
    let mut child_rejects = 0u64;

    for _ in 0..iters {
        // Fresh root key + cap-id per iteration.
        let root_arr: [u8; ROOT_KEY_LEN] = random_bytes::<ROOT_KEY_LEN>(&mut state);
        let root = Zeroizing::new(root_arr);
        let id: [u8; CAP_ID_LEN] = random_bytes::<CAP_ID_LEN>(&mut state);

        // Parent: 0–5 random initial caveats.
        let parent_caveats = (next_rng(&mut state) as usize) % 6;
        let mut parent = Capability::root(id, &root);
        for _ in 0..parent_caveats {
            parent = parent.attenuate(random_caveat(&mut state));
        }

        // Child: parent + 0–10 additional caveats (strict attenuation).
        let extra_caveats = (next_rng(&mut state) as usize) % 11;
        let mut child = parent.clone();
        for _ in 0..extra_caveats {
            child = child.attenuate(random_caveat(&mut state));
        }

        // Random context.
        let ctx_owned = random_context(&mut state);
        let ctx = ctx_owned.as_ctx();

        let parent_ok = parent.accepts(&root, &ctx);
        let child_ok = child.accepts(&root, &ctx);

        // The soundness invariant: child accepting ⇒ parent accepting.
        // Equivalently: there must NOT exist a (child, ctx) where child
        // accepts but parent does not.
        if child_ok && !parent_ok {
            soundness_fail += 1;
        }
        if child_ok {
            child_accepts += 1;
        } else {
            child_rejects += 1;
        }
    }

    eprintln!(
        "soundness gate: iters={iters} child_accepts={child_accepts} child_rejects={child_rejects} violations={soundness_fail}"
    );
    assert_eq!(
        soundness_fail, 0,
        "macaroon attenuation soundness violated: {soundness_fail} cases where child accepts ctx that parent rejects (out of {iters})"
    );
    // Sanity: across random contexts the child must reject at least
    // some non-trivial fraction (otherwise the test is vacuously true).
    assert!(
        child_rejects > iters / 100,
        "child rejected fewer than 1% of contexts ({child_rejects}/{iters}) — test is vacuous"
    );
}

#[test]
fn appending_caveat_can_only_shrink_acceptance() {
    // Stronger pointwise statement of the same property: for any cap C
    // and any caveat K, (C ⊕ K).accepts(ctx) ⇒ C.accepts(ctx). We
    // exercise this at small scale (10k) as a direct invariant check.
    let mut state: u64 = 0xC0DE_BEEF;
    let iters = 10_000u64;
    for _ in 0..iters {
        let root_arr: [u8; ROOT_KEY_LEN] = random_bytes::<ROOT_KEY_LEN>(&mut state);
        let root = Zeroizing::new(root_arr);
        let id: [u8; CAP_ID_LEN] = random_bytes::<CAP_ID_LEN>(&mut state);

        let cap = Capability::root(id, &root);
        let attenuated = cap.attenuate(random_caveat(&mut state));

        let ctx_owned = random_context(&mut state);
        let ctx = ctx_owned.as_ctx();

        if attenuated.accepts(&root, &ctx) {
            assert!(
                cap.accepts(&root, &ctx),
                "attenuated cap accepted a ctx the parent rejected"
            );
        }
    }
}
