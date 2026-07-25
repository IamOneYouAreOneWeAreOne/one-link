//! Fan-out planner.
//!
//! Given a file manifest, the per-chunk placement map, and a set of
//! per-source capacity profiles, compute an assignment of chunks to
//! sources that:
//!
//! 1. Respects "only holders can serve" (the placement is the
//!    source of truth for who owns what).
//! 2. Spreads load across sources weighted by capacity (faster
//!    sources carry more chunks).
//! 3. Is deterministic: same input → same output, so any device
//!    in the mesh can re-derive the plan locally without a fresh
//!    coordination round.
//! 4. Optionally over-requests: ask for `ceil(k * overrequest_factor)`
//!    shards even though `k` suffice, so the receiver completes
//!    when ANY `k` arrive — masking slow sources without
//!    re-planning.

use std::collections::BTreeMap;

use crate::distributed_fs::{ChunkHash, ChunkPlacement, FileManifest};
use crate::errors::{DeviceMeshError, DeviceMeshResult};
use crate::subkey::DEVICE_ID_LEN;

/// One source's capacity profile, as the receiver estimates it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceCapacity {
    /// Source device id.
    pub device_id: [u8; DEVICE_ID_LEN],
    /// Estimated bytes-per-second the source can deliver to this
    /// receiver. Typically a Phase D bandit estimate. Higher = more
    /// chunks assigned.
    pub estimated_bps: u64,
    /// Current in-flight bytes already-assigned to this source from
    /// other plans. The planner adds the new assignment on top so
    /// load tracking stays accurate across overlapping fan-outs.
    pub current_load_bytes: u64,
}

/// Per-source assignment in a fan-out plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FanOutAssignment {
    /// Which source serves these chunks.
    pub source_device_id: [u8; DEVICE_ID_LEN],
    /// Chunk hashes assigned to this source (sorted ascending).
    pub chunk_hashes: Vec<ChunkHash>,
    /// Estimated bytes the source will deliver (= chunks ×
    /// `manifest.chunk_size`).
    pub estimated_bytes: u64,
}

/// The full plan: per-source assignments + over-request factor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FanOutPlan {
    /// File the plan targets.
    pub file_id: crate::distributed_fs::FileId,
    /// Per-source assignment list. Order is by `source_device_id`
    /// ascending so the plan hashes deterministically.
    pub assignments: Vec<FanOutAssignment>,
    /// Number of distinct chunk hashes asked for across all sources.
    /// May exceed `manifest.policy.k` when `overrequest_factor > 1`.
    pub total_chunks: usize,
}

/// Compute a fan-out plan.
///
/// Algorithm: for each chunk in the manifest (in canonical order),
/// pick the eligible source — a device that (a) holds the chunk and
/// (b) has the smallest projected `current_load + assigned_so_far /
/// estimated_bps`. Tie-break on lex device id.
///
/// `overrequest_factor` ≥ 1.0; values like 1.2 trade ~20 % extra
/// bandwidth for resilience against straggling sources. Set to 1.0
/// for the strict-shards mode.
pub fn fan_out_plan(
    manifest: &FileManifest,
    placements: &[ChunkPlacement],
    sources: &[SourceCapacity],
    overrequest_factor: f64,
) -> DeviceMeshResult<FanOutPlan> {
    manifest.shape_check()?;
    if sources.is_empty() {
        return Err(DeviceMeshError::FanOutNoSources);
    }
    if overrequest_factor < 1.0 || !overrequest_factor.is_finite() {
        return Err(DeviceMeshError::FanOutBadOverrequestFactor {
            got_bits: overrequest_factor.to_bits(),
        });
    }
    // Build a lookup: chunk_hash → set of holder device ids (from
    // the placement records). Chunks not in any placement get an
    // empty holder set, which causes the planner to skip them.
    let mut holders: BTreeMap<ChunkHash, Vec<[u8; DEVICE_ID_LEN]>> = BTreeMap::new();
    for p in placements {
        holders.insert(p.chunk_hash, p.device_ids.iter().copied().collect());
    }
    // Mutable per-source projected load (current + accumulated).
    let mut load: BTreeMap<[u8; DEVICE_ID_LEN], u128> = sources
        .iter()
        .map(|s| (s.device_id, s.current_load_bytes as u128))
        .collect();
    let cap: BTreeMap<[u8; DEVICE_ID_LEN], u64> = sources
        .iter()
        .map(|s| (s.device_id, s.estimated_bps.max(1)))
        .collect();
    // Determine how many of the manifest's chunks to actually fetch.
    // Manifest has `chunks.len()` shards total (= k*stripes + m*stripes).
    // `k_total` is the number of data shards across all stripes.
    let stripe = manifest.policy.total_shards() as usize;
    let n_stripes = manifest.chunks.len() / stripe;
    let k_total = n_stripes * (manifest.policy.k as usize);
    // k_total ≤ chunks.len() ≤ MAX_CHUNKS_PER_FILE = 2^20, well
    // within f64's 53-bit mantissa.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let target = ((k_total as f64) * overrequest_factor).ceil() as usize;
    let target = target.min(manifest.chunks.len());
    // Per-source bucket of assigned chunks.
    let mut bucket: BTreeMap<[u8; DEVICE_ID_LEN], Vec<ChunkHash>> =
        sources.iter().map(|s| (s.device_id, Vec::new())).collect();
    let mut assigned = 0usize;
    for chunk in &manifest.chunks {
        if assigned >= target {
            break;
        }
        let Some(holder_list) = holders.get(chunk) else {
            continue;
        };
        // Among holders that are ALSO known sources, pick the
        // smallest projected `(load + chunk_size) / bps`. Tie-break
        // on lex device id.
        let chunk_bytes = manifest.chunk_size as u128;
        let pick = holder_list
            .iter()
            .filter(|h| cap.contains_key(*h))
            .min_by(|a, b| {
                let la = load.get(*a).copied().unwrap_or(0) + chunk_bytes;
                let lb = load.get(*b).copied().unwrap_or(0) + chunk_bytes;
                let ca = *cap.get(*a).unwrap_or(&1) as u128;
                let cb = *cap.get(*b).unwrap_or(&1) as u128;
                // Compare la / ca vs lb / cb without floats:
                //   la * cb  vs  lb * ca.
                let lhs = la.saturating_mul(cb);
                let rhs = lb.saturating_mul(ca);
                match lhs.cmp(&rhs) {
                    std::cmp::Ordering::Equal => a.cmp(b),
                    other => other,
                }
            });
        let Some(&pick) = pick else {
            // No eligible source for this chunk; skip it. The
            // receiver may still recover if it gets enough other
            // shards via fountain decoding.
            continue;
        };
        let bucket_entry = bucket.entry(pick).or_default();
        bucket_entry.push(*chunk);
        *load.entry(pick).or_insert(0) += chunk_bytes;
        assigned += 1;
    }
    // Build the assignment list — deterministic order.
    let mut assignments: Vec<FanOutAssignment> = bucket
        .into_iter()
        .filter(|(_, chunks)| !chunks.is_empty())
        .map(|(device_id, mut chunks)| {
            chunks.sort_unstable();
            let estimated_bytes = (chunks.len() as u64).saturating_mul(manifest.chunk_size as u64);
            FanOutAssignment {
                source_device_id: device_id,
                chunk_hashes: chunks,
                estimated_bytes,
            }
        })
        .collect();
    assignments.sort_by_key(|a| a.source_device_id);
    Ok(FanOutPlan {
        file_id: manifest.file_id(),
        assignments,
        total_chunks: assigned,
    })
}

/// Replan after a source fails mid-transfer.
///
/// `still_needed_chunks` is the list of chunks that haven't yet
/// arrived (the receiver's pending+in-flight set). `failed_source`
/// is the source id to drop from the eligible pool. The function
/// returns a fresh plan covering the unmet chunks via the surviving
/// sources.
pub fn replan_after_source_failure(
    manifest: &FileManifest,
    placements: &[ChunkPlacement],
    sources: &[SourceCapacity],
    failed_source: [u8; DEVICE_ID_LEN],
    still_needed_chunks: &[ChunkHash],
    overrequest_factor: f64,
) -> DeviceMeshResult<FanOutPlan> {
    manifest.shape_check()?;
    // Synthesize a sub-manifest containing ONLY the still-needed
    // chunks. The planner is policy-agnostic so this is sound; it
    // just needs the chunk list + chunk_size to compute load.
    if still_needed_chunks.is_empty() {
        return Err(DeviceMeshError::FanOutNothingToReplan);
    }
    let surviving_sources: Vec<SourceCapacity> = sources
        .iter()
        .filter(|s| s.device_id != failed_source)
        .copied()
        .collect();
    if surviving_sources.is_empty() {
        return Err(DeviceMeshError::FanOutNoSources);
    }
    // Build a sub-manifest. We use the original manifest's policy
    // so total_shards / k math stays consistent. The chunks list
    // is rounded up to the next stripe-multiple by padding with
    // copies of the last needed chunk; the planner skips chunks
    // it can't place (no holder in surviving_sources), so padding
    // is harmless.
    let stripe = manifest.policy.total_shards() as usize;
    let mut chunks = still_needed_chunks.to_vec();
    // Sort + dedup so the planner's lookup hits.
    chunks.sort_unstable();
    chunks.dedup();
    // Pad to stripe multiple.
    let Some(&last_chunk) = chunks.last() else {
        return Err(DeviceMeshError::FanOutNothingToReplan);
    };
    while !chunks.len().is_multiple_of(stripe) {
        chunks.push(last_chunk);
    }
    let sub_manifest = FileManifest {
        file_size: manifest.file_size,
        chunk_size: manifest.chunk_size,
        chunks,
        mime: manifest.mime.clone(),
        created_unix: manifest.created_unix,
        policy: manifest.policy,
    };
    fan_out_plan(
        &sub_manifest,
        placements,
        &surviving_sources,
        overrequest_factor,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distributed_fs::{ChunkPlacement, ErasurePolicy};

    fn manifest(chunks: Vec<ChunkHash>) -> FileManifest {
        let policy = ErasurePolicy::new(2, 1, 1).unwrap();
        FileManifest {
            file_size: 1024,
            chunk_size: 256,
            chunks,
            mime: b"x".to_vec(),
            created_unix: 0,
            policy,
        }
    }

    fn placement(chunk: ChunkHash, holders: &[[u8; DEVICE_ID_LEN]]) -> ChunkPlacement {
        let mut p = ChunkPlacement::empty(chunk);
        for h in holders {
            p.add_holder(*h, 1);
        }
        p
    }

    #[test]
    fn fan_out_assigns_each_chunk_to_one_source() {
        let chunks = vec![[0x01; 32], [0x02; 32], [0x03; 32]];
        let m = manifest(chunks.clone());
        let placements: Vec<ChunkPlacement> = chunks
            .iter()
            .map(|c| placement(*c, &[[1; 16], [2; 16], [3; 16]]))
            .collect();
        let sources = vec![
            SourceCapacity {
                device_id: [1; 16],
                estimated_bps: 100_000_000,
                current_load_bytes: 0,
            },
            SourceCapacity {
                device_id: [2; 16],
                estimated_bps: 100_000_000,
                current_load_bytes: 0,
            },
            SourceCapacity {
                device_id: [3; 16],
                estimated_bps: 100_000_000,
                current_load_bytes: 0,
            },
        ];
        let plan = fan_out_plan(&m, &placements, &sources, 1.0).unwrap();
        let total: usize = plan.assignments.iter().map(|a| a.chunk_hashes.len()).sum();
        // policy k=2, m=1, 3 chunks = 1 stripe → k_total = 2.
        assert_eq!(total, 2);
    }

    #[test]
    fn fan_out_with_overrequest_increases_target() {
        let chunks = vec![[0x01; 32], [0x02; 32], [0x03; 32]];
        let m = manifest(chunks.clone());
        let placements: Vec<ChunkPlacement> =
            chunks.iter().map(|c| placement(*c, &[[1; 16]])).collect();
        let sources = vec![SourceCapacity {
            device_id: [1; 16],
            estimated_bps: 100_000_000,
            current_load_bytes: 0,
        }];
        let plan = fan_out_plan(&m, &placements, &sources, 1.5).unwrap();
        // 1.5 × k(=2) = 3 chunks ⇒ overrequest brings us to the full set.
        let total: usize = plan.assignments.iter().map(|a| a.chunk_hashes.len()).sum();
        assert_eq!(total, 3);
    }

    #[test]
    fn fan_out_skips_chunks_with_no_eligible_holder() {
        let chunks = vec![[0x01; 32], [0x02; 32], [0x03; 32]];
        let m = manifest(chunks.clone());
        // Only first chunk has a holder.
        let placements = vec![
            placement(chunks[0], &[[1; 16]]),
            ChunkPlacement::empty(chunks[1]),
            ChunkPlacement::empty(chunks[2]),
        ];
        let sources = vec![SourceCapacity {
            device_id: [1; 16],
            estimated_bps: 100_000_000,
            current_load_bytes: 0,
        }];
        let plan = fan_out_plan(&m, &placements, &sources, 1.0).unwrap();
        // Only 1 chunk had an eligible holder.
        let total: usize = plan.assignments.iter().map(|a| a.chunk_hashes.len()).sum();
        assert_eq!(total, 1);
    }

    #[test]
    fn higher_capacity_source_gets_more_chunks() {
        // 6 chunks, all held by both sources, but source 1 is 10×
        // faster — it should carry most of the work.
        let chunks: Vec<ChunkHash> = (1u8..=6).map(|i| [i; 32]).collect();
        let policy = ErasurePolicy::new(2, 1, 1).unwrap();
        let m = FileManifest {
            file_size: 6,
            chunk_size: 1,
            chunks: chunks.clone(),
            mime: b"x".to_vec(),
            created_unix: 0,
            policy,
        };
        let placements: Vec<ChunkPlacement> = chunks
            .iter()
            .map(|c| placement(*c, &[[1; 16], [2; 16]]))
            .collect();
        let sources = vec![
            SourceCapacity {
                device_id: [1; 16],
                estimated_bps: 100_000_000,
                current_load_bytes: 0,
            },
            SourceCapacity {
                device_id: [2; 16],
                estimated_bps: 10_000_000,
                current_load_bytes: 0,
            },
        ];
        let plan = fan_out_plan(&m, &placements, &sources, 1.0).unwrap();
        let s1: usize = plan
            .assignments
            .iter()
            .filter(|a| a.source_device_id == [1; 16])
            .map(|a| a.chunk_hashes.len())
            .sum();
        let s2: usize = plan
            .assignments
            .iter()
            .filter(|a| a.source_device_id == [2; 16])
            .map(|a| a.chunk_hashes.len())
            .sum();
        assert!(s1 >= s2);
    }

    #[test]
    fn replan_after_source_failure_drops_failed_source() {
        let chunks: Vec<ChunkHash> = (1u8..=3).map(|i| [i; 32]).collect();
        let m = manifest(chunks.clone());
        let placements: Vec<ChunkPlacement> = chunks
            .iter()
            .map(|c| placement(*c, &[[1; 16], [2; 16], [3; 16]]))
            .collect();
        let sources = vec![
            SourceCapacity {
                device_id: [1; 16],
                estimated_bps: 100_000_000,
                current_load_bytes: 0,
            },
            SourceCapacity {
                device_id: [2; 16],
                estimated_bps: 100_000_000,
                current_load_bytes: 0,
            },
            SourceCapacity {
                device_id: [3; 16],
                estimated_bps: 100_000_000,
                current_load_bytes: 0,
            },
        ];
        let plan =
            replan_after_source_failure(&m, &placements, &sources, [2; 16], &chunks, 1.0).unwrap();
        for a in &plan.assignments {
            assert_ne!(a.source_device_id, [2; 16]);
        }
    }

    #[test]
    fn empty_sources_rejected() {
        let m = manifest(vec![[0x01; 32], [0x02; 32], [0x03; 32]]);
        let err = fan_out_plan(&m, &[], &[], 1.0).unwrap_err();
        assert!(matches!(err, DeviceMeshError::FanOutNoSources));
    }

    #[test]
    fn bad_overrequest_factor_rejected() {
        let m = manifest(vec![[0x01; 32], [0x02; 32], [0x03; 32]]);
        let sources = vec![SourceCapacity {
            device_id: [1; 16],
            estimated_bps: 1,
            current_load_bytes: 0,
        }];
        let err = fan_out_plan(&m, &[], &sources, 0.5).unwrap_err();
        assert!(matches!(
            err,
            DeviceMeshError::FanOutBadOverrequestFactor { .. }
        ));
    }

    #[test]
    fn fan_out_is_deterministic() {
        let chunks: Vec<ChunkHash> = (1u8..=6).map(|i| [i; 32]).collect();
        let m = manifest(chunks.clone());
        let placements: Vec<ChunkPlacement> = chunks
            .iter()
            .map(|c| placement(*c, &[[1; 16], [2; 16]]))
            .collect();
        let sources = vec![
            SourceCapacity {
                device_id: [1; 16],
                estimated_bps: 50,
                current_load_bytes: 0,
            },
            SourceCapacity {
                device_id: [2; 16],
                estimated_bps: 50,
                current_load_bytes: 0,
            },
        ];
        let p1 = fan_out_plan(&m, &placements, &sources, 1.0).unwrap();
        let p2 = fan_out_plan(&m, &placements, &sources, 1.0).unwrap();
        assert_eq!(p1, p2);
    }
}
