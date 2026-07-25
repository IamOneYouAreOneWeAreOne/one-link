// Indexed loops address parallel data/parity shard arrays positionally;
// iterators would obscure the Reed-Solomon shard correspondence.
#![allow(clippy::needless_range_loop)]
//! Proptest property coverage for `ol_fec`.

use ol_fec::Codec;
use proptest::prelude::*;

proptest! {
    /// Any valid `(k, m)` codec encodes K shards into M parity shards
    /// of the same length, and decoding from the full K+M slots
    /// recovers the original data.
    #[test]
    fn rs_full_recovery_arbitrary_km(
        k in 1usize..16,
        m in 1usize..16,
        shard_len in 1usize..512,
        seed in any::<u64>(),
    ) {
        prop_assume!(k + m <= 255);
        let codec = Codec::new(k, m).unwrap();
        let mut state = seed;
        let data: Vec<Vec<u8>> = (0..k).map(|_| {
            (0..shard_len).map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (state >> 33).to_le_bytes()[0]
            }).collect()
        }).collect();
        let data_refs: Vec<&[u8]> = data.iter().map(std::vec::Vec::as_slice).collect();
        let parity = codec.encode(&data_refs).unwrap();
        prop_assert_eq!(parity.len(), m);
        for p in &parity {
            prop_assert_eq!(p.len(), shard_len);
        }
        // Decode with all shards present.
        let mut present: Vec<Option<&[u8]>> = data.iter().map(|d| Some(d.as_slice())).collect();
        for p in &parity {
            present.push(Some(p.as_slice()));
        }
        let decoded = codec.decode(&present).unwrap();
        prop_assert_eq!(decoded, data);
    }

    /// Any subset of K of the K+M shards recovers the K data shards.
    #[test]
    fn rs_recovers_any_k_subset(
        k in 2usize..10,
        m in 1usize..6,
        shard_len in 1usize..256,
        drop_mask in 0u32..0x3FF,
        seed in any::<u64>(),
    ) {
        prop_assume!(k + m <= 14);
        let codec = Codec::new(k, m).unwrap();
        let mut state = seed;
        let data: Vec<Vec<u8>> = (0..k).map(|_| {
            (0..shard_len).map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (state >> 33).to_le_bytes()[0]
            }).collect()
        }).collect();
        let data_refs: Vec<&[u8]> = data.iter().map(std::vec::Vec::as_slice).collect();
        let parity = codec.encode(&data_refs).unwrap();

        // Build a "present" mask: bit i set in drop_mask means drop shard i.
        let total = k + m;
        let mut drops_count = 0;
        for i in 0..total {
            if (drop_mask >> i) & 1 == 1 {
                drops_count += 1;
            }
        }
        prop_assume!(drops_count <= m);

        let mut present: Vec<Option<&[u8]>> = Vec::with_capacity(total);
        for i in 0..k {
            if (drop_mask >> i) & 1 == 1 {
                present.push(None);
            } else {
                present.push(Some(data[i].as_slice()));
            }
        }
        for i in 0..m {
            let shard_idx = k + i;
            if (drop_mask >> shard_idx) & 1 == 1 {
                present.push(None);
            } else {
                present.push(Some(parity[i].as_slice()));
            }
        }
        let decoded = codec.decode(&present).unwrap();
        prop_assert_eq!(decoded, data);
    }

    /// Decoding with too few present shards must error, never panic.
    #[test]
    fn rs_too_few_shards_errors(
        k in 2usize..10,
        m in 1usize..4,
        shard_len in 1usize..64,
    ) {
        prop_assume!(k + m <= 14);
        let codec = Codec::new(k, m).unwrap();
        let buf = vec![0u8; shard_len];
        let data: Vec<&[u8]> = vec![buf.as_slice(); k];
        let parity = codec.encode(&data).unwrap();
        // Construct a present vector with only k-1 shards.
        let mut present: Vec<Option<&[u8]>> = vec![None; k + m];
        let mut filled = 0;
        for i in 0..(k - 1) {
            present[i] = Some(data[i]);
            filled += 1;
        }
        let _ = filled;
        prop_assert_eq!(parity.len(), m);
        let r = codec.decode(&present);
        prop_assert!(r.is_err());
    }
}
