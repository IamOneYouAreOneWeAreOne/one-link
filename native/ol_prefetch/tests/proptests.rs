//! Property-based tests for `ol_prefetch`.

use ol_prefetch::PrefetchPredictor;
use proptest::prelude::*;

proptest! {
    /// predict_top_n confidences are always bounded in [0, 1].
    #[test]
    fn predictions_have_bounded_confidence(
        ops in proptest::collection::vec((any::<u8>(), any::<u8>()), 0..64),
    ) {
        let mut p = PrefetchPredictor::default();
        let mut t = 0u64;
        for (peer_b, file_b) in &ops {
            let mut peer = [0u8; 32];
            peer[0] = *peer_b;
            let mut file = [0u8; 32];
            file[0] = *file_b;
            t += 10;
            p.observe(&peer, file, t);
        }
        // Query each distinct peer for predictions.
        let unique_peers: std::collections::HashSet<u8> =
            ops.iter().map(|(p, _)| *p).collect();
        for peer_b in unique_peers {
            let mut peer = [0u8; 32];
            peer[0] = peer_b;
            let preds = p.predict_top_n(&peer, 5);
            for pred in preds {
                prop_assert!(pred.confidence >= 0.0 && pred.confidence <= 1.0);
            }
        }
    }

    /// decay_counts is idempotent in spirit: applying it once then
    /// querying predict_top_n still returns confidences in [0, 1].
    #[test]
    fn decay_preserves_invariants(
        observations in proptest::collection::vec((any::<u8>(), any::<u8>()), 5..30),
    ) {
        let mut p = PrefetchPredictor::default();
        let mut t = 0u64;
        for (peer_b, file_b) in &observations {
            let mut peer = [0u8; 32];
            peer[0] = *peer_b;
            let mut file = [0u8; 32];
            file[0] = *file_b;
            t += 10;
            p.observe(&peer, file, t);
        }
        p.decay_counts();
        // Query each peer; confidences must still be valid.
        let unique_peers: std::collections::HashSet<u8> =
            observations.iter().map(|(p, _)| *p).collect();
        for peer_b in unique_peers {
            let mut peer = [0u8; 32];
            peer[0] = peer_b;
            let preds = p.predict_top_n(&peer, 3);
            for pred in preds {
                prop_assert!(pred.confidence >= 0.0 && pred.confidence <= 1.0);
            }
        }
    }
}
