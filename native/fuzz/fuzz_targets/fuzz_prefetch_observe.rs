#![no_main]
//! Fuzz the prefetch predictor. Observation sequences must never
//! cause panic; predicted confidences must stay in [0, 1].

use libfuzzer_sys::fuzz_target;
use ol_prefetch::PrefetchPredictor;

fn take_byte(input: &mut &[u8]) -> Option<u8> {
    let b = *input.first()?;
    *input = &input[1..];
    Some(b)
}

fuzz_target!(|data: &[u8]| {
    let mut input = data;
    let mut p = PrefetchPredictor::default();
    let mut t = 0u64;
    while let Some(peer_b) = take_byte(&mut input) {
        let Some(file_b) = take_byte(&mut input) else { break };
        let mut peer = [0u8; 32];
        peer[0] = peer_b;
        let mut file = [0u8; 32];
        file[0] = file_b;
        t += 10;
        p.observe(&peer, file, t);
        let preds = p.predict_top_n(&peer, 3);
        for pred in preds {
            assert!(
                pred.confidence >= 0.0 && pred.confidence <= 1.0,
                "prefetch confidence out of bounds: {}",
                pred.confidence
            );
        }
    }
});
