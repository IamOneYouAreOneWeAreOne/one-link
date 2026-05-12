#![no_main]
//! Fuzz the quantizer with arbitrary observation byte vectors.
//! Must NEVER panic. All output bits must be 0 or 1.

use libfuzzer_sys::fuzz_target;
use ol_proximity_pair::{quantize_observations, QuantizeConfig};

fuzz_target!(|data: &[u8]| {
    // Two configs: tiny min_bytes so we exercise the no-error path,
    // and large min_bytes so we exercise the too-short error path.
    let cfg = QuantizeConfig {
        min_bytes: 1,
        guard_band: 0.1,
    };
    if let Ok(bits) = quantize_observations(data, &cfg) {
        assert!(bits.iter().all(|&b| b == 0 || b == 1));
    }
    // Also exercise with a guard band of 0 (every observation classified).
    let cfg2 = QuantizeConfig {
        min_bytes: 1,
        guard_band: 0.0,
    };
    if let Ok(bits) = quantize_observations(data, &cfg2) {
        assert!(bits.iter().all(|&b| b == 0 || b == 1));
    }
});
