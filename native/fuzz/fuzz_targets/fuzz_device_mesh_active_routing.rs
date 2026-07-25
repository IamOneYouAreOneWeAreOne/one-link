#![no_main]
//! Fuzz the Layer 9 active-routing surface.

use libfuzzer_sys::fuzz_target;
use ol_device_mesh::active_routing::{
    pick_device_for_context, CohortPrior, DeviceActionRecord, RoutingContext, RoutingHistory,
};
use ol_device_mesh::{DeviceClass, DEVICE_ID_LEN};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fuzz_target!(|data: &[u8]| {
    // 1. RoutingContext hash on fuzz-derived inputs.
    let mut contact = [0u8; 32];
    for (i, b) in data.iter().take(32).enumerate() {
        contact[i] = *b;
    }
    let ctx = RoutingContext {
        contact_pin: contact,
        hour_bucket: data.get(32).copied().unwrap_or(0),
        day_of_week: data.get(33).copied().unwrap_or(0),
        message_class: [
            data.get(34).copied().unwrap_or(0),
            data.get(35).copied().unwrap_or(0),
            data.get(36).copied().unwrap_or(0),
            data.get(37).copied().unwrap_or(0),
        ],
        urgency: data.get(38).copied().unwrap_or(0),
    };
    let _ = ctx.canonical_hash();

    // 2. DeviceActionRecord observe + decay on extreme inputs.
    let mut rec = DeviceActionRecord::empty(ctx.canonical_hash(), [0x01; DEVICE_ID_LEN]);
    for &b in data.iter().take(64) {
        rec.observe((b & 1) == 1, u64::from(b));
    }
    let _ = rec.decay(u64::from(data.first().copied().unwrap_or(0)) * 1_000, 60);
    let _ = rec.posterior_mean();

    // 3. History observe + decay.
    let mut h = RoutingHistory::empty();
    for &b in data.iter().take(32) {
        h.observe(
            ctx.canonical_hash(),
            [b; DEVICE_ID_LEN],
            (b & 1) == 1,
            u64::from(b),
            1,
            1,
        );
    }
    h.decay_all(u64::from(data.first().copied().unwrap_or(0)) * 1_000, 60);

    // 4. Picker with arbitrary candidate set.
    let candidates: Vec<([u8; DEVICE_ID_LEN], DeviceClass)> = data
        .iter()
        .take(16)
        .map(|b| ([*b; DEVICE_ID_LEN], DeviceClass::Phone))
        .collect();
    let mut rng = ChaCha20Rng::from_seed([0xAFu8; 32]);
    let _ = pick_device_for_context(&ctx, &candidates, &h, &CohortPrior::uniform(), &mut rng);
});
