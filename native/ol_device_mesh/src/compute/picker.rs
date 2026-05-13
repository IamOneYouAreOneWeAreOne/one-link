//! Executor picker.
//!
//! Given a set of required capabilities + the registry + per-source
//! capacity profiles (reusing the Layer-5 `SourceCapacity` type),
//! pick the eligible device with the best
//! `estimated_bps / current_load` score. Tie-break on lex device id
//! so the result is deterministic.

use std::collections::BTreeMap;

use crate::fan_out::SourceCapacity;
use crate::subkey::DEVICE_ID_LEN;

use super::capability::DeviceCapability;
use super::registry::CapabilityRegistry;

/// Pick the eligible executor with the best ratio of estimated
/// bandwidth to current load. Returns `None` when no device in the
/// registry holds ALL the required capabilities OR no eligible
/// device has a known capacity profile.
#[must_use]
pub fn pick_executor(
    needed: &[DeviceCapability],
    registry: &CapabilityRegistry,
    capacities: &[SourceCapacity],
    day: u64,
) -> Option<[u8; DEVICE_ID_LEN]> {
    let candidates = registry.devices_with(needed, day);
    if candidates.is_empty() {
        return None;
    }
    let cap_map: BTreeMap<[u8; DEVICE_ID_LEN], &SourceCapacity> =
        capacities.iter().map(|c| (c.device_id, c)).collect();
    // Among candidates that have a capacity profile, pick the one
    // with the highest `bps / (load + 1)` score.
    let mut best: Option<([u8; DEVICE_ID_LEN], u128)> = None;
    for id in &candidates {
        let Some(cap) = cap_map.get(id) else { continue };
        let denom = (cap.current_load_bytes as u128).saturating_add(1);
        let score = (cap.estimated_bps as u128).saturating_mul(1_000_000) / denom;
        match best {
            None => best = Some((*id, score)),
            Some((cur_id, cur_score)) => {
                let better = score > cur_score
                    || (score == cur_score && *id < cur_id);
                if better {
                    best = Some((*id, score));
                }
            }
        }
    }
    best.map(|(id, _)| id)
}

#[cfg(test)]
mod tests {
    use super::super::attestation::sign_capability_attestation;
    use super::*;
    use crate::master::MasterIdentity;
    use rand::rngs::OsRng;

    fn d(byte: u8) -> [u8; DEVICE_ID_LEN] {
        [byte; DEVICE_ID_LEN]
    }

    fn make_reg() -> (MasterIdentity, CapabilityRegistry) {
        let master = MasterIdentity::generate(&mut OsRng);
        let mut reg = CapabilityRegistry::empty();
        // Phone: Microphone + Camera
        reg.ingest(
            sign_capability_attestation(
                &master,
                d(1),
                vec![DeviceCapability::Microphone, DeviceCapability::Camera],
                0,
                365,
            )
            .unwrap(),
            &master.verifying_key(),
        )
        .unwrap();
        // Laptop: CpuHeavy + Display + LargeDisk
        reg.ingest(
            sign_capability_attestation(
                &master,
                d(2),
                vec![
                    DeviceCapability::CpuHeavy,
                    DeviceCapability::Display,
                    DeviceCapability::LargeDisk,
                ],
                0,
                365,
            )
            .unwrap(),
            &master.verifying_key(),
        )
        .unwrap();
        // Desktop: GPU + CpuHeavy + AlwaysOn + LargeDisk
        reg.ingest(
            sign_capability_attestation(
                &master,
                d(3),
                vec![
                    DeviceCapability::Gpu,
                    DeviceCapability::CpuHeavy,
                    DeviceCapability::AlwaysOn,
                    DeviceCapability::LargeDisk,
                ],
                0,
                365,
            )
            .unwrap(),
            &master.verifying_key(),
        )
        .unwrap();
        (master, reg)
    }

    #[test]
    fn picks_desktop_for_gpu_task() {
        let (_m, reg) = make_reg();
        let caps = vec![
            SourceCapacity { device_id: d(1), estimated_bps: 50_000, current_load_bytes: 0 },
            SourceCapacity { device_id: d(2), estimated_bps: 100_000, current_load_bytes: 0 },
            SourceCapacity { device_id: d(3), estimated_bps: 1_000_000_000, current_load_bytes: 0 },
        ];
        let pick = pick_executor(&[DeviceCapability::Gpu], &reg, &caps, 100);
        assert_eq!(pick, Some(d(3)));
    }

    #[test]
    fn no_eligible_returns_none() {
        let (_m, reg) = make_reg();
        let caps: Vec<SourceCapacity> = Vec::new();
        let pick =
            pick_executor(&[DeviceCapability::Tee], &reg, &caps, 100);
        assert!(pick.is_none());
    }

    #[test]
    fn picks_least_loaded_when_capabilities_tie() {
        let (_m, reg) = make_reg();
        // Both laptop + desktop have CpuHeavy. Desktop has more load.
        let caps = vec![
            SourceCapacity { device_id: d(2), estimated_bps: 100, current_load_bytes: 0 },
            SourceCapacity { device_id: d(3), estimated_bps: 100, current_load_bytes: 1_000 },
        ];
        let pick = pick_executor(&[DeviceCapability::CpuHeavy], &reg, &caps, 100);
        assert_eq!(pick, Some(d(2)));
    }

    #[test]
    fn empty_capacity_returns_none() {
        let (_m, reg) = make_reg();
        let pick = pick_executor(
            &[DeviceCapability::Gpu],
            &reg,
            &[],
            100,
        );
        assert!(pick.is_none());
    }
}
