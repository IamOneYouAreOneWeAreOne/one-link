# ol_device_mesh (Row 8 — ALL 10 LAYERS COMPLETE) microbenchmark results

Captured against `0.21.0-alpha.0` on Windows 11 Intel host, release
profile (`cargo bench -p ol_device_mesh --bench device_mesh_bench`).

## Final numbers

| Benchmark                                       | Time     | Notes                            |
|---                                              |---       |---                               |
| `device_mesh::derive_subkey_seed`               | 221 ns   | BLAKE3-keyed HKDF, 64-byte out   |
| `device_mesh::derive_field_bound_subkey_seed`   | 352 ns   | + field-witness XOR mask         |
| `device_mesh::ratchet_one_day`                  | 238 ns   | one-way step + zeroize prev      |
| `device_mesh::master_pin_handle`                | 1.6 µs   | BLAKE3 over master VK            |
| `device_mesh::software_wrapper_wrap_64`         | 326 ns   | BLAKE3 keystream + MAC           |
| `device_mesh::software_wrapper_unwrap_64`       | 330 ns   | MAC verify + keystream           |
| `device_mesh::liveness_proof_verify`            | 53.2 µs  | hybrid signature verify          |
| `device_mesh::mint_subkey`                      | 433 µs   | derive seed + master signs vk    |
| `device_mesh::liveness_proof_issue`             | 688 µs   | subkey signs transcript          |

## Layer 10 — duress + deniable + steg-pair

| Benchmark                                              | Time     | Notes                                       |
|---                                                     |---       |---                                          |
| `device_mesh::duress_pair_commitment_build`            | 111 ns   | BLAKE3 over (domain, channel, secret, nonce, ts) |
| `device_mesh::duress_envelope_create`                  | 29.1 ms  | 2× Argon2id derivation + 2× AEAD encrypt    |
| `device_mesh::duress_envelope_unlock_real`             | 30.1 ms  | 2× Argon2id (real + decoy paths both run)   |

Argon2id at OWASP-recommended `(m=19,456 KiB, t=2, p=1)` deliberately
takes ~15 ms per derivation so brute-forcing a captured envelope is
prohibitive at the duress-code entropy levels users actually pick
(4-8 character codes typed under stress).

## Layer 9 — active-inference device routing

| Benchmark                                              | Time      | Notes                                       |
|---                                                     |---        |---                                          |
| `device_mesh::active_routing_observe`                  | 52.0 ns   | Bayesian update on Beta(α, β) posterior     |
| `device_mesh::active_routing_context_hash`             | 112 ns    | BLAKE3 over (contact, hour, day, class, urg)|
| `device_mesh::active_routing_pick_device_4`            | 642 ns    | Thompson sampling (Marsaglia–Tsang), 4 cand |

Picker is sub-microsecond now. The earlier sum-of-exponentials
gamma sampler was O(α + β) so it would have degraded as the
routing history accumulated thousands of observations; the
Marsaglia–Tsang upgrade gives constant-time-per-draw regardless
of posterior depth.

## Layer 8 — cross-device distributed compute

| Benchmark                                              | Time      | Notes                                       |
|---                                                     |---        |---                                          |
| `device_mesh::compute_pick_executor_8_devices`         | 176 ns    | capability-match + capacity-score over 8    |
| `device_mesh::compute_task_request_sign`               | 265 µs    | requester-subkey signs transcript           |
| `device_mesh::compute_cap_attestation_sign`            | 1.32 ms   | master signs capability attestation         |

Executor picking is essentially free — under 200 ns to choose
among 8 devices. The daemon recomputes assignments on every
heartbeat without noticeable cost.

## Layer 7 — self-onion

| Benchmark                                              | Time     | Notes                                       |
|---                                                     |---       |---                                          |
| `device_mesh::self_onion_derive_identity`              | 205 ns   | BLAKE3-XOF + Ristretto255 scalar reduce     |
| `device_mesh::self_onion_build_circuit_2_hop`          | 72.2 µs  | Sphinx Coherence packet build, 2 hops       |
| `device_mesh::self_onion_peel_layer`                   | 27.8 µs  | Sphinx peel + DEVICE_ID_LEN slot-id recover |

## Layer 6 — self-routing

| Benchmark                                                  | Time     | Notes                                       |
|---                                                         |---       |---                                          |
| `device_mesh::self_routing_announcement_sign_8`            | 355 µs   | subkey signs 8-link transcript              |
| `device_mesh::self_routing_pick_best_route_6_node_clique`  | 316 ns   | max-min-τ Dijkstra over 6-device clique     |

## Layer 5 — multi-device fan-out

| Benchmark                                              | Time     | Notes                                       |
|---                                                     |---       |---                                          |
| `device_mesh::fan_out_plan_112_chunks_4_sources`       | 15.3 µs  | greedy capacity-weighted assignment         |
| `device_mesh::fan_out_fetch_request_sign_8`            | 525 µs   | receiver-subkey signs 8-chunk request       |
| `device_mesh::fan_out_chunk_ack_sign`                  | 540 µs   | source-subkey signs delivery receipt        |

## Layer 4 — distributed filesystem

| Benchmark                                              | Time     | Notes                                       |
|---                                                     |---       |---                                          |
| `device_mesh::dfs_manifest_canonical_bytes_140`        | 115 ns   | length-prefixed encoder, 140-chunk manifest |
| `device_mesh::dfs_file_id_140`                         | 2.55 µs  | BLAKE3 over the manifest bytes              |
| `device_mesh::dfs_storage_attest_sign_256`             | 380 µs   | subkey signs 256-chunk attestation          |
| `device_mesh::dfs_storage_attest_verify_256`           | 56.6 µs  | hybrid verify over 256-chunk transcript     |
| `device_mesh::dfs_repair_plan_64_chunks_4_devices`     | 9.55 µs  | least-loaded planner over 64 chunks         |

## Layer 3 — mesh state

| Benchmark                                              | Time     | Notes                                       |
|---                                                     |---       |---                                          |
| `device_mesh::mesh_state_auth_op_sign`                 | 318 µs   | subkey signs canonical transcript           |
| `device_mesh::mesh_state_auth_op_verify`               | 53.2 µs  | hybrid signature verify                     |
| `device_mesh::mesh_state_root_16_subtrees_8_keys`      | 8.45 µs  | BLAKE3 over 16 subtrees × 8 entries each    |
| `device_mesh::mesh_state_ingest_single_op`             | 330 µs   | verify + apply + log + state-root update    |

## Layer 2 — quorum

| Benchmark                                       | Time     | Notes                            |
|---                                              |---       |---                               |
| `device_mesh::quorum_mint_policy_3_of_5`        | 267 µs   | master signs policy transcript   |
| `device_mesh::quorum_sign_approval`             | 330 µs   | approver signs proposal_id       |
| `device_mesh::quorum_propose_operation`         | 538 µs   | issuer signs full proposal       |
| `device_mesh::quorum_certificate_verify_2_of_3` | 559 µs   | end-to-end cert verify           |

## What this means for the daemon

- **Subkey derivation is free**: 221 ns. Re-deriving any historical
  day on the master takes microseconds for a 365-day chain.
- **Field binding costs ~130 ns extra**: the OTP mask is one BLAKE3
  XOF expansion, then byte-XOR. Negligible.
- **Ratchet step is free**: 238 ns. The daemon advances at midnight
  local time; runtime cost is well under any scheduling jitter.
- **Master pin handle is fast enough for UI**: 1.6 µs. The friend's
  app can re-derive the pin handle on every render without it being
  measurable.
- **Hardware-wrap round-trip is ~330 ns per direction**: cold-storage
  + load happens once per device boot. Even a daemon that boots 100
  times a day pays only microseconds total.
- **Mint + attestation is ~430 µs**: this is the master signing a
  fresh subkey. Once per device pair, period.
- **Liveness verify is ~53 µs**: same cost as a single PQ-hybrid
  signature verify (row 1). At a 60-second heartbeat across 10
  siblings, total verify cost is ~530 µs per minute.
- **Liveness issue is ~688 µs**: dominated by the ML-DSA sign cost,
  same as row 1's `pqsig::sign`. Each device pays this once per
  heartbeat interval.
- **Quorum cert verify is ~559 µs**: one master-signed-policy verify
  + one master-signed-attestation verify per signer + one subkey
  verify per signer. For 2-of-3, that's ~6 hybrid-verify calls,
  bounded by ML-DSA verify (~50 µs) + book-keeping. Sublinear in
  K for the bounded MAX_APPROVALS=64.
- **Mint a policy in ~267 µs**: one master sign over a small
  transcript. The master pays this once per policy version.

## Repro

```text
cargo bench -p ol_device_mesh --bench device_mesh_bench
```
