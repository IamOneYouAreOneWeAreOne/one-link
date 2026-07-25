# ADR-0015: Fountain Codes — LT codes for swarm-resilient chunk distribution

**Status:** ACCEPTED (Phase B acceptance number)
**Phase:** B
**Depends on:** ADR-0011 (Bloom transfer init), ADR-0013 (TransferEngine)

---

## Context

Phase B-1 ships chunk fetching as a request/response pattern (`ChunkRequest → ChunkResponse`). For a small number of peers and a small number of chunks this is fine. It breaks down on three workloads:

1. **One sender, K receivers wanting the same big file.** The sender uploads K×N chunks total — strict O(K) bandwidth at the source. A swarm protocol can do O(N): every receiver helps every other receiver after it gets a chunk.
2. **One receiver, K seeders.** Naive request/response makes the receiver pick *which* seeder serves each chunk. If the chosen seeder gets slow or disconnects mid-transfer, the request retries elsewhere — wasted RTT. A rateless code lets every seeder send "any encoded packet" and the receiver reconstructs once it has enough.
3. **Lossy or jittery links.** Naive request/response retransmits on packet loss; rateless codes have ARQ-less recovery — every received packet is useful, regardless of which packets were lost.

The fountain-codes layer (per `FILE_ENGINE_V2_PLAN.md` Layer 5) is the architectural answer to all three. It sits *between* the transport (ol_quic) and the chunk-fetch protocol (ol_transfer). Senders can wrap a chunk in a stream of encoded packets and any K of them at the receiver reconstructs the chunk.

## Decision

**Phase B v1: ship Luby Transform (LT) codes per Luby 2002. Wire-compatible upgrade to RaptorQ (RFC 6330) deferred to Phase B-2 once we've verified the IPR situation.**

### Why LT codes for v1, not RaptorQ

- **RaptorQ (RFC 6330)** is faster decode and a few percent lower overhead, but has Qualcomm IPR declarations. We need to verify the IPR grant terms before shipping in our binary. **Falsifiable check: confirm the IPR grant covers FOSS use before flipping the default.** If verified clean, Phase B-2 swaps LT → RaptorQ with a one-byte wire-format version bump. If blocked, we ship LT codes only.
- **LT codes (Luby 2002)** are 22 years old, well past any patent term, used in Tornado/Raptor patents that have expired. Zero supply-chain risk.
- **Reference implementations** for LT exist in Rust (`raptorq` crate has both LT and RaptorQ paths; ~300 LoC of the LT path is portable + auditable).

### Wire format

Each fountain-encoded packet has shape:

```text
+--------+--------+--------+--------+-----------+
| chunk_id (32B) | symbol_id (4B) | encoded_payload (length_symbol B) |
+--------+--------+--------+--------+-----------+
```

- `chunk_id` (32 bytes): the BLAKE3 chunk address (raw or convergent, per ADR-0006).
- `symbol_id` (4 bytes, u32 LE): the LT encoded symbol index. Senders monotonically increment; receivers use it to derive the degree-sequence seed.
- `encoded_payload` (length_symbol bytes): the LT-encoded symbol bytes. For Phase B v1, `length_symbol = 1024 bytes`. K source symbols per chunk = `length_plaintext / 1024` rounded up.

A 64 KiB chunk = K=64 source symbols. The sender's encode loop produces ~80 encoded symbols (25% overhead) for a target decode probability ≥99.9% at the receiver. Receivers attempt decode after each new symbol arrives; once decode succeeds, they signal "done" via a `FountainAck` frame so the sender stops emitting.

### Degree distribution

LT codes' performance hinges on the degree distribution `Ω(d)`. We use the **Robust Soliton Distribution** (Luby 2002) with parameters:

| Parameter | Value | Rationale |
|---|---|---|
| K (source symbols / chunk) | 8 to 256 (chunk-size dependent) | 8 KiB-256 KiB chunks at 1 KiB symbols. |
| c | 0.03 | Standard RSD knob. |
| δ | 0.05 | Target decoding failure prob ≤5%. Receivers see this only on adversarial loss; honest senders saturate K×1.25 symbols quickly. |

Symbol-degree selection is **seeded deterministically by symbol_id**. The receiver re-derives the same degree sequence from the symbol_id alone — no extra metadata on the wire. This is the standard fountain-code trick.

### Senders, receivers, protocol semantics

- **Sender side**: when serving a chunk fetched via `ChunkRequest`, the sender can opt to respond with one of:
  - **`ChunkResponse` (kind 0x02)** — full chunk record (current Phase B behavior; default for small chunks or single-receiver flows).
  - **`FountainBurst` (kind 0x22)** — a sequence of N fountain-encoded packets carrying the same chunk_id (new in v1.5+). Used when the sender knows multiple receivers want the same chunk (peer-discovery hint) or the link is known-lossy.
- **Receiver side**: maintains an in-progress decoder per `chunk_id` it's actively fetching via fountain. Each `FountainBurst` packet feeds the decoder; when decode succeeds, the receiver:
  1. Validates `BLAKE3(decoded_plaintext) == chunk_id` (or convergent-derived address per ADR-0006).
  2. Wraps in a `ChunkRecord` and appends to the local chunk_store via `store.append_chunk` + `store.flush`.
  3. Sends `FountainAck` (kind 0x23) carrying the chunk_id to tell the sender to stop.
- **Memory cap**: receiver's in-progress decoder set is bounded by `MAX_INFLIGHT_FOUNTAIN = 64` per peer. Anything beyond is dropped on the floor with a back-pressure signal.

### Wire-compatibility with non-fountain peers

A peer that doesn't speak fountain codes (Phase A2 peer running plain ol_transfer) sees the new frame kinds as unknown and replies `ProtoError` (existing v1 behavior). The sender falls back to `ChunkResponse`. **No flag negotiation needed at the engine level — the protocol gracefully degrades.**

### Falsifiable acceptance number

**Decode success ≥99% at 5% packet loss across ≥1,000 random seeds for K ∈ {8, 64, 256}.**

This is the gate. If the decoder fails more often than 1%, the parameters are wrong, the seeding is buggy, or the loss model is off. Phase B doesn't ship without it.

## Consequences

**Positive:**
- One-sender / K-receivers becomes O(N) source bandwidth instead of O(K×N). Big files distribute through a small swarm cleanly.
- Lossy links can reduce explicit slot retransmission when enough independent
  symbols arrive. This improves selected loss models but is not “unbreakable”:
  bounded retries, integrity failure, resource exhaustion, path loss, process
  death, and unqualified connection migration remain explicit failure modes.
- Phase B v1 ships only the **LT path**; RaptorQ is a Phase B-2 upgrade if/when IPR is clean.
- No new on-disk format changes; fountain-decoded chunks are stored exactly like fetched chunks (same `ChunkRecord` shape, including the `convergent` flag if applicable).

**Negative:**
- LT codes have ~5-10% decode overhead (worse than RaptorQ's ~1-2%, better than naive ARQ at 5%+ loss). Acceptable trade for v1.
- Receiver memory cost = K × `length_symbol` per in-progress decode. At K=256, length_symbol=1024 → 256 KiB per chunk in flight. With `MAX_INFLIGHT_FOUNTAIN=64`, worst case 16 MiB. Bounded.
- Sender's encoding cost is small (XOR of ~log(K) source symbols per encoded packet). Receiver's decoding cost is dominated by the belief-propagation pass, O(K log K) on the average. Both fit on a single core easily even at line rate.
- Pollution-resistance: a malicious peer can flood `FountainBurst` packets for any `chunk_id`. We verify decode against the BLAKE3 chunk_id and drop on hash mismatch. Cost: wasted bytes; not corruption. Phase B-2 may add per-burst signed attestations.

## Verification

1. **LT decode correctness on K ∈ {8, 64, 256}, ε = 5% loss, 1000 seeds → ≥99% decode success**.
2. **End-to-end: sender encodes 64 KiB chunk → receiver decodes from a noisy stream → BLAKE3(decoded) == chunk_id**.
3. **Wire-format round trip: encode a FountainBurst packet → decode header → reproduce chunk_id + symbol_id**.
4. **Pollution test: feed the decoder fake packets for a non-existent chunk_id → no false decode, decoder eventually times out and is garbage-collected**.
5. **Fuzz: 24h cargo-fuzz on the wire-format decoder → zero crashes**.
6. **Wire-compat: non-fountain peer receives FountainBurst → replies ProtoError → sender falls back to ChunkResponse**.

## References

- Luby 2002 LT codes paper: https://ieeexplore.ieee.org/document/1181950
- RaptorQ RFC 6330: https://datatracker.ietf.org/doc/html/rfc6330
- `raptorq` Rust crate: https://crates.io/crates/raptorq (we will harvest the LT path or implement a leaner subset)
- ADR-0011 (Bloom transfer init) — Bloom-init narrows what's transferred; fountain codes carry it.
- ADR-0013 (TransferEngine) — the wire-protocol owner.
- ADR-0006 (BLAKE3 derive scheme) — chunk addressing used by fountain decode validation.
