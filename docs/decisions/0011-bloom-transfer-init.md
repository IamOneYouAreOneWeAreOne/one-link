# ADR-0011: Bloom-Filter Transfer Initiation

**Status:** ACCEPTED (Phase B acceptance number — do not revisit without ADR amendment)
**Phase:** B (the genius layer)
**Depends on:** ADR-0003 (chunk_id format), ADR-0006 (BLAKE3 derive), ADR-0009 (QUIC frames)

---

## Context

The legacy P2P transfer model is "I want this manifest; please send me every chunk listed." The receiver may already have most of those chunks (because dedup) but the sender doesn't know. So the protocol either (a) sends everything wastefully or (b) requires an explicit "do you have this?" round-trip per chunk — the latter inflating latency proportionally to the chunk count.

Bloom-filter transfer initiation collapses both problems into a single round-trip:

1. Receiver computes a Bloom filter of the chunk_ids it already has in its memtable + manifest.
2. Receiver sends the filter to the sender as the first frame of the transfer.
3. Sender iterates the chunks it intends to send; for each, it tests against the receiver's filter; if absent, the chunk is in the "must transfer" set; if present, skipped.
4. Sender returns the list of `chunk_ids` it WILL transfer (i.e. chunks the receiver definitely doesn't have).

This single mechanism unifies:
- **Fresh transfer** (receiver Bloom is empty → all chunks transferred)
- **Resume** (receiver Bloom is partial → only the missing chunks transferred)
- **Dedup** (receiver Bloom contains chunks already present → skipped)
- **Cross-folder dedup** (receiver Bloom is the union of all chunks across all folders → swarm-wide dedup hits land for free)

False positives are acceptable: if Bloom says "I might have X" but actually doesn't, the transfer just appears to skip a chunk that should have been sent. Mitigation: the receiver verifies post-transfer that every chunk in the manifest is present in its memtable; missing chunks trigger an explicit re-request (which goes via the standard `ChunkRequest` frame, no Bloom involved). The Bloom layer is therefore a fast-path optimization, not a correctness load-bearing primitive.

## Decision

### Bloom filter sizing

For a target false-positive rate `p` and `n` chunk_ids, the optimal filter size in bits is:

```
m = -(n × ln(p)) / (ln(2)^2)
k = (m / n) × ln(2)   // hash functions
```

Phase B targets `p = 0.01` (1% false positive). For typical receiver corpus sizes:

| Receiver chunks (n) | Filter size (bits) | Filter size (bytes) | Hash funcs (k) |
|---|---|---|---|
| 1,024 | 9,816 | 1,228 (~1.2 KiB) | 7 |
| 16,384 | 157,066 | 19,634 (~19 KiB) | 7 |
| 262,144 | 2,513,066 | 314,134 (~307 KiB) | 7 |
| 1,048,576 | 10,052,266 | 1,256,534 (~1.2 MiB) | 7 |

A 1 MiB receiver-side memtable produces ~1.2 MiB of Bloom over the wire. **At 1.2 MiB and >100 MiB/s QUIC throughput, the Bloom round-trip costs <12 ms.** Compared to per-chunk request round trips for the same corpus (~16K × 1 ms ≈ 16 seconds), Bloom-init is 1300× faster.

Filter size is determined by the receiver and capped at **1 MiB** for the wire layer (matches `MAX_BULK_FRAME_BYTES` in [ADR-0009](0009-quic-transport.md)). Receivers with > 1M chunks (rare in v0) split the filter into multiple frames; senders process each in turn.

### Hash function

The Bloom filter uses **k double-hashing** based on two BLAKE3-derived hashes per chunk_id, per [Kirsch + Mitzenmacher 2006]:

```
h1 = BLAKE3.derive_key("ol-bloom-h1-v1", chunk_id) -> first 8 bytes -> u64
h2 = BLAKE3.derive_key("ol-bloom-h2-v1", chunk_id) -> first 8 bytes -> u64

for i in 0..k:
    bit_index = (h1 + i * h2) % m
    set_bit(filter, bit_index)
```

Both context strings are registered in [ADR-0006 §"Registered domain contexts"](0006-blake3-derive-scheme.md). They are added in this ADR; ADR-0006's registry list grows by 2.

### Wire format

```
+--------+--------+----------+--- bit array ---+
| m_bits | k_funcs| reserved | filter bits     |
| u32 LE | u32 LE | u32 LE=0 | ceil(m/8) bytes |
+--------+--------+----------+-----------------+
```

12-byte header + filter bits. Total = 12 + ceil(m/8). Carried in the QUIC `BloomFilter` frame (kind 0x20 per ADR-0009). Single frame for filters ≤ 1 MiB; multi-frame for larger.

### Sender response

Sender enumerates the chunks it would transfer (the sender's transfer set, e.g. all chunks for a folder share or a manifest sync). For each, it queries the receiver's filter:

- **filter says present**: skip (probabilistic — may be a false positive).
- **filter says absent**: include in `MissingChunks` response (definite).

Returned in the QUIC `MissingChunks` frame (kind 0x21):

```
+----------+--- chunk_ids ---+
| count u32| count × 32 bytes|
+----------+-----------------+
```

Sender then transfers those chunks via the standard `ChunkResponse` frame (kind 0x02) — one frame per chunk on its own QUIC stream.

### Post-transfer verification

After all returned chunks transfer, the receiver verifies the manifest is satisfied (every chunk_id in the manifest now has a memtable entry). Missing chunks (false-positive collisions) trigger explicit `ChunkRequest` frames. Worst case: 1% of chunks (the FP rate) require a per-chunk request fallback. For a 64K-chunk corpus, that's ~640 fallback round trips — still substantially less than the alternative of per-chunk requests for everything.

### Filter staleness

A receiver's Bloom reflects the memtable state at the moment of construction. Concurrent writes during a transfer can cause "I just stored this; my Bloom doesn't reflect it" → the sender re-sends a chunk the receiver actually has. Cost: bandwidth wasted on a redundant chunk; receiver simply re-stores (idempotent). Mitigation: receivers refresh the Bloom for each transfer initiation; long-running transfers don't refresh mid-stream.

## Consequences

**Positive:**
- Single round-trip replaces per-chunk has-this-already queries.
- 1.2 MiB Bloom for 1M chunks is <12 ms over QUIC; per-chunk round trips would be hours.
- Same mechanism for fresh / resume / dedup. Less code.
- False positives are correctness-neutral: receiver verifies and re-requests. Worst case: small bandwidth waste.
- BLAKE3 double-hashing is hardware-accelerated and deterministic across platforms.
- 1% FP rate fits the Phase B latency budget; can tune to 0.1% (more bits) or 5% (smaller filter, more fallbacks) per workload.

**Negative:**
- Bloom filters are not removable: a chunk that gets reclaimed locally remains "set" in the filter until the next reconstruction. Acceptable: filters are rebuilt per transfer initiation, not persisted.
- Filter constructed-at-snapshot-time means reads during a long transfer may briefly diverge from the live memtable. Acceptable per "filter staleness" mitigation above.
- Filter size grows linearly with corpus size. At 10M chunks (rare), filter is ~12 MiB — still under the 1 MiB single-frame cap but requires multi-frame split. Implementation handles this transparently.
- Two new BLAKE3 derive contexts — ADR-0006 registry grows by 2.

## Verification

1. **FP-rate gate**: empirical FP rate over 100 random `(insert N chunks, query M unrelated chunks, count false hits)` runs at `p = 0.01` target ≤ 1.5% measured (allowing for noise).
2. **Idempotence gate**: insert chunk_id X; query 1M times; result is `true` every time.
3. **Encoding round-trip**: build filter F; encode to bytes; decode back to F'; F.contains(x) == F'.contains(x) for all x.
4. **Cross-platform determinism**: filter built on x86 and ARM64 with same chunk_id list produces byte-identical encoded bytes.
5. **Wire-frame size cap**: filter ≤ 1 MiB fits in one `BloomFilter` frame; >1 MiB triggers multi-frame split.
6. **End-to-end**: receiver with 1024 chunks asks sender for 2048 chunks (1024 overlap + 1024 new); sender transfers ≤1.5% extra (FP allowance) and the receiver's manifest validates post-transfer.

## References

- Bloom 1970: original CACM paper.
- Kirsch + Mitzenmacher 2006 "Less hashing, same performance": double-hashing trick (saves k-2 BLAKE3 calls per insert/query).
- ADR-0003 (chunk_id format) — what we're filtering.
- ADR-0006 (BLAKE3 derive scheme) — where the bloom-h1 / bloom-h2 contexts register.
- ADR-0009 (QUIC framing) — `BloomFilter` (0x20) and `MissingChunks` (0x21) frame kinds.
