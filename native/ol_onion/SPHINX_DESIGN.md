# Sphinx onion routing design (F3-polish v3, deferred)

This historical design note captures the intended Sphinx packet
construction for an F3 research iteration. It is not product-route,
interoperability, anonymity, or release evidence. The first F3 polish
attempt got the high-level
architecture right but got the *filler-byte* construction wrong:
each relay's trailing-slot padding must be derived from the
*cumulative* PRG outputs of upstream relays' stream-cipher
keystreams, not from a single per-relay seed. The fix requires
implementing Sphinx's `phi_i` filler computation exactly.

## Why Sphinx (vs. the current nested-AEAD design)

Current `packet.rs` design carries one ephemeral X25519 pubkey
**per layer** of the onion. A global passive adversary watching
every relay can correlate the same circuit's packets by their
shrinking sizes + per-layer ephemeral-pubkey changes.

The target Sphinx packet format provides these narrow construction
properties when implemented correctly:

1. **Single packet-level ephemeral pubkey**, BLINDED at each hop.
   The same circuit's `alpha` changes at relay R_i. Security of that
   transformation is a cryptographic assumption; byte-frequency tests do
   not prove observer unlinkability.
2. **Fixed-size packets** at every hop. Header is shifted-and-XOR'd
   rather than removed.
3. **Per-hop MAC** binds the header so no relay can mutate routing
   info without detection at the next hop.

## Wire format (target)

```
version       : u8                       (= 2)
alpha         : [u8; 32]                 (blinded ephemeral pubkey)
header_mac    : [u8; 16]                 (BLAKE3-keyed MAC over header)
header        : [u8; HEADER_LEN]         (stream-encrypted routing info)
payload       : [u8; PAYLOAD_LEN]        (stream-encrypted user data)
```

Constants:
- `SLOT_LEN  = 32 (hop_id) + 16 (mac) = 48`
- `MAX_HOPS  = 5`
- `HEADER_LEN = MAX_HOPS * SLOT_LEN = 240`
- `PAYLOAD_LEN = 1024`
- `PACKET_LEN  = 1 + 32 + 16 + 240 + 1024 = 1313`

## Cryptographic primitives

- Ed25519 / Curve25519 via `curve25519-dalek` (Edwards-form scalar
  multiplication for blinding).
- BLAKE3-keyed for MAC.
- ChaCha20 stream cipher (raw, not Poly1305) for header + payload
  encryption.

## Per-hop key derivation

```
s_i = relay_static_sk * alpha_i              (Edwards-form ECDH, both sides)
mac_key_i      = BLAKE3(domain || "-sphinx-mac-v1" || s_i || alpha_i)
header_stream_i = BLAKE3(domain || "-sphinx-hdr-v1" || s_i || alpha_i)
payload_stream_i = BLAKE3(domain || "-sphinx-pay-v1" || s_i || alpha_i)
b_i (blind)    = BLAKE3(domain || "-sphinx-blind-v1" || s_i || alpha_i)
                  (clamped to a multiple of 8; lives in the prime-order subgroup)
```

## Sender precomputation

For circuit `[r_0, r_1, ..., r_{n-1}]` (last is destination):

1. Random ephemeral X25519 secret `x` (clamped).
2. `alpha_0 = x * G_edwards` (Edwards form).
3. For `i = 0..n`:
    - `alpha_i = cumulative_blind_i * alpha_0`
    - `s_i = x * cumulative_blind_i * r_i.pubkey_edwards`
    - Derive `(mac_key_i, header_stream_i, payload_stream_i, b_i)`.
    - `cumulative_blind_{i+1} = cumulative_blind_i * b_i`.

## Filler construction (the part the first attempt got WRONG)

The sender pre-computes a `filler` byte string of growing length
that accumulates the trailing-slot bytes each upstream relay will
produce after its peel + left-shift.

```
filler = empty
for i in 0..n-1:
    # Extend filler by SLOT_LEN zero bytes — these are the bytes
    # relay i will SEE in the trailing slot after its peel.
    extended = filler || [0u8; SLOT_LEN]
    # Apply hop i's header stream cipher to the extended filler,
    # using the SAME byte positions that hop i would use during peel.
    # In ChaCha20 terms: skip the first (HEADER_LEN - (i+1)*SLOT_LEN)
    # keystream bytes (those decrypt the visible portion of the
    # header), then XOR the next (i+1)*SLOT_LEN keystream bytes onto
    # the extended filler.
    apply_chacha20_at_offset(header_stream_i, HEADER_LEN - (i+1)*SLOT_LEN, extended)
    filler = extended
```

After this loop, `filler` is `(n-1) * SLOT_LEN` bytes long. It
represents the cumulative trailing-slot bytes that the destination
will receive.

## Header construction (inside-out)

```
# Innermost layer (destination):
# header = pad_random_to_HEADER_LEN_minus_filler_len || filler
# where the first part is bytes the destination expects at slots
# 0..n-2 (which it will ignore — only slot 0 matters to dest, and
# it's the destination-marker zero slot).
header = [0u8; SLOT_LEN] || random_bytes(HEADER_LEN - SLOT_LEN - filler.len()) || filler
# Stream-encrypt with destination's header_stream key.
header = chacha20(header_stream_{n-1}, header)
prev_mac = mac(mac_key_{n-1}, header)

# Outer layers (n-2 down to 0):
for i in (0..n-1).rev():
    # Prepend slot (next_hop_id || prev_mac), drop trailing SLOT_LEN.
    new_slot = circuit[i+1].id || prev_mac
    header = new_slot || header[..HEADER_LEN - SLOT_LEN]
    # Stream-encrypt with hop i's header_stream key.
    header = chacha20(header_stream_i, header)
    prev_mac = mac(mac_key_i, header)
```

## Relay peel

```
1. Compute s_i = my_sk * alpha (Edwards form).
2. Derive (mac_key, header_stream, payload_stream, b).
3. Verify packet.header_mac == mac(mac_key, packet.header). Drop on fail.
4. Decrypt header: header_clear = chacha20(header_stream, packet.header || [0u8; SLOT_LEN])
   (note the trailing SLOT_LEN — we treat the stream as HEADER_LEN + SLOT_LEN bytes)
5. Read slot 0: (next_hop_id, next_mac).
6. If next_hop_id == [0u8; HOP_ID_LEN]: this is the destination.
   Strip payload's stream cipher; deliver.
7. Otherwise (relay): shift header_clear left by SLOT_LEN; the new
   trailing SLOT_LEN bytes are the last SLOT_LEN bytes of the
   keystream we just generated.
8. Blind alpha: alpha_next = b * alpha (Edwards form).
9. Decrypt payload one layer: payload_next = chacha20(payload_stream, packet.payload).
10. Forward (version, alpha_next, next_mac, shifted_header, payload_next).
```

## Implementation notes / pitfalls

1. **Edwards-form ECDH on both sides** — the relay MUST do
   `relay_sk_scalar * alpha_edwards` in Edwards form (NOT via X25519
   Montgomery ladder). The Montgomery ladder's clamping interferes
   with the cumulative-blind-scalar math on the sender side.
2. **MontgomeryPoint::to_edwards(0) sign convention** — use `sign=0`
   uniformly across sender + relay. The sign ambiguity washes out
   when converting back to Montgomery.
3. **Blinding factor must be a multiple of 8** — clamp the BLAKE3
   output's bit 0..2 to zero before constructing the Scalar. This
   keeps the chain inside the prime-order subgroup (cofactor
   8 considerations).
4. **Stream cipher state is per-layer-fresh** — use a zero nonce
   with a fresh per-layer key. NEVER reuse a nonce across layers.
5. **Filler byte construction** must use the SAME chacha20
   keystream position the relay will see during peel. Off-by-one in
   the byte offset is the highest-risk implementation bug. Cross-
   check against a Sphinx reference implementation (Nymtech
   `sphinx-packet` is well-audited).

## Test plan

1. KAT vectors with fixed seeds (sender_sk, relay_0..n_sk, payload)
   → pinned packet bytes at every layer.
2. Property test: random circuits up to MAX_HOPS round-trip 1M times.
3. Constant-size assertion: every layer's wire packet is exactly
   PACKET_LEN bytes.
4. Adversarial: tampered MAC, swapped alpha, replay across circuits,
   small-order pubkey.
5. Alpha-evolution and byte-distribution smoke tests. A global passive
   observer also sees timing, direction, volume, endpoints, and topology;
   this test plan cannot establish random-chance circuit linkage or
   anonymity.
6. TLA+ model extension with the alpha-blinding step explicit.

## References

- Danezis & Goldberg, "Sphinx: A Compact and Provably Secure Mix
  Format" (2009), the canonical paper.
- Nymtech `sphinx-packet` Rust crate, useful as a cross-reference for the
  filler-byte algorithm. One Link's implementation and wire format still
  require their own interoperability and security review.
- Tor's variable-length cell spec (different but related design).
