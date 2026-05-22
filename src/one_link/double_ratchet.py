"""Signal-style Double Ratchet for One Link.

Pure crypto primitive — no I/O, no protocol — so the One Link
channel can be upgraded to forward secrecy + post-compromise
security incrementally without touching the wire format until
the activation release lands.

What this gives you over a static handshake key:

  - Forward secrecy: every plaintext message is encrypted with a
    one-shot derived from a chain key that's irreversibly advanced
    by HKDF on every send. An attacker who captures the chain key
    after-the-fact cannot decrypt earlier messages.

  - Post-compromise security: each direction sender attaches a
    fresh ephemeral X25519 public key to its messages. The first
    time the receiver sees a *new* ephemeral, both sides perform
    a DH ratchet — fresh ECDH, fresh root_key, fresh sending and
    receiving chain keys. An attacker who has the current state
    can no longer decrypt anything past the next DH step.

  - Out-of-order delivery: skipped message keys are stashed
    (bounded) so a delayed message can still decrypt within a
    window without breaking the chain.

  - Replay defence: each (dh_pub, msg_num) tuple decrypts at most
    once. A second receive of the same header is rejected.

References (independently re-implemented; this module relies on
no third-party Signal lib):
  - https://signal.org/docs/specifications/doubleratchet/
  - https://moderncrypto.org/mail-archive/messaging/2016/002320.html

The algorithm uses a Diffie-Hellman ratchet (X25519) and a symmetric
key chain (HKDF-SHA256). AEAD is ChaCha20-Poly1305. The associated
data passed in is bound to the wire header so a header tamper fails
the integrity check.
"""
from __future__ import annotations

import os
import struct
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ─── primitives ────────────────────────────────────────────────────

# Skipped-message-key cap. Without a bound an attacker can spam
# headers with absurd msg_num values and we'd derive arbitrary
# many keys. Discard older entries beyond the cap.
MAX_SKIP_KEYS = 1000

# Per-direction message-number cap. A single chain shouldn't
# go past 2**32 messages; rotate the DH ratchet long before.
MAX_MSG_PER_CHAIN = 1 << 32


# Domain separation strings for HKDF derivations. Distinct labels
# guarantee no key-reuse across stages even if input material
# repeats by accident.
HKDF_LABEL_ROOT = b"OL1/dr/root|"
HKDF_LABEL_CHAIN = b"OL1/dr/chain|"
HKDF_LABEL_MSG = b"OL1/dr/msg|"


def _hkdf(material: bytes, *, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(material)


def _hmac(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def kdf_root(root_key: bytes, dh_output: bytes) -> tuple[bytes, bytes]:
    """Root chain step: input = current root_key + DH output;
    output = (new_root_key, new_chain_key). Length 32 each."""
    out = _hkdf(dh_output, salt=root_key, info=HKDF_LABEL_ROOT, length=64)
    return out[:32], out[32:]


def kdf_chain(chain_key: bytes) -> tuple[bytes, bytes]:
    """Symmetric-chain step: input = current chain_key; output =
    (next_chain_key, this_message_key). HMAC-SHA256 keyed by
    chain_key with two distinct one-byte tags makes the message
    key independent from the next chain key."""
    next_chain = _hmac(chain_key, b"\x02")
    msg_key = _hmac(chain_key, b"\x01")
    return next_chain, msg_key


def x25519_keypair() -> tuple[X25519PrivateKey, bytes]:
    sk = X25519PrivateKey.generate()
    pk = sk.public_key().public_bytes_raw()
    return sk, pk


# RFC 7748 §6.1 + libsodium's blocklist: the 13 X25519 u-coordinate
# pubkeys that produce a zero (or otherwise small-subgroup-confined)
# shared secret regardless of the local private key. ``priv.exchange``
# on these inputs returns 32 zero bytes — useful for a small-subgroup
# attacker because every party derives the SAME root step from a known
# value. We reject before even touching the exchange so a malformed
# header from an outer-AEAD-broken state never even reaches the curve
# op. The set covers:
#   - u=0, u=1 (identity / generator-of-order-2 family)
#   - the two points of order 8
#   - p-1 (≡ -1 mod p), p (≡ 0), p+1 (≡ 1)
#   - and the additive equivalents (pubkey high bit flipped — RFC 7748
#     says implementations MUST mask the high bit of u, but a peer
#     that doesn't may submit raw values with the bit set).
# Phase C constant-time audit (ADR-0017 acceptance gate item):
# the small-order block-list is consulted on every inbound peer key
# exchange. The previous v0.20 implementation used a `frozenset`
# (`pub in _X25519_SMALL_ORDER_POINTS`) which short-circuits on the
# first byte-mismatch via the dictionary lookup path — that's a
# data-dependent timing leak. Even though the block-listed points are
# public values, timing differences distinguish "rejected here" from
# "rejected later", and "rejected at entry k vs k+1" reveals which
# attack the peer attempted. Per the Phase C gate:
#
#   > Constant-time check: timing variance across cap-validity /
#   > crypto-input-validity < 1% of mean.
#
# Replace with a constant-time linear scan that compares every entry
# regardless of an early match. `hmac.compare_digest` does
# constant-time byte-wise comparison; we OR the results into a single
# accumulator (no short-circuit branch) so the function's runtime is
# data-independent.
_X25519_SMALL_ORDER_POINTS: tuple[bytes, ...] = tuple(
    bytes.fromhex(h) for h in (
        # u=0
        "0000000000000000000000000000000000000000000000000000000000000000",
        # u=1
        "0100000000000000000000000000000000000000000000000000000000000000",
        # order-8 points
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        # p-1 (mod 2^255 - 19) = 0x7fffffff_..._ffffec
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        # p   (mod 2^255 - 19) = 0x7fffffff_..._ffffed → reduces to 0
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        # p+1 (mod 2^255 - 19) = 0x7fffffff_..._ffffee → reduces to 1
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        # u=0, u=1, order-8s with the (canonically masked) high bit
        # flipped — covers peers that don't strip bit 255 of u.
        "00000000000000000000000000000000000000000000000000000000000000ff",
        "010000000000000000000000000000000000000000000000000000000000ff7f",
        "010000000000000000000000000000000000000000000000000000000000ffff",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
        # p-1 with high bit flipped
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    )
)


def _is_small_order_x25519(pub: bytes) -> bool:
    """Constant-time check whether ``pub`` is in the small-order block-list.

    Phase C constant-time gate (per the file-engine-v2 plan): timing
    variance must be < 1% of the mean across all inputs. We achieve
    this by:

      * Comparing ``pub`` to **every** block-list entry via
        ``hmac.compare_digest`` (constant-time byte-wise XOR over the
        32-byte key), regardless of whether an earlier entry matched.
      * Accumulating the boolean results into an ``int`` via ``|`` so
        no Python-level short-circuit branch leaks "which entry hit."
      * Returning a single bool at the end.

    Cost: 13 × (32-byte ``compare_digest``) ≈ a few µs per call.
    The curve-op cost dominates; this gate is negligible.
    """
    import hmac

    # Wrong-length inputs are not "small order" per se, but they're
    # malformed; reject them up front. Treating a wrong-length input
    # as accepted-but-pending-curve-op would let the curve operation
    # fail later in a way that mixes lengths into timing. Length itself
    # isn't secret (it's the protocol frame size), so this guard is
    # public-info-only and safe to branch on.
    if len(pub) != 32:
        return True
    matched = 0
    for entry in _X25519_SMALL_ORDER_POINTS:
        # bool → int (0/1) via int(); OR into the accumulator without
        # short-circuiting. compare_digest itself is CT byte-wise.
        matched |= int(hmac.compare_digest(pub, entry))
    # 2026-05-22 audit Batch Q: use "!= 0" rather than "== 1". Today
    # this is equivalent because compare_digest yields 0/1 and OR
    # caps at 1, but a future refactor that switches to additive
    # accumulation (e.g. summing match counts) would silently break
    # the rejection on duplicate-entry hits. "!= 0" is the precise
    # semantic check: ANY match means small-order.
    return matched != 0


def x25519_dh(priv: X25519PrivateKey, peer_pub: bytes) -> bytes:
    """ECDH on Curve25519. v0.20.7 (security audit M5): two layers of
    small-order defence:

      1. **Reject known small-order inputs** before calling exchange()
         (RFC 7748 §6.1 + libsodium's blocklist of 13 points). A
         malicious-but-paired peer can craft a header with one of these
         pubkeys to drive every party to the SAME root step from a
         deterministic shared value — refuse outright.

      2. **Reject all-zero outputs** as belt-and-suspenders. The
         cryptography library implements RFC 7748 X25519 faithfully,
         which means ``priv.exchange(low_order_pub)`` returns 32 zero
         bytes rather than raising. Any pub we missed in (1) still
         dies here. Channel treats either failure the same as InvalidTag
         and tears down."""
    if len(peer_pub) != 32:
        raise ValueError(
            f"ratchet: peer X25519 pubkey must be 32 bytes, got {len(peer_pub)}"
        )
    if _is_small_order_x25519(peer_pub):
        raise ValueError(
            "ratchet: peer X25519 pubkey is a known small-order point "
            "(RFC 7748 §6.1)"
        )
    out = priv.exchange(X25519PublicKey.from_public_bytes(peer_pub))
    if out == b"\x00" * 32:
        raise ValueError(
            "ratchet: peer X25519 pubkey produced zero shared secret "
            "(low-order point)"
        )
    return out


# ─── header ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Header:
    """v=1 ratchet header. Wire shape: 1+1+32+4+4 = 42 bytes packed.
    Fields:
        v: protocol version (1)
        flags: reserved, 0
        dh: 32-byte X25519 sender public key
        pn: previous chain length (number of messages on the OLD
            sending chain when this message was sent — receiver
            uses this to derive any skipped keys it missed)
        n: this message's number on the current sending chain
    """
    v: int
    flags: int
    dh: bytes
    pn: int
    n: int

    def encode(self) -> bytes:
        if len(self.dh) != 32:
            raise ValueError("dh must be 32 bytes")
        return struct.pack(
            ">BB32sII",
            self.v & 0xFF, self.flags & 0xFF, self.dh, self.pn, self.n,
        )

    @classmethod
    def decode(cls, raw: bytes) -> "Header":
        if len(raw) < 42:
            raise ValueError("header too short")
        v, flags, dh, pn, n = struct.unpack(">BB32sII", raw[:42])
        if v != 1:
            raise ValueError(f"unsupported ratchet header version: {v}")
        return cls(v=v, flags=flags, dh=dh, pn=pn, n=n)


# ─── state ─────────────────────────────────────────────────────────

@dataclass
class RatchetState:
    """Mutable per-peer ratchet state. Hold ONE of these per
    encrypted session.

    Half of the fields exist only on Alice (initiator) at first;
    Bob (responder) populates them after Alice's first message
    arrives.
    """
    # 32-byte root chain key. Updated on every DH ratchet step.
    root_key: bytes

    # Local DH key pair for the current sending chain. Rotated
    # when we DH-ratchet (we always rotate before sending if our
    # last operation was a recv).
    dh_send: X25519PrivateKey
    dh_send_pub: bytes  # cached raw bytes

    # Peer's DH public key. None until we've seen at least one
    # ratchet message from them. On Alice's side this is set at
    # init from the bundle; on Bob's it's None until first recv.
    dh_recv_pub: Optional[bytes]

    # Symmetric chain keys.
    send_chain_key: Optional[bytes] = None
    recv_chain_key: Optional[bytes] = None

    # Message numbers within the current chain.
    send_n: int = 0
    recv_n: int = 0

    # Number of messages we sent on the previous sending chain
    # (before our last DH ratchet). Receiver uses this to know
    # how many skipped keys to derive on the prior receiving
    # chain when it picks up our new ephemeral.
    prev_send_n: int = 0

    # Skipped message keys: (dh_pub, msg_num) -> message_key.
    # An OOO message arrives with a known dh_pub but a higher n
    # than recv_n; we precompute keys for the gap, store them
    # here, and consume on later arrival. Bounded to MAX_SKIP_KEYS;
    # oldest evicted on overflow.
    skipped: dict[tuple[bytes, int], bytes] = field(default_factory=dict)

    # Replay defence: track which (dh_pub, n) pairs we've
    # successfully decrypted. A second receive of the same tuple is
    # rejected. Bounded — when we exceed MAX_SKIP_KEYS*4 we drop the
    # OLDEST entries in insertion order (FIFO).
    #
    # v0.20.7 (security audit H2): use OrderedDict instead of set so
    # the trim-on-overflow path has deterministic eviction order.
    # The previous code did ``list(set)[-1000:]`` which picks an
    # arbitrary 1000 of the 4000+ entries (Python set order is
    # implementation-defined). That gap let a long-lived session
    # accept replays of frames whose seen-entry got randomly
    # evicted while the corresponding skipped-key still lived in
    # state.skipped — _try_skipped would re-decrypt and re-add.
    decrypted_seen: "OrderedDict[tuple[bytes, int], bool]" = field(
        default_factory=OrderedDict
    )


def _evict_skipped_if_full(state: RatchetState) -> None:
    """Bound the skipped-key table. Drop oldest insertion; Python's
    dict is insertion-ordered so popitem(last=False) gets the head."""
    while len(state.skipped) > MAX_SKIP_KEYS:
        try:
            # Pop FIRST inserted (FIFO eviction).
            k = next(iter(state.skipped))
            state.skipped.pop(k, None)
        except StopIteration:
            return


def init_alice(*, shared_secret: bytes, peer_pub: bytes) -> RatchetState:
    """Initialise the side that will send the first message.

    Inputs:
      shared_secret — 32 bytes from the prior handshake (e.g. the
        existing One Link channel's HKDF output). Treat this as
        the initial root_key.
      peer_pub — Bob's 32-byte X25519 public key from the
        prekey bundle (or static identity, repurposed).

    Alice immediately rotates her own DH and runs a root step
    so her first ciphertext already advances the ratchet."""
    if len(shared_secret) != 32 or len(peer_pub) != 32:
        raise ValueError("shared_secret and peer_pub must be 32 bytes each")
    sk, pk = x25519_keypair()
    state = RatchetState(
        root_key=shared_secret,
        dh_send=sk, dh_send_pub=pk,
        dh_recv_pub=peer_pub,
    )
    dh_out = x25519_dh(sk, peer_pub)
    new_root, new_send_chain = kdf_root(state.root_key, dh_out)
    state.root_key = new_root
    state.send_chain_key = new_send_chain
    return state


def init_bob(*, shared_secret: bytes, dh_priv: X25519PrivateKey) -> RatchetState:
    """Initialise the side that will receive the first message.

    Bob holds onto the prekey private key here — it'll be used
    once when Alice's first ciphertext arrives, then replaced by
    a freshly-rotated keypair on Bob's first ratchet step."""
    if len(shared_secret) != 32:
        raise ValueError("shared_secret must be 32 bytes")
    pk = dh_priv.public_key().public_bytes_raw()
    return RatchetState(
        root_key=shared_secret,
        dh_send=dh_priv, dh_send_pub=pk,
        dh_recv_pub=None,
    )


def _dh_ratchet(state: RatchetState, header: Header) -> None:
    """Execute a DH ratchet step in response to a new sender pubkey.

    1. Derive any skipped keys we missed on the OLD receive chain
       up to header.pn.
    2. ECDH(our current dh_send_priv, header.dh) → root step →
       new recv_chain_key.
    3. Rotate our own dh_send keypair.
    4. ECDH(new dh_send_priv, header.dh) → root step → new
       send_chain_key. Reset send counters.
    """
    # 1. Skip-derive prior-chain keys.
    # 2026-05-21 audit T2-C: cap the skip-derive loop to MAX_SKIP_KEYS
    # per DH ratchet step. Without this an attacker who sends a frame
    # with ``header.pn = 2**32`` forces 4 billion HKDF iterations
    # before the MAX_MSG_PER_CHAIN safety raises. Even ``pn = 10_000``
    # is 10k KDF calls per packet — a cheap CPU DoS amplifier. The
    # cap mirrors ``_skip_recv_keys`` on the SAME chain; combined,
    # one decrypt call can derive at most ``MAX_SKIP_KEYS`` (prior)
    # + ``MAX_SKIP_KEYS`` (current) keys.
    if state.recv_chain_key is not None and state.dh_recv_pub is not None:
        if header.pn > state.recv_n + MAX_SKIP_KEYS:
            raise RuntimeError(
                "ratchet: too many skipped messages on prior chain"
                f" ({header.pn - state.recv_n} > {MAX_SKIP_KEYS})"
            )
        while state.recv_n < header.pn:
            if state.recv_n >= MAX_MSG_PER_CHAIN:
                raise RuntimeError("ratchet: prior chain past safety bound")
            state.recv_chain_key, mk = kdf_chain(state.recv_chain_key)
            key_id = (state.dh_recv_pub, state.recv_n)
            state.skipped[key_id] = mk
            state.recv_n += 1
            _evict_skipped_if_full(state)

    # 2. Derive new receive chain.
    state.dh_recv_pub = header.dh
    dh_out = x25519_dh(state.dh_send, header.dh)
    new_root, new_recv_chain = kdf_root(state.root_key, dh_out)
    state.root_key = new_root
    state.recv_chain_key = new_recv_chain
    state.recv_n = 0

    # 3. Rotate our own DH.
    new_priv, new_pub = x25519_keypair()
    state.prev_send_n = state.send_n
    state.dh_send = new_priv
    state.dh_send_pub = new_pub
    state.send_n = 0

    # 4. Derive new send chain.
    dh_out2 = x25519_dh(state.dh_send, header.dh)
    new_root2, new_send_chain = kdf_root(state.root_key, dh_out2)
    state.root_key = new_root2
    state.send_chain_key = new_send_chain


# ─── encrypt / decrypt ─────────────────────────────────────────────

def _aead_for(key: bytes) -> ChaCha20Poly1305:
    return ChaCha20Poly1305(key)


def _aead_nonce(message_number: int) -> bytes:
    """ChaCha20-Poly1305 takes a 12-byte nonce. The Double Ratchet
    pattern uses the message number directly because each message
    key is fresh — the (key, nonce) pair never repeats across the
    protocol since the key changes every message."""
    return b"\x00\x00\x00\x00" + struct.pack(">Q", message_number & ((1 << 64) - 1))


def encrypt(state: RatchetState, plaintext: bytes, ad: bytes = b"") -> tuple[Header, bytes]:
    """Encrypt one application message. Returns (header, ciphertext).

    The header MUST be transmitted alongside the ciphertext and the
    receiver MUST pass the same `ad` (associated data) into decrypt
    or AEAD will reject the integrity check.

    The header itself is bound into AD so a man-in-the-middle who
    swaps headers fails verification."""
    if state.send_chain_key is None:
        raise RuntimeError(
            "ratchet not ready to send — call init_alice for initiator,"
            " or wait for first peer message before sending on the responder."
        )
    if state.send_n >= MAX_MSG_PER_CHAIN:
        raise RuntimeError("ratchet: send chain exhausted, must DH-ratchet")
    state.send_chain_key, msg_key = kdf_chain(state.send_chain_key)
    header = Header(
        v=1, flags=0,
        dh=state.dh_send_pub,
        pn=state.prev_send_n, n=state.send_n,
    )
    nonce = _aead_nonce(state.send_n)
    aead_ad = header.encode() + (ad or b"")
    ct = _aead_for(msg_key).encrypt(nonce, plaintext, aead_ad)
    state.send_n += 1
    return header, ct


def _try_skipped(
    state: RatchetState, header: Header, ciphertext: bytes, ad: bytes,
) -> Optional[bytes]:
    """If we previously derived a key for (header.dh, header.n),
    use it once and discard. Returns plaintext or None if no
    skipped key matches."""
    key = (header.dh, header.n)
    msg_key = state.skipped.pop(key, None)
    if msg_key is None:
        return None
    if key in state.decrypted_seen:
        # Replay — drop without consuming.
        return None
    nonce = _aead_nonce(header.n)
    aead_ad = header.encode() + (ad or b"")
    pt = _aead_for(msg_key).decrypt(nonce, ciphertext, aead_ad)
    # v0.20.7 (security audit H2): see RatchetState.decrypted_seen.
    state.decrypted_seen[key] = True
    while len(state.decrypted_seen) > MAX_SKIP_KEYS * 4:
        state.decrypted_seen.popitem(last=False)
    return pt


def _skip_recv_keys(state: RatchetState, until: int) -> None:
    """Advance the current receive chain forward, stashing each
    intermediate message key. Used when a message arrives whose
    n > our recv_n on the SAME chain."""
    if state.recv_chain_key is None or state.dh_recv_pub is None:
        return
    if until > state.recv_n + MAX_SKIP_KEYS:
        raise RuntimeError(
            "ratchet: too many skipped messages requested"
            f" ({until - state.recv_n} > {MAX_SKIP_KEYS})"
        )
    while state.recv_n < until:
        if state.recv_n >= MAX_MSG_PER_CHAIN:
            raise RuntimeError("ratchet: recv chain past safety bound")
        state.recv_chain_key, mk = kdf_chain(state.recv_chain_key)
        state.skipped[(state.dh_recv_pub, state.recv_n)] = mk
        state.recv_n += 1
        _evict_skipped_if_full(state)


def decrypt(
    state: RatchetState, header: Header, ciphertext: bytes, ad: bytes = b"",
) -> bytes:
    """Decrypt one application message. Header + ad must match
    what the sender used; otherwise InvalidTag is raised by AEAD.

    Side effects on success:
      - Advances the receive chain
      - May trigger a DH ratchet step if header.dh is new
      - Stashes any skipped keys we passed over
      - Records (header.dh, header.n) as consumed (replay defence)

    Atomicity (2026-05-21 audit T1-A): any state mutation done before
    the AEAD decrypt MUST be reverted on AEAD failure. Previously
    ``_dh_ratchet`` was run before ``_aead_for(msg_key).decrypt``;
    a forged frame with a random ``header.dh`` mutated ``root_key``,
    ``recv_chain_key``, ``send_chain_key``, ``dh_send`` etc. before
    the AEAD tag check failed — and the corrupted state was committed,
    leaving the channel unable to decrypt the next legitimate frame.
    That's a 1-packet DoS by any network-positioned attacker on a
    paired pair. We now snapshot every field the path may mutate and
    restore them on any failure (including AEAD ``InvalidTag``).
    The hot path (no DH step, no skipped keys, AEAD succeeds) pays
    one struct-of-scalars assignment for snapshot — negligible.
    """
    # Replay check before any state mutation.
    seen_key = (header.dh, header.n)
    if seen_key in state.decrypted_seen:
        raise RuntimeError("ratchet: replayed message rejected")
    # 1. Try the skipped-key cache first (OOO delivery). Note that
    # _try_skipped pops the key BEFORE its AEAD verify; we handle
    # that revert below via the same snapshot.
    _snap_skipped = state.skipped.copy()
    pt = _try_skipped(state, header, ciphertext, ad)
    if pt is not None:
        return pt
    # No skipped-key match; _try_skipped's pop was a no-op for the
    # subsequent paths, but the snapshot is cheap to hold.

    # 2-3. We may need to run a DH ratchet step and/or skip-recv-keys.
    # Both mutate state. Snapshot every scalar BEFORE either runs so
    # we can revert on AEAD failure.
    _snap_root_key = state.root_key
    _snap_recv_chain_key = state.recv_chain_key
    _snap_send_chain_key = state.send_chain_key
    _snap_recv_n = state.recv_n
    _snap_send_n = state.send_n
    _snap_prev_send_n = state.prev_send_n
    _snap_dh_send = state.dh_send
    _snap_dh_send_pub = state.dh_send_pub
    _snap_dh_recv_pub = state.dh_recv_pub

    try:
        # 2. Fresh ephemeral from peer? Run DH ratchet.
        if state.dh_recv_pub != header.dh:
            _dh_ratchet(state, header)
        # 3. Advance the receive chain to header.n, stashing skipped keys.
        if header.n > state.recv_n:
            _skip_recv_keys(state, header.n)
        elif header.n < state.recv_n:
            # An old-chain message? Should have been served from skipped.
            raise RuntimeError(
                f"ratchet: out-of-order delivery on current chain"
                f" (n={header.n} < recv_n={state.recv_n}) — message lost"
            )
        if state.recv_chain_key is None:
            raise RuntimeError("ratchet: receive chain not initialized")
        state.recv_chain_key, msg_key = kdf_chain(state.recv_chain_key)
        nonce = _aead_nonce(header.n)
        aead_ad = header.encode() + (ad or b"")
        pt = _aead_for(msg_key).decrypt(nonce, ciphertext, aead_ad)
    except BaseException:
        # ANY failure (AEAD InvalidTag, RuntimeError from our own
        # validations, asyncio.CancelledError, etc.) reverts every
        # mutation. Without this revert a single forged frame poisons
        # the channel permanently — see T1-A above.
        state.root_key = _snap_root_key
        state.recv_chain_key = _snap_recv_chain_key
        state.send_chain_key = _snap_send_chain_key
        state.recv_n = _snap_recv_n
        state.send_n = _snap_send_n
        state.prev_send_n = _snap_prev_send_n
        state.dh_send = _snap_dh_send
        state.dh_send_pub = _snap_dh_send_pub
        state.dh_recv_pub = _snap_dh_recv_pub
        # Restore the skipped-key dict (preserves order in 3.7+).
        state.skipped.clear()
        state.skipped.update(_snap_skipped)
        raise

    # AEAD verified. Commit the trailing mutations + replay-cache entry.
    state.recv_n += 1
    # v0.20.7 (security audit H2): record the (dh, n) pair in
    # insertion order. On overflow, evict the OLDEST entry — never
    # an arbitrary one. This keeps the replay window deterministic.
    state.decrypted_seen[seen_key] = True
    while len(state.decrypted_seen) > MAX_SKIP_KEYS * 4:
        state.decrypted_seen.popitem(last=False)
    return pt


# ─── ergonomic constructors ────────────────────────────────────────

def init_pair(shared_secret: bytes) -> tuple[RatchetState, RatchetState]:
    """Convenience: build matched Alice + Bob states from one
    shared secret. Generates Bob's prekey internally and threads
    his public key into Alice. The first send must be Alice → Bob;
    Bob can only respond after receiving."""
    bob_sk, bob_pk = x25519_keypair()
    alice = init_alice(shared_secret=shared_secret, peer_pub=bob_pk)
    bob = init_bob(shared_secret=shared_secret, dh_priv=bob_sk)
    return alice, bob
