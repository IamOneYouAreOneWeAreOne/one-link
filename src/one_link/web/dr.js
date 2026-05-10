// Signal-style Double Ratchet — pure WebCrypto port of one_link.double_ratchet
//
// v0.20.7 (security audit H7): the desktop daemon's Python ratchet ships
// forward secrecy + post-compromise security on the channel transport.
// The browser-as-peer (DataChannel) transport rode plain DTLS with no
// app-layer key rotation, so a single private-key compromise (e.g. the
// browser's IndexedDB-stored Ed25519 priv) decrypted every captured DC
// frame retroactively. SECURITY.md §T3 claimed "Double Ratchet on top of
// DTLS-SRTP for defense in depth"; on the daemon path that was true,
// on the browser-as-peer path it was aspirational.
//
// This module closes that gap. It mirrors the Python double_ratchet.py
// algorithm exactly, with two intentional substitutions for the
// browser primitive surface:
//
//   - **AEAD: AES-GCM-256** instead of ChaCha20-Poly1305. WebCrypto
//     (Chrome / Safari / Firefox baseline) does not expose ChaCha20-
//     Poly1305 directly; AES-GCM is the WebCrypto-native authenticated
//     encryption with comparable security and ubiquitous hardware
//     support (AES-NI / ARM crypto extensions). The Python daemon-side
//     adapter for the JS-DR transport uses the matching AES-GCM
//     variant; both ends stay in lock-step.
//
//   - **DH: WebCrypto X25519** (Chrome 124+, Safari 17+, Firefox 130+).
//     Same curve, same RFC 7748 cofactor handling. Small-order points
//     produce a 32-zero shared output which we explicitly reject —
//     same defense as the Python `x25519_dh`.
//
// Header wire format is identical to Python (42 bytes, big-endian):
//
//     u8  v        version  (1)
//     u8  flags    reserved (0)
//     [32]bytes dh        sender's X25519 ephemeral pubkey
//     u32 pn       prior chain length
//     u32 n        msg num on current chain
//
// AAD into the AEAD = encoded(header) || transcript_hash. The
// transcript_hash is the channel-handshake binding from the outer
// DTLS / pair flow, so a frame spliced from one channel into another
// fails verification.
//
// Replay defence + skipped-key cap are bounded the same way as the
// Python impl: MAX_SKIP_KEYS=1000, MAX_MSG_PER_CHAIN=2^32. Out-of-
// order delivery up to MAX_SKIP_KEYS ahead of recv_n is tolerated.
//
// API:
//
//     await initAlice({ sharedSecret, peerPub })  -> state
//     await initBob({ sharedSecret, dhPriv })    -> state
//     await encrypt(state, plaintext, ad)         -> { header, ciphertext, nextState }
//     await decrypt(state, header, ciphertext, ad)-> { plaintext, nextState }
//
// Where:
//   sharedSecret: Uint8Array(32) — initial root key from prior handshake
//   peerPub:      Uint8Array(32) — recipient's X25519 ephemeral pub
//   dhPriv:       CryptoKey       — Bob's X25519 priv held until first recv
//   plaintext, ciphertext, ad: Uint8Array
//   header:       Uint8Array(42)
//   state:        opaque object (do not mutate; returned next state replaces it)

export const HEADER_LEN = 42;
export const MAX_SKIP_KEYS = 1000;
export const MAX_MSG_PER_CHAIN = 1 << 30;  // 2^30, safely below JS 32-bit
export const HKDF_LABEL_ROOT = new TextEncoder().encode("OL1/dr/root|");
export const HKDF_LABEL_CHAIN = new TextEncoder().encode("OL1/dr/chain|");

const ZERO32 = new Uint8Array(32);

// RFC 7748 §6.1 small-order point blocklist (subset; the all-zero output
// check below catches the rest). Mirror of double_ratchet.py.
const _SMALL_ORDER = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
  "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
];
const _SMALL_ORDER_SET = new Set(_SMALL_ORDER);

function _hex(u8) {
  let s = "";
  for (const b of u8) s += b.toString(16).padStart(2, "0");
  return s;
}

function _eq(a, b) {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i++) if (a[i] !== b[i]) return false;
  return true;
}

function _concat(...arrs) {
  let total = 0;
  for (const a of arrs) total += a.byteLength;
  const out = new Uint8Array(total);
  let o = 0;
  for (const a of arrs) {
    out.set(a, o);
    o += a.byteLength;
  }
  return out;
}

// ── primitives ─────────────────────────────────────────────────────

async function _hkdf(material, { salt, info, length = 32 }) {
  const baseKey = await crypto.subtle.importKey(
    "raw", material, { name: "HKDF" }, false, ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info },
    baseKey,
    length * 8,
  );
  return new Uint8Array(bits);
}

async function _hmacSha256(key, data) {
  const k = await crypto.subtle.importKey(
    "raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", k, data);
  return new Uint8Array(sig);
}

export async function kdfRoot(rootKey, dhOutput) {
  const out = await _hkdf(dhOutput, {
    salt: rootKey, info: HKDF_LABEL_ROOT, length: 64,
  });
  return [out.slice(0, 32), out.slice(32, 64)];
}

export async function kdfChain(chainKey) {
  const next = await _hmacSha256(chainKey, new Uint8Array([0x02]));
  const msg = await _hmacSha256(chainKey, new Uint8Array([0x01]));
  return [next, msg];
}

// ── X25519 ─────────────────────────────────────────────────────────

export async function x25519Keypair() {
  const kp = await crypto.subtle.generateKey(
    { name: "X25519" }, true, ["deriveBits"],
  );
  const pubRaw = await crypto.subtle.exportKey("raw", kp.publicKey);
  return { priv: kp.privateKey, pub: new Uint8Array(pubRaw) };
}

export async function x25519DH(priv, peerPub32) {
  if (peerPub32.byteLength !== 32) {
    throw new Error("ratchet: peer X25519 pub must be 32 bytes");
  }
  if (_SMALL_ORDER_SET.has(_hex(peerPub32))) {
    throw new Error("ratchet: peer X25519 pub is a known small-order point");
  }
  const peerKey = await crypto.subtle.importKey(
    "raw", peerPub32, { name: "X25519" }, false, [],
  );
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "X25519", public: peerKey }, priv, 256,
  );
  const shared = new Uint8Array(sharedBits);
  if (_eq(shared, ZERO32)) {
    throw new Error("ratchet: peer X25519 produced zero shared secret");
  }
  return shared;
}

// ── AEAD: AES-GCM-256 (WebCrypto native; substituted for ChaCha20-
//         Poly1305 because WebCrypto doesn't expose ChaCha20-Poly1305
//         directly. AES-GCM gives equivalent IND-CCA security with
//         hardware acceleration on every modern CPU.) ───────────────

async function _aeadKey(rawKey32) {
  return await crypto.subtle.importKey(
    "raw", rawKey32, { name: "AES-GCM" }, false, ["encrypt", "decrypt"],
  );
}

// We derive the 12-byte nonce deterministically from a 64-bit counter
// (LE) padded to 12. Combined with the per-direction msg_key (which
// is itself a fresh HMAC output every send), the nonce never repeats
// under the same key — same property as the Python impl.
function _nonceFromN(n) {
  const buf = new Uint8Array(12);
  // Little-endian u64 in the LOW 8 bytes; high 4 stay zero.
  let v = BigInt(n);
  for (let i = 0; i < 8; i++) {
    buf[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return buf;
}

async function _aeadEncrypt(msgKey, plaintext, ad, n) {
  const k = await _aeadKey(msgKey);
  const iv = _nonceFromN(n);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: ad },
    k, plaintext,
  );
  return new Uint8Array(ct);
}

async function _aeadDecrypt(msgKey, ciphertext, ad, n) {
  const k = await _aeadKey(msgKey);
  const iv = _nonceFromN(n);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: ad },
    k, ciphertext,
  );
  return new Uint8Array(pt);
}

// ── header ─────────────────────────────────────────────────────────

export function encodeHeader({ v, flags, dh, pn, n }) {
  if (dh.byteLength !== 32) throw new Error("dh must be 32 bytes");
  const out = new Uint8Array(HEADER_LEN);
  const dv = new DataView(out.buffer);
  out[0] = v & 0xff;
  out[1] = flags & 0xff;
  out.set(dh, 2);
  dv.setUint32(34, pn, false);  // big-endian
  dv.setUint32(38, n, false);
  return out;
}

export function decodeHeader(raw) {
  if (raw.byteLength < HEADER_LEN) {
    throw new Error("ratchet: header truncated");
  }
  const dv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  const v = raw[0];
  if (v !== 1) throw new Error("ratchet: unsupported header version " + v);
  return {
    v,
    flags: raw[1],
    dh: raw.slice(2, 34),
    pn: dv.getUint32(34, false),
    n: dv.getUint32(38, false),
  };
}

// ── state ──────────────────────────────────────────────────────────

function _emptyState() {
  return {
    rootKey: null,         // Uint8Array(32)
    dhSendPriv: null,      // CryptoKey
    dhSendPub: null,       // Uint8Array(32)
    dhRecvPub: null,       // Uint8Array(32) | null
    sendChainKey: null,    // Uint8Array(32) | null
    recvChainKey: null,    // Uint8Array(32) | null
    sendN: 0,
    recvN: 0,
    prevSendN: 0,
    skipped: new Map(),    // key=hex(dh)+"|"+n → msgKey Uint8Array(32)
    decryptedSeen: new Map(),  // same key shape → true (insertion order)
  };
}

export async function initAlice({ sharedSecret, peerPub }) {
  if (sharedSecret.byteLength !== 32 || peerPub.byteLength !== 32) {
    throw new Error("sharedSecret + peerPub must be 32 bytes each");
  }
  const state = _emptyState();
  state.rootKey = new Uint8Array(sharedSecret);
  state.dhRecvPub = new Uint8Array(peerPub);
  const { priv, pub } = await x25519Keypair();
  state.dhSendPriv = priv;
  state.dhSendPub = pub;
  const dhOut = await x25519DH(priv, peerPub);
  const [newRoot, newSendChain] = await kdfRoot(state.rootKey, dhOut);
  state.rootKey = newRoot;
  state.sendChainKey = newSendChain;
  return state;
}

export async function initBob({ sharedSecret, dhPriv, dhPub }) {
  if (sharedSecret.byteLength !== 32) {
    throw new Error("sharedSecret must be 32 bytes");
  }
  const state = _emptyState();
  state.rootKey = new Uint8Array(sharedSecret);
  state.dhSendPriv = dhPriv;
  state.dhSendPub = new Uint8Array(dhPub);
  state.dhRecvPub = null;
  return state;
}

// ── encrypt ────────────────────────────────────────────────────────

export async function encrypt(state, plaintext, ad) {
  if (state.sendChainKey === null) {
    throw new Error("ratchet: not ready to send (Bob waiting for Alice's first msg)");
  }
  if (state.sendN >= MAX_MSG_PER_CHAIN) {
    throw new Error("ratchet: send-chain past safety bound");
  }
  const [nextChain, msgKey] = await kdfChain(state.sendChainKey);
  const header = encodeHeader({
    v: 1, flags: 0, dh: state.dhSendPub,
    pn: state.prevSendN, n: state.sendN,
  });
  const aad = _concat(header, ad || new Uint8Array(0));
  const ct = await _aeadEncrypt(msgKey, plaintext, aad, state.sendN);
  const newState = { ...state };
  newState.sendChainKey = nextChain;
  newState.sendN = state.sendN + 1;
  // Don't share the skipped Map across versions accidentally:
  newState.skipped = state.skipped;
  newState.decryptedSeen = state.decryptedSeen;
  return { header, ciphertext: ct, nextState: newState };
}

// ── decrypt ────────────────────────────────────────────────────────

function _seenKey(dh, n) { return _hex(dh) + "|" + String(n); }

async function _trySkipped(state, header, ciphertext, ad) {
  const k = _seenKey(header.dh, header.n);
  const msgKey = state.skipped.get(k);
  if (!msgKey) return null;
  const aad = _concat(encodeHeader(header), ad || new Uint8Array(0));
  const pt = await _aeadDecrypt(msgKey, ciphertext, aad, header.n);
  // Consume the cached key.
  state.skipped.delete(k);
  state.decryptedSeen.set(k, true);
  return pt;
}

async function _skipMessageKeys(state, until) {
  if (state.recvChainKey === null) return;
  while (state.recvN < until) {
    if (state.recvN >= MAX_MSG_PER_CHAIN) {
      throw new Error("ratchet: recv-chain past safety bound");
    }
    if (state.skipped.size >= MAX_SKIP_KEYS) {
      // FIFO eviction.
      const oldest = state.skipped.keys().next().value;
      state.skipped.delete(oldest);
    }
    const [nextChain, msgKey] = await kdfChain(state.recvChainKey);
    const dh = state.dhRecvPub;
    state.skipped.set(_seenKey(dh, state.recvN), msgKey);
    state.recvChainKey = nextChain;
    state.recvN += 1;
  }
}

async function _dhRatchet(state, header) {
  state.prevSendN = state.sendN;
  state.sendN = 0;
  state.recvN = 0;
  state.dhRecvPub = new Uint8Array(header.dh);
  let dhOut = await x25519DH(state.dhSendPriv, state.dhRecvPub);
  let [newRoot, newRecvChain] = await kdfRoot(state.rootKey, dhOut);
  state.rootKey = newRoot;
  state.recvChainKey = newRecvChain;
  const { priv, pub } = await x25519Keypair();
  state.dhSendPriv = priv;
  state.dhSendPub = pub;
  dhOut = await x25519DH(priv, state.dhRecvPub);
  [newRoot, newRecvChain] = await kdfRoot(state.rootKey, dhOut);
  state.rootKey = newRoot;
  state.sendChainKey = newRecvChain;
}

export async function decrypt(state, header, ciphertext, ad) {
  // Replay check via decryptedSeen.
  const seenK = _seenKey(header.dh, header.n);
  if (state.decryptedSeen.has(seenK)) {
    throw new Error("ratchet: replayed message");
  }
  // Try skipped keys first.
  const skipped = await _trySkipped(state, header, ciphertext, ad);
  if (skipped !== null) {
    return { plaintext: skipped, nextState: state };
  }
  // Mutable working copy — we don't want to mutate the caller's
  // state if any step throws.
  const next = {
    ...state,
    skipped: new Map(state.skipped),
    decryptedSeen: new Map(state.decryptedSeen),
  };
  if (!_eq(header.dh, state.dhRecvPub || new Uint8Array(32))) {
    // New ephemeral from peer → DH ratchet step. Skip-derive keys
    // for any gaps in the OLD recv chain up to header.pn.
    await _skipMessageKeys(next, header.pn);
    await _dhRatchet(next, header);
  }
  // Skip-derive within the CURRENT recv chain up to header.n.
  await _skipMessageKeys(next, header.n);
  // Derive the message key for this counter.
  const [nextChain, msgKey] = await kdfChain(next.recvChainKey);
  next.recvChainKey = nextChain;
  next.recvN += 1;
  const aad = _concat(encodeHeader(header), ad || new Uint8Array(0));
  const pt = await _aeadDecrypt(msgKey, ciphertext, aad, header.n);
  next.decryptedSeen.set(seenK, true);
  // Bound the seen-set with FIFO eviction (4× MAX_SKIP_KEYS — same
  // bound as the Python H2 fix).
  while (next.decryptedSeen.size > MAX_SKIP_KEYS * 4) {
    const oldest = next.decryptedSeen.keys().next().value;
    next.decryptedSeen.delete(oldest);
  }
  return { plaintext: pt, nextState: next };
}
