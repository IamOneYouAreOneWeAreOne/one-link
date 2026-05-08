# Sovereignty — corporate-substrate defang specification

Status: living document. Implementation contract for principle #5
of [`PRINCIPLES.md`](./PRINCIPLES.md).
Last updated: 2026-05-08.

> "For the people" means free of corporations, by default.

This document is the engineering contract behind that statement.
Every layer of corporate substrate One Link sits on, every
mitigation we ship for it, every paranoia tier the user can choose,
specified in detail.

---

## The principle, restated

We can't always eliminate corporate substrate — Apple still made
the phone, Mozilla still made part of the browser engine, ICANN
still runs DNS. But for every layer where a corporation could
insert itself between us and the user, we ship at least one
engineering mitigation that makes using that substrate against our
users prohibitively expensive.

There are two shapes of mitigation:

- **Total elision.** The dependency goes away entirely. Used wherever
  possible. Example: signed `.html` archive on USB instead of CDN.
- **Cost-of-attack escalation.** The dependency stays, but compromising
  it doesn't yield useful access. Example: encrypted Web Push payloads
  mean Apple/Google see "blob arrived," nothing more.

The default user gets convenience. The hardened user gets paranoia.
The air-gap user gets neither corporate nor internet involvement at
all. All three tiers are real, tested, and shipped.

---

## The full corporate-substrate map

Every layer One Link touches, paired with mitigation strategy:

### Browser engine

| What corporations see | Where it lives | Mitigations we ship |
|---|---|---|
| Page load events, JS execution, storage access | Apple WebKit on iOS (forced), Google Blink on Chrome, Mozilla Gecko on Firefox | Avoid fingerprinting APIs (canvas, audio context, fonts, hardware concurrency). Use feature-detection over UA-sniffing. **Capacitor wrapper for Android sideloading + EU alternative app stores.** **Single signed `.html` archive** that runs from `file://` for fully engine-version-pinned deployments. Detect WebKit; degrade gracefully on iOS-specific quirks. |

### DNS

| What corporations see | Where it lives | Mitigations we ship |
|---|---|---|
| Your IP, the domain you looked up, the time you looked it up | ISP DNS, Cloudflare 1.1.1.1, Google 8.8.8.8, ISP-default resolvers | **IPFS distribution** as the canonical fetch path: `ipfs://bafy.../one-link/`. Content hash, not domain name. **`.onion` mirror** (no DNS resolution at all over Tor). **Signed `.html` archive** distribution: download once, run forever from disk; no DNS lookup ever. Document encrypted DNS (DoH) configuration on user platforms; recommend Mullvad / NextDNS / Quad9 endpoints. |

### CDN / hosting

| What corporations see | Where it lives | Mitigations we ship |
|---|---|---|
| Who downloaded the static bundle, when, from what IP | GitHub Pages, Cloudflare, the project's own server | **Multi-source mirror set**: GitHub Pages, GitLab Pages, Codeberg, IPFS, Tor hidden service, project's own server, community-run mirrors. The user can fetch from whichever they trust most. **Subresource Integrity** on every script tag means a compromised mirror can't inject. **Reproducible builds**: clone source, build, compare hash byte-for-byte to the signed release. **`Dockerfile`** for one-command self-hosting on a $5/mo VPS. |

### TLS / Certificate Authorities

| What corporations see | Where it lives | Mitigations we ship |
|---|---|---|
| The CA that issued our cert can revoke it; a compromised CA could issue a fake cert and MITM users | Let's Encrypt (ISRG, non-profit) by default; any CA in theory | **Pinned release public key** in source. Each release is signed by an Ed25519 maintainer key. **Service Worker verifies updates against the pinned key**: a CA-MITM-served fake bundle fails signature check, refuses to install. **HTTP/3 with self-signed cert + cert hash in URL** (like `.onion` semantics) for the hardened tier. |

### OS keychain (iCloud Keychain / Google Password Manager)

| What corporations see | Where it lives | Mitigations we ship |
|---|---|---|
| Encrypted blobs of synced credentials. They can't read them; they store them and notice when you sync them | iCloud Keychain on iOS, Google Password Manager / Samsung Pass on Android | **Identity stored in OPFS**, NOT in the OS keychain. Web Crypto generates the keypair; OPFS stores it; AES-GCM at rest with a key derived (Argon2id) from a passphrase the user sets at install. **Threshold-of-N device bootstrap** (see ARCHITECTURE.md) syncs identity across the user's devices over our own P2P link, not via any cloud. **Passkeys exist as opt-in** for users who specifically want iCloud/Google sync of public credentials and accept the metadata exposure. |

### Push notifications (APNS / FCM)

| What corporations see | Where it lives | Mitigations we ship |
|---|---|---|
| Encrypted payloads (they can't read), but: device + timing of every push, sender pseudonym (default behavior leaks contact graph) | Apple's APNS via web push, Google's FCM via web push | **Off by default**. Prompt the user with a plain-language tradeoff: "background message alerts route a tiny encrypted ping through Apple/Google's servers (they can't read it, but they see when one arrives). Off / On / Tell me more." When enabled, payloads are E2E-encrypted to per-device keys; **per-device rotating pseudonyms** so APNS/FCM can't build a contact graph from "this device gets pushes from these senders." **No-push fallback**: BLE/LAN proximity wakes the SW, no internet path. **Poll-when-on-Wi-Fi** mode: tiny periodic SW background-sync that draws minimal battery and never touches Apple/Google. |

### NTP / OS clock

| What corporations see | Where it lives | Mitigations we ship |
|---|---|---|
| OS time-set by Apple/Google's default NTP source. A clock can be wrong (deliberately or otherwise) and break crypto timestamp validation | OS-default NTP, set on phone setup | **Hybrid Logical Clocks (HLC)** for message ordering, not wall time. Reuses `coherence_lang/std/crdt/causality.cl::HybridLogicalClock`. The OS clock can be 6 months wrong and message ordering still works. Per-message timestamp is HLC, not wall time; wall time is a hint, not authority. |

### Hardware RNG

| What corporations see | Where it lives | Mitigations we ship |
|---|---|---|
| Output of `crypto.getRandomValues()` is OS-implemented; in theory backdoorable | Apple's RNG implementation on iOS, Google's on Android, browser-vendor's underneath | **Multi-source entropy mixing** via HKDF: pointer/touch coordinates + audio API noise floor + network jitter + keystroke timing + accelerometer (when available) + `crypto.getRandomValues()`. Output is secure if **any one** source is non-adversarial. Reuses `coherence_lang/std/crypto/kdf.cl::HKDF` patterns. |

### App store gatekeeping

| What corporations see | Where it lives | Mitigations we ship |
|---|---|---|
| Apple/Google have approval power over native apps; can deplatform | Apple App Store, Google Play | **PWA install path** (manifest + Service Worker + HTTPS) **bypasses both stores entirely**. v1.1+ Capacitor wrappers go through stores for users who want store-discovery, but the same web build is always available outside the stores. **Sideload-friendly Android APK** via F-Droid + direct download. **EU alternative app stores** for iOS via Apple's compelled compliance. |

### STUN servers (WebRTC NAT traversal)

| What corporations see | Where it lives | Mitigations we ship |
|---|---|---|
| Your public IP, that you're attempting a P2P connection at this moment. Does NOT see who you connect to or what content | Public STUN servers (Google, Cloudflare, Mozilla, Twilio, etc.) | **Multi-vendor STUN list** (6+ from 6 different orgs) shipped by default; rotated per session. **User-overridable** via Settings → Network → "Use my own STUN servers." **Same-LAN mode skips STUN entirely** (mDNS-equivalent local-only ICE candidates). **Manual-signaling QR mode**: zero servers, peer A scans peer B's QR-encoded WebRTC offer, B scans A's answer; pure local handshake. |

### Rendezvous (signaling) servers

| What corporations see | Where it lives | Mitigations we ship |
|---|---|---|
| WebRTC offer/answer exchange; presence pings; metadata (who's online when) | Project-hosted rendezvous, self-hosted rendezvous, or none (LAN-only) | **Mix-net cover routing**: signaling messages route through 2-3 hops of volunteer peers, each hop sees only previous + next. Even rendezvous can't profile contact graphs. **Decentralized rendezvous via DHT + gossip** (long-term goal): no central signaling server at all; the network is the rendezvous. **Fixed-rate cover traffic + padded packet sizes**: even an observer with full traffic visibility can't tell when you actually sent something. **Tor routing for hardened tier**: signaling routes through Tor SOCKS proxy. |

---

## The three paranoia tiers

Every user picks one in setup. Tier sets the defaults; individual
toggles override.

### Tier: Default

> "Most people. Convenience-first. Strong defaults."

**Posture:** trust the substrate enough to enable conveniences.
Apple/Google are visible at the metadata layer (timing of pushes,
that you connect to the internet) but never at the content layer.

**Active corporate-touching paths:**
- CDN-served PWA from `https://one-link.example/` (Let's Encrypt cert)
- Multi-vendor STUN for NAT traversal (6 orgs rotated)
- Optional encrypted Web Push (off until user opts in)
- Project-hosted rendezvous for cross-network reach (with cover traffic)

**Inactive:**
- No analytics, no SDK, no fingerprinting, no third-party login,
  no tracking pixel, no telemetry — same as every other tier.

**Use case:** the friend, family member, casual user. They want to
chat with people. They don't care about state-actor adversaries.

### Tier: Hardened

> "Activists, journalists, professionals. Paranoia-first."

**Posture:** assume substrate is adversarial. Trust nothing
corporate. Slower. Battery cost. Fully usable.

**Active corporate-touching paths:**
- Loaded from local `.html` archive (downloaded once, run from disk)
  OR `.onion` mirror via Tor browser
- Self-hosted STUN OR LAN-only mode (no STUN at all)
- No Web Push — open the app to see new messages
- Tor-routed signaling
- Threshold identity across user's devices (no Passkeys, no OS keychain)

**Inactive (additionally):**
- No DNS lookup of project domain
- No CDN-fetched bundle
- No corporate push servers ever

**Use case:** the journalist's source, the activist coordinating in
a hostile country, the professional handling sensitive client data.

### Tier: Air-gap

> "Strict. No internet. Period."

**Posture:** the only acceptable connection is local.

**Active corporate-touching paths:** none, in steady state.

**Inactive:**
- Internet entirely. The app refuses to make any network request
  outside the local network.

**Available channels:**
- BLE proximity pairing (Android web; iOS falls back to QR + ultrasonic)
- LAN mDNS-equivalent peer discovery
- USB transfer of message bundles (export → physical media → import)
- QR-code message exchange (high-density QR encodes 2-3KB; chain
  multiple QRs for longer messages)

**Use case:** physically co-present people who never want any third
party to even know they communicate. Air-gapped operations. Off-grid.

---

## The tier-selector UX

A single screen at first install:

```
┌──────────────────────────────────────────────────┐
│  How private do you want to be?                  │
│                                                  │
│  ◉ Default                                       │
│    Strong privacy. Convenience-first defaults.   │
│    Most people. (Recommended.)                   │
│                                                  │
│  ○ Hardened                                      │
│    Paranoia-first. Slower. Activists,           │
│    journalists, professionals.                  │
│                                                  │
│  ○ Air-gap                                       │
│    No internet ever. Only physically nearby      │
│    people. Ultra-strict.                        │
│                                                  │
│  You can change this later. Settings → Privacy.  │
│                                                  │
│              [ Continue ]                        │
└──────────────────────────────────────────────────┘
```

That's the entire surface for tier selection. The plumbing
underneath — STUN endpoints, push routing, rendezvous mode, Tor
configuration, identity storage choice — is set by the tier.
The user is never asked about Kyber, Dilithium, mix-net hops, or
attestation chains.

The tier is persisted in `chat-prefs` as `paranoia_tier:
"default" | "hardened" | "air-gap"`. Every relevant default in
settings derives from it on read, with explicit per-setting
overrides taking priority.

---

## Tier behavior matrix

For implementers: exact behavioral differences across tiers.

| Capability | Default | Hardened | Air-gap |
|---|---|---|---|
| PWA bundle source | CDN (HTTPS) | `.onion` or local `.html` | Local `.html` only |
| STUN servers | Multi-vendor (6 orgs) | Self-hosted or LAN-only | None (LAN-only) |
| Rendezvous | Project-hosted + cover traffic | Tor-routed + cover traffic | None |
| Cover traffic | Off (battery cost named at opt-in) | On | N/A |
| Web Push | Off until opted in (encrypted, rotating pseudonym) | Always off | N/A |
| Identity storage | OPFS, AES-GCM at rest | OPFS, AES-GCM at rest, plausibly deniable | OPFS, AES-GCM at rest, plausibly deniable |
| Cross-device identity sync | Threshold-of-N over P2P (or opt-in Passkey) | Threshold-of-N over P2P | Threshold-of-N over LAN/USB only |
| BLE proximity pairing | Yes (Android) | Yes (Android) | Yes (Android, primary path) |
| Ultrasonic pairing fallback | iOS | iOS | iOS, primary path |
| Address-book contact discovery | Off (default) or PSI-based opt-in | Off | N/A |
| On-device LLM | Available (auto-activates if WebGPU + battery + thermal allow) | Available | Available |
| Federated learning across user devices | On | On | LAN-only sync |
| Reproducible build verification | Background check on update | Mandatory (refuse-update on mismatch) | Mandatory + manual signature inspection prompt |
| Tor proxy | Off | On (all signaling) | N/A |

---

## Implementation hooks (for the v0.15.0+ ships)

Each defang lands as part of an architectural ship:

| Defang | Ship | Notes |
|---|---|---|
| Multi-vendor STUN list | v0.18.0 | Lands with WebRTC DataChannel transport |
| Same-LAN mode + manual QR signaling | v0.18.0 | Lands with WebRTC |
| Mix-net cover routing | v0.22.0 | Lands with sealed sender + cover traffic ship |
| OPFS identity (no OS keychain default) | v0.16.0 | Lands with OPFS storage layer |
| Threshold-of-N device bootstrap | v0.17.0 | Lands with Passkey integration ship |
| Encrypted optional Web Push | v0.19.0+ | Lands as bg-sync extension |
| HLC for message ordering | v0.23.0 | Lands with CRDT layer; reuses Coherence stdlib HLC |
| Multi-source entropy mixing | v0.16.0 | Lands with at-rest encryption (entropy needed for keys) |
| Signed updates / SW verification | v0.15.0 | Lands with PWA shell |
| IPFS distribution + `.onion` mirror | v0.15.0+ | Build pipeline change; can land alongside any v0.15.x |
| Reproducible builds + SLSA-3 attestation | v0.15.0 | Build pipeline; one-time setup |
| Tor-aware build / Hardened tier | v0.20.0+ | Lands with paranoia tier UX |
| Capacitor sideload build | v1.1+ | Post-PWA-stable |
| Plausibly deniable storage | v0.16.0 | Lands with at-rest encryption |
| Per-device rotating push pseudonym | v0.19.0 | Lands with Web Push integration |
| Decentralized rendezvous via DHT | v1.2+ | Long-term; replaces project-hosted |

---

## What the user sees vs what we ship

The point of all this engineering is **the user sees one tier-
selector at install, then nothing else about corporations.** The
plumbing delivers the right paranoia level for them. They don't
need to understand mix-nets, Argon2, Kyber, or HKDF.

For users who want to know more, every layer above is documented
publicly (this file, plus inline help text per setting) and every
mitigation is verifiable in source. Trust by transparency, not by
decoration.

---

## Audit cadence

Per `PRINCIPLES.md`, every quarter:

1. Re-read this document. Has any new layer of corporate substrate
   crept in via a feature ship? File a defang debt ticket.
2. Pick one mitigation. Has it bit-rotted (e.g., a STUN endpoint
   went down; the IPFS mirror lost pinning)? Fix.
3. Re-test the Hardened tier and Air-gap tier end-to-end. Both must
   remain real and usable, not theoretical.
4. Re-publish the warrant canary.

A sovereignty document that doesn't get audited becomes
decoration. Audit this.
