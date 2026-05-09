# Security — threat model + hardening contract

Status: living document. The companion to
[`SOVEREIGNTY.md`](./SOVEREIGNTY.md): where Sovereignty says
"don't trust corporations," Security says "match or exceed every
real security primitive corporations provide, and document every
threat model with the countermeasure that addresses it."

Last updated: 2026-05-09 (v0.20.7 audit honesty pass).

---

## Storage tiers and where each defense applies

The threat-model statuses below distinguish two implementation tiers,
because the same product ships in two shapes that have very different
at-rest stories. Mixing the two created false-positive ✅ cells in
earlier revisions of this doc; the audit on 2026-05-09 corrected them.

**Tier A — Browser PWA (planned, partial).** The PWA shell described
in `ARCHITECTURE.md` v0.16+ is the load-bearing target for OPFS at-rest
encryption, Argon2id passphrase derivation, plausibly deniable storage,
and Service-Worker signature verification of update bundles. As of
v0.20.7 the PWA shell renders, browser-as-peer transport is alive over
WebRTC, but the at-rest encryption + signature verification primitives
are still in flight (sw.js does not yet pin or verify a release pubkey;
OPFS encryption is on the v0.21+ track). T2 / T4 / T5 cells that read
✅ in earlier revisions of this doc were forward-looking commitments,
not currently shipped guarantees.

**Tier B — Desktop daemon (alive).** The Python daemon shipped via
`pip install one_link` or the bundled binary is what most users run
today. Its at-rest story is intentionally narrower than the PWA story
above: the SQLite state file, blob store, UI bearer token, and Ed25519
identity key live cleartext on disk under the user-account directory
by default. The user can encrypt the identity key by setting
`ONE_LINK_PASSPHRASE` before launch (PBKDF2-wrapped PKCS#8); the rest
of the at-rest scope is documented as future work.

**What this means for each threat status below.** Status cells that
explicitly call out browser-PWA-only mechanisms (OPFS, Web Crypto
non-extractable keys, Service Worker pinning) should be read as
"defended in Tier A once those primitives ship; defended in Tier B
only by user-account isolation today." Where this distinction matters,
the threat row notes it inline.

---

## The tension this document resolves

Corporations provide some real security:

- **Hardware-backed key storage.** Apple's Secure Enclave and
  Google/Samsung's StrongBox keep key material in tamper-resistant
  silicon, never visible to JavaScript or even to the OS proper.
- **Hardware RNG.** Dedicated entropy sources on modern phone
  chipsets are good (modulo the perennial "is it backdoored"
  question, which we hedge with multi-source mixing).
- **OS-level patching.** Apple and Google fix CVEs in WebKit,
  Blink, the kernel, the driver stack. We benefit by running on
  patched OSes.
- **App Store review.** Imperfect, but it does catch some malware
  before it reaches users.
- **Corporate CAs.** Globally trusted certificate authorities
  underpin HTTPS. Without them, every connection is an
  authentication problem.

Stripping corporate substrate without engineering equivalents
would degrade real security. That's not what `SOVEREIGNTY.md`
asks for. The contract is:

> **Defang corporate influence over our users; preserve and
> exceed corporate security primitives.**

This document specifies what we accept from the substrate
(because it's real security), what we replace because we can do
better, and what we add that no corporation provides.

---

## Threat model

We commit to defending against the following adversary classes,
in increasing order of capability. A "tier passed" means the
default product is hardened against that class. Hardened tier
extends defenses; air-gap tier extends further.

### T1 — Casual snoop (network-adjacent, passive)

**Capabilities:** can read packets on the same Wi-Fi, on the
same coffee-shop hotspot, or as the user's ISP. Cannot inject;
cannot break TLS.

**Defenses (default tier):**
- All wire traffic is end-to-end encrypted (Double Ratchet 1:1,
  MLS for groups), nested inside TLS for the rendezvous hop.
- Sealed sender: even given the rendezvous traffic, this attacker
  can't tell who is talking to whom.
- Per-message random pseudonyms for outer envelope.

**Status:** ✅ defeated by default.

### T2 — Active network attacker (MITM)

**Capabilities:** can inject, replay, and manipulate packets.
Can attempt to MITM the TLS connection to our CDN.

**Defenses (default tier):**
- Service Worker pins our release Ed25519 public key in source.
  An update fetched over MITM-broken TLS still has to verify
  against the pinned key. Mismatch → SW refuses to install.
  *Tier A status: planned for v0.21+. As of v0.20.7 the SW does
  cache-first asset delivery without pinned-pubkey signature
  verification; release integrity for the PWA path currently
  rests on GitHub release HTTPS plus the multi-mirror parity
  story rather than cryptographic verification.*
- WebRTC DataChannel uses DTLS-SRTP (active negotiation; certs
  exchanged at handshake; tampered offer/answer breaks the
  handshake). *Audit 2026-05-09 finding C1: the daemon-side
  /api/v1/peer-rtc signaling endpoint accepts an unsigned answer,
  and neither side cross-checks the SDP a=fingerprint against the
  Ed25519 identity, so a network-on-path attacker can MITM the
  DataChannel. Active fix in flight; until it lands, browser-as-
  peer should be treated as MITM-vulnerable on hostile networks.*
- Wire frames carry HMAC over content + sequence; replay attacks
  fail. *Daemon-to-daemon channel: solid (transcript-bound AEAD
  AAD plus required CAPS channel_bind as of v0.20.7 fix H1).*
- Subresource Integrity on every external script (none currently;
  future-proofed).

**Status:** ✅ defeated for daemon-to-daemon channels at v0.20.7
(transcript-bound AEAD, transcript-bound CAPS, no third-party
JS / scripts). 🔄 in progress for browser-as-peer transport
(audit C1) and Service Worker update integrity (audit C2). The
release process compensates for the SW gap today; the WebRTC
gap requires the C1 fix before it becomes "defeated".

### T3 — Compromised peer (a "friend" turns)

**Capabilities:** holds valid pairing credentials, can send
arbitrary messages claiming to be themselves, can read everything
the user sent them historically.

**Defenses (default tier):**
- Forward secrecy via Double Ratchet: even compromise of the
  peer's CURRENT keys doesn't expose old messages, because old
  ratchet keys are deleted. *The Double Ratchet primitive ships
  at `src/one_link/double_ratchet.py` and the activation pathway
  is wired into the channel. Audit 2026-05-09 finding C4: the
  daemon currently filters `double_ratchet_v1` out of advertised
  CAPS, so the activation half-step never fires and channels
  remain on the static AEAD keys derived once at handshake. DR
  activation ships next.*
- Post-compromise security: future messages between user and a
  not-yet-compromised peer recover security after the ratchet
  steps forward. *Same caveat as above; PCS depends on DR being
  active in the channel.*
- Block / unpair: cryptographic cutoff is the goal; today
  `revoke_peer` is app-state only (drops the outbound session and
  the DB trust flag). Once DR activates, a forced ratchet step
  on block will give the documented "old session keys are useless"
  guarantee. Audit 2026-05-09 finding H14.
- Capability gate: as of v0.20.7 fix C3, SAS-pair finalize
  installs a deny-by-default per-peer capability policy
  (chat-only). A compromised paired peer cannot drive file
  transfer, folder sync, or group operations without explicit
  user consent for each capability.
- Verifiable revocation log (v1.x): users can publish a
  revocation that propagates through the network; their other
  contacts cryptographically refuse messages from the revoked
  peer key.

**Status:** 🔄 partially contained at v0.20.7. The deny-by-default
capability policy (C3 fix) limits a compromised peer's reach to
chat-only without user consent. Forward secrecy + post-compromise
security + cryptographic block-cutoff land when the DR activation
ship completes (in flight). Until then a peer-key compromise
exposes captured ciphertext history under that peer's static key.

### T4 — Lost / stolen device

**Capabilities:** physical possession of a locked phone. Cannot
break Secure Enclave but may attempt brute-force on the screen
lock.

**Defenses (Tier A — browser PWA, planned for v0.16+):**
- Device-bound storage encryption: OPFS + IDB at-rest AES-GCM
  with a key derived (Argon2id, ≥256MB memory, ≥3 iterations) from
  a passphrase the user sets at install. A physical exfiltration
  of OPFS yields ciphertext indistinguishable from random.
- The passphrase is required on each app session start; the
  derived key never persists to disk.
- Optional Touch ID / Face ID protected unlock (when Secure
  Enclave present): the enclave protects a second symmetric key
  that decrypts the on-disk key; biometric unlock on the device
  is the only way to access it. **This IS using corporate
  hardware as a security primitive — it's free security with no
  privacy cost, since the enclave doesn't phone home.**
- Threshold-of-N device cluster (v0.17.0+): a lost device is
  signed-out remotely from any 2 of the user's other devices.
  Its share of the master secret is revoked; the cluster reseals.

**Defenses (Tier B — desktop daemon, alive at v0.20.7):**
- The SQLite state file, blob store, and UI bearer token live
  cleartext on disk under the user-account directory. The
  user-account isolation provided by the OS is the primary
  defense. As of v0.20.7 (audit fix H22) `PRAGMA secure_delete=ON`
  makes the disappearing-messages reaper actually scrub plaintext
  from freed pages + WAL.
- The Ed25519 identity key is unencrypted PEM by default. Setting
  `ONE_LINK_PASSPHRASE` before launch wraps it with PBKDF2-derived
  PKCS#8 encryption (transparent migration from unencrypted on
  next successful load).
- File-mode 0600 on POSIX (audit fix H19 makes the write atomic).
  On Windows, `os.chmod` is a partial story; the inherited
  `%APPDATA%` ACL is the practical defense until the explicit
  user-only DACL ships (audit finding H3).

**Status:** 🔄 contained for Tier A once OPFS encryption ships
(planned v0.16+). Partially contained for Tier B at v0.20.7: the
disappearing-messages contract is honored, identity-key passphrase
is opt-in via `ONE_LINK_PASSPHRASE`, but the at-rest story for
chat bodies + group chain keys + UI token is still user-account
isolation rather than ciphertext-on-disk. Audit 2026-05-09
finding C5 tracks the gap.

### T5 — Compromised CDN / mirror

**Capabilities:** controls the bytes served at the user's
canonical install URL. Could push a backdoored bundle.

**Defenses (default tier):**
- Pinned release public key in source. The Service Worker checks
  every update's signature against it. A backdoored bundle from
  a compromised mirror fails signature → install refused.
- Reproducible builds: any third party can clone source + build
  + verify hash. Community watchdogs.
- SLSA-3 build provenance attestation published with every
  release.
- Multi-source mirrors (v0.18.0+): user can fetch from
  whichever they trust most; signature check is the same.

**Status:** 🔄 in progress. The pinned-pubkey + signature
verification path described above is the v0.21+ design; today
(v0.20.7) `web/sw.js` is plain cache-first with no crypto, and
the published binaries / pip wheels rely on GitHub release
HTTPS plus the multi-mirror parity story rather than
cryptographic signature verification at the client. Audit
2026-05-09 finding C2 tracks the gap. Multi-maintainer threshold
signing (T6 below) is the structural defense that, once SW
verification ships, blocks the compromised-mirror path.

### T6 — Compromised maintainer key

**Capabilities:** has a valid release-signing key; can sign a
backdoored release.

**Defenses (default tier):**
- Multi-maintainer threshold release signing. A release is valid
  only if signed by ≥2-of-N maintainer keys. A single compromised
  key can't ship malware.
- Reproducible builds: a backdoored release whose source doesn't
  reproduce gets caught by community rebuilders within a release
  cycle.
- Warrant canary: the absence of a regularly-signed canary
  signals "something happened to a maintainer."

**Status:** ✅ defeated by structural threshold requirement.

### T7 — Compromised browser engine (RCE in WebKit / Blink)

**Capabilities:** arbitrary code execution within the browser's
sandbox (e.g., via a 0-day in WebKit). Cannot escape the OS sandbox
without an additional escape vuln.

**Defenses (default tier):**
- Content Security Policy headers: `default-src 'self'; script-src
  'self' 'wasm-unsafe-eval'; connect-src 'self' wss: https:;
  style-src 'self' 'unsafe-inline'`. No third-party JS / CSS / fonts.
- Trusted Types policy where supported.
- All sensitive crypto runs in a Web Worker for isolation; the
  main thread can't read worker memory.
- Identity key material lives in non-extractable Web Crypto
  CryptoKey objects when possible (AES-GCM keys are extractable
  by spec, but Ed25519 / ML-KEM private keys can be marked
  non-extractable). Even RCE in the main thread can't read them.
- OPFS-stored data is encrypted; even read access via RCE yields
  ciphertext.

**Status:** mitigated. RCE in the browser engine is out-of-scope
for us to fix (that's Apple/Google/Mozilla's job), but our
hardening reduces the blast radius significantly. v0.20.7 audit
fixes H9 (CSP on `/`) and H10 (Host + Origin checks defending
against DNS-rebinding) shipped; Trusted Types is still aspirational
and many of the worker-isolation primitives are part of the
Tier A browser PWA roadmap rather than the Tier B daemon today.

### T8 — Compromised OS

**Capabilities:** root access to the phone OS; can inspect any
process memory; can extract Secure Enclave-protected data only via
the legitimate API (the enclave itself remains tamper-resistant).

**Defenses (hardened tier):**
- Secure Enclave-backed keys are still safe — the enclave's whole
  purpose is to defeat OS root access.
- For the parts of state that aren't enclave-protected: OPFS at
  rest is encrypted; the in-memory derived key is wiped on app
  background. A snapshot of the OS state at lock-screen yields
  ciphertext.
- Plausibly deniable storage: outer file headers don't identify
  content type. A forensic exfiltrator without the unlock secret
  sees opaque bytes.

**Status:** partially mitigated. A compromised OS during an
active session is a hard problem; we minimize live memory exposure
(crypto in workers, key material non-extractable where possible)
but don't claim full immunity.

### T9 — State-actor adversary

**Capabilities:** can compel CAs to issue fake certs; can monitor
all internet traffic globally; can compel app store removal; can
compel cloud providers to disclose stored data.

**Defenses (hardened tier + air-gap tier):**
- All real defenses above, plus:
- Tor-routed signaling (hardened tier).
- `.onion` mirror distribution (no DNS, no clearnet visible).
- Cover traffic + mix-net (hardened tier default-on): traffic
  shape uninformative to bulk surveillance.
- IPFS distribution: content-addressed, no canonical CDN.
- Air-gap tier: no internet at all. BLE/LAN/USB pairing only.
- Threshold-of-N identity: no single compelled-disclosure target.
- AGPLv3 license + non-profit trademark holding +
  refuse-acquisition charter (`GOVERNANCE.md`): no corporate entity
  can be compelled to ship a backdoor on our behalf.

**Status:** hardened tier defeats most observable
state-actor capabilities; air-gap tier defeats them all by
removing internet.

---

## What we accept from corporate substrate (because it's real security)

We use these hardware/OS-level primitives as **opt-in security
upgrades**, never as the only line of defense, and never letting
them communicate with us back-side:

1. **Secure Enclave / StrongBox for key wrapping.** When Touch ID /
   Face ID protected key storage is available, we offer it as a
   convenience. The enclave protects a key that wraps our OPFS
   encryption key. **The enclave doesn't talk to Apple's servers
   about our key — it's a local primitive.** Free security.

2. **Hardware RNG via `crypto.getRandomValues()`.** Mixed with
   multi-source entropy (touch coordinates, audio noise floor,
   network jitter, accelerometer) via HKDF. The product is secure
   if any one source is non-adversarial. The hardware RNG is one
   of the better sources; we use it but never alone.

3. **OS-level CVE patching.** Out of our control; we benefit when
   the user keeps their OS up to date. We surface a hint in
   diagnostics when the OS is on a known-vulnerable version, but
   we can't force.

4. **Sandboxing (browser, OS).** The browser sandbox is a real
   defense against malicious websites. We benefit by running in
   it. Our CSP further restricts our own attack surface within
   the sandbox.

5. **DTLS-SRTP (in WebRTC).** The browser's WebRTC stack does the
   transport-layer encryption. We layer Double Ratchet on top
   (defense in depth) but DTLS handles the network-level attacker
   without our needing to reimplement it.

6. **TLS to the rendezvous.** Let's Encrypt cert + browser TLS
   stack provides the network-layer encryption to the rendezvous.
   We layer sealed sender on top to ensure the rendezvous itself
   can't read what passes through.

What we **don't** accept:
- iCloud Keychain / Google Password Manager **default** sync of
  identity. (Opt-in only; default is OPFS.)
- Apple Push Notification Service **default** routing of message
  alerts. (Opt-in only.)
- Single corporate CA as the **only** trust root. (Pinned release
  key supplements.)

---

## Cryptographic correctness

This is where security engineering gets surgical. Every primitive
we ship has to be correct.

### Constant-time everything

All cryptographic operations + their wrappers must be
constant-time and constant-memory. Pinned in tests:

- AES-GCM via Web Crypto: browser-provided; assumed correct (modulo
  CVEs we can't fix). Wrapper code (key wrap/unwrap, IV generation)
  must be constant-time.
- ChaCha20-Poly1305: same.
- Ed25519 + X25519: Web Crypto where available; `@noble/curves`
  fallback (it's audited constant-time).
- ML-KEM, ML-DSA: `@noble/post-quantum` (audited constant-time).
- HMAC, HKDF: Web Crypto. Wrapper constant-time.

### Nonce / IV uniqueness

The single most common cryptographic failure. Defenses:

- AES-GCM nonces: 96-bit, deterministic counter for sequential
  ratchet keys, random for one-shot. Counter is per-key, not
  per-message. Reuse → game over for that key, so we abort if
  counter wraps.
- ChaCha20-Poly1305 nonces: 192-bit XChaCha20 variant, random.
  Birthday bound is comfortable (~2^96 messages before collision
  risk).
- WebRTC DataChannel sequence numbers: tracked per session.
- Tests: a "nonce reuse detector" that tracks (key, nonce) pairs
  in a test database and fails any message that reuses one.

### Forward secrecy + post-compromise security

- Double Ratchet (Signal protocol) for 1:1, **always-on** (no
  "advanced" toggle).
- MLS for groups (RFC 9420), TreeKEM-based, automatic key rotation
  on every member add/remove, application keys rotate per epoch.
- Old keys deleted from memory and storage as soon as they're no
  longer needed. Forward-secrecy regression test: simulate
  compromise of current state; verify old messages can't be
  decrypted.

### Key separation

Every cryptographic context uses a distinct key derived via HKDF
with a context-binding `info` parameter. No key is reused across
purposes. Specifically:

- Identity signing key (Ed25519) ≠ identity encryption key (X25519).
- Identity encryption key ≠ session ratchet key.
- Session ratchet key ≠ chunk encryption key.
- Per-conversation, per-direction, per-purpose subkeys via HKDF.

### Post-quantum hybrid

From v0.21.0 onward, every long-term key agreement is hybrid
ML-KEM-768 + X25519. Even if a quantum attacker breaks X25519 in
2030, captured 2026 traffic remains opaque because ML-KEM-768
holds. Reuses
[`std/crypto/quantum_safe.cl`](../../coherence_lang/coherence_lang/bootstrap/stdlib/std/crypto/quantum_safe.cl)
where mature, else `@noble/post-quantum`.

---

## Runtime hardening

Beyond cryptographic correctness, the running app needs to be
hard to exploit even given a vulnerability.

### Content Security Policy

Strict CSP shipped as a `<meta>` tag and HTTP header:

```
default-src 'self';
script-src 'self' 'wasm-unsafe-eval';
style-src 'self' 'unsafe-inline';
img-src 'self' data: blob:;
connect-src 'self' wss: https:;
worker-src 'self' blob:;
frame-src 'none';
object-src 'none';
base-uri 'self';
form-action 'none';
```

No inline scripts, no eval (except wasm), no third-party origins,
no iframes, no plugins. A successful XSS injection has nothing to
exfiltrate to.

### Trusted Types

Where supported (Chrome, Edge), enforce that all DOM-text-as-HTML
sinks go through a sanitizer policy. Defense against DOM-based
XSS that survives CSP.

### Subresource Integrity

If we ever load a third-party resource (we don't, currently), it
ships with `integrity="sha384-..."` so a compromised CDN can't
replace it.

### Memory safety

JavaScript / WebAssembly are memory-safe by construction. No
buffer overflows, no use-after-free. Our crypto code prefers
audited libraries (`@noble`) over hand-rolled implementations.

### Sensitive material lifecycle

- Identity keys: non-extractable Web Crypto CryptoKey objects
  where possible. Generated in workers; never handled by the main
  thread.
- Session keys: zeroized when the session closes.
- Passphrase-derived keys: zeroized on app background. App
  re-prompts on resume.
- Clipboard: never write secrets. Copy-fingerprint copies the
  fingerprint hex; copying the actual key material is not exposed
  in any UI.

### Worker isolation

Crypto operations run in a Web Worker (`worker.js`). The main UI
thread can request operations via postMessage but cannot inspect
the worker's memory. An XSS-style compromise of the main thread
cannot read identity keys from the worker.

### Dependency hygiene

- Zero runtime dependencies on third-party SDKs. Currently shipped:
  `cryptography`, `aiohttp`, `zeroconf`, `click`, `blake3`,
  `platformdirs`, `watchdog`. All open-source, audited, no telemetry.
- For the v0.15.0+ JS bundle: `@noble/curves`, `@noble/hashes`,
  `@noble/post-quantum`, `yjs`. Audited, no telemetry, MIT/Apache.
- Each dependency pinned by exact version + integrity hash.
- `pip-audit` + `npm audit` run in CI; fail-the-build on critical /
  high severity CVE.
- Reproducible builds end-to-end (Python + JS).

---

## Supply chain security

Where the bytes come from is as important as how they're written.

- **Reproducible builds.** Source → bundle is deterministic. Any
  third party can rebuild and verify.
- **SLSA-3 attestations.** Build provenance signed by HSM-bound
  CI keys.
- **Multi-maintainer threshold release signing.** ≥2-of-N
  maintainers' Ed25519 signatures required to ship a release.
- **Pinned release public key** in source. Service Worker verifies
  every update against the pin. CA-MITM cannot ship a working
  update.
- **Mirror diversity.** Releases distributed via GitHub, GitLab,
  Codeberg, IPFS, Tor hidden service, project's own server.
  Cryptographic verification doesn't care which mirror; mirror
  takedowns don't deplatform us.
- **Dependency transparency.** SBOM (CycloneDX) auto-generated and
  published with every release.

---

## Vulnerability response

- **Coordinated disclosure.** A `SECURITY.md` at repo root (separate
  from this design doc) tells researchers how to report. PGP key
  for encrypted reporting. 90-day disclosure window standard.
- **CVE response process.** A documented runbook: triage → patch →
  ship → backport → publish advisory → update warrant canary if
  applicable.
- **Bug bounty.** Funded by donations; no corporate sponsor with
  influence. Tiered payouts for severity.
- **Penetration test cadence.** Annual external pentest by a
  reputable firm. Findings published after fix.
- **Cryptographic review.** Major crypto changes (Double Ratchet
  activation, MLS landing, post-quantum hybrid) get external
  cryptographer review before ship.

---

## What we promise vs. what we can't promise

**We promise (v0.20.7 — what's actually shipped today):**
- Source is open and auditable.
- Reproducible builds (planned; pinning + SBOM gates landed at
  v0.7.2).
- The cryptographic primitives we ship are vetted libraries
  (`cryptography` + audited `@noble/*` for the JS path) used in
  constant-time, with key separation and unique nonces. The
  Double Ratchet primitive ships at `src/one_link/double_ratchet.py`
  and is wired into the channel; activation is gated behind audit
  finding C4 and lands next.
- No analytics, telemetry, third-party SDK, or phone-home of any
  kind from the daemon or PWA shell. WebRTC's STUN traffic is the
  one third-party touchpoint; that's documented in
  `architecture.md` and tunable.
- Every layer of corporate substrate has a documented defang
  (some shipped, some in flight; see the matrix above).
- T1 (casual snoop) defeated.
- T2 (active MITM) defeated for daemon-to-daemon channels;
  browser-as-peer transport requires the C1 fix to fully defeat.
- T3 (compromised peer) bounded to chat-only by the deny-by-
  default capability gate (v0.20.7 fix C3); forward secrecy +
  post-compromise security + cryptographic block-cutoff arrive
  with the C4 / H14 ship.
- T4 (lost device): Tier A (browser PWA) defended once the
  OPFS-encryption + Argon2id ship lands. Tier B (desktop daemon)
  protected today by user-account isolation only; identity-key
  passphrase encryption is opt-in via `ONE_LINK_PASSPHRASE`.
- T5-T6 (supply chain): in progress.

**We don't promise:**
- That the at-rest cell for Tier B (desktop daemon) is encrypted
  by default. It isn't, today; user-account isolation is the
  current line of defense. The roadmap to closing this is in
  `docs/ROADMAP.md` under "first-launch lockbox".
- Immunity from a 0-day RCE in WebKit / Blink. (Apple/Mozilla/
  Google's job.)
- Immunity from a fully compromised OS during an active session.
- Anonymity at the network-metadata layer in the default tier
  (default tier still uses the project rendezvous; Hardened or
  air-gap tier is what does this).
- That we'll never ship a bug. (Bugs happen; CVE response process
  exists.)

**We don't promise:**
- Immunity from a 0-day RCE in WebKit / Blink. (Apple/Mozilla/
  Google's job.)
- Immunity from a fully compromised OS during an active session.
- Anonymity at the network-metadata layer in the default tier
  (default tier still uses the project rendezvous; Hardened or
  air-gap tier is what does this).
- That we'll never ship a bug. (Bugs happen; CVE response process
  exists.)

We also don't promise that the user's PHONE is secure. They have
to keep their OS patched and not install malicious apps. We can
strengthen the door of our own house; we can't strengthen the
locks on theirs.

---

## Threat-model coverage matrix

The matrix tracks what's actually shipped at the indicated tier as
of v0.20.7 (2026-05-09). ✅ = defeated as documented. 🔄 = in
progress (design committed; implementation still landing). ⚠️ =
known gap; reading the threat row above describes the compensating
control. Tier A = browser PWA path; Tier B = desktop daemon path;
"Default" sums them (where a threat applies to both, the WORSE
status wins).

| Threat | Default | Hardened | Air-gap |
|---|---|---|---|
| T1 Casual snoop | ✅ | ✅ | N/A |
| T2 Active MITM (daemon channel) | ✅ | ✅ | N/A |
| T2 Active MITM (browser-as-peer) | ⚠️ audit C1 | 🔄 fix in flight | N/A |
| T3 Compromised peer (chat only) | ✅ (cap policy C3) | ✅ | ✅ |
| T3 Compromised peer (FS / PCS) | 🔄 awaits DR activation (C4) | 🔄 | 🔄 |
| T4 Lost device (Tier A — browser PWA) | 🔄 (OPFS + Argon2id v0.16+) | 🔄 (plausibly deniable) | 🔄 |
| T4 Lost device (Tier B — daemon) | ⚠️ user-account isolation only; identity-key passphrase opt-in | ⚠️ same | ⚠️ same |
| T5 Compromised CDN/mirror | 🔄 (audit C2; SW pinning planned) | 🔄 (.onion / IPFS planned) | ✅ (no fetch ever) |
| T6 Compromised maintainer key | 🔄 (threshold-quorum design; not yet enforced) | 🔄 | ✅ |
| T7 Compromised browser engine | mitigated (CSP on `/` + `/peer` at v0.20.7) | mitigated (Trusted Types aspirational) | mitigated |
| T8 Compromised OS (Tier A) | mitigated (Secure Enclave on) | mitigated (no Secure Enclave reliance) | mitigated |
| T8 Compromised OS (Tier B) | ⚠️ keys swappable to disk; no mlock yet | ⚠️ same | ⚠️ same |
| T9 State actor (passive global obs) | partial (sealed sender planned; rendezvous still seen) | 🔄 (Tor + cover traffic planned) | ✅ (no internet) |
| T9 State actor (active disruption) | partial (no app store; signed updates pending C2) | 🔄 | ✅ |

The cells that read ✅ in the 2026-05-08 revision of this doc and
now read 🔄 / ⚠️ were not regressions in the code; they were
overstated promises. The 2026-05-09 audit identified five critical
gaps (C1-C5 in the audit findings file) and the project is shipping
fixes for all of them across the v0.20.7 → v0.21 cycle. Bundles 1-6
of those fixes shipped on 2026-05-09 (commits `8857bcf`, `cd64bd6`,
`e56e7ce`, `9a880f7`, `9f5a137`, `8a2cb1d` — 32 audit findings closed).

---

## Audit cadence

Per `PRINCIPLES.md`, every quarter:

1. Re-read this document. Has the threat model expanded? (New
   adversary capabilities, new attack patterns published, new CVE
   classes.)
2. Re-test the cryptographic primitives. Run nonce-reuse detector
   over recent code. Verify constant-time tests still pass.
3. Re-verify reproducible builds: clone HEAD, build, hash matches
   latest release.
4. Re-publish the warrant canary (also tracked in `GOVERNANCE.md`).
5. External pentest: annual. Cryptographic review: per-major-crypto-
   change.
6. Publish a quarterly "Security state" summary on the project
   website. What we patched, what threats we updated against, what
   was found in the last pentest.

A security document that doesn't get audited becomes
decoration. **Audit this with religious discipline.** This is the
floor of the user trust we asked for; we honor it by checking the
floor regularly.
