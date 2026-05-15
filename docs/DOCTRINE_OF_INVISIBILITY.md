# Doctrine of Invisibility

> **Status:** Normative. Every PR is reviewed against this document.
> Adding a new forbidden surface costs nothing. Removing one requires
> a written exception per §6.3.

> **Companion to:**
> [LIVING_PRESENCE_ARCHITECTURE.md](LIVING_PRESENCE_ARCHITECTURE.md) — the
> architecture that makes invisibility possible.
> [PRINCIPLES.md](PRINCIPLES.md) — project-wide engineering principles.

> **The discipline of invisibility is half the build.** Every settings
> toggle we refuse to add is engineering work the engines must absorb.
> Every error code we replace with a graceful transition is engineering
> work. Every "advanced mode" we never ship is engineering work. This
> document is where we keep score.

---

## §0 — How to use this document

**If you are writing code that touches the user surface:** check §3
(forbidden) before adding any string, control, or indicator. If your
addition is in §3, the design is wrong; redesign instead.

**If you are reviewing a PR:** the PR description must list every
user-visible string, control, or indicator added. Cross-reference §3.
If anything matches, reject or escalate to exception process (§6.3).

**If you find a surface that should be forbidden but isn't listed:**
add it to §3 with a PR. The catalog is meant to grow as we encounter
new failure modes.

**If you find a surface that the doctrine prohibits but the user
genuinely needs:** see §5 (accessibility) and §6.3 (exception process).
The bar is high; most "users need this" arguments are misframed.

---

## §1 — The three design laws (reminder)

The doctrine derives from three laws. Every refusal in §3 is grounded
in at least one of them.

| Law | What it means | What it kills |
|---|---|---|
| **For the people** | Free, universal, on any device, any network. No tiering of humans. | Paywalls, premium tiers, "this feature unavailable in your region," CAPTCHA, phone-number requirements. |
| **Just works** | One button. Zero settings. No error codes. The engines handle complexity invisibly. | Settings menus, error toasts, quality bars, "reconnecting..." overlays, retry buttons. |
| **We are one** | The user, their devices, conversations, and substrate move as one living system. | Per-device opt-in, device pickers, "use my phone's mic" toggles, separate identities per device. |

When in doubt, ask: which law does this serve? If none, it doesn't ship.

---

## §2 — The review rule

Every PR that introduces or modifies user-visible content must include
in its description:

```markdown
## User-visible changes
- [ ] No new strings           OR  list every new string verbatim
- [ ] No new controls          OR  list every new control + its purpose
- [ ] No new indicators        OR  list every new indicator + states
- [ ] No new settings          OR  doctrine exception filed: <link>
- [ ] No new error paths       OR  describe replacement engine behavior

## Doctrine check
- [ ] I have read DOCTRINE_OF_INVISIBILITY.md §3
- [ ] None of my additions match a forbidden surface
- [ ] CI lint test_doctrine_of_invisibility.py passes
```

If any box is unchecked or any new content matches §3, the PR is
**blocked** until either:
- The content is removed (preferred), or
- An exception is filed per §6.3 and approved.

No exceptions are granted retroactively. PRs cannot ship with
doctrine violations.

---

## §3 — Forbidden surfaces (catalog)

Each entry has the form:

> **§3.x.y — Short name**
> *Refusal:* what we will not ship.
> *Why:* which law(s) this serves.
> *Instead:* what the engines must do.
> *Lint:* regex or test that catches this.

---

### §3.1 — Configuration surfaces

#### §3.1.a — No advanced settings menu

*Refusal:* No "Advanced settings," "Developer options," "Power user
mode," "Show more options," or equivalent.

*Why:* Just works. The presence of "advanced" admits the engines are
incomplete. Every option is engineering work shifted to the user.

*Instead:* The engines decide. If a decision is genuinely user-
specific (e.g., recording preference, language), it lives in
accessibility-level Preferences (§5), not under "advanced."

*Lint:* `r"\b(advanced|developer|power.?user)\s+(settings|options|mode)\b"`

---

#### §3.1.b — No codec picker

*Refusal:* The user cannot choose Opus vs semantic, VP9 vs raw, or
any other codec or compression mode.

*Why:* Just works. The user does not know the word "codec."

*Instead:* The Presence Compiler picks. The capability-intersection
+ network conditions + model-pack hash determine the active rung.
The Reality dot's detail pane shows current representation in plain
language ("audio only", "reconstructed from model"), but never as a
control.

*Lint:* `r"\b(codec|encoding|bitrate)\s+(picker|selector|preference)\b"`

---

#### §3.1.c — No device picker mid-call

*Refusal:* During an active call, the user cannot manually choose
"use my phone's mic" or "use my laptop's camera."

*Why:* We are one. Devices are organs; the user does not pilot organs.

*Instead:* The Multi-Device Body Engine arbitrates surface roles via
the CRDT lattice. Crossfade protocol handles seams. If the user is
unhappy with the chosen surface, they cover or close the device they
don't want used; the Body Engine reads the signal and rebalances.

*Lint:* `r"\b(microphone|camera|speaker|display)\s+selector\b"` in
call-active UI scope.

---

#### §3.1.d — No relay / route picker

*Refusal:* No "use TURN," "force relay," "prefer P2P," or "VPN mode"
toggles.

*Why:* Just works. Route choice is internal mechanism.

*Instead:* The Route Brain picks. The Reality detail pane shows
the current path class ("Local network," "Via relay") for trust
transparency, never as a control.

*Lint:* `r"\b(relay|turn|p2p)\s+(mode|toggle|preference|selector)\b"`

---

#### §3.1.e — No bandwidth or quality picker

*Refusal:* No "HD," "SD," "Low data mode," "Save data," or numeric
bitrate target.

*Why:* For the people (no tiering). Just works (engines decide).

*Instead:* The Compiler adapts. Low-data conditions select lower
rungs automatically. Users who genuinely want to "save data" are
better served by a system-level data-saver flag the OS already
provides.

*Lint:* `r"\b(hd|sd|low.?data|save.?data|data.?saver)\s+mode\b"`

---

#### §3.1.f — No notification settings (per-conversation)

*Refusal:* No per-contact "ring volume," "vibrate pattern," "ringtone
selector," or "mute exceptions" UI.

*Why:* Just works.

*Instead:* OS-level notification settings handle per-app behavior.
Per-contact behavior is inferred from the relationship: a contact
that consistently calls during quiet hours can be auto-routed to
silent ring by the Immune System, with a calm UI nudge after the
fact, never a config screen.

*Lint:* `r"\b(ringtone|vibration|notification)\s+(picker|selector|settings)\b"`

---

### §3.2 — Error / status surfaces

#### §3.2.a — No "Reconnecting..." overlay

*Refusal:* No fullscreen or modal "Reconnecting...," "Trying to
connect...," "Reestablishing call...," or animated spinners during
call recovery.

*Why:* Just works. The user feels the pain of "I am not connected."
Showing them an overlay confirms it; it does not help.

*Instead:* The Immune System has already prewarmed a backup route
or is converting to capsule. The picture softens; nothing pops up.
If the call dies, it converts to capsule with a single calm message
(§4.b).

*Lint:* `r"\b(reconnecting|reestablishing|trying.?to.?connect)\b"`

---

#### §3.2.b — No "Connection unstable" toast

*Refusal:* No banners, toasts, or pop-ups about poor network
conditions.

*Why:* Just works.

*Instead:* The Compiler descends a rung. Video softens to a face-
still; audio stays. No language about the network appears.

*Lint:* `r"\b(connection|network)\s+(unstable|poor|weak|slow)\b"`

---

#### §3.2.c — No quality bars or signal indicators

*Refusal:* No green/yellow/red quality bars. No "good / fair / poor"
labels. No SNR/RTT/loss readouts.

*Why:* Just works. Users have no actionable response to "fair signal."

*Instead:* The user feels good media or doesn't. The Reality dot
indicates trust state (path class, recording, identity), not quality.

*Lint:* `r"\b(signal|connection|quality)\s+(bar|indicator|strength)\b"`,
       `r"\b(good|fair|poor)\s+connection\b"`

---

#### §3.2.d — No error codes (ever)

*Refusal:* No "Error 0x80004005," "ICE_FAILED," "code 1001," or any
machine identifier surfaced to the user.

*Why:* Just works. Error codes are an admission of helplessness.

*Instead:* Errors are logged locally for engineering. The user sees
the consequence (call became capsule, message will send when
possible), not the cause. Codes appear only in
[daemon.log](../logs/daemon.log) for diagnostic purposes.

*Lint:* `r"\b(error|code)\s+\d+\b"`,
       `r"\b0x[0-9a-f]+\b"` (user-facing UI strings only)

---

#### §3.2.e — No "Call failed"

*Refusal:* No "Call could not be completed," "Call failed,"
"Disconnected," or "Lost connection."

*Why:* Just works. Calls do not fail in our model; they convert.

*Instead:* The Compiler descends to async capsule (§4.b). The phrase
shown is something like "Saving your message for Mom" — never a
failure event.

*Lint:* `r"\bcall\s+(failed|could.?not|disconnected|lost)\b"`

---

#### §3.2.f — No "User not registered"

*Refusal:* No "Mom doesn't have One Link," "User not found," "Not a
One Link user," or "Invite to install" modals.

*Why:* For the people. The platform should never gatekeep "real"
users.

*Instead:* If the recipient is reachable via QR pair or known
endpoint, the call proceeds. If not, the system silently turns the
attempt into an invitation: the would-be call becomes a voice note
that the user can forward via SMS, email, or QR with a short message
"someone wants to reach you on One Link."

*Lint:* `r"\b(not\s+(registered|found|installed)|doesn't\s+have)\b"`

---

#### §3.2.g — No "Update required to call"

*Refusal:* No modal blocking the call because the app or
counterparty is on an older version.

*Why:* Just works. Updates are background.

*Instead:* Capability negotiation gracefully degrades to the
intersection. If the older client lacks SEMANTIC_MEDIA_V1, the
Compiler masks rung 2; Opus/VP9 still works. Updates are signed,
background-installed, gated by the Service Worker pubkey pinning
(audit C2 closure).

*Lint:* `r"\b(update|upgrade)\s+(required|needed)\b"` in call flow.

---

#### §3.2.h — No "Please try again"

*Refusal:* The phrase "please try again" or any equivalent.

*Why:* Just works. If it can be tried again, the engine tries it
silently.

*Instead:* The Immune System retries. If retries fail, the call
gracefully converts (§4.b).

*Lint:* `r"\btry\s+again\b"`

---

### §3.3 — Modal interruptions

#### §3.3.a — No CAPTCHA

*Refusal:* No CAPTCHA. Ever. Including for rate-limiting, anti-bot,
or anti-abuse.

*Why:* For the people. CAPTCHAs are an admission of failed
authentication architecture and exclude users with disabilities.

*Instead:* Rate-limiting at the macaroon-capability layer. Abuse
prevention via cryptographic identity (each peer holds a hardware-
bound master_vk; abuse → revoke at the cap layer; no CAPTCHA needed).

*Lint:* `r"\bcaptcha|recaptcha|hcaptcha|human\s+verification\b"`

---

#### §3.3.b — No "Verify your phone number"

*Refusal:* No phone number, no email verification, no third-party
identity proof.

*Why:* For the people. Identity sovereignty is foundational.

*Instead:* QR pair (`ol_pair_qr`, Row 2). Identity is the device-
bound master_vk; verification is the 5-word SAS on first call.

*Lint:* `r"\bverify\s+your\s+(phone|email)\b"`,
       `r"\bphone\s+number\s+verification\b"`

---

#### §3.3.c — No "Allow microphone access?" mid-call

*Refusal:* No OS-permission prompts during an active call.

*Why:* Just works. The prompt mid-call is jarring and unrecoverable
(if the user denies, the call dies with no graceful path).

*Instead:* All permissions are requested at install or first call,
in plain language, with concrete rationale. The Immune System
checks permissions BEFORE the call begins; if missing, the call
converts to whatever subset of media the available permissions
allow.

*Lint:* policy-level (no specific regex). Manual review.

---

#### §3.3.d — No "Are you sure?" confirmations

*Refusal:* No "Are you sure you want to end this call?" "Confirm
hangup," or similar friction prompts.

*Why:* Just works. The user pressed the button; the user meant it.

*Instead:* The hangup is instant. If it was accidental, the resume
affordance (10-minute window) is available. The default is action;
the recovery is undo.

*Lint:* `r"\bare\s+you\s+sure\b"`,
       `r"\bconfirm\s+(hangup|end|delete)\b"`

---

#### §3.3.e — No analytics or telemetry consent banner

*Refusal:* No "We use cookies," "Help us improve One Link by sharing
diagnostics," or any banner asking permission to collect data.

*Why:* For the people. We don't collect user telemetry. Banners
asking permission are an artifact of products that do.

*Instead:* Call vitals are sensed locally for the Immune System to
learn from; they never leave the device. There is no analytics
infrastructure to gate.

*Lint:* `r"\b(cookies?|analytics|telemetry|diagnostics?)\s+(banner|consent|opt.?in)\b"`

---

### §3.4 — Tiering / commerce

#### §3.4.a — No paywall

*Refusal:* No "Upgrade to Pro," "Premium tier," "Subscribe for HD,"
or any feature gated by payment.

*Why:* For the people. Calls are free, forever, on any device, any
network.

*Instead:* The federated relay model funds operating costs
([SOVEREIGN_NETWORK_BLUEPRINT.md](SOVEREIGN_NETWORK_BLUEPRINT.md)).
Volunteer relays, no cloud bill. Heavy users may volunteer relay
capacity, never pay.

*Lint:* `r"\b(upgrade|subscribe|premium|pro|plus)\s+(for|to)\s+\w+"`,
       `r"\bunlock|in.?app.?purchase|monthly.?plan\b"`

---

#### §3.4.b — No "Get HD video" upsell

*Refusal:* No quality tier sold as a feature.

*Why:* For the people. Quality is determined by network + engines,
not by payment.

*Instead:* The Compiler picks the highest viable rung. Hardware
attestation may unlock semantic codecs (because they require a model
pack signed by the project), but that's capability gating, not
commerce.

*Lint:* `r"\b(hd|4k|hi.?def)\s+(upgrade|plan|tier)\b"`

---

#### §3.4.c — No region-locked features

*Refusal:* No "This feature is unavailable in your country/region."

*Why:* For the people.

*Instead:* All features available globally. Regulatory rails (e.g.,
recording laws, RF transmission limits) are handled at the
compile-time rail layer, not as feature gates. If a specific local
law actually prohibits something, the engine refuses with a calm
explanation, but this is exceptional and requires legal review.

*Lint:* `r"\b(unavailable|not\s+available)\s+in\s+your\s+(country|region|area)\b"`

---

#### §3.4.d — No "Limited time offer"

*Refusal:* No promotional banners, countdown timers, urgency UX, or
artificial scarcity.

*Why:* For the people.

*Instead:* The product does not need to manipulate. It is the
product.

*Lint:* `r"\b(limited\s+time|expires\s+in|only\s+\d+\s+left|act\s+now)\b"`

---

### §3.5 — Privacy theater

#### §3.5.a — No "Your data is safe" trust banners

*Refusal:* No "Bank-level encryption," "HIPAA compliant," "Your
privacy matters to us," or other reassurance-without-evidence
banners.

*Why:* For the people. Trust is established by visible cryptographic
properties (Reality dot, SAS verification, attestation tier), not by
marketing language.

*Instead:* The Reality detail pane shows what's actually true
(path class, recording state, identity verification, attestation
tier). No claims that aren't verifiable in code.

*Lint:* `r"\b(bank.?level|military.?grade|enterprise.?grade)\s+(encryption|security)\b"`,
       `r"\byour\s+privacy\s+matters\b"`

---

#### §3.5.b — No "Recorded for quality assurance"

*Refusal:* No silent or automatic recording. No "this call may be
recorded" banner that does not require explicit consent.

*Why:* For the people. Silent recording is doctrine-fatal.

*Instead:* Recording requires explicit mutual consent (RECORDING_REQUEST
+ RECORDING_GRANT wire types). The recording badge in the Reality
pane is visible — not subtle — for the entire recording duration.
Either party can stop instantly. The recorded artifact carries
cryptographic provenance.

*Lint:* `r"\bmay\s+be\s+recorded\b"`,
       `r"\bquality\s+assurance\b"` in call context.

---

#### §3.5.c — No surreptitious indicators

*Refusal:* No 1-pixel recording dots, no faint icons users wouldn't
notice, no "discoverable but not announced" recording states.

*Why:* For the people. If something is happening that the user might
want to know about, they SEE it.

*Instead:* The Reality dot is the canonical indicator. Recording
turns it red and adds a clear "Recording" label below. Privacy-
sensitive state changes (recording on, recording off, path becomes
relay) appear briefly in the dot's detail pane.

*Lint:* policy-level. Manual review of any opacity < 0.6 or font
size < 12px on privacy indicators.

---

### §3.6 — Hardware abstraction leaks

#### §3.6.a — No battery percentage warnings

*Refusal:* No "Battery low; call may end" or "Low battery warning."

*Why:* Just works. The user already knows their battery is low; the
OS told them. The app telling them again is noise.

*Instead:* The Immune System reads battery state and silently
suggests handoff to another of the user's devices (Body Engine
Tier ε ASSIST), or descends rungs to conserve power.

*Lint:* `r"\bbattery\s+(low|warning|critical)\b"` in call UI scope.

---

#### §3.6.b — No thermal warnings

*Refusal:* No "Device is overheating; reducing quality" or
"Performance throttled."

*Why:* Just works.

*Instead:* The Body Engine handoffs to a cooler device or the
Compiler descends a rung. No surface event.

*Lint:* `r"\b(overheating|thermal|throttled|performance)\b"` in call UI.

---

#### §3.6.c — No network type labels

*Refusal:* No "On WiFi," "On cellular," "On 5G," "Roaming," or
network-technology language.

*Why:* Just works. Users don't think in network types.

*Instead:* The Reality detail pane shows path *class* in user terms:
"Local network," "Direct," "Via relay," "Through onion." Never
"WiFi" or "4G."

*Lint:* `r"\bon\s+(wi.?fi|cellular|5g|4g|lte|3g)\b"` in call UI scope.

---

#### §3.6.d — No "Microphone in use" indicators

*Refusal:* Beyond what the OS itself shows, no app-level "Mic active"
warning during normal call flow.

*Why:* Just works. The OS handles this universally.

*Instead:* Rely on platform OS indicators (iOS green dot, Android
mic indicator). The call surface implicitly shows mic state via the
voice level visualization.

*Lint:* `r"\bmicrophone\s+(in\s+use|active|enabled)\b"` (warn level).

---

### §3.7 — Process leaks

#### §3.7.a — No "Establishing connection..."

*Refusal:* No "Establishing connection," "Negotiating," "Handshaking,"
"Authenticating," or any technical phase indicator.

*Why:* Just works. The call either connects or converts. No middle
state surfaces.

*Instead:* From tap to face is sub-second when conditions allow.
When slower, the call shows the calm pre-connect surface (ring on
the other side, or capsule-recording-in-progress on this side) —
never a process indicator.

*Lint:* `r"\b(establishing|negotiating|handshaking|authenticating)\b"`

---

#### §3.7.b — No "Loading..." spinners

*Refusal:* No animated spinners on call surfaces.

*Why:* Just works. If something is slow, redesign so it isn't.

*Instead:* Pre-computed first paint. Capability negotiation is
cached. UI is responsive immediately even if media isn't yet
flowing.

*Lint:* `r"\bloading|spinner\b"` in call surface markup.

---

#### §3.7.c — No "Checking for updates..."

*Refusal:* No update-check progress indicator at call time.

*Why:* Just works. Updates are background.

*Instead:* Service Worker background-fetches signed updates; install
on next launch. Calls never block on update flow.

*Lint:* `r"\bchecking\s+for\s+updates?\b"`

---

### §3.8 — Reactive degradation surfaces

#### §3.8.a — No "Switching to audio only" notifications

*Refusal:* No banner or toast announcing rung changes.

*Why:* Just works. Transitions are smooth, not announced.

*Instead:* Video softly fades to a face-still. A single line under
the picture "audio only" appears for 2 seconds during the transition
only, then fades. No banner, no toast.

*Lint:* `r"\bswitching\s+to\b"` in call UI.

---

#### §3.8.b — No "Network slow" or "Bandwidth limited" labels

*Refusal:* No display of bandwidth state to the user.

*Why:* Just works. The user can't act on it.

*Instead:* The Compiler descends silently. The Reality detail pane
shows the current representation in plain language ("face still,
voice live"), never a "bandwidth limited" label.

*Lint:* `r"\b(network|bandwidth)\s+(slow|limited|low)\b"`

---

#### §3.8.c — No "Trying lower quality" announcements

*Refusal:* No "Reducing video quality to maintain call" messaging.

*Why:* Just works.

*Instead:* Same as §3.8.a — silent transition with brief plain-
language affirmation only during the moment of change.

*Lint:* `r"\b(reducing|lowering)\s+(quality|resolution|bitrate)\b"`

---

### §3.9 — Identity surfaces

#### §3.9.a — No raw fingerprint hex

*Refusal:* No "Mom's fingerprint: 8A:F3:12:7E:BD:..." or other
machine-format identity strings shown to the user.

*Why:* For the people. Fingerprints are inhuman.

*Instead:* The 5-word SAS (`ol_pair_qr`) on first contact. Plain
language ("you verified Mom on Mar 4") for subsequent state. The
detail pane offers a "show technical details" affordance for
engineers, but the default surface is the human-readable form.

*Lint:* `r"[0-9a-f]{2}(:[0-9a-f]{2}){4,}"` in user-facing strings.

---

#### §3.9.b — No public-key blobs

*Refusal:* No base64 public keys, no PEM blocks, no key import/
export dialogs as part of normal user flow.

*Why:* For the people.

*Instead:* QR pair handles key exchange. Sovereign-export of the
user's own identity is available in a dedicated "Backup Identity"
flow that uses threshold recovery (`ol_threshold_recovery`, Row 9)
and never shows raw key material.

*Lint:* `r"-----BEGIN\s+\w+\s+KEY-----"`,
       large base64 strings (≥64 chars) in user-facing UI.

---

#### §3.9.c — No "Trust level: 73%" or numeric trust scores

*Refusal:* No quantitative trust display.

*Why:* For the people. Trust is binary at the user surface (you
verified them or you haven't); quantification invites
misinterpretation.

*Instead:* The Reality dot shows binary states: verified, not yet
verified, key rotated since verification. Each state is plain
language with a clear next action.

*Lint:* `r"\btrust\s+(level|score)\b"`,
       `r"\d+%\s+trust\b"`

---

#### §3.9.d — No "Add a profile picture" requirement

*Refusal:* No required profile picture, display name, or biographical
field.

*Why:* For the people. Identity is the master_vk + the verified SAS,
not a presentation field.

*Instead:* If a user chooses to share a display name or photo, it's
an optional addition synced via the existing chat persistence.
Default is no profile at all; calls work fine without one. The peer
sees whatever name the user has saved for them locally.

*Lint:* `r"\b(required|please\s+add)\b.*\b(profile|picture|avatar|display\s+name)\b"`

---

### §3.10 — Persistence / history

#### §3.10.a — No "Missed call" badge with a count

*Refusal:* No "(3) missed calls" notification badge, no list of
"missed events."

*Why:* Just works. There are no "missed events"; there are only
conversation states.

*Instead:* The capsule from each unanswered call lives in the
chat surface as a voice note + resume affordance. The chat thread
itself shows unread state via its existing mechanism.

*Lint:* `r"\bmissed\s+call\b"`,
       `r"\(\d+\)\s+missed\b"`

---

#### §3.10.b — No "Call history" page

*Refusal:* No dedicated "Call Log" or "Recents" tab listing past
calls as discrete events.

*Why:* We are one. Conversations are continuous; calls are one
intensity-setting within them.

*Instead:* The chat surface IS the conversation history. Past calls
appear inline in the chat thread as voice notes, capsules, and
duration markers ("voice call · 23 min"). To "see all my calls with
Mom," open Mom's conversation.

*Lint:* `r"\bcall\s+(log|history|recents)\b"` as standalone navigation.

---

#### §3.10.c — No "Delete call history" button

*Refusal:* No explicit "clear call log" affordance, because there is
no call log (§3.10.b).

*Why:* Composability of doctrine.

*Instead:* Delete operates on conversations and individual messages
(including voice notes / capsules) via the existing chat affordance.
Granularity is the same as any chat message.

*Lint:* `r"\bdelete\s+call\s+history\b"`

---

### §3.11 — Time and waiting

#### §3.11.a — No countdown timers

*Refusal:* No "Call ends in 30 seconds," "Subscription renews in
14 days," "Recording stops in...".

*Why:* For the people, just works.

*Instead:* No call time limit. No subscription. Recording stops
when either party stops it. If there's any meaningful timer, it's
the 10-minute resume window after a capsule conversion, which is
expressed in human language ("for the next few minutes, you can
pick up where you left off") in the resume affordance.

*Lint:* `r"\b\d+\s+(seconds?|minutes?)\s+(left|remaining|until)\b"`

---

#### §3.11.b — No "Time on call" stopwatch (by default)

*Refusal:* No prominent stopwatch counting up the call duration.

*Why:* Just works. Most users don't care.

*Instead:* The duration appears in the post-call chat marker ("voice
call · 23 min"). Some users (therapists charging by the minute,
support agents) may want a duration counter; this is an accessibility-
adjacent affordance available in Preferences (§5), defaulted off.

*Lint:* `r"\bcall\s+(duration|timer)\b"` in always-visible scope.

---

### §3.12 — Decision-fatigue surfaces

#### §3.12.a — No "Choose your privacy level"

*Refusal:* No "Strict / Balanced / Permissive" privacy presets.

*Why:* For the people. Privacy is not a slider; it's a default
posture.

*Instead:* Maximum privacy is the only setting. Capabilities are
deny-by-default at the cap layer (existing). Conversations refuse
abilities they haven't been granted.

*Lint:* `r"\bprivacy\s+(level|preset|mode)\b"`

---

#### §3.12.b — No A/B testing of doctrine

*Refusal:* No feature flag that exposes some users to a forbidden
surface to "see if they like it."

*Why:* For the people. We don't experiment on humans without consent;
we don't experiment on doctrine at all.

*Instead:* Doctrine is normative. A/B testing happens on internal
mechanism (route brain thresholds, codec parameters), never on
visible surfaces.

*Lint:* policy-level. Code review of any feature flag whose name
matches `/ui|surface|user.facing/i`.

---

#### §3.12.c — No "Tip of the day" / coach marks / onboarding popups

*Refusal:* No "Did you know you can...?" tooltips, no onboarding
tour, no coach marks after install.

*Why:* Just works. If users need to be taught the UI, the UI is
wrong.

*Instead:* The product is one button. The button is labeled. The
SAS verification on first call is the only onboarding moment, and
it's framed as the meaningful trust gesture it is, not as a tutorial.

*Lint:* `r"\b(did\s+you\s+know|pro\s+tip|tip\s+of\s+the\s+day)\b"`,
       `r"\bonboarding\s+(tour|tutorial|coach)\b"`

---

## §4 — Required surfaces (what MUST be visible)

The doctrine forbids many things. It also requires a small set.

### §4.a — The call button

The "Call Mom" button is the entire product. It must be present,
labeled, instant.

### §4.b — The conversion message

When a call converts to async capsule, one calm line of plain
language appears on the originator's side. Examples:

> "Mom seems to have lost connection. Recording your message for her."

> "Saving this for Mom. She'll see it when she's back."

This message is REQUIRED to surface (the user needs to know what's
happening). It is not a doctrine violation; it's the doctrine's
positive form.

### §4.c — The Reality dot

A single calm provenance indicator on the call surface. Tappable to
reveal:
- Who you're calling (verified state).
- What representation is active (in plain language).
- Path class (in plain language).
- Recording state.

### §4.d — The intensity dial

The slider/control by which the user moves between AMBIENT / LOW /
MED / HIGH intensity. At Tier α, this is implicit (tapping "Call
Mom" = HIGH; ending = AMBIENT). At Beyond tier, it becomes explicit.

### §4.e — The ring (incoming call)

Visible + audible + (where supported) tactile. Always-on; not a
preference.

### §4.f — The resume affordance

Within the 10-minute window after a capsule conversion, both sides
see "Resume call with Mom" in the conversation surface. Calm, single
action.

### §4.g — The end button

A single, instant end action. No confirmation (§3.3.d).

### §4.h — The mute toggle

Audio mute is allowed because it's a privacy-positive control with
no alternative (the engines cannot know you want privacy without
being told). The mute state is reflected in the Reality dot
("Muted").

### §4.i — The camera toggle

Same as mute, for video.

### §4.j — The accessibility surfaces (§5)

Captions, screen reader output, visual ring, tactile alerts — all
REQUIRED when applicable.

---

## §5 — Accessibility doctrine

Some surfaces are required *because* they serve users who would
otherwise be excluded. These are not doctrine violations; they are
the doctrine's expression of *for the people*.

### §5.a — Live captions

For deaf and hard-of-hearing users. On-device transcription only,
never cloud. Toggle at system-accessibility level, not as a per-
call setting. When on, captions overlay the call surface
unobtrusively; FrameProvenance signs them
(`FrameKind.RECONSTRUCTED` from audio source).

### §5.b — Screen reader output

For blind and low-vision users. Every UI element ARIA-labeled.
Identity SAS spoken aloud. Intensity dial single-axis. All call
controls keyboard-navigable.

### §5.c — Visual ring

For deaf users. Flash or color cue alongside ringtone, defaulted on
when the OS reports the user as having hearing accessibility enabled.

### §5.d — Tactile ring

For deaf users with wearables. Haptic pulse pattern matching ring
cadence.

### §5.e — Voice-only mode

A first-class mode (not a degradation). For blind users, defaults to
audio-only with the bandwidth budget reallocated to higher-fidelity
voice (Opus 64k instead of Opus 16k + low-res video).

### §5.f — Caption-first mode

For deaf users. Video + always-on captions; audio optional.

### §5.g — High contrast / large text

Inherits from OS accessibility settings. No in-app duplicate.

### §5.h — Reduced motion

Crossfade durations and ring animations respect OS reduced-motion
preference.

### §5.i — The "Show technical details" affordance

In the Reality detail pane, advanced users (especially auditors,
journalists, security researchers) need to see fingerprints, key
material, attestation tier, path class details. A single
unobtrusive "Show technical details" button reveals these. Hidden
by default; never required for normal use.

---

## §6 — Enforcement

### §6.1 — The CI lint

[tests/test_doctrine_of_invisibility.py](../tests/test_doctrine_of_invisibility.py)
scans all UI source for forbidden patterns from §3. Every PR runs it.
A doctrine violation = a failing test = PR blocked.

```python
# tests/test_doctrine_of_invisibility.py — sketch

FORBIDDEN_PATTERNS = [
    # §3.1.a
    (r"\b(advanced|developer|power.?user)\s+(settings|options|mode)\b",
     "§3.1.a — No advanced settings"),
    # §3.2.a
    (r"\b(reconnecting|reestablishing|trying.?to.?connect)\b",
     "§3.2.a — No 'Reconnecting...' overlay"),
    # ... one entry per §3 clause
]

UI_GLOBS = [
    "src/one_link/web/**/*.html",
    "src/one_link/web/**/*.js",
    "src/one_link/web/**/*.ts",
    "src/one_link/web/**/*.jsx",
    "src/one_link/web/**/*.tsx",
    "src/one_link/web/**/*.svelte",
    "desktop/**/*.tsx",
    "desktop/**/*.html",
    # mobile: TBD
]

def test_no_doctrine_violations():
    violations = []
    for glob_pattern in UI_GLOBS:
        for path in glob.glob(glob_pattern, recursive=True):
            content = open(path, encoding='utf-8').read()
            content = strip_comments(content)  # comments don't lint
            content = strip_doctrine_references(content)  # this doc allowed
            for pattern, clause in FORBIDDEN_PATTERNS:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    line = content[:match.start()].count('\n') + 1
                    violations.append(f"{path}:{line} — {clause}\n  match: {match.group(0)!r}")
    assert not violations, "\n".join(violations)
```

The lint is intentionally aggressive. False positives are easier to
allowlist (add inline `# doctrine-ok: <reason>`) than violations are
to catch retroactively.

### §6.2 — The PR review checklist

Every PR that modifies any file under `src/one_link/web/`,
`desktop/`, or mobile UI source must include the review block from
§2 in its description. Reviewers check it before approving.

### §6.3 — The exception process

A doctrine clause can be relaxed for a specific surface in a specific
context if and only if:

1. A written exception is filed at
   [docs/decisions/](decisions/) following the existing ADR
   pattern, titled `ADR-NNNN-doctrine-exception-<short-name>.md`.
2. The exception specifies: the clause being relaxed, the precise
   surface in scope, the precise alternative behavior that justifies
   the relaxation, the law-level justification.
3. The exception is reviewed by at least two engineers + the design
   lead.
4. The exception is approved by writing into the ADR; the lint adds
   the allow-listed surface inline with `# doctrine-ok: ADR-NNNN`.
5. Approved exceptions are reviewed annually for continued necessity.

**No exception is approved without a written ADR.** The friction is
the point; it ensures we only relax doctrine when the case is
genuinely beyond what the engines can absorb.

### §6.4 — Doctrine archaeology (when violations are found in shipped code)

If a violation is found in code that already shipped:

1. File an issue tagged `doctrine-violation`.
2. The fix is treated as a privacy/security-class fix: prioritized,
   tested, shipped in the next release.
3. No retroactive exceptions. If a shipped surface is found to
   violate doctrine, it is removed (or replaced) before the next
   release, full stop.

---

## §7 — When the doctrine evolves

This document is intentionally a living artifact. It grows when:

- A new failure mode is identified (a kind of surface we hadn't
  thought to forbid).
- A capability becomes possible that was previously infeasible
  (e.g., live captions became feasible when on-device models got
  small enough; this changes what §5 requires).
- A clause turns out to be wrong (rare; requires §6.3 process to
  retire).

**When adding a new clause:**

1. Open a PR adding the clause to §3 with the standard format
   (refusal / why / instead / lint).
2. Add the lint pattern to [tests/test_doctrine_of_invisibility.py](../tests/test_doctrine_of_invisibility.py).
3. Sweep existing source for matches; if any exist, file a
   `doctrine-violation` issue per §6.4.

**When retiring a clause:**

1. File an ADR per §6.3 explaining why the clause is wrong.
2. The bar is high: "users requested this" is not a reason.
   Doctrine serves users, not their stated preferences in the
   moment.

---

## §8 — Worked examples (specific user moments)

Each example shows: the user moment, the wrong (doctrine-violating)
response, and the right (doctrine-compliant) response.

### §8.a — User has poor WiFi mid-call

**Wrong:** Banner pops up: "Your connection is unstable. Try moving
closer to your router." Quality bars go yellow.

**Right:** Video softly fades to a face-still. A single line below
the picture reads "audio only" for 2 seconds, fades. Audio continues
uninterrupted. The Reality dot detail pane (if tapped) shows
"Reconstructed (audio only)."

---

### §8.b — User taps "Call Mom" but Mom is offline

**Wrong:** Modal: "Could not reach Mom. Please try again later."
Or: "Mom is offline."

**Right:** Surface becomes the capsule-recording UI with the line:
"Saving this for Mom. She'll see it when she's back." User records,
ends. Voice note delivered when Mom returns. No "offline" language.

---

### §8.c — User's call drops completely

**Wrong:** "Call lost. Retry?" button. Or: "Disconnected."

**Right:** Surface auto-transitions to capsule-mode with: "Mom's
connection dropped. Picking up the rest of your message for her."
The audio buffer that was in flight becomes the voice note. Resume
affordance available in chat for the next 10 minutes.

---

### §8.d — User's master_vk rotates on the peer side

**Wrong:** Modal: "Mom's identity has changed. Continue anyway?
(Y/N)" with cryptic warning text.

**Right:**
- If the rotation chains to the prior key: Reality dot detail pane
  shows "Mom updated her keys" with a calm "Verify again?" offer.
  Call proceeds.
- If the rotation does NOT chain: call refuses with the line
  "Something changed. This may not be Mom. Verify in person before
  continuing." Single tap to start fresh QR pair. No fingerprint
  hex shown.

---

### §8.e — User on a 2010 Android phone with 1 GB RAM

**Wrong:** "Your device doesn't meet minimum requirements" gate.

**Right:** Compiler defaults to rung 4 (audio only) with Opus 16k.
Body Engine routes through this device only as audio surface. Calls
work, just without video. No warnings.

---

### §8.f — User accidentally taps end

**Wrong:** "Are you sure you want to end this call?" modal.

**Right:** Call ends instantly. Resume affordance appears in chat
within 200ms. Single tap to redial; CallSession state preserved.

---

### §8.g — User wants to record the call

**Wrong:** Inline toggle: "Record this call." Recording starts;
small icon appears.

**Right:** User taps a "Save this call" affordance. A clear request
goes to the peer: "Alex wants to save this call. Allow?" Peer
explicitly grants. Reality dot turns visible-red with "RECORDING"
label below for the entire duration. Either party can stop at any
moment with one tap.

---

### §8.h — Connection is via a federated relay

**Wrong:** "Connection is being relayed. This may be slower." status
banner.

**Right:** Reality dot detail pane (if tapped) shows "Via relay."
Nothing surfaces unless the user looks. Call proceeds normally.

---

### §8.i — User's mic is being used by another app

**Wrong:** Error modal: "Microphone in use. Please close other apps."

**Right:** The Immune System detects the conflict. If the user has
a paired device with an available mic, the Body Engine handoffs to
it ("Mic moved to Phone" appears briefly in the Reality detail pane
during the transition). If no alternative, the call uses video-only
with a calm "you're muted" inline below the picture.

---

### §8.j — User has never made a call before, just installed

**Wrong:** Onboarding tour with 6 swipe-through screens explaining
features.

**Right:** App opens to the QR-pair screen with one line: "Share
this with someone you trust." User pairs. Sees their first contact.
Taps it. Calls. Done.

---

## §9 — Glossary (doctrine-specific terms)

| Term | Meaning |
|---|---|
| **Calm surface** | A UI element that conveys necessary information without alarm, jargon, or interruption. Example: the Reality dot. |
| **Conversion** | The act of transforming a live call into an async capsule without surfacing failure. Replaces "drop" / "fail" / "disconnect" in user-facing language. |
| **Doctrine exception (ADR)** | A formal, written, peer-reviewed relaxation of one clause for one surface, filed per §6.3. |
| **Doctrine violation** | A user-visible surface that matches a §3 clause without an approved ADR. Treated as a class-1 bug. |
| **Engine work** | Engineering effort that absorbs complexity so the user never has to. Every refusal in §3 generates engine work. |
| **Live state** | The currently-rendered representation of presence (face, voice, capsule, ambient). |
| **Plain language** | User-visible text that contains no jargon, no acronyms, no error codes, no machine identifiers. |
| **Positive form** | A REQUIRED surface (§4 or §5) that exists because removing it would harm users. Distinguished from a doctrine violation by its law-level justification. |
| **Reality dot** | The calm provenance indicator on the call surface (per
[LIVING_PRESENCE_ARCHITECTURE.md §4.5](LIVING_PRESENCE_ARCHITECTURE.md)). |
| **Resume affordance** | The "tap to pick up where you left off" surface that appears in chat after a capsule conversion, for the 10-minute live-resumable window. |
| **Surface** | Any user-visible element: a string, control, indicator, banner, modal, animation, badge. The unit doctrine acts on. |

---

## Closing — Why this matters

Every product that has ever shipped a settings menu shipped a failure.
The settings menu is the engineer saying: "I could not figure out
which behavior is right, so I'm asking you." Each toggle adds
combinatorial state space, each preference adds bugs, each tier adds
inequity.

The discipline of invisibility is the act of taking those failures
back inside. Every refusal in §3 corresponds to engineering work — in
the Immune System, the Compiler, the Body Engine, the Route Brain,
the Reality Engine, the Predictive Continuity, the Semantic pipeline.
The engines exist *so the surfaces don't have to*.

When this is shipped well, a user opens One Link, taps "Call Mom,"
and a face appears. Networks fluctuate. Devices move. Codecs switch.
Routes flap. Identities verify. None of it surfaces. The call lives
through it.

That is the bar. Anything we add that breaks it makes the product
weaker, not richer.

**For the people. Just works. We are one.**
