# One Setup: First-Run Experience

Status: design target

One Link should not have a weak tutorial. It should have a beautiful first-run experience that helps a person become ready, safe, and confident without feeling taught.

The goal is not to explain the app. The goal is to make One Link work for the person in front of it.

Core promise:

> Your devices become one private fabric. No account. No cloud dependency. No confusion. You are One.

## Product Bar

This is the bar a billion-dollar product team would hold:

- The user reaches a real win in under 60 seconds.
- The user can skip setup without punishment.
- The app teaches by doing, not by lecturing.
- Every screen has one obvious primary action.
- Advanced concepts are proven visually, not explained in walls of text.
- Privacy, trust, recovery, and device safety are part of setup from the beginning.
- The experience feels calm, premium, human, and inevitable.

This should feel less like "here is a tutorial" and more like "One Link just woke up around me."

## Doctrine Alignment

The existing Doctrine of Invisibility rejects onboarding tours, coach marks, and tip popups. This document respects that.

One Setup is not a tour. It is a setup flow that performs real work:

- creates or confirms identity
- names the current device
- pairs another trusted device
- sends a first message or file
- proves the route and privacy state
- explains recovery only when the user has enough trust context

After first run, there must be no nagging tutorial popups. The app may show quiet contextual empty states and one-line next actions, but it must not become a classroom.

## Audience Modes

One Setup needs two explanation layers.

### Human Mode

Default for everyone.

Purpose:

- explain what One Link is doing in plain language
- avoid system jargon
- focus on confidence, safety, and useful actions
- show proof without making the user decode engineering terms

Human Mode phrases:

- "Add your phone"
- "Trust this device"
- "Send a test message"
- "Sent directly"
- "No account was used"
- "Freeze a lost device"
- "Clear app traces"
- "One Link picked the best path"

Human Mode must answer:

- What should I do next?
- Is this safe?
- Did it work?
- Where did my file/message go?
- What can I do if a device is lost?

### Technical Mode

Optional, available from Settings and Details disclosures.

Purpose:

- give technical users a precise view of what happened
- expose diagnostics, route details, trust material summaries, and audit events
- help developers, admins, and power users verify the system
- never be required for normal use

Entry points:

- Settings > Setup > Technical view
- Privacy proof > Details
- Activity > One Now > Details
- Device card > Advanced
- Transfer details disclosure

Technical Mode phrases:

- root identity
- device certificate
- self-mesh enrollment
- trust code / SAS
- secure channel
- route candidate
- remote instruction
- capability scope
- replay protection
- audit event
- transport path
- CDC/native fast path

Technical Mode must answer:

- Which identity/device key was used?
- Which device certificate was enrolled?
- Which route was selected and why?
- Was the channel authenticated?
- Was replay protection active?
- Which capabilities allowed the action?
- Which audit event proves it happened?
- What fallback path was used if direct transport failed?

Technical Mode should be a separate layer, not a separate product. The same setup step can render both a plain explanation and a technical receipt.

## System Translation Map

One Link has advanced systems under the hood. The setup experience must translate each one into words people understand.

| Real system | Human words | Technical view |
| --- | --- | --- |
| Root identity | Your One identity | Root identity, recovery material, signing authority |
| Device certificate | This device belongs to you | Device cert, issuer, fingerprint, expiry/revocation |
| Self-mesh | Your personal device fabric | Self-mesh device graph, presence, target selection |
| Pairing invite | Add a device | Short-lived invite, QR payload, expiry, nonce |
| SAS verification | Check the trust code | Transcript-bound SAS, authentication confirmation |
| Secure channel | Private trusted connection | Encrypted session, peer fingerprint, replay window |
| Comms fabric | Best private path | Route candidates, score, transport, fallback |
| Remote instruct | Ask another device to do this | Signed command, capability scope, nonce, audit id |
| File send | Send a file | Transfer id, route, CDC chunks, wire bytes, cache savings |
| Folder sync | Keep this folder matched | Folder root, watcher, manifest, conflict policy |
| Privacy proof | What happened receipt | Route truth, channel state, audit event, policy decisions |
| Clear traces | Clear app history here | Trace categories, local records, retention policy |
| Freeze device | Block a lost device | Freeze command, authority proof, propagation status |
| Revoke device | Permanently remove trust | Revocation record, cert invalidation, audit event |
| Recovery device | A trusted way back in | Recovery authority, quorum or trusted-device policy |

The user should never need the right column to succeed. The right column exists so technical people can verify and trust the system.

## Expert System Inventory

One Setup should be built by understanding the whole One Link system, not by guessing at generic onboarding patterns.

The setup flow must know how these systems work:

- identity creation and import
- current-device naming
- root identity and device certificate minting
- self-mesh enrollment
- self-mesh presence and best-device selection
- QR/code pairing
- trust-code verification
- peer/device list rendering
- secure channel establishment
- chat send path
- file send path
- received file inbox
- sent transfer status
- folder sync setup
- local/no-router guide
- courier fallback
- remote instruction policy
- capability scopes
- privacy proof and audit events
- trace clearing and local wipe semantics
- stolen/lost device freeze
- permanent revocation
- recovery-device flow
- calls/video readiness
- camera/mic permissions
- desktop packaged app behavior
- mobile/browser peer behavior

If a setup step talks about one of these systems, it must use the real API/state behind that system. No fake completed checkmarks.

## Experience Name

User-facing name:

**One Setup**

Internal names:

- `one_setup`
- `first_success_flow`
- `setup_checklist`
- `setup_completed`

Avoid user-facing phrases like:

- tutorial
- product tour
- coach marks
- training
- tips

## Modes

One Setup has three modes.

### 1. Full Setup

Shown on first launch when the app detects no completed setup and no trusted peer.

Purpose:

- make this device ready
- pair one additional device if possible
- produce the first successful transfer or message
- show privacy proof

### 2. Quick Start

For users who do not want setup.

Purpose:

- skip the full flow
- land in the app immediately
- keep a small Setup checklist available in Activity or Settings

The skip button must be clear:

**Skip for now**

Skipping should set `one_setup_skipped_at_ms`, not `one_setup_completed`.

### 3. Resume Setup

Available from Activity, Settings, and empty states.

Purpose:

- let the user continue setup later
- never force them back into a modal
- show progress as plain completed items

## First Launch Decision

On first launch, One Link should decide what the person needs.

Inputs:

- paired peers count
- self-mesh devices count
- root identity exists
- display name exists
- onboarding/setup completion flags
- camera permission availability
- mic permission availability
- local network permission/connectivity state
- inbox has files
- outgoing transfers exist
- app traces exist
- recovery contact/device exists
- current device has been seen before

Decision examples:

- No identity, no devices: show One Setup.
- Identity exists, no paired devices: show Add Device step.
- One trusted device exists, no successful send: show First Send step.
- Successful send exists, no safety review: show Safety step quietly.
- User skipped: go straight to the app and show one Setup checklist chip.
- Returning user: never show the full-screen setup automatically.

## Primary User Journey

The ideal first-run journey:

1. Welcome
2. Name this device
3. Create or confirm One identity
4. Add phone or laptop
5. Verify trust
6. Send first thing
7. See privacy proof
8. Safety and recovery
9. Finish into the real app

This is the only flow we should consider "complete."

## Screen 1: Welcome

Purpose:

Make the promise instantly clear.

Visual:

- full-screen calm layout
- One Link glyph centered
- one-line promise
- two buttons
- no feature grid
- no marketing copy

Headline:

**You are One**

Body:

Your devices can talk directly, privately, and without an account.

Primary action:

**Set up One Link**

Secondary action:

**Skip for now**

Micro-proof row:

- No account
- End-to-end encrypted
- Works locally when possible

Behavior:

- `Set up One Link` moves to device naming.
- `Skip for now` closes setup, records skip time, and lands on the main app.
- `Esc` closes setup only after showing a simple confirmation if setup is in progress.

Do not show:

- long privacy paragraph
- all features
- technical route language
- "next, next, finish" wizard feeling

## Screen 2: Name This Device

Purpose:

Give the current device a human name so trust surfaces feel personal.

Headline:

**Name this device**

Body:

This name appears only to devices you trust.

Input:

- placeholder: `Alex's laptop`
- suggested names from OS where safe
- allow edit
- max length 64
- required for Full Setup, optional for Quick Start

Primary action:

**Continue**

Secondary action:

**Use default**

Validation:

- trim whitespace
- block empty name only when continuing full setup
- do not allow invisible/control characters
- warn on duplicate names in the user's mesh

Completion state:

Show a small device card:

- device name
- local device type
- trust state: `This device`

## Screen 3: One Identity

Purpose:

Create or import the root identity without making the user think about cryptography.

Headline:

**Create your One identity**

Body:

This lets your phone, laptop, and desktop belong to you without an account.

Primary action:

**Create identity**

Secondary action:

**I already have one**

Advanced disclosure:

**Import recovery key**

Behavior:

- If root identity already exists, skip this screen or show it as complete.
- If creating, mint local root identity and local device certificate.
- If importing, use explicit recovery/import flow with strong warnings and local-only handling.

Proof shown after creation:

**Identity ready**

Details:

- This device can now add your other devices.
- Your identity stays on your devices.
- One Link does not require a cloud account.

Security requirements:

- never expose raw root seed by default
- require explicit reveal action for recovery material
- record identity creation audit event
- bind current device certificate to root identity

## Screen 4: Add Your Phone Or Laptop

Purpose:

Get the user to the first magical moment: another device appears.

Headline:

**Add a device**

Body:

Open One Link on your phone or another computer and scan this.

Primary visual:

- large QR code
- short pairing code underneath
- "Waiting for device" presence animation
- current device card on the left
- incoming device card appears on the right
- subtle connection line between them

Primary action:

**Show QR**

Secondary actions:

- **Use code instead**
- **Pair later**

Behavior:

- generate short-lived invite
- show expiration timer
- rotate invite automatically
- allow copy code
- show detected incoming device before final trust
- require trust verification before enrollment completes

Empty state if camera unavailable on second device:

Use this code instead.

No-router state:

One Link should offer local options:

- same Wi-Fi
- direct cable
- local route token
- courier fallback

Do not dump those options unless needed.

## Screen 5: Verify Trust

Purpose:

Make security understandable and meaningful.

Headline:

**Check the trust code**

Body:

Both devices should show the same code.

Visual:

- six-digit SAS code in large type
- optional visual pattern/art
- device names on both sides
- "What if it does not match?" disclosure

Primary action:

**Codes match**

Secondary action:

**Codes do not match**

Helpful actions:

- **Read code aloud**
- **Show visual code**

Behavior:

- `Codes match` enrolls the device.
- `Codes do not match` cancels pairing, records rejected trust event, and explains calmly.
- The flow must never auto-trust a device without a clear user confirmation.

Copy for mismatch:

Stop here. The devices did not prove they are talking directly to each other. Try again when both screens are in front of you.

Security requirements:

- SAS must be bound to the actual pairing transcript.
- Trust confirmation must be explicit.
- Replayed invite codes must fail.
- Expired invites must fail.
- All trust decisions must be audit-visible.

## Screen 6: First Success

Purpose:

Let the user feel the product.

Headline:

**Send something to yourself**

Body:

Pick a tiny file or send a quick message. One Link will choose the best private path.

Primary action options:

- **Send test message**
- **Send a file**

Recommended default:

**Send test message**

Why:

- no file picker friction
- works instantly
- proves the channel

After the message succeeds:

Show a success card:

**Sent directly**

Details:

- encrypted end to end
- trusted device verified
- route used: local/direct/relay/courier as appropriate
- time taken

If sending a file:

Use a small generated text file by default:

`hello-from-one-link.txt`

Contents:

`This moved through your private One Link fabric.`

Behavior:

- offer file picker only as secondary
- send over real transport
- show transfer progress
- collapse technical details
- allow Details disclosure for route and performance proof

## Screen 7: Privacy Proof

Purpose:

Turn privacy from a claim into proof.

Headline:

**What just happened**

Body:

One Link sent it through your trusted fabric.

Proof card:

- Encrypted: yes
- Trusted device: yes
- Cloud account: not used
- Route: direct/local/relay/courier
- App traces: visible and clearable

Primary action:

**Looks good**

Secondary action:

**View details**

Details disclosure:

- route candidate chosen
- secure channel status
- device identity used
- replay protection active
- audit event recorded

Do not make this scary. It should feel like a receipt.

## Screen 8: Safety And Recovery

Purpose:

Teach stolen-device safety without making the user afraid.

Headline:

**If a device is lost**

Body:

You can freeze a trusted device from another trusted device.

Primary action:

**Review safety**

Secondary action:

**Do this later**

Safety checklist:

- Freeze a lost device
- Revoke a device permanently
- Clear app traces on this device
- Keep original computer files unless user chooses otherwise
- Recover a device if it was a mistake

Recommended setup:

- choose one recovery device
- explain that recovery requires an already trusted device or recovery key
- do not allow random remote "mark stolen" without authority

Important copy:

Freezing protects your One Link access. It does not erase your whole computer.

Security requirements:

- freeze requires authenticated trusted authority
- revoke requires stronger confirmation
- stolen-device action must be visible in audit
- recovery must not let an attacker unfreeze themselves
- local wipe must explain exactly what it clears

## Screen 9: Finish

Purpose:

End with confidence and route the user into the app.

Headline:

**One Link is ready**

Body:

Your devices can now act as one private fabric.

Primary action:

**Start using One Link**

Completion summary:

- identity ready
- this device named
- trusted device paired
- first message/file sent
- privacy proof viewed
- safety reviewed or intentionally skipped

After finish:

- close setup
- land on Chat if message was sent
- land on Files if file was sent
- show One Now strip with a helpful state
- set `one_setup_completed=true`
- persist completion server-side and locally

## Permanent Setup Checklist

One Setup should continue as a quiet checklist, not a modal.

Location:

- Activity panel near One Now
- Settings > Setup

Checklist items:

- Identity
- Current device name
- Add phone or laptop
- First message
- First file
- Privacy proof
- Recovery device
- Device safety
- Calls readiness
- Technical verification

Each item has:

- status: done / recommended / optional / needs attention
- one short line
- one action button

Example:

Identity: Done

Your One identity lives on this device.

Example:

Recovery: Recommended

Choose a trusted device that can help if one is lost.

The checklist must be dismissible but recoverable.

### Technical Verification Checklist

This is hidden in Human Mode and visible only when Technical Mode is enabled.

Items:

- root identity exists
- local device certificate exists
- device certificate is not revoked
- secure channel handshake succeeds
- self-mesh presence is fresh
- best-device selector returns a target
- remote instruction signing works
- remote instruction replay is blocked
- file transfer dispatch works
- privacy proof references a real audit event
- trace clearing dry-run reports correct categories
- freeze/revoke policy is available
- call media permissions are known

Each item should show:

- state
- last checked time
- related API endpoint
- related audit event id when available
- repair action if failed

## Contextual Empty States

Every empty state should be a launchpad.

### Empty Chat

Headline:

**No trusted device selected**

Action:

**Add a device**

Secondary:

**Send test message to myself**

### Empty Files

Headline:

**No files here yet**

Action:

**Send a test file**

Secondary:

**Open inbox folder**

### Empty Folders

Headline:

**No folders connected**

Action:

**Choose a folder**

Secondary:

**Learn what folder sync does**

### Empty Activity

Headline:

**Everything is quiet**

Action:

**Check privacy proof**

Secondary:

**Add a device**

### Empty Calls

Headline:

**Calls are ready when your devices are**

Action:

**Test camera and mic**

Secondary:

**Call my other device**

## One Now Integration

The One Now strip should be the living version of setup.

It should ask:

What is the next most useful thing for this person right now?

Priority order:

1. Security risk requiring action
2. Active transfer/call requiring attention
3. Pair first device
4. Finish first success
5. Review privacy proof
6. Set recovery
7. Try a main feature
8. Quiet state

Examples:

- Your phone is nearby. Add it?
- First message sent. View privacy proof?
- Desktop is faster for this file. Use it?
- Laptop has not checked in for 3 days. Review?
- You have duplicate received files. Collapse list?
- Everything is quiet.

One Now must never feel like an ad banner. It is the system being helpful.

## Skip Behavior

Skip must be first-class.

When the user clicks **Skip for now**:

- close setup immediately
- set `one_setup_skipped_at_ms`
- do not set completed
- do not show setup automatically again for at least 7 days
- keep checklist available
- use empty states instead of popups

If the user skips during an in-progress pairing:

- ask whether to cancel pairing
- revoke/expire pending invite
- leave no half-trusted device

If the user skips after identity creation:

- keep identity
- mark remaining steps as recommended

If the user skips after pairing:

- keep trusted device
- recommend first send

## Accessibility

Requirements:

- full keyboard navigation
- visible focus rings
- Esc behavior consistent
- screen-reader labels for every input and primary button
- no icon-only required actions
- QR code has code fallback
- SAS code can be copied and read aloud
- text contrast passes WCAG AA
- motion reduced when `prefers-reduced-motion`
- progress must not rely on color alone

Onboarding name input must have:

- visible label or screen-reader label
- placeholder
- validation message

## Visual Direction

Tone:

- calm
- private
- premium
- direct
- human

Layout:

- full-screen or centered setup shell
- narrow readable content
- one primary action
- secondary action visible but quiet
- device cards over text-heavy explanations
- real status receipts
- concise copy

Avoid:

- marketing feature grids
- giant paragraphs
- nested cards
- purple-only palette
- cluttered settings language
- scary security warnings unless there is actual risk

Device card fields:

- device name
- device type
- trust state
- last seen
- role: this device / trusted device / pending

Trust receipt fields:

- encrypted
- identity verified
- route used
- replay protection
- audit recorded

## Copy Principles

Use:

- "Add your phone"
- "Codes match"
- "Freeze a lost device"
- "Clear app traces"
- "No account needed"
- "Sent directly"
- "Your devices are ready"

Avoid:

- "cryptographic identity root"
- "self-mesh enrollment certificate"
- "remote instruction capability"
- "transport operator guide"
- "daemon"
- "SAS" unless paired with "trust code"

Technical language can exist in Details disclosures, never in the main path.

## Data Model

Suggested local/server settings:

- `one_setup_completed`
- `one_setup_completed_at_ms`
- `one_setup_skipped_at_ms`
- `one_setup_last_prompted_at_ms`
- `one_setup_current_step`
- `one_setup_first_identity_at_ms`
- `one_setup_first_device_paired_at_ms`
- `one_setup_first_message_at_ms`
- `one_setup_first_file_at_ms`
- `one_setup_privacy_proof_viewed_at_ms`
- `one_setup_safety_reviewed_at_ms`
- `one_setup_recovery_configured_at_ms`

Suggested audit events:

- `setup_started`
- `setup_skipped`
- `setup_completed`
- `identity_created`
- `identity_import_started`
- `device_invite_created`
- `device_pairing_started`
- `device_pairing_rejected`
- `device_pairing_completed`
- `first_message_sent`
- `first_file_sent`
- `privacy_proof_viewed`
- `safety_reviewed`
- `recovery_configured`

## API Requirements

Needed endpoints or endpoint capabilities:

- read setup status
- write setup status
- create root identity
- import identity
- name current device
- mint short-lived device invite
- poll pairing status
- confirm trust code match
- reject trust code
- send test message
- send generated test file
- fetch privacy proof for last setup action
- fetch safety status
- configure recovery device
- mark setup complete
- mark setup skipped
- fetch setup checklist
- fetch technical setup diagnostics
- rerun technical setup diagnostics
- export setup receipt

Every mutation must return:

- success/failure
- user-safe message
- next suggested step
- audit event id where relevant

## Settings Integration

Settings should include a dedicated Setup page.

Name:

**Setup**

Default view:

- Human Mode checklist
- Resume setup
- Add device
- Review safety
- Privacy proof

Technical toggle:

**Show technical setup details**

When enabled, Settings shows:

- identity status
- device certificate status
- self-mesh device graph
- current route candidates
- last secure channel proof
- last transfer proof
- replay protection status
- capability scopes
- recent setup audit events
- run diagnostics button
- export technical receipt button

Technical receipt export:

- JSON for machines
- Markdown for humans
- must redact secrets by default
- explicit "include sensitive material" should not exist unless a future security design proves it safe

The Settings page should make One Link feel powerful without making the main UI complicated.

## Dual Copy Examples

Every major event should have Human Mode and Technical Mode copy.

### Identity Created

Human:

Your One identity is ready. This device can now add your other devices.

Technical:

Root identity exists. Local device certificate minted and bound to current device.

### Device Paired

Human:

Your phone is trusted.

Technical:

Device certificate enrolled under root identity. Trust-code confirmation completed. Audit event recorded.

### First Message Sent

Human:

Message sent privately to your trusted device.

Technical:

Secure channel active. Message dispatched to selected peer target. Replay protection enabled.

### File Sent

Human:

File sent. One Link only moved the pieces it needed.

Technical:

Transfer completed through selected route. CDC/cache savings recorded. Wire bytes and effective speed available in transfer proof.

### Device Frozen

Human:

This device is blocked from One Link until you recover it.

Technical:

Freeze command accepted from trusted authority, signed, audited, and propagated to known devices.

### Traces Cleared

Human:

One Link cleared this app's local history for the selected area. Your original computer files were not deleted.

Technical:

Selected local trace categories cleared. File-system originals untouched. Audit event recorded.

## Failure States

Failures must be calm and recoverable.

### Pairing Timeout

Message:

The invite expired. Create a fresh one when both devices are nearby.

Action:

**Create new invite**

### Trust Code Mismatch

Message:

The codes did not match, so One Link stopped before trusting anything.

Action:

**Try again**

### Network Not Available

Message:

One Link cannot see another device yet.

Actions:

- **Use same Wi-Fi**
- **Use cable**
- **Use code**
- **Pair later**

### Permission Blocked

Message:

One Link needs camera permission on the device scanning the QR.

Actions:

- **Use code instead**
- **Open permission help**

### First Send Failed

Message:

The device is trusted, but the send did not finish. One Link can retry or use another path.

Actions:

- **Retry**
- **Use best path**
- **Show details**

## Security Red-Team Cases

The setup flow must defend against:

- invite replay
- expired invite reuse
- QR screenshot reuse
- pairing race with malicious nearby device
- trust code mismatch ignored by user
- device name spoofing
- duplicate device names causing confusion
- unauthorized freeze/revoke
- malicious "lost device" report
- recovery device compromise
- local trace wipe being misrepresented as full disk wipe
- remote action capability escalation
- pairing started by background page without user awareness

Required mitigations:

- short-lived invites
- explicit trust confirmation
- show device name and fingerprint fragment
- clear pending state
- audit every trust decision
- stronger confirmation for revoke/wipe
- freeze is reversible only through trusted authority
- no silent remote access

## Test Plan

Unit tests:

- setup state transitions
- skip vs complete semantics
- identity created only once
- device name validation
- invite expiration
- trust-code mismatch rejection
- privacy proof generation
- audit event emission

UI tests:

- all setup buttons wired
- skip works from every step
- back/continue works from every step
- QR fallback code visible
- trust mismatch path visible
- details disclosures hidden by default
- checklist appears after skip
- checklist disappears or marks complete after finish
- empty states point to correct setup actions
- keyboard-only completion path
- Esc behavior

Integration tests:

- two daemon pairing
- root identity created
- device cert minted
- trusted device enrolled
- first message over actual channel
- generated test file transfer
- privacy proof references actual transfer
- freeze/revoke visible after enrollment

Performance tests:

- setup status endpoint latency
- invite creation latency
- QR render latency
- pairing poll interval avoids waste
- first message dispatch latency
- first file dispatch latency

Manual QA:

- first launch on clean profile
- returning launch after complete
- returning launch after skip
- offline/no-router path
- small window
- high DPI
- keyboard only
- screen reader basics
- reduced motion

## Completion Criteria

One Setup is complete only when:

- first-run user can skip immediately
- first-run user can complete the main setup path
- setup performs real identity/device/send/proof work
- no fake success states exist
- every setup action has backend/API support
- trust decisions are explicit and audited
- failure states are recoverable
- empty states point to useful next actions
- setup checklist reflects real system state
- tests cover skip, complete, pairing, first send, privacy proof, and safety review
- the old passive four-slide onboarding is removed or replaced

## Build Order

Recommended implementation order:

1. Add setup state model and API status endpoint.
2. Replace old onboarding markup with One Setup shell.
3. Implement skip/complete persistence.
4. Wire device naming.
5. Wire identity create/import.
6. Wire add-device invite and pairing status.
7. Wire trust-code confirmation and rejection.
8. Wire first test message.
9. Wire generated test file.
10. Wire privacy proof receipt.
11. Wire safety/recovery review.
12. Add permanent Setup checklist.
13. Connect empty states and One Now.
14. Add exhaustive tests.
15. Remove stale onboarding copy and tests.

## North Star

The user should finish setup thinking:

> I did not make an account. I did not learn a complicated system. My devices found each other, trusted each other, sent something, showed me proof, and gave me a way to protect myself if something goes wrong.

That is One Link.

For the people.

Just works.

We are One.
