# One Link Operating Principles

Living document. Every ship is gated on these. If a ship-spec
fails the checklist, it doesn't merge. No exceptions.

---

## North stars

One Link's name is the project's spec. It is not "another P2P chat
app." It is the most direct expression in software of:

- **One** — nothing standing between two humans who want to talk.
- **We Are One** — anyone who wants in can get in. Not just
  technologists.
- **Everything is connected** — your message reaches its
  destination whether the recipient is online, offline, on a
  plane, or asleep.
- **It just works for the people** — the protocol's complexity
  is hidden from the user without lying about safety. The
  five-year-old can pair and chat.

These are not aspirations to feel good about. They are the
acceptance tests for every line of code we ship.

---

## The four principles

### 1. Reach over polish

> Who can use One Link this week who couldn't last week?

Polish that doesn't expand reach is allowed but is never the
priority. A new feature that only existing users notice is worth
less than a refactor that lets a new class of user (mobile,
non-technical, offline, low-power) join the network.

Every ship spec writes one sentence: **"This ship lets X use One
Link who couldn't before."** If the sentence is hard to write,
the ship is wrong.

### 2. Hide the engine

> What protocol detail can this ship stop showing the user
> without lying about safety?

Jargon, knobs, and "advanced" settings are technical debt. Pay
them down on every ship. The user shouldn't need to know what a
fingerprint, rendezvous URL, SAS, capability, ratchet, or chunk
hash is to use the product. They will need to know about *some*
of it to make trust decisions — that's where we don't lie. But
zero knobs the user can't make a sane choice about.

Every ship spec answers: **"What word, button, or knob disappears
because of this ship?"** If the answer is "none," the surface is
wrong.

### 3. Async by default

> Does this feature work when one side is offline, asleep, on a
> plane, or on the move?

The model is email/SMS, not phone calls. If the only path through
the feature requires both sides reachable, it is not done. Outbox
is the default; the synchronous path is the optimization. We
build for the assumption that the recipient is asleep right now.

Every ship spec answers: **"Where does this feature buffer when
the recipient is gone?"** "It just doesn't" is not an answer.

### 4. Frontier behind the surface

> Smart enough to be invisible.

Every feature carries at least one component that measurably
pushes a limit. Mediocre internals don't ship even when the
surface looks identical to a "normal" version. We're not
competing on the surface; we're competing on what runs behind it.

Frontier means measurable: an SLA, a regression test, a learned
model with a calibrated metric, a proof, a benchmark on a tier
of hardware nobody else targets. "Smart" without a number is
marketing.

Every ship spec answers: **"What is the measurable frontier this
ship pushes, and how do we regression-test it?"** If the answer
is "the surface is nicer," the engine isn't done.

---

## The discipline that pairs with the principles

> Smallest surface, deepest internals.

The four principles together create a strong gravitational pull
toward sprawl ("we should also do X, and Y, and Z..."). The
discipline that prevents this:

**Don't add ten features. Add one feature whose engine is ten
times the depth of the obvious version.**

Concrete examples of how this changes ship-specs:

- **Mobile UI.** Obvious: CSS breakpoints. Deep: sub-100ms input
  latency as a tested SLA on a 5-year-old phone, predictive
  prefetch of the next likely conversation, frame-budget
  regression tests in CI.
- **Multi-device-per-identity.** Obvious: "messages sync between
  your devices." Deep: your phone has the next message
  pre-decoded before you open the app, paths chosen from a
  learned reachability model, CRDT proofs of commutativity under
  partition + clock skew + edit storms.
- **Auto-accept rules.** Obvious: "this extension allowed." Deep:
  a learned per-user calibrated model of what THIS user has
  accepted historically, prompting only when uncertainty crosses
  a threshold.

The user sees the obvious version. The engine delivers the deep
version. They never know why their phone is "just" up to date
instantly.

---

## Ship-gate checklist

Every ship-spec answers all four before the first line of code:

```
[ ] Reach: __________________________________________
    (one sentence: who can use One Link who couldn't before)
[ ] Hide:  __________________________________________
    (what word/button/knob disappears)
[ ] Async: __________________________________________
    (where this buffers when the recipient is gone)
[ ] Depth: __________________________________________
    (the measurable frontier + the regression test that pins it)
```

If any answer is "n/a" or hand-wavy, the ship-spec needs more
work, not less. The principles are the floor, not aspirations.

---

## What the principles deliberately exclude

These things are NOT north stars and ship-specs that prioritize
them get challenged:

- "Modern aesthetic." Looking like 2026 is fine; designing for it
  is not.
- "Feature parity with X." We do not ship to match a competitor.
  We ship if it serves the four principles.
- "Power-user productivity." Power users are welcome but they
  are not the customer being optimized for. The grandparent in
  Tulsa is.
- "Faster shipping cadence." Cadence is a side effect. Pushing
  the frontier sometimes takes longer than a quick ship would
  imply; that's correct.

---

## How the principles get audited

These principles fail if nobody ever pulls a ship back over them.
Every quarter:

1. Re-read the four principles in light of what shipped.
2. Pick one ship that BARELY passed the checklist and ask
   honestly whether it should have shipped.
3. Pick one user-visible surface and ask: would a non-technical
   first-time user understand what this is and why it's there?
   If not, file a hide-the-engine debt ticket.
4. Pick one feature and ask: where is its frontier? If you can't
   point at a number, file a depth debt ticket.

Documents that don't get audited become decoration. Audit these.
