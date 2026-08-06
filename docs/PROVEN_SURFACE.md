# The Proven Surface

**An interface that cannot lie.**

Status: **Phase 1 and 1b are BUILT** (`idem/surface.py`, 34 tests, committed `6890441`); Phases
0 and 2–6 are design. Every capability this stands on is cited with its real maturity label, and
every gap it must cross is named rather than glossed. Where measurement has contradicted this
document, the document has been corrected in place and the correction recorded — never reverted.

---

## 0. The thesis, in one paragraph

Every user interface ever shipped renders a model and then validates edits against it afterward.
The picture is a *report about* the state, produced by code nobody can check, and there is no way —
for the user, an auditor, or a court — to establish that what appeared on screen corresponded to
what was true. This document describes the inversion: **the interface is the proof object.** The
renderer is specified as an Obligation whose laws are proven over *all* inputs, not tested on some;
proven-equal renderers collapse into one equivalence class so optimization cannot change meaning;
every frame is a pure function of state and therefore carries a receipt a stranger can re-derive;
and an interaction that would change meaning is not rejected — it is *unreachable*.

The claim that makes it worth building, stated so it can be falsified:

> **A One Link window can prove that the ✓ Verified badge has never, in any reachable state,
> appeared for a peer that was not verified — and can prove it as a theorem over all inputs, not
> as a test over some.**

If that cannot be made to hold on real product code, this design is wrong and should be abandoned.

---

## 1. The inversion

| Every UI ever built | The Proven Surface |
|---|---|
| Renders a model; validates edits afterward | The picture **is** the proof object |
| A click hits a widget | `pick(x,y)` back-maps the pixel to the **deepest IR node**, with provenance and coverage weight |
| Illegal edit → error message | Illegal edit → **the scene does not move**. *"The law is a wall, not an error."* |
| Design system = convention, enforced by review | Layout invariants = **theorems**, enforced by the discharge gate |
| Icons are decoration | A glyph is minted from the **equivalence class**, so proven-equal things share a symbol |
| Optimization risks behaviour change | Optimization is **selection within a proven class** — meaning cannot move |
| Screenshots are forgeable | Frames carry receipts a stranger re-derives in <500 LOC |
| Vendor pushes updates | Improvements propagate as **certificates** each device verifies independently |

---

## 2. What already exists

Verified by reading source and running tests on 2026-08-06, with the atlas's honest-tense
vocabulary (`PROVEN` / `GATED` / `BUILT` / `PROTOTYPE`).

| Component | Where | Maturity | Evidence |
|---|---|---|---|
| **Equivalence classes** — union-find per fence, transitivity free | `idem/merge.py`, `classes.py` | **GATED** | 18/18 gates, S0–S8, D1–D8, 97.44% mutation kill |
| **Congruence closure** — one leaf proof admits every caller | `idem/congruence.py` | **GATED** | Field grows with the call graph, not the proof budget |
| **Obligations** — laws as source; `ObligationClass` has *no free constructor* | `idem/obligations.py` | **GATED** | `validate()` refuses a rubber stamp; `oid()` folds laws so weakening mints a NEW obligation |
| **SIGIL** — Scene whose regions ARE IR nodes; `deform` is a wall | `idem/sigil.py` (244 lines) | **PROTOTYPE / first stone** | 39 sigil+soma tests pass |
| **SOMA** — perception graded, "the command is not the deed" | `idem/soma.py` | **GATED** | 24/24 mutation kill, 20 gates |
| **Epistemic typing** — theorem/observation/estimate as non-substitutable species | `idem/epistemic.py` | **GATED** | A measurement offered to `admit` is a `TypeError` |
| **Joint extraction** — argmin over (member × backend) | `idem/extract.py` | **GATED + MEASURED** | 10.55× dividend on `{loovm, python_cpu}`; ~1.0 on full set (honest scope) |
| **Measured joules + Landauer distance** | `idem/energy.py` | **GATED** | Absent instrument ⇒ no number, ever |
| **`.cl` → WGSL compiler** (216 lines, zero deps, browser + Node) | `living-glyph/cl2wgsl.js` | **PROTOTYPE** | 20 effects compiled; **zero tests, no CI, no remote, UNLICENSED** |
| **Self-hosted compiler as WASM** (4,593 bytes) | `Coherence_Energy_Labs_Website/future_mode/phase6_selfhost/` | **BUILT** | Verified end-to-end Node + headless real-GPU; drives a 1,048,576-cell PDE. **"Built in isolation; NOT connected to the live site."** |
| **0-ULP CPU↔GPU twin** — same AST, `Math.fround` per op | `cl2wgsl.js` ~143–212 | **PROTOTYPE** | The determinism receipt this whole design rests on |
| **Canonical receipt + <500-LOC stranger verifier** | coherence_covenant | **PROVEN** | — |
| **PQ transparency log** (Ed25519 + ML-DSA-65, DNS-pinned) | CEL website | **GATED** | 10/10 attack suite, two green controls |
| **Certified compilation + Z3 total equivalence** | coherence_lang | **GATED** | Proves two implementations equal over ALL inputs |

**One Link today has none of it.** No WebGPU, no `.cl`, no living-glyph. Clean integration surface.

---

## 3. The central design decision

The obvious reading of SIGIL is "render the program's IR and let people drag it." That is a
developer inspector, not a product, and it is not the interesting half.

The move that makes this a new category:

> ### The user interface is itself an Obligation.
>
> A view is a pure function `State → Scene`. A pure function can carry an Obligation. An
> Obligation's laws are **proven over all inputs**. Therefore **UI invariants become theorems.**

Design systems today are conventions enforced by review. Here, "a message marked unverified can
never render with the verified glyph" is discharged by the CHC induction lane over every input, and
because `Obligation.oid()` folds the laws into the content address, **nobody can quietly weaken it**
— a relaxed law is a *different obligation*, and the existing class's proofs do not transfer to it.

That property is the whole security argument. It is not that we checked; it is that the bar cannot
be lowered without minting a new, visibly different thing.

### Layout invariants are theorems too

Not just semantics. Structure:

- the badge region and the name region **never overlap**
- the row's contents **never exceed** the row's bounds
- the unread-count region is empty **iff** `unread == 0`
- every message carrying a verdict **displays** that verdict

Each is a universal predicate over the renderer's parameters and `__result`. Each is provable.
No UI framework in existence offers this, because no UI framework's renderer is a proof object.

---

## 4. Architecture

```
  L0  OBLIGATION        idem/obligations.py     human-legible law; anchored in the PQ log
        │               "what must be TRUE, never how"
        ▼
  L1  MEMBERS           .cl source              alternative renderers, all satisfying L0
        │               idem/member.py::make_member(src, entry)
        ▼
  L2  CANON             idem/merge.py           proven-equal members → ONE class
        │               congruence.py, mining.py   transitivity free; merges mine rewrite rules
        ▼
  L3  EXTRACTION        idem/extract.py         joint argmin (member × backend)
        │               energy.py, context.py      measured joules, call-site aware
        ▼
  L4  PAINT             cl2wgsl → WGSL          GPU; 0-ULP CPU twin → frame receipt
        │               coherence_lang → WASM      CPU layout (structs/lists live here)
        ▼
  L5  SURFACE           idem/sigil.py           Scene regions ARE IR nodes; deform = wall
        │
        ▼
  L6  MEMBRANE          idem/soma.py            peer claims are OBSERVATIONS, never theorems
        │               idem/epistemic.py          enforced as a type, not a convention
        ▼
  L7  TRANSPORT         One Link channel        certificates gossip peer-to-peer
        │
        ▼
  L8  TRUST             covenant + PQ log       <500-LOC stranger verifier
```

### Why `.cl` is forced, and why that is good news

`make_member(src, entry)` compiles `.cl` and canonicalizes its AST. So a renderer that participates
in proofs **must be written in `.cl`**. That looked like a constraint and is actually the keystone:

- `.cl` → **WGSL** (cl2wgsl) — the GPU paint path
- `.cl` → **WASM** (coherence_lang, M1–M3.6 typed numerics/strings/lists/structs) — the CPU layout path
- `.cl` → **member** (idem) — the proof path
- the **same AST** drives the WGSL emitter and the CPU evaluator — which is what makes the 0-ULP
  receipt possible at all

One language, four consumers, one canonical AST. The renderer is not ported from the existing
Python/JS UI; it is **new `.cl` code**, and that is unavoidable.

### The CPU/GPU split is not a compromise

The WGSL subset is scalars-only, no vectors, no `break` (`effects/raymarch.cl` proves it is still
Turing-useful — a full SDF sphere-tracer in 56 march steps). Layout needs structs and lists, which
exist in the **WASM** backend, not the WGSL one. So:

- **Layout runs on CPU** (`.cl` → WASM): produces a `Scene` — pure geometry + node identity
- **Paint runs on GPU** (`.cl` → WGSL): consumes the Scene, emits pixels
- **Attestation runs on CPU** (the 0-ULP twin): re-derives the same pixels bit-exactly

The layers fall out of the toolchain's real shape rather than being imposed on it.

### Fixed point, not float — and the fence system says why

Layout arithmetic in `f32` is not provable over a clean semantics, and idem **fences by lane**: it
refuses to link `exact` and `math-int`, and refuses an undeclared lane outright rather than merging
at whatever model it happens to use. `_semantic_veto` will refuse a certificate that claims `exact`
while declaring a proof over the mathematical integers — *"a proof over Z is not a proof over
Z/2^64, and division alone breaks the lift."*

Therefore: **layout math is fixed-point integer** (the Obsign fixed-point spec + torture tests are
the canonical home). This is not a performance choice. It is what puts layout inside a lane the
prover can actually vouch for.

---

## 5. The frame receipt

```
frame_digest = H( "one-link-frame/v1" ‖ ui_class_root ‖ state_digest ‖ viewport ‖ frame_index )
```

The subtle and important field is the first one.

**`ui_class_root` is the equivalence-class root, not the member id.** Every proven-equal renderer
has the same root. Which means:

> A device that swaps to a faster or lower-energy renderer **does not invalidate its receipts** —
> because the substitution was proven meaning-preserving. The attestation is stable under
> optimization.

That is not a convenience. It is the property that lets L3 (extraction) and L8 (trust) coexist. Bind
a receipt to a *member* and every optimization breaks verification; bind it to the *class* and
optimization is free. This falls directly out of idem's model and is, as far as I can establish, not
available anywhere else.

### What a verifier does

1. Fetch the Obligation by `oid` from the PQ transparency log
2. Fetch the class root and its witness paths
3. Re-discharge the laws (or trust the anchored discharge receipt)
4. Re-run the renderer's CPU twin on the claimed state
5. Compare `frame_digest`

Steps 4–5 are the <500-LOC stranger verifier's job. Step 3 is the expensive one and is why
**proving is admission-time, not frame-time** — see §7.

---

## 6. SOMA is the right law for a peer-to-peer product

One Link's entire domain is claims from machines you do not control. SOMA already types this:

- A peer's assertion enters as a **graded OBSERVATION** carrying instrument + calibration
- Unattested it may only `configure`; attested it may `order`; **it may never `admit`**
- *"The command is not the deed"* — `actuate` returns `commanded`; success is claimed only by an
  **independent** outcome measurement, because the actuator measuring itself is self-agreement
- Every record frozen — *a mutable receipt is forgeable*

Mapped onto the product: a peer claiming "I am verified" can influence *ordering* and *display
hints*. It can never become a theorem the interface presents as proven. And `epistemic.py` makes
that a **type error** rather than a discipline — the code cannot pass an observation where a theorem
is required, which is precisely the class of bug the audit has been finding all week under different
names.

---

## 7. Where the proving actually happens

A reader will reasonably assume this means proving 60 times a second. It does not.

| When | What runs | Cost |
|---|---|---|
| **Authoring** | `Obligation.validate()` — refuses a law-free rubber stamp | instant |
| **Admission** | `discharge()` — CHC induction over all inputs; `ObligationClass.admit()` | seconds to minutes, **once per member** |
| **Merge** | `merge.py` — prover call, or free via transitivity / congruence / a mined rule | once per pair, often zero |
| **Install / first run** | extraction: joint argmin, measured joules on *this* machine | once, then cached |
| **Every frame** | layout + paint + `H(...)` | a hash — microseconds |

**Proofs are build-time and admission-time. Frames are runtime. Receipts are hashes.** If that
separation ever blurs, the design is being implemented wrong.

---

## 8. The self-evolving alphabet

`mint` ties a glyph to the **class**, not the member: *"two members of one proven class MINT THE SAME
SIGIL — CANON identity merges glyphs for free… tying it to the class representative is what makes
the alphabet converge instead of fragmenting into dialects."*

The consequence is strange and worth stating plainly. As the system proves more equalities, distinct
notations **collapse into a shared symbol**. The interface's vocabulary is not designed; it is
*discovered by proof*, and it converges rather than sprawling.

Over a long enough horizon the surface develops a notation where each glyph denotes a proven
equivalence class — a written language whose spelling rules are theorems. SIGIL's source calls this
"the self-evolving alphabet's promotion-gate embryo" and names the failure it avoids: the
minting-drift wall.

This is the most speculative section of this document and is labelled accordingly. It is also the
reason to build the rest.

---

## 9. Improvements travel as theorems

`mining.py`: every admitted merge **is** a proven identity, and `synthesize_rule` turns one into a
rewrite rule that merges future pairs at zero prover cost. Every mined rule is **re-discharged over
fresh variables** before it may be cited.

Now put that on the One Link channel:

1. Your laptop's extraction finds a lower-energy proven-equal renderer
2. The merge that admitted it is a certificate with a witness path
3. That certificate gossips to your peers over the existing PQ channel
4. Each peer **verifies independently** — nothing is trusted for its origin
5. Peers adopt it, or refuse

The class root is unchanged, so **every existing frame receipt stays valid** while devices paint
faster and cooler. The mesh improves without a release, and without anyone trusting a vendor.

This is the payoff loop. It is also the part that most needs the covenant as an immune system:
an unverified certificate must be refused, and `frontier.py`'s witness ratchet already encodes the
matching hard rule — *a `proven` verdict contradicting a stored witness is a hard halt: one of the
two is wrong and the process cannot tell which.*

---

## 10. What must be built

Honest gap list. Nothing here is a detail.

### 10.1 Text — the killer

A UI without excellent text is a toy. Shaping, hinting, subpixel AA, bidi, complex scripts:
HarfBuzz is decades of accumulated correctness and cannot be waved away.

The design has a real answer — **deterministic glyph rasterization from a pinned font in fixed
point makes text part of the attestation rather than an obstacle** — but it is years of work to do
well, and "well" is the only bar that matters for text.

**This is the single most likely cause of death for the whole design.** §12 makes it the first
experiment for that reason.

### 10.2 Scene must grow up

`sigil.Scene` today is `Region`s from `canonical_ast` struct-repr, and `render()` returns a *string*.
It renders the IR of a **function**. A product surface needs a render tree with text runs, images,
clipping, scrolling, and z-order. This is a substantial extension of a 244-line first stone.

### 10.3 Accessibility — and this is a genuine upside

A pixel surface normally has no semantic tree, which is a legal problem in several markets. But
**this surface has one natively**: Scene regions *are* IR nodes, and `pick` already back-maps
coordinate → node → provenance. A11y trees can be **generated from the Scene** rather than
maintained alongside it — structurally better than the DOM, where the semantic tree and the visual
tree drift apart by default. Still has to be built and bound to UIA / AT-SPI / NSAccessibility.

### 10.4 The window

A native shell (WebView2 / WKWebView / WebKitGTK, or a raw WGPU surface). Note the daemon must stay
detached — One Link's launcher deliberately survives window close so peers stay online.

### 10.5 Input → deform → re-render

`pick` and `deform` exist; the gesture loop does not. And a hard question: **most product
interactions are not meaning-preserving deformations.** Sending a message changes state, it does not
rewrite the program. §11.1 is where that gets resolved.

### 10.6 Lifting One Link's real logic

Members must be `.cl`. The renderer is new `.cl` code, not a port. Scope it: this design does not
require rewriting One Link. It requires writing *the view layer* of one surface in `.cl`.

### 10.7 living-glyph needs hardening before it is load-bearing

Zero tests, no CI, no remote, UNLICENSED, 7 commits. The 0-ULP twin — the linchpin of every frame
receipt — is a prototype. Before anything depends on it: a test suite, a CI gate, and a
**cross-vendor** 0-ULP measurement (§12.1).

---

## 11. Open questions I could not settle

Recorded rather than resolved, per the estate law that "evidence unlocated" is an honest verdict and
a confident guess is not.

### 11.1 State versus program

The program is a proof object. The application also has **state** — messages, peers, transfers —
which is not a member and cannot be. Two candidate models:

- **(a) State is a parameter.** The view is `render(State) → Scene`; state flows through a proven
  pure function. Laws quantify over all states. Clean, and probably right.
- **(b) State transitions are themselves obligations.** `send_message: State → State` with laws
  ("no message is ever lost", "trust never silently upgrades"). Much more powerful, much larger.

(a) is the buildable start. (b) is where it gets interesting and should not be attempted first.

### 11.2 Does the wall generalize?

`deform` refuses drags with no e-graph edge. That is exactly right for manipulating a *program*.
Whether it is the right metaphor for a *user* — who wants to send a message, not rewrite a
renderer — is genuinely unclear to me. It may be that SIGIL is the **developer/audit surface** and
ordinary interaction is conventional but frame-attested. That would be a smaller, still-novel
system.

### 11.3 Cross-vendor 0-ULP

The CPU twin is bit-faithful to f32 GPU arithmetic *on the paths measured*. Whether it holds across
NVIDIA / AMD / Intel / Apple drivers is **unmeasured**, and every frame receipt depends on it.
Fixed-point layout sidesteps this for geometry; paint may still differ. Measure before claiming.

### 11.4 First-run cost

Discharge + extraction on install could take minutes. Unknown, and directly determines whether this
is shippable. Measure with the joules instrument that already exists.

---

## 12. Build plan

Each phase has an exit criterion that **can say no**. A phase that cannot fail is a rubber stamp —
`Obligation.validate()` refuses those, and so should we.

### Phase 0 — Kill the two things that would waste the whole effort *(1–2 weeks)*

Run these **before** any building. Both are cheap and either can end the project.

**0.1 Deterministic text probe.** Rasterize a glyph run from a pinned font in fixed point; compare
bit-exactness across two machines and two GPUs.
→ **Exit:** bit-identical raster of a 200-glyph run on ≥2 machines.
→ **If it fails:** text is not attestable; scope collapses to §11.2's smaller system. Say so.

**0.2 Cross-vendor 0-ULP.** Same `.cl` effect through cl2wgsl on ≥3 GPU vendors vs the CPU twin.
→ **Exit:** 0 ULP on all, or a *characterized* bound with a named cause.
→ **If it fails:** frame receipts attest the class + state, not the pixels. Weaker, still novel.

> Do not skip these because they might say no. That is the reason to run them.

### Phase 1 — The badge theorem *(BUILT 2026-08-06)*

**Status: done.** `idem/surface.py` + three suites, 34 tests, 3/3 mutants killed, idem's full
962-test suite still green. Committed as `6890441`.

**The law form in this document was WRONG, and measuring it produced a better one.** The original
plan specified `("property", expr)` laws. Measured against the real engine:

| case | verdict | scope |
|---|---|---|
| straight-line renderer + `property` | **REFUSED** — `out_of_scope` | — |
| recursive control + `property` | discharged | `math-int` |
| straight-line renderer + `reference` | **discharged** | **`exact`** |

Every UI renderer is straight-line, so the property lane can never see one — and it says so
honestly rather than admitting it. The working form reuses `epsilon.py`'s reduction instead of
inventing a lane: `holds(x) = 1 iff P(x)`, then prove `holds == const-1`. It discharges at scope
`exact`, **stronger** than the property lane would have given.

```python
BADGE_LAW = LawSpec(
    name="badge-never-lies",
    law_src="""
fn holds(trust: Int) -> Int {
    if trust != 2 { if badge(trust) != 7 { 1 } else { 0 } } else { 1 }
}
""",
    predicate=lambda trust, r: trust == TRUST_VERIFIED or r["badge"] != GLYPH_VERIFIED,
)
```

**Exit criteria, all met:**

1. ✅ the correct renderer proves at scope `exact`, with the claim re-derived on 26 real inputs
2. ✅ **a renderer wrong on ONE un-exampled input (`trust == 9`) is `refuted` by the prover** — the
   examples are 0, 1, −1, so a test suite ships that bug and the prover does not
3. ✅ a second, differently-written renderer merges into the same class; a law-abiding but
   *different* renderer does not
4. ✅ an illegal `deform` returns `moved=False` with the wall message; the glyph mints from the
   class, so A and B share a sigil and C does not

**And a second correction, found by the tests failing:** the non-overlap law originally compared
against `min(name_end, 290)` — which hard-codes truncation into the LAW, so a clamping layout that
genuinely overlaps the name *proved* it. A law that assumes the answer is not a law. Fixed at root
with `LawSpec.observes`, letting a law read multiple entries of a member so it can see where the
name **actually is** rather than where it ought to be.

### Phase 1b — Layout invariants are theorems *(BUILT 2026-08-06)*

Not anticipated in the original plan and, I think, the part with no precedent. Three layouts, two
laws:

| layout | in-bounds | non-overlap |
|---|---|---|
| naive — `NAME_X + n*CHAR_W + GAP` | ❌ overflows at n≥42 | ✅ |
| **clamped** — `min(that, ROW_W − BADGE_W)` | ✅ | ❌ **draws the badge on top of the name** |
| truncated — cap the NAME, then place | ✅ | ✅ |

Clamping is what a developer writes when the bug report says *"the badge falls off the edge"*. It
fixes the reported symptom and silently creates an overlap that appears only for names longer than
~41 characters — which survives review and testing because nobody types one.

**Nobody told the prover that bug exists.** It follows from stating both laws at all.

### Phase 2 — The frame receipt *(3–6 weeks)*

Paint Phase 1's Scene through cl2wgsl; re-derive on the CPU twin; emit and verify a receipt.

→ **Exit:** a stranger verifier (<500 LOC, no import of our renderer) re-derives `frame_digest`
from `(oid, class_root, state)` and matches. **And a tampered state must fail it.**

### Phase 3 — Optimization must not move meaning *(2–4 weeks)*

Add a third member; let extraction pick by measured joules on the local machine.

→ **Exit:** the selected member differs across two machines with different hardware, **and the
`frame_digest` is identical on both** — because the receipt binds the class, not the member. This is
the design's central claim, and this is the experiment that proves or kills it.

### Phase 4 — The membrane *(3–5 weeks)*

Route a real peer trust claim through SOMA. Unattested → `configure` only. Attested → `order`.

→ **Exit:** an attempt to `admit` a peer observation raises a `TypeError` from `epistemic.py`, in a
test that fails if the typing is removed.

### Phase 5 — Certificates on the wire *(6–10 weeks)*

Gossip a mined rewrite rule over the One Link channel; peers verify independently.

→ **Exit:** peer B adopts an improvement discovered on peer A **without trusting A** — and a forged
certificate is refused, proven by injecting one.

### Phase 6 — Grow the surface

Only now: more views, text at scale, a11y from the Scene, the native window.

**Phase 0 and Phase 1 are the whole decision.** Everything after is engineering.

---

## 13. How this dies

Written down first, so it is not rationalized later.

| Failure | Detected by | Consequence |
|---|---|---|
| Text is not deterministically rasterizable at quality | Phase 0.1 | Attested *text* is out; badges/glyphs survive |
| 0-ULP does not hold cross-vendor | Phase 0.2 | Receipts attest class + state, not pixels |
| The wrong member is not refused | Phase 1 exit 2 | **Stop.** The gate is a rubber stamp |
| Laws come back `out_of_scope` on real renderers | Phase 1 | The prover cannot see this code; scope shrinks to kernels |
| First-run cost is minutes | Phase 3 | Precompute server-side, or ship a warmed class |
| Users don't want a deformable program | Phase 6 | SIGIL becomes the audit surface; §11.2's smaller system |

The honest floor, if **everything** above fails except Phase 1: *One Link's security verdicts are
rendered by a proven renderer whose laws cannot be weakened without minting a new obligation.*
That alone is something no other application has.

---

## 14. Why this belongs in One Link specifically

Not opportunism — fit.

One Link's product **is** telling users what to trust. Look at the current window: `✓ Verified`,
`Older build`, `✗ Needs attention`. Every one of those is a security verdict rendered as pixels,
with no way for anyone to establish that the pixels reflected the truth.

Every other application would be *decorated* by this. One Link is **completed** by it. And it
already carries the pieces: a PQ channel for certificates, a transparency log to anchor obligations,
Sigstore, a transactional updater proven on hardware, and TLA+-checked protocols with the attacker
switched on.

It also dissolves a problem I flagged as the blocker for reach: code signing attests *who built it*.
This attests *what it does* — strictly stronger, and unavailable from any notarization service.

---

## Appendix A — Reading order

1. `idem/obligations.py` — the inversion. Start here.
2. `idem/sigil.py` (244 lines) — read `deform` last; it is the thesis in one function.
3. `idem/soma.py` + `idem/epistemic.py` — the membrane and its type system.
4. `living-glyph/cl2wgsl.js` ~143–212 — the CPU twin; the linchpin.
5. `idem/extract.py::joint_vs_sequential` — why selection is a joint argmin.

## Appendix B — Estate laws this design must obey

- An instrument that cannot be read **does not exist** — no path from absent instrument to a number
- A gate that cannot say no is a **rubber stamp** — every phase exit has a negative control
- **Measured is not proven** — `epistemic.py` makes it a type; do not launder it back
- A `proven` verdict contradicting a stored witness is a **hard halt**
- A builder that cannot see its inputs must **abort**, never emit a plausible empty
- Weakening an obligation mints a **new** obligation — the bar cannot be quietly lowered
- **Verify every claim, including good news** — including every claim in this document

---

*Written 2026-08-06. Every capability cited was read from source; the sigil and soma suites were run
(39 passing) rather than taken from the card. Nothing here has been built.*
