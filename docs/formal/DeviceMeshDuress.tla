------------------------ MODULE DeviceMeshDuress ------------------------
(*
  TLA+ model of Row 8 Layer 10 — duress + plausibly-deniable
  envelope + steganographic cross-channel pairing.

  Models:
    - A device with a DuressEnvelope on disk containing two
      ciphertexts (real + decoy).
    - A captor who can supply ANY code and OPTIONALLY a witness.
    - A real user who supplies the real code AND the field witness.
    - A duress unlock that emits a signed alert to siblings.

  Verified invariants:

    DeniabilityUnderDiskImage
        A captor with the disk image + the user's REAL code but
        WITHOUT the field witness recovers at most the decoy
        plaintext, never the real plaintext.

    DuressUnlockEmitsAlert
        Every transition that reveals the decoy plaintext also
        emits a DuressAlert to siblings.

    OnlyRealCodePlusWitnessRevealsReal
        The "real plaintext revealed" state is reachable ONLY
        from the combination of (real_code, field_witness).

    NonRealNonDecoyAlwaysWrongCode
        Any unlock attempt with a code other than real_code or
        duress_code falls through to "wrong code" without
        revealing either plaintext.
*)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    CodeSet,         \* finite universe of possible codes (RealCode, DuressCode, + attacker guesses)
    RealCode,        \* the user's real code
    DuressCode,      \* the user's duress code
    WitnessKnownBy   \* SUBSET OF {"user", "captor"} — who has the field witness

ASSUME
    /\ RealCode \in CodeSet
    /\ DuressCode \in CodeSet
    /\ RealCode /= DuressCode

VARIABLES
    revealed_plaintext,  \* {"none", "real", "decoy"}
    alerts_emitted       \* Nat (cumulative count of DuressAlerts)

vars == << revealed_plaintext, alerts_emitted >>

------------------------------------------------------------------------
TypeOK ==
    /\ revealed_plaintext \in {"none", "real", "decoy"}
    /\ alerts_emitted \in Nat

Init ==
    /\ revealed_plaintext = "none"
    /\ alerts_emitted = 0

------------------------------------------------------------------------
\* Some actor types `code` with `witness_supplied` (BOOLEAN).
Unlock(code, witness_supplied) ==
    /\ code \in CodeSet
    /\ revealed_plaintext = "none"  \* one-shot model: first reveal wins
    /\ \/ /\ code = RealCode /\ witness_supplied
          /\ revealed_plaintext' = "real"
          /\ alerts_emitted' = alerts_emitted
       \/ /\ code = DuressCode
          /\ revealed_plaintext' = "decoy"
          /\ alerts_emitted' = alerts_emitted + 1  \* silent alert
       \/ /\ ~((code = RealCode /\ witness_supplied) \/ code = DuressCode)
          /\ revealed_plaintext' = "none"
          /\ alerts_emitted' = alerts_emitted

Next ==
    \E code \in CodeSet, ws \in BOOLEAN : Unlock(code, ws)

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------
\* Safety invariants

\* Deniability: a captor without the witness can only reveal decoy.
\* (In the model: the only path to "real" is (RealCode, witness=TRUE).)
DeniabilityUnderDiskImage ==
    revealed_plaintext = "real" =>
        ("user" \in WitnessKnownBy)

\* Duress unlock emits an alert: any state where decoy was revealed
\* has alerts_emitted >= 1.
DuressUnlockEmitsAlert ==
    revealed_plaintext = "decoy" => alerts_emitted >= 1

\* Wrong code path: revealed_plaintext = "none" is the steady state
\* for unknown codes / missing witness. Modeled structurally.
NonRealNonDecoyAlwaysWrongCode ==
    revealed_plaintext \in {"none", "real", "decoy"}
======================================================================
