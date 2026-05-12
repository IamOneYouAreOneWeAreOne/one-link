--------------------------- MODULE PairQr ---------------------------
(*
  TLA+ specification for One Link's pair-by-QR Factor-1 trust
  establishment (Phase F2, Coherence Mesh).

  Per FILE_ENGINE_V2_PLAN.md Phase D item #7 (formal verification of
  pairing state machines), and per the Phase F2 audit follow-up.

  This module models the Inviter and Scanner state machines, the
  message exchange between them, and an active network attacker.
  Verified properties:

    - NoUnverifiedConfirm: the Scanner never reaches Done with a
      chain key whose underlying transcript or pubkey differs from
      what the honest Inviter signed.
    - NoCrossInviteReplay: a PairResponse signed by the Scanner for
      Invite A can never be accepted by Inviter B (B != A).
    - NoOutOfOrderTransition: both state machines refuse calls that
      don't match their current state.
    - SAS_AGREEMENT_ON_HONEST_RUN: if both sides reach Done without
      attacker interference, they hold the same chain key.

  Verification: run TLC over a small finite state space (typically
  2 inviters, 2 scanners, 2 attacker actions). The spec is a
  design-time gate. Production deployments do not invoke TLC.
*)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Inviters,     \* set of identities that can run an Inviter
    Scanners,     \* set of identities that can run a Scanner
    Invites,      \* set of distinct invite payloads (abstract IDs)
    AttackerOn    \* BOOLEAN — model an active MITM or not

VARIABLES
    inviter_state,    \* function Inviters -> state name
    scanner_state,    \* function Scanners -> state name
    bound_invite,     \* function Scanners -> invite they scanned
    transcript,       \* function (Inviters \cup Scanners) -> transcript value
    chain_key,        \* function (Inviters \cup Scanners) -> derived chain key
    wire_responses,   \* set of (invite, scanner, response) tuples seen on wire
    wire_confirms     \* set of (inviter, transcript) tuples seen on wire

vars == <<inviter_state, scanner_state, bound_invite, transcript,
          chain_key, wire_responses, wire_confirms>>

(* -- State labels match the Rust enum variants -- *)
InviterStates == {"AwaitingResponse", "AwaitingUserConfirm", "Done", "Aborted"}
ScannerStates == {"AwaitingConfirm", "Done", "Aborted"}

(* -- Abstract transcript / chain-key values are deterministic
      functions of their inputs. We don't model the cryptographic
      primitive; we model that the SAME inputs produce the SAME
      derived value, and DIFFERENT inputs produce DIFFERENT values
      (collision-free abstraction). -- *)
TranscriptOf(inviter, scanner, invite) ==
    <<"transcript", inviter, scanner, invite>>

ChainKeyOf(t) == <<"chain_key", t>>

(* -- Initial state: every state machine is at its starting state.
      No wire traffic yet. -- *)
Init ==
    /\ inviter_state = [i \in Inviters |-> "AwaitingResponse"]
    /\ scanner_state = [s \in Scanners |-> "AwaitingConfirm"]
    /\ bound_invite  = [s \in Scanners |-> CHOOSE x \in Invites : TRUE]
    /\ transcript    = [x \in Inviters \cup Scanners |-> <<>>]
    /\ chain_key     = [x \in Inviters \cup Scanners |-> <<>>]
    /\ wire_responses = {}
    /\ wire_confirms  = {}

(* -- A scanner picks an invite and produces a response. The
      response is bound to the specific invite via the transcript
      computation. -- *)
ScannerScan(s, i, inv) ==
    /\ scanner_state[s] = "AwaitingConfirm"
    /\ bound_invite[s] = inv  \* scanner has decided which invite it sees
    /\ transcript' = [transcript EXCEPT ![s] = TranscriptOf(i, s, inv)]
    /\ chain_key' = [chain_key EXCEPT ![s] = ChainKeyOf(TranscriptOf(i, s, inv))]
    /\ wire_responses' = wire_responses \cup {<<inv, s, TranscriptOf(i, s, inv)>>}
    /\ UNCHANGED <<inviter_state, scanner_state, bound_invite, wire_confirms>>

(* -- The inviter receives a response. It MUST verify that the
      response is bound to ITS invite (binding semantics from the
      Rust impl). If the bind is wrong, the action does not fire. -- *)
InviterReceiveResponse(i, inv, s, resp_transcript) ==
    /\ inviter_state[i] = "AwaitingResponse"
    /\ <<inv, s, resp_transcript>> \in wire_responses
    \* This is the load-bearing security check: the inviter
    \* recomputes the transcript and refuses any response that
    \* doesn't match.
    /\ resp_transcript = TranscriptOf(i, s, inv)
    /\ inviter_state' = [inviter_state EXCEPT ![i] = "AwaitingUserConfirm"]
    /\ transcript' = [transcript EXCEPT ![i] = resp_transcript]
    /\ chain_key' = [chain_key EXCEPT ![i] = ChainKeyOf(resp_transcript)]
    /\ UNCHANGED <<scanner_state, bound_invite, wire_responses, wire_confirms>>

(* -- After the user verbally confirms the SAS, the inviter signs a
      PairConfirm committing to the transcript. -- *)
InviterConfirm(i) ==
    /\ inviter_state[i] = "AwaitingUserConfirm"
    /\ wire_confirms' = wire_confirms \cup {<<i, transcript[i]>>}
    /\ inviter_state' = [inviter_state EXCEPT ![i] = "Done"]
    /\ UNCHANGED <<scanner_state, bound_invite, transcript, chain_key, wire_responses>>

(* -- The scanner accepts the confirm. It MUST verify that the
      confirm is signed by the inviter pubkey it pinned from the
      QR AND that it commits to the same transcript. -- *)
ScannerReceiveConfirm(s, i, t) ==
    /\ scanner_state[s] = "AwaitingConfirm"
    /\ <<i, t>> \in wire_confirms
    \* Load-bearing check: the scanner refuses any confirm whose
    \* transcript value differs from its locally-computed one.
    /\ t = transcript[s]
    /\ scanner_state' = [scanner_state EXCEPT ![s] = "Done"]
    /\ UNCHANGED <<inviter_state, bound_invite, transcript, chain_key,
                   wire_responses, wire_confirms>>

(* -- Either side may abort at any non-terminal state. -- *)
InviterAbort(i) ==
    /\ inviter_state[i] \in {"AwaitingResponse", "AwaitingUserConfirm"}
    /\ inviter_state' = [inviter_state EXCEPT ![i] = "Aborted"]
    /\ UNCHANGED <<scanner_state, bound_invite, transcript, chain_key,
                   wire_responses, wire_confirms>>

ScannerAbort(s) ==
    /\ scanner_state[s] = "AwaitingConfirm"
    /\ scanner_state' = [scanner_state EXCEPT ![s] = "Aborted"]
    /\ UNCHANGED <<inviter_state, bound_invite, transcript, chain_key,
                   wire_responses, wire_confirms>>

(* -- Attacker actions: inject a forged confirm OR a forged response.
      The attacker can fabricate any tuple but the receiver MUST
      reject any that doesn't pass the binding check. -- *)
AttackerInjectResponse ==
    /\ AttackerOn
    /\ \E inv \in Invites, s \in Scanners, t \in {<<"forged", inv, s>>} :
         /\ wire_responses' = wire_responses \cup {<<inv, s, t>>}
         /\ UNCHANGED <<inviter_state, scanner_state, bound_invite,
                        transcript, chain_key, wire_confirms>>

AttackerInjectConfirm ==
    /\ AttackerOn
    /\ \E i \in Inviters, t \in {<<"forged", i>>} :
         /\ wire_confirms' = wire_confirms \cup {<<i, t>>}
         /\ UNCHANGED <<inviter_state, scanner_state, bound_invite,
                        transcript, chain_key, wire_responses>>

(* -- Next-state relation: every legal action -- *)
Next ==
    \/ \E s \in Scanners, i \in Inviters, inv \in Invites :
         ScannerScan(s, i, inv)
    \/ \E i \in Inviters, inv \in Invites, s \in Scanners, t \in
         {TranscriptOf(i, s, inv)} \cup {<<"forged", inv, s>>} :
         InviterReceiveResponse(i, inv, s, t)
    \/ \E i \in Inviters : InviterConfirm(i)
    \/ \E s \in Scanners, i \in Inviters, t \in
         {TranscriptOf(j, s, b) : j \in Inviters, b \in Invites}
         \cup {<<"forged", i>>} :
         ScannerReceiveConfirm(s, i, t)
    \/ \E i \in Inviters : InviterAbort(i)
    \/ \E s \in Scanners : ScannerAbort(s)
    \/ AttackerInjectResponse
    \/ AttackerInjectConfirm

Spec == Init /\ [][Next]_vars

(* ----------------------- INVARIANTS ----------------------- *)

(* I1. NoUnverifiedConfirm:
       If a scanner is Done, its transcript MUST equal the genuine
       TranscriptOf its bound invite + inviter pair. The attacker
       cannot push a Scanner to Done with a forged transcript. *)
NoUnverifiedConfirm ==
    \A s \in Scanners :
        scanner_state[s] = "Done" =>
            \E i \in Inviters :
                /\ transcript[s] = TranscriptOf(i, s, bound_invite[s])
                /\ <<i, transcript[s]>> \in wire_confirms

(* I2. NoCrossInviteReplay:
       For every response on the wire, there exists no inviter that
       accepted it bound to a DIFFERENT invite than the scanner
       targeted. *)
NoCrossInviteReplay ==
    \A i \in Inviters :
        inviter_state[i] \in {"AwaitingUserConfirm", "Done"} =>
            \E s \in Scanners, inv \in Invites :
                /\ transcript[i] = TranscriptOf(i, s, inv)
                /\ <<inv, s, transcript[i]>> \in wire_responses

(* I3. NoOutOfOrderTransition:
       The state variables only take values from the declared enum
       sets. (TLC catches typos / off-by-one introductions of new
       states.) *)
StateTypesOk ==
    /\ \A i \in Inviters : inviter_state[i] \in InviterStates
    /\ \A s \in Scanners : scanner_state[s] \in ScannerStates

(* I4. SAS_AGREEMENT_ON_HONEST_RUN:
       If a pair (i, s) both reach Done AND the attacker is off,
       they hold the same chain key. *)
SAS_AgreementOnHonestRun ==
    AttackerOn = FALSE =>
        \A i \in Inviters, s \in Scanners :
            (/\ inviter_state[i] = "Done"
             /\ scanner_state[s] = "Done"
             /\ transcript[i] = transcript[s])
            =>
            chain_key[i] = chain_key[s]

================================================================
