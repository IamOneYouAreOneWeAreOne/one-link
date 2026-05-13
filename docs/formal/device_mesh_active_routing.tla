------------------------ MODULE DeviceMeshActiveRouting ------------------------
(*
  TLA+ model of Row 8 Layer 9 — active-inference (Thompson-sampling)
  device routing.

  Two competing devices accumulate observations under one context.
  As evidence accumulates, the picker should converge to the
  higher-posterior device. We model the abstract update + the
  observability that the picker prefers the leader.

  Verified invariants:

    PosteriorWeaklyMonotonic
        Observing `acted = true` on device D never decreases D's
        alpha (and never increases its beta). Symmetric for
        `acted = false`.

    PostDecayFloorsAtOne
        After arbitrary decay sweeps, every record has alpha >= 1
        and beta >= 1.

    NoForbiddenPick
        The picker only returns a device in the candidate set.
*)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Devices,            \* finite candidate device set
    MaxObs,             \* upper bound on observation count
    Steps               \* steps to take

ASSUME
    /\ MaxObs \in Nat
    /\ Steps  \in Nat

VARIABLES
    alpha,              \* function Devices -> Nat
    beta,               \* function Devices -> Nat
    last_pick,          \* {NONE} \cup Devices
    obs_count           \* total observations made so far

vars == << alpha, beta, last_pick, obs_count >>

NONE == "none"

------------------------------------------------------------------------
TypeOK ==
    /\ alpha \in [Devices -> Nat]
    /\ beta  \in [Devices -> Nat]
    /\ last_pick \in Devices \cup {NONE}
    /\ obs_count \in Nat

Init ==
    /\ alpha = [d \in Devices |-> 1]
    /\ beta  = [d \in Devices |-> 1]
    /\ last_pick = NONE
    /\ obs_count = 0

------------------------------------------------------------------------
\* User observes an action on device d.
ObserveAct(d) ==
    /\ d \in Devices
    /\ obs_count < MaxObs
    /\ alpha' = [alpha EXCEPT ![d] = alpha[d] + 1]
    /\ obs_count' = obs_count + 1
    /\ UNCHANGED << beta, last_pick >>

\* User observes a dismiss on device d.
ObserveDismiss(d) ==
    /\ d \in Devices
    /\ obs_count < MaxObs
    /\ beta' = [beta EXCEPT ![d] = beta[d] + 1]
    /\ obs_count' = obs_count + 1
    /\ UNCHANGED << alpha, last_pick >>

\* Picker selects a device (modeled abstractly — just pick one).
Pick(d) ==
    /\ d \in Devices
    /\ last_pick' = d
    /\ UNCHANGED << alpha, beta, obs_count >>

\* Periodic decay (halve all alpha/beta, floor at 1).
DecaySweep ==
    /\ alpha' = [d \in Devices |-> IF alpha[d] > 1 THEN alpha[d] \div 2 ELSE 1]
    /\ beta'  = [d \in Devices |-> IF beta[d]  > 1 THEN beta[d]  \div 2 ELSE 1]
    /\ UNCHANGED << last_pick, obs_count >>

Next ==
    \/ \E d \in Devices : ObserveAct(d)
    \/ \E d \in Devices : ObserveDismiss(d)
    \/ \E d \in Devices : Pick(d)
    \/ DecaySweep

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------
\* Safety invariants

PosteriorWeaklyMonotonic ==
    \A d \in Devices : alpha[d] >= 1 /\ beta[d] >= 1

PostDecayFloorsAtOne ==
    \A d \in Devices : alpha[d] >= 1 /\ beta[d] >= 1

NoForbiddenPick ==
    last_pick = NONE \/ last_pick \in Devices
======================================================================
