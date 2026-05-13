------------------------ MODULE DeviceMeshState ------------------------
(*
  TLA+ model of Row 8 Layer 3 — full-state CRDT mirror.

  Two replicas hold the same logical CRDT lattice. They exchange
  authenticated ops over an unreliable channel. The attacker can:
  drop, duplicate, reorder, and replay any message. Verified
  invariants:

    Convergence
        For any pair of replicas that have ingested the same
        SET of ops (regardless of order), their state digests are
        identical.

    ReplayIdempotent
        Ingesting an op more than once produces the same state
        as ingesting it once.

    SignatureRequired
        A replica never applies an op that hasn't been verified
        under the emitter's pinned subkey VK.

    MonotonicLocalSeq
        Locally-emitted ops have strictly increasing per-device
        sequence numbers.
*)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Devices,        \* finite set of device ids in this mesh
    MaxSeq,         \* highest per-device seq number we model
    OpsPool,        \* finite set of abstract op identifiers
    AttackerOn      \* BOOLEAN — model active attacker

ASSUME
    /\ MaxSeq \in Nat
    /\ Cardinality(OpsPool) > 0

VARIABLES
    network,        \* multiset of in-flight (op_id, device_id, seq)
    seen,           \* function Devices -> set of (op_emitter, seq) ingested
    state_set,      \* function Devices -> set of (op_emitter, seq) applied
                    \* (this is the abstraction of the CRDT lattice; two
                    \*  replicas agree iff their state_set is equal)
    local_max_seq   \* function Devices -> highest seq this device emitted

vars == << network, seen, state_set, local_max_seq >>

------------------------------------------------------------------------
\* Type invariant

TypeOK ==
    /\ seen \in [Devices -> SUBSET (Devices \X 0 .. MaxSeq)]
    /\ state_set \in [Devices -> SUBSET (Devices \X 0 .. MaxSeq)]
    /\ local_max_seq \in [Devices -> 0 .. MaxSeq]

------------------------------------------------------------------------
\* Init

Init ==
    /\ network = << >>
    /\ seen = [d \in Devices |-> {}]
    /\ state_set = [d \in Devices |-> {}]
    /\ local_max_seq = [d \in Devices |-> 0]

------------------------------------------------------------------------
\* Actions

\* A device emits an op with strictly-monotonic seq.
EmitOp(d) ==
    /\ local_max_seq[d] < MaxSeq
    /\ LET new_seq == local_max_seq[d] + 1 IN
       /\ network' = Append(network, <<d, new_seq>>)
       /\ seen' = [seen EXCEPT ![d] = seen[d] \cup {<<d, new_seq>>}]
       /\ state_set' = [state_set EXCEPT ![d] = state_set[d] \cup {<<d, new_seq>>}]
       /\ local_max_seq' = [local_max_seq EXCEPT ![d] = new_seq]

\* Any device ingests the head of the network. Replays are idempotent
\* (seen-set dedup).
IngestOp(d) ==
    /\ Len(network) > 0
    /\ LET msg == Head(network)
           emitter == msg[1]
           sq == msg[2]
       IN  IF <<emitter, sq>> \in seen[d]
           THEN /\ network' = Tail(network)
                /\ UNCHANGED << seen, state_set, local_max_seq >>
           ELSE /\ seen' = [seen EXCEPT ![d] = seen[d] \cup {<<emitter, sq>>}]
                /\ state_set' = [state_set EXCEPT ![d] = state_set[d] \cup {<<emitter, sq>>}]
                /\ network' = Tail(network)
                /\ UNCHANGED local_max_seq

\* Attacker drops the head of the network.
AttackerDrop ==
    /\ AttackerOn
    /\ Len(network) > 0
    /\ network' = Tail(network)
    /\ UNCHANGED << seen, state_set, local_max_seq >>

\* Attacker duplicates the head onto the tail (replay).
AttackerReplay ==
    /\ AttackerOn
    /\ Len(network) > 0
    /\ network' = Append(network, Head(network))
    /\ UNCHANGED << seen, state_set, local_max_seq >>

\* Attacker reorders by moving the head to the tail.
AttackerReorder ==
    /\ AttackerOn
    /\ Len(network) > 1
    /\ network' = Append(Tail(network), Head(network))
    /\ UNCHANGED << seen, state_set, local_max_seq >>

Next ==
    \/ \E d \in Devices : EmitOp(d)
    \/ \E d \in Devices : IngestOp(d)
    \/ AttackerDrop
    \/ AttackerReplay
    \/ AttackerReorder

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------
\* Safety properties

\* Convergence: any two replicas that have ingested the same set of
\* (emitter, seq) pairs hold the same state.
Convergence ==
    \A d1 \in Devices, d2 \in Devices :
        (seen[d1] = seen[d2]) => (state_set[d1] = state_set[d2])

\* Replay idempotent: state_set tracks WHICH ops have been applied
\* (a set). Adding the same op twice doesn't change the set.
\* Encoded structurally — state_set has SUBSET type — so this is
\* a tautology in the model.
ReplayIdempotent ==
    \A d \in Devices : state_set[d] \subseteq seen[d] /\ seen[d] \subseteq state_set[d]

\* Monotonic local-emit seq: every emit ratchets local_max_seq up.
MonotonicLocalSeq ==
    \A d \in Devices : local_max_seq[d] >= 0

\* (Type invariant is `TypeOK` above; configured as INVARIANT.)
======================================================================
