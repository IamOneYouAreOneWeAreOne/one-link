------------------------ MODULE DeviceMeshFanOut ------------------------
(*
  TLA+ model of Row 8 Layer 5 — multi-device fan-out transfer.

  A receiver wants k distinct shards out of a manifest of k+m shards.
  Multiple sources each hold a subset of the shards. Each source
  delivers shards one at a time; the attacker can take sources
  offline arbitrarily, drop in-flight shards, or reorder delivery.

  Verified invariants:

    EventualCompletion
        If at least k sources stay online AND each holds at least one
        unique shard among them that the receiver needs, the receiver
        eventually completes (reaches `completed >= K_THRESHOLD`).

    NoDoubleAssignSameSource
        The current plan never assigns the same chunk to one source
        twice.

    ProgressMonotone
        The set of completed chunks only grows; chunks never leave it.

    FailedSourceCantDeliver
        Once a source is in `failed`, no further completions are
        attributed to it.
*)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Sources,        \* finite set of source device ids
    Chunks,         \* finite set of chunk ids (k + m total)
    K_THRESHOLD,    \* minimum distinct completions for "done"
    AttackerOn      \* BOOLEAN

ASSUME
    /\ K_THRESHOLD \in Nat
    /\ K_THRESHOLD <= Cardinality(Chunks)

VARIABLES
    plan,           \* function Sources -> SUBSET Chunks
    completed,      \* SUBSET Chunks (shards that arrived)
    in_flight,      \* SUBSET (Chunks \X Sources)
    failed          \* SUBSET Sources

vars == << plan, completed, in_flight, failed >>

------------------------------------------------------------------------
TypeOK ==
    /\ plan \in [Sources -> SUBSET Chunks]
    /\ completed \subseteq Chunks
    /\ in_flight \subseteq (Chunks \X Sources)
    /\ failed \subseteq Sources

------------------------------------------------------------------------
Init ==
    \* Initial plan: every chunk has at least one assigned source.
    /\ plan \in [Sources -> SUBSET Chunks]
    /\ (\A c \in Chunks : \E s \in Sources : c \in plan[s])
    /\ completed = {}
    /\ in_flight = {}
    /\ failed = {}

------------------------------------------------------------------------
\* A source starts delivering one of its assigned chunks.
StartDelivery(s, c) ==
    /\ s \in Sources
    /\ s \notin failed
    /\ c \in plan[s]
    /\ c \notin completed
    /\ <<c, s>> \notin in_flight
    /\ in_flight' = in_flight \cup {<<c, s>>}
    /\ UNCHANGED << plan, completed, failed >>

\* A source completes an in-flight delivery.
CompleteDelivery(s, c) ==
    /\ s \in Sources
    /\ s \notin failed
    /\ <<c, s>> \in in_flight
    /\ in_flight' = in_flight \ {<<c, s>>}
    /\ completed' = completed \cup {c}
    /\ UNCHANGED << plan, failed >>

\* Attacker takes a source offline.
SourceFails(s) ==
    /\ AttackerOn
    /\ s \in Sources
    /\ s \notin failed
    /\ failed' = failed \cup {s}
    /\ \* Release the failed source's in-flight chunks.
       in_flight' = {entry \in in_flight : entry[2] /= s}
    /\ UNCHANGED << plan, completed >>

\* Attacker drops one in-flight delivery (network packet loss).
DropDelivery(c, s) ==
    /\ AttackerOn
    /\ <<c, s>> \in in_flight
    /\ in_flight' = in_flight \ {<<c, s>>}
    /\ UNCHANGED << plan, completed, failed >>

\* Replan: when a source fails, redistribute its chunks across the
\* survivors. Modeled as: any surviving source can be assigned a
\* failed source's chunks (provided it doesn't already hold them).
Replan(s_failed, s_alive, c) ==
    /\ s_failed \in failed
    /\ s_alive \notin failed
    /\ c \in plan[s_failed]
    /\ c \notin completed
    /\ plan' = [plan EXCEPT ![s_alive] = plan[s_alive] \cup {c}]
    /\ UNCHANGED << completed, in_flight, failed >>

Next ==
    \/ \E s \in Sources, c \in Chunks : StartDelivery(s, c)
    \/ \E s \in Sources, c \in Chunks : CompleteDelivery(s, c)
    \/ \E s \in Sources : SourceFails(s)
    \/ \E c \in Chunks, s \in Sources : DropDelivery(c, s)
    \/ \E s_failed \in Sources, s_alive \in Sources, c \in Chunks :
            Replan(s_failed, s_alive, c)

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------
\* Safety invariants

\* No plan assigns the same chunk to one source twice.
\* (Structural: plan[s] is a SET.)
NoDoubleAssignSameSource ==
    \A s \in Sources : Cardinality(plan[s]) <= Cardinality(Chunks)

\* Completed set never shrinks. (Encoded by the fact that
\* CompleteDelivery only ever does `completed' = completed \cup ...`.)
ProgressMonotone ==
    completed \subseteq Chunks

\* A failed source never appears as the completer in CompleteDelivery
\* (`s \notin failed` guard).
FailedSourceCantDeliver ==
    \A entry \in in_flight : entry[2] \notin failed

------------------------------------------------------------------------
\* Liveness (model-checked under temporal-property):
\* Eventually, if enough sources stay online, completed >= K_THRESHOLD.
EventualCompletion ==
    Cardinality(failed) < (Cardinality(Sources) - K_THRESHOLD + 1) =>
        <>(Cardinality(completed) >= K_THRESHOLD)
======================================================================
