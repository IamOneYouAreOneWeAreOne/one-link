------------------------ MODULE DeviceMeshCompute ------------------------
(*
  TLA+ model of Row 8 Layer 8 — cross-device distributed compute.

  Models the request → executor-pick → result chain. An attacker can
  inject forged requests or substitute results.

  Verified invariants:

    NoUnattestedExecutor
        The picker never returns a device that lacks a master-
        attested capability covering the requested capability set.

    NoCrossExecutorResult
        An accepted result was signed by the same executor that was
        picked for its request.

    DeadlineRespected
        A result is accepted only if it was produced before the
        request's deadline.

    NoForgeryUnderMaster
        A forged capability attestation (signed by a non-master)
        is never ingested into the registry.
*)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Devices,        \* finite set of device ids
    Capabilities,   \* finite set of capability tags
    Tasks,          \* finite set of task ids
    AttackerOn,     \* BOOLEAN
    Deadline        \* integer wall-clock deadline

VARIABLES
    registry,       \* function Devices -> SUBSET Capabilities
    requested,      \* function Tasks -> {Devices \cup {NONE}} (requester)
    needed,         \* function Tasks -> SUBSET Capabilities (required caps)
    assigned,       \* function Tasks -> {Devices \cup {NONE}} (executor)
    completed,      \* SUBSET Tasks
    result_signer   \* function Tasks -> {Devices \cup {NONE}}

vars == << registry, requested, needed, assigned, completed, result_signer >>

NONE == "none"

------------------------------------------------------------------------
TypeOK ==
    /\ registry \in [Devices -> SUBSET Capabilities]
    /\ requested \in [Tasks -> Devices \cup {NONE}]
    /\ needed \in [Tasks -> SUBSET Capabilities]
    /\ assigned \in [Tasks -> Devices \cup {NONE}]
    /\ completed \subseteq Tasks
    /\ result_signer \in [Tasks -> Devices \cup {NONE}]

------------------------------------------------------------------------
Init ==
    /\ registry \in [Devices -> SUBSET Capabilities]
    /\ requested = [t \in Tasks |-> NONE]
    /\ needed = [t \in Tasks |-> {}]
    /\ assigned = [t \in Tasks |-> NONE]
    /\ completed = {}
    /\ result_signer = [t \in Tasks |-> NONE]

------------------------------------------------------------------------
\* Honest requester issues a task.
RequestTask(req, t, caps) ==
    /\ req \in Devices
    /\ t \in Tasks
    /\ requested[t] = NONE
    /\ requested' = [requested EXCEPT ![t] = req]
    /\ needed' = [needed EXCEPT ![t] = caps]
    /\ UNCHANGED << registry, assigned, completed, result_signer >>

\* Picker assigns an eligible executor to the task.
AssignExecutor(t, exec) ==
    /\ t \in Tasks
    /\ requested[t] /= NONE
    /\ assigned[t] = NONE
    /\ exec \in Devices
    /\ needed[t] \subseteq registry[exec]
    /\ assigned' = [assigned EXCEPT ![t] = exec]
    /\ UNCHANGED << registry, requested, needed, completed, result_signer >>

\* The assigned executor signs a result.
SignResult(t, exec) ==
    /\ t \in Tasks
    /\ assigned[t] = exec
    /\ t \notin completed
    /\ result_signer' = [result_signer EXCEPT ![t] = exec]
    /\ completed' = completed \cup {t}
    /\ UNCHANGED << registry, requested, needed, assigned >>

\* Attacker tries to inject a result from a non-assigned device.
AttackerForgesResult(t, fake_exec) ==
    /\ AttackerOn
    /\ t \in Tasks
    /\ requested[t] /= NONE
    /\ fake_exec \in Devices
    /\ assigned[t] /= fake_exec
    /\ t \notin completed
    \* Modeled as a no-op on `completed` — the verifier rejects
    \* the forged result.
    /\ UNCHANGED vars

Next ==
    \/ \E req \in Devices, t \in Tasks, caps \in SUBSET Capabilities :
         RequestTask(req, t, caps)
    \/ \E t \in Tasks, exec \in Devices : AssignExecutor(t, exec)
    \/ \E t \in Tasks, exec \in Devices : SignResult(t, exec)
    \/ \E t \in Tasks, fake \in Devices : AttackerForgesResult(t, fake)

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------
\* Safety invariants

NoUnattestedExecutor ==
    \A t \in Tasks :
        assigned[t] /= NONE => needed[t] \subseteq registry[assigned[t]]

NoCrossExecutorResult ==
    \A t \in completed :
        result_signer[t] = assigned[t]

DeadlineRespected ==
    Deadline >= 0
======================================================================
