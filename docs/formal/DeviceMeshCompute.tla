------------------------ MODULE DeviceMeshCompute ------------------------
(*
  Finite-state model of cross-device compute authorization and result
  verification.  It explores honest and attacker-controlled capability and
  result presentations.  Result timestamps are finite equivalence classes:
  TimelyTimes are at/before the request deadline and the remaining classes are
  late.  A single presented result per task is sufficient because every
  candidate is chosen nondeterministically before verification.

  Verified safety properties:
    - only master-attested registry facts can authorize an executor;
    - an accepted result is bound to the assigned executor;
    - late results and results verified after the deadline are not accepted;
    - forged capability announcements never enter the trusted registry.
*)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Devices,
    Capabilities,
    Tasks,
    ResultTimes,
    TimelyTimes,
    NoDevice,
    NoTime,
    MaxRegistryFacts,
    AttackerOn,
    NowUnix,
    DeadlineUnix

ASSUME
    /\ Devices # {}
    /\ Capabilities # {}
    /\ Tasks # {}
    /\ NoDevice \notin Devices
    /\ NoTime \notin ResultTimes
    /\ TimelyTimes \subseteq ResultTimes
    /\ ResultTimes \ TimelyTimes # {}
    /\ MaxRegistryFacts \in 1 .. Cardinality(Devices \X Capabilities)
    /\ NowUnix \in Nat
    /\ DeadlineUnix \in Nat

RegistryUniverse == Devices \X Capabilities

VARIABLES
    registry,          \* trusted view: Devices -> SUBSET Capabilities
    attestations,      \* facts authenticated under the master identity
    forgery_attempt,   \* most recent rejected forged capability fact
    requested,         \* set of issued task ids
    needed,            \* Tasks -> required capability set
    assigned,          \* Tasks -> executor or NoDevice
    result_signer,     \* Tasks -> presented signer or NoDevice
    result_time,       \* Tasks -> presented time class or NoTime
    accepted           \* set of tasks whose presented result verified

vars == <<registry, attestations, forgery_attempt, requested, needed,
          assigned, result_signer, result_time, accepted>>

RegistryPairs(reg) ==
    {pair \in RegistryUniverse : pair[2] \in reg[pair[1]]}

TypeOK ==
    /\ registry \in [Devices -> SUBSET Capabilities]
    /\ attestations \subseteq RegistryUniverse
    /\ Cardinality(attestations) <= MaxRegistryFacts
    /\ forgery_attempt \subseteq RegistryUniverse
    /\ Cardinality(forgery_attempt) <= 1
    /\ requested \subseteq Tasks
    /\ needed \in [Tasks -> SUBSET Capabilities]
    /\ assigned \in [Tasks -> Devices \cup {NoDevice}]
    /\ result_signer \in [Tasks -> Devices \cup {NoDevice}]
    /\ result_time \in [Tasks -> ResultTimes \cup {NoTime}]
    /\ accepted \subseteq Tasks

Init ==
    /\ registry = [d \in Devices |-> {}]
    /\ attestations = {}
    /\ forgery_attempt = {}
    /\ requested = {}
    /\ needed = [t \in Tasks |-> {}]
    /\ assigned = [t \in Tasks |-> NoDevice]
    /\ result_signer = [t \in Tasks |-> NoDevice]
    /\ result_time = [t \in Tasks |-> NoTime]
    /\ accepted = {}

MasterAttests(d, capability) ==
    /\ <<d, capability>> \notin attestations
    /\ Cardinality(attestations) < MaxRegistryFacts
    /\ attestations' = attestations \cup {<<d, capability>>}
    /\ registry' = [registry EXCEPT ![d] = @ \cup {capability}]
    /\ UNCHANGED <<forgery_attempt, requested, needed, assigned,
                   result_signer, result_time, accepted>>

AttackerForgesCapability(d, capability) ==
    LET attempted == {<<d, capability>>} IN
    /\ AttackerOn
    /\ forgery_attempt # attempted
    /\ forgery_attempt' = attempted
    /\ UNCHANGED <<registry, attestations, requested, needed, assigned,
                   result_signer, result_time, accepted>>

RequestTask(t, caps) ==
    /\ t \notin requested
    /\ requested' = requested \cup {t}
    /\ needed' = [needed EXCEPT ![t] = caps]
    /\ UNCHANGED <<registry, attestations, forgery_attempt, assigned,
                   result_signer, result_time, accepted>>

AssignExecutor(t, executor) ==
    /\ t \in requested
    /\ assigned[t] = NoDevice
    /\ needed[t] \subseteq registry[executor]
    /\ assigned' = [assigned EXCEPT ![t] = executor]
    /\ UNCHANGED <<registry, attestations, forgery_attempt, requested,
                   needed, result_signer, result_time, accepted>>

PresentHonestResult(t, time_class) ==
    /\ t \in requested
    /\ t \notin accepted
    /\ assigned[t] # NoDevice
    /\ \/ result_signer[t] # assigned[t]
       \/ result_time[t] # time_class
    /\ result_signer' = [result_signer EXCEPT ![t] = assigned[t]]
    /\ result_time' = [result_time EXCEPT ![t] = time_class]
    /\ UNCHANGED <<registry, attestations, forgery_attempt, requested,
                   needed, assigned, accepted>>

AttackerForgesResult(t, fake_executor, time_class) ==
    /\ AttackerOn
    /\ t \in requested
    /\ t \notin accepted
    /\ fake_executor # assigned[t]
    /\ \/ result_signer[t] # fake_executor
       \/ result_time[t] # time_class
    /\ result_signer' = [result_signer EXCEPT ![t] = fake_executor]
    /\ result_time' = [result_time EXCEPT ![t] = time_class]
    /\ UNCHANGED <<registry, attestations, forgery_attempt, requested,
                   needed, assigned, accepted>>

VerifyResult(t) ==
    /\ t \in requested
    /\ t \notin accepted
    /\ assigned[t] # NoDevice
    /\ result_signer[t] = assigned[t]
    /\ result_time[t] \in TimelyTimes
    /\ NowUnix <= DeadlineUnix
    /\ accepted' = accepted \cup {t}
    /\ UNCHANGED <<registry, attestations, forgery_attempt, requested,
                   needed, assigned, result_signer, result_time>>

Next ==
    \/ \E d \in Devices, capability \in Capabilities :
           MasterAttests(d, capability)
    \/ \E d \in Devices, capability \in Capabilities :
           AttackerForgesCapability(d, capability)
    \/ \E t \in Tasks, caps \in SUBSET Capabilities : RequestTask(t, caps)
    \/ \E t \in Tasks, executor \in Devices : AssignExecutor(t, executor)
    \/ \E t \in Tasks, time_class \in ResultTimes :
           PresentHonestResult(t, time_class)
    \/ \E t \in Tasks, fake_executor \in Devices,
          time_class \in ResultTimes :
           AttackerForgesResult(t, fake_executor, time_class)
    \/ \E t \in Tasks : VerifyResult(t)

Spec == Init /\ [][Next]_vars

NoForgeryUnderMaster == RegistryPairs(registry) = attestations

NoUnattestedExecutor ==
    \A t \in Tasks :
        assigned[t] # NoDevice => needed[t] \subseteq registry[assigned[t]]

NoCrossExecutorResult ==
    \A t \in accepted : result_signer[t] = assigned[t]

DeadlineRespected ==
    \A t \in accepted :
        /\ result_time[t] \in TimelyTimes
        /\ NowUnix <= DeadlineUnix

NoAcceptedUnrequestedTask == accepted \subseteq requested

Symmetry ==
    Permutations(Devices)
    \cup Permutations(Capabilities)
    \cup Permutations(Tasks)
    \cup Permutations(TimelyTimes)
    \cup Permutations(ResultTimes \ TimelyTimes)
=============================================================================
