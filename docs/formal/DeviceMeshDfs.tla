------------------------ MODULE DeviceMeshDfs ------------------------
(*
  TLA+ model of Row 8 Layer 4 — content-addressed distributed
  filesystem with erasure-coded redundancy.

  Models:
    - A finite set of devices, each either ONLINE or OFFLINE.
    - A finite set of chunks.
    - A per-chunk placement (set of holders).
    - An attacker that can take devices offline arbitrarily.

  Verified invariants:

    DurabilityUnderKLoss
        For any reachable state where at most K-1 devices have gone
        OFFLINE simultaneously, every chunk still has at least one
        ONLINE holder if it had at least K holders before any went
        offline. (Models "k-of-(k+m) erasure recovers under m-1 simul
        failures.")

    NoDoubleAssignPerChunk
        The repair plan never assigns the same device twice to the
        same chunk.

    NoAssignmentToExistingHolder
        The repair plan never assigns a chunk to a device that
        already holds it.
*)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Devices,        \* finite set of device ids
    Chunks,         \* finite set of chunk hashes
    MinDevices,     \* min_devices_per_shard from the policy
    MaxConcurrentFails,  \* m parity shards (max simul failures)
    AttackerOn      \* BOOLEAN

ASSUME
    /\ MinDevices \in Nat
    /\ MinDevices > 0
    /\ MaxConcurrentFails \in Nat

VARIABLES
    holders,        \* Chunks -> SUBSET Devices (current holders)
    online,         \* SUBSET Devices  (currently online devices)
    repair_plan     \* pending set of (chunk, device) assignments

vars == << holders, online, repair_plan >>

------------------------------------------------------------------------
TypeOK ==
    /\ holders \in [Chunks -> SUBSET Devices]
    /\ online \subseteq Devices
    /\ repair_plan \subseteq (Chunks \X Devices)

------------------------------------------------------------------------
\* Initially: every device online; every chunk held by some initial
\* set of MinDevices devices. We pick a deterministic initial
\* assignment for tractability.
Init ==
    /\ online = Devices
    /\ holders \in [Chunks -> {S \in SUBSET Devices : Cardinality(S) >= MinDevices}]
    /\ repair_plan = {}

------------------------------------------------------------------------
\* Actions

\* A device d ∈ Devices goes offline (attacker action).
DeviceGoesOffline(d) ==
    /\ AttackerOn
    /\ d \in online
    /\ Cardinality(Devices \ (online \ {d})) <= MaxConcurrentFails
    /\ online' = online \ {d}
    /\ UNCHANGED << holders, repair_plan >>

\* A device comes back online.
DeviceComesOnline(d) ==
    /\ d \in Devices
    /\ d \notin online
    /\ online' = online \cup {d}
    /\ UNCHANGED << holders, repair_plan >>

\* The repair planner picks an under-replicated chunk + an eligible
\* device and adds the assignment.
RepairAssign(c, d) ==
    /\ c \in Chunks
    /\ d \in online
    /\ d \notin holders[c]
    /\ <<c, d>> \notin repair_plan
    /\ Cardinality({entry \in repair_plan : entry[1] = c}) < (Cardinality(Devices) - Cardinality(holders[c]))
    /\ repair_plan' = repair_plan \cup {<<c, d>>}
    /\ UNCHANGED << holders, online >>

\* A device picks up an assigned chunk (the fetch completes).
DeviceAcquiresChunk(c, d) ==
    /\ <<c, d>> \in repair_plan
    /\ d \in online
    /\ d \notin holders[c]
    /\ holders' = [holders EXCEPT ![c] = holders[c] \cup {d}]
    /\ repair_plan' = repair_plan \ {<<c, d>>}
    /\ UNCHANGED online

Next ==
    \/ \E d \in Devices : DeviceGoesOffline(d)
    \/ \E d \in Devices : DeviceComesOnline(d)
    \/ \E c \in Chunks, d \in Devices : RepairAssign(c, d)
    \/ \E c \in Chunks, d \in Devices : DeviceAcquiresChunk(c, d)

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------
\* Safety invariants

\* If at most MaxConcurrentFails devices are offline AND a chunk had
\* at least (MaxConcurrentFails + 1) holders, then at least one of
\* the holders is still online.
DurabilityUnderKLoss ==
    Cardinality(Devices \ online) <= MaxConcurrentFails =>
        (\A c \in Chunks :
            Cardinality(holders[c]) > MaxConcurrentFails =>
                (\E d \in holders[c] : d \in online))

\* The repair plan never assigns the same device twice to the same
\* chunk. (Structural: repair_plan is a SET.)
NoDoubleAssignPerChunk ==
    \A c \in Chunks, d \in Devices :
        Cardinality({e \in repair_plan : e[1] = c /\ e[2] = d}) <= 1

\* The repair plan never assigns a chunk to a device that already
\* holds it.
NoAssignmentToExistingHolder ==
    \A entry \in repair_plan :
        LET c == entry[1]
            d == entry[2]
        IN d \notin holders[c]
======================================================================
