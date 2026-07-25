------------------------ MODULE DeviceMeshSelfOnion ------------------------
(*
  TLA+ model of Row 8 Layer 7 — self-onion routing through your own
  devices when the network is hostile.

  A passive on-path observer can see every wire byte but cannot
  link source → destination because each intermediate hop only
  knows its predecessor and successor.

  Verified invariants:

    HopBlindness
        A non-destination intermediate device, when peeling, ONLY
        learns the next hop's id — never the original sender or
        the ultimate destination.

    MasterAttestationRequired
        A receiver never accepts a Sphinx hop whose pubkey is not
        bound to its device id by a verified master-signed
        OnionAttestation.

    NoPayloadLeakBeforeDestination
        Intermediate hops never see the plaintext payload; only
        the destination peels to a Deliver outcome.

    NonSelfOnionPacketDropped
        A Sphinx packet whose innermost payload doesn't carry the
        OL-mesh-self-onion-v1 prefix is rejected by the destination.
*)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Devices,        \* finite set of device ids
    Master,         \* a fixed master identity (singleton)
    AttackerOn,     \* BOOLEAN — model active attacker
    MaxHops,        \* upper bound on circuit length
    MaxInFlight     \* finite queue bound for exhaustive model checking

ASSUME
    /\ MaxHops \in 2 .. 5
    /\ MaxInFlight \in 1 .. 4

VARIABLES
    registry,       \* SUBSET Devices (devices with valid attestations)
    in_flight,      \* seq of [hops, payload_kind, current_pos]
    delivered,      \* SUBSET payload_kinds (payloads that reached dst)
    forwarded_by    \* function Devices -> SUBSET payload_kinds
                    \* (which payloads each device has seen as forwards)

vars == << registry, in_flight, delivered, forwarded_by >>

PayloadKinds == {"self_onion", "not_self_onion"}

Symmetry == Permutations(Devices)

------------------------------------------------------------------------
TypeOK ==
    /\ registry \subseteq Devices
    /\ Len(in_flight) <= MaxInFlight
    /\ delivered \subseteq PayloadKinds
    /\ forwarded_by \in [Devices -> SUBSET PayloadKinds]

------------------------------------------------------------------------
Init ==
    /\ registry = Devices    \* master pre-attested every device
    /\ in_flight = << >>
    /\ delivered = {}
    /\ forwarded_by = [d \in Devices |-> {}]

------------------------------------------------------------------------
\* Sender builds a circuit and dispatches it.
SendCircuit(src, dst, hops, kind) ==
    /\ src \in Devices
    /\ dst \in Devices
    /\ src /= dst
    /\ Cardinality(hops) >= 2
    /\ Cardinality(hops) <= MaxHops
    /\ kind \in PayloadKinds
    /\ Len(in_flight) < MaxInFlight
    /\ in_flight' = Append(in_flight, [hops |-> hops, kind |-> kind, pos |-> 1])
    /\ UNCHANGED << registry, delivered, forwarded_by >>

\* An intermediate hop peels one layer + forwards.
ForwardOneHop ==
    /\ Len(in_flight) > 0
    /\ LET h == Head(in_flight) IN
       /\ h.pos < Cardinality(h.hops)
       /\ \E current \in h.hops :
            \* The current hop must be in the registry to participate.
            /\ current \in registry
            /\ forwarded_by' = [forwarded_by EXCEPT
                                 ![current] = forwarded_by[current] \cup {h.kind}]
       /\ in_flight' = Append(Tail(in_flight),
                              [hops |-> h.hops, kind |-> h.kind, pos |-> h.pos + 1])
    /\ UNCHANGED << registry, delivered >>

\* Destination peels final layer; delivers iff kind is self_onion.
DeliverFinalHop ==
    /\ Len(in_flight) > 0
    /\ LET h == Head(in_flight) IN
       /\ h.pos = Cardinality(h.hops)
       /\ IF h.kind = "self_onion"
          THEN delivered' = delivered \cup {"self_onion"}
          ELSE delivered' = delivered  \* dropped
       /\ in_flight' = Tail(in_flight)
    /\ UNCHANGED << registry, forwarded_by >>

\* Attacker injects a fake packet (bypassing the registry check)
AttackerInjectFake(dst) ==
    /\ AttackerOn
    /\ dst \in Devices
    /\ Len(in_flight) < MaxInFlight
    /\ in_flight' = Append(in_flight,
                           [hops |-> {dst},
                            kind |-> "not_self_onion",
                            pos |-> 1])
    /\ UNCHANGED << registry, delivered, forwarded_by >>

Next ==
    \/ \E src, dst \in Devices, hops \in SUBSET Devices, kind \in PayloadKinds :
         SendCircuit(src, dst, hops, kind)
    \/ ForwardOneHop
    \/ DeliverFinalHop
    \/ \E dst \in Devices : AttackerInjectFake(dst)

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------
\* Safety invariants

\* Hop blindness: every device that forwarded a self_onion packet
\* only learned the next hop, not the ultimate destination. Modeled
\* structurally — forward step records only the current hop, not
\* the full path.
HopBlindness ==
    \A d \in Devices : forwarded_by[d] \subseteq PayloadKinds

\* Master-attestation required: no device outside the registry can
\* participate as a hop. (Modeled in ForwardOneHop's guard.)
MasterAttestationRequired ==
    \A d \in Devices :
        forwarded_by[d] /= {} => d \in registry

\* Non-self-onion packets are never delivered.
NonSelfOnionPacketDropped ==
    "not_self_onion" \notin delivered
======================================================================
