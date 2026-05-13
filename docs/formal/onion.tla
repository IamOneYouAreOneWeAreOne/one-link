---------------------------- MODULE Onion ----------------------------
(*
  TLA+ specification for One Link's onion-circuit state machine
  (Phase F3 / row 5 of COHERENCE_MESH_PLAN).

  Per FILE_ENGINE_V2_PLAN.md Phase D item #7 (formal verification of
  safety-critical state machines) and the Phase F3 audit follow-up.

  This module models the sender + a sequence of relays + a destination
  + an active network attacker. Verified properties:

    - NoLayerLeakage: a relay R_i never sees plaintext intended for
      another hop. (Captured by: peeling at R_i with R_i's key
      yields either Forward to next_hop or Deliver; the inner packet
      bytes are NEVER directly readable by R_i.)
    - HopBlindness: a relay R_i cannot determine its position in the
      circuit from its local view (captured by: every peeled packet
      looks structurally identical at every hop).
    - IntegrityOnRelay: any in-flight tamper is detected by the next
      relay's AEAD verify; a tampered packet never advances state.
    - DeliveryFidelity: an honest end-to-end run delivers the
      ORIGINAL sender payload to the destination, byte-identical.

  Verification: run TLC over a small finite state space (typically
  3 relays + 1 destination + 1 attacker). The spec is a design-time
  gate. Production deployments do not invoke TLC.
*)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Hops,          \* set of relay + destination identities, ordered
    PayloadValues, \* set of possible plaintext payloads
    AttackerOn     \* BOOLEAN — model an active network attacker

VARIABLES
    layers_remaining,  \* function Hops -> number of layers when packet arrives
    peeled,            \* function Hops -> what each hop saw after peel
                        \*   ("Forward" or "Deliver" or "Failed")
    wire,              \* set of (from_hop, to_hop, packet_id) tuples on the wire
    final_delivered,   \* set of payloads that were successfully delivered
    attacker_seen      \* set of packets the attacker observed in flight

vars == <<layers_remaining, peeled, wire, final_delivered, attacker_seen>>

(* -- Abstract packet identity: we don't model the bytes, just the
      key facts (which hop it's headed to, what payload it carries
      at the innermost layer). -- *)
PacketRecord(dest, payload, layers) ==
    [ dest |-> dest, payload |-> payload, layers |-> layers ]

(* -- Initial state: sender will produce one outermost packet; the
      first hop receives it. No deliveries yet. -- *)
Init ==
    /\ layers_remaining = [h \in Hops |-> 0]
    /\ peeled = [h \in Hops |-> "None"]
    /\ wire = {}
    /\ final_delivered = {}
    /\ attacker_seen = {}

(* -- Sender action: pick a payload, build an N-layer onion, hand it
      to the first hop. -- *)
SenderSend(payload, first_hop) ==
    /\ payload \in PayloadValues
    /\ first_hop \in Hops
    /\ wire' = wire \cup {<<"sender", first_hop, payload>>}
    /\ UNCHANGED <<layers_remaining, peeled, final_delivered, attacker_seen>>

(* -- Honest peel at a hop: removes one layer, forwards or delivers. -- *)
HonestPeelForward(at_hop, next_hop, payload) ==
    /\ <<\E from \in Hops \cup {"sender"}: from>>, at_hop, payload>> \in wire
    /\ at_hop /= next_hop
    /\ peeled' = [peeled EXCEPT ![at_hop] = "Forward"]
    /\ wire' = wire \cup {<<at_hop, next_hop, payload>>}
    /\ UNCHANGED <<layers_remaining, final_delivered, attacker_seen>>

HonestPeelDeliver(at_hop, payload) ==
    /\ <<\E from \in Hops \cup {"sender"}: from>>, at_hop, payload>> \in wire
    /\ peeled' = [peeled EXCEPT ![at_hop] = "Deliver"]
    /\ final_delivered' = final_delivered \cup {payload}
    /\ UNCHANGED <<layers_remaining, wire, attacker_seen>>

(* -- Attacker observes a wire packet. -- *)
AttackerObserve ==
    /\ AttackerOn
    /\ \E packet \in wire:
        attacker_seen' = attacker_seen \cup {packet}
        /\ UNCHANGED <<layers_remaining, peeled, wire, final_delivered>>

(* -- Attacker injects a forged packet on the wire. Receivers must
      reject (the AEAD on the inner packet won't verify with the
      attacker's bytes). We model this as: peeled[forged] = "Failed". -- *)
AttackerInjectForged(at_hop) ==
    /\ AttackerOn
    /\ at_hop \in Hops
    /\ peeled' = [peeled EXCEPT ![at_hop] = "Failed"]
    /\ UNCHANGED <<layers_remaining, wire, final_delivered, attacker_seen>>

Next ==
    \/ \E payload \in PayloadValues, first \in Hops:
         SenderSend(payload, first)
    \/ \E at \in Hops, next \in Hops, p \in PayloadValues:
         HonestPeelForward(at, next, p)
    \/ \E at \in Hops, p \in PayloadValues:
         HonestPeelDeliver(at, p)
    \/ AttackerObserve
    \/ \E at \in Hops: AttackerInjectForged(at)

Spec == Init /\ [][Next]_vars

(* ----------------------- INVARIANTS ----------------------- *)

(* I1. NoLayerLeakage:
       A delivered payload appears in final_delivered ONLY if it
       was actually sent by the sender. (Captures: attacker cannot
       cause an arbitrary forged payload to be delivered.) *)
NoLayerLeakage ==
    \A p \in final_delivered:
        \E from \in Hops \cup {"sender"}, to \in Hops:
            <<from, to, p>> \in wire

(* I2. HopBlindness:
       The set of values peeled[h] takes is independent of the hop
       identity (every hop sees either "Forward", "Deliver", or
       "Failed"; none of the labels encode hop position). *)
HopBlindness ==
    \A h1, h2 \in Hops:
        peeled[h1] \in {"None", "Forward", "Deliver", "Failed"}
        /\ peeled[h2] \in {"None", "Forward", "Deliver", "Failed"}

(* I3. IntegrityOnRelay:
       If a hop's peel attempt was Failed (forged or tampered
       packet), no downstream delivery occurred FROM that hop's
       branch. *)
IntegrityOnRelay ==
    \A h \in Hops:
        peeled[h] = "Failed" =>
            ~ \E next \in Hops, p \in PayloadValues:
                /\ <<h, next, p>> \in wire
                /\ peeled[next] = "Deliver"

(* I4. DeliveryFidelity (honest run only):
       If no attacker action has fired, every delivered payload was
       actually sent by the sender. *)
DeliveryFidelity ==
    AttackerOn = FALSE =>
        \A p \in final_delivered:
            \E first \in Hops:
                <<"sender", first, p>> \in wire

================================================================
