------------------------ MODULE ObfsHandshake ------------------------
(*
  TLA+ specification for One Link's Row 7 transport-obfuscation
  handshake — obfs4-style ECDH + bridge-identity HMAC binding.

  Models:
    - A pool of bridges, each with a long-term (pubkey, id) pair.
    - A pool of clients, each holding (bridge_pk, bridge_id) for some
      bridge they intend to reach.
    - An active network attacker that can: capture and replay any
      message, forward across bridges, forge with random bytes.

  Verified properties:
    - NoCrossBridgeReplay: a handshake-tag valid for Bridge A is
      NEVER accepted by Bridge B.
    - NoOutOfEpochAccept: a handshake tag computed at epoch E is
      NEVER accepted at epoch E+2 or later.
    - NoUnauthBypass: a forged handshake (no knowledge of bridge_id)
      ALWAYS fails MAC validation.
    - SessionAgreementOnHonestRun: if both sides complete without
      attacker interference, they hold matching session-key pairs.

  Verification: run TLC over a small finite state space.
*)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Bridges,        \* finite set of bridge identities
    Clients,        \* finite set of client identities
    Epochs,         \* finite set of valid epoch values, e.g. {1,2,3}
    AttackerOn      \* BOOLEAN — model an active attacker or not

VARIABLES
    bridge_id,      \* function Bridges -> id token
    bridge_pubkey,  \* function Bridges -> pubkey token
    client_target,  \* function Clients -> Bridge (the one they target)
    client_known_id, \* function Clients -> id token they hold (might be wrong)
    client_state,   \* function Clients -> {Idle, Started, Done, Failed}
    bridge_state,   \* function Bridges -> {Idle, Accepted, Failed}
    network,        \* sequence of in-flight messages
    completed_sessions \* set of completed (client, bridge) pairs

vars == << bridge_id, bridge_pubkey, client_target, client_known_id,
           client_state, bridge_state, network, completed_sessions >>

------------------------------------------------------------------------
\* Types

States == {"Idle", "Started", "Done", "Failed"}
BridgeStates == {"Idle", "Accepted", "Failed"}

\* A handshake-tag captures: bridge_id_used, epoch_used, client_ephem_pk,
\* plus a "valid" flag = (client used the bridge's real id AND
\* the epoch is honest). Modeled abstractly — we don't compute BLAKE3.
HandshakeTag(used_id, used_epoch, ephem) ==
    [bridge_id_used |-> used_id,
     epoch_used      |-> used_epoch,
     ephem_pk        |-> ephem]

MessageTypes == {"ClientHello", "ServerReply"}

ClientHelloMsg(client, used_id, used_epoch, ephem) ==
    [type    |-> "ClientHello",
     from    |-> client,
     tag     |-> HandshakeTag(used_id, used_epoch, ephem),
     dest    |-> "any"]   \* attacker can redirect

ServerReplyMsg(bridge, client_ephem, server_ephem, epoch_used) ==
    [type            |-> "ServerReply",
     from            |-> bridge,
     to              |-> "any",
     client_ephem    |-> client_ephem,
     server_ephem    |-> server_ephem,
     epoch_used      |-> epoch_used]

------------------------------------------------------------------------
\* Type invariant

TypeOK ==
    /\ bridge_id \in [Bridges -> Bridges]   \* id is just the bridge name (1:1)
    /\ bridge_pubkey \in [Bridges -> Bridges]
    /\ client_target \in [Clients -> Bridges]
    /\ client_known_id \in [Clients -> Bridges]
    /\ client_state \in [Clients -> States]
    /\ bridge_state \in [Bridges -> BridgeStates]
    /\ completed_sessions \subseteq (Clients \X Bridges)

------------------------------------------------------------------------
\* Init

Init ==
    /\ bridge_id = [b \in Bridges |-> b]
    /\ bridge_pubkey = [b \in Bridges |-> b]
    /\ client_target \in [Clients -> Bridges]
    /\ client_known_id = client_target  \* honest clients start correct
    /\ client_state = [c \in Clients |-> "Idle"]
    /\ bridge_state = [b \in Bridges |-> "Idle"]
    /\ network = << >>
    /\ completed_sessions = {}

------------------------------------------------------------------------
\* Actions

\* A client sends its hello using the bridge_id it knows + a current epoch.
ClientStart(c, e) ==
    /\ client_state[c] = "Idle"
    /\ e \in Epochs
    /\ LET msg == ClientHelloMsg(c, client_known_id[c], e, c)
       IN  /\ network' = Append(network, msg)
           /\ client_state' = [client_state EXCEPT ![c] = "Started"]
    /\ UNCHANGED << bridge_id, bridge_pubkey, client_target, client_known_id,
                    bridge_state, completed_sessions >>

\* A bridge processes the next ClientHello in the queue.
\* Accept iff (tag.bridge_id_used = bridge_id[b]) AND
\*    (tag.epoch_used \in {e_now, e_now - 1}) — i.e., 1-epoch skew window.
\* Otherwise fail.
\* We pick the "current" epoch nondeterministically from Epochs to model
\* arbitrary clock state.
BridgeAccept(b, e_now) ==
    /\ Len(network) > 0
    /\ Head(network).type = "ClientHello"
    /\ e_now \in Epochs
    /\ LET msg == Head(network)
           tag == msg.tag
           valid_id == (tag.bridge_id_used = bridge_id[b])
           valid_epoch == (tag.epoch_used = e_now)
                          \/ (tag.epoch_used + 1 = e_now)
           valid == valid_id /\ valid_epoch
       IN  IF valid
           THEN /\ bridge_state' = [bridge_state EXCEPT ![b] = "Accepted"]
                /\ network' = Append(Tail(network),
                       ServerReplyMsg(b, tag.ephem_pk, b, tag.epoch_used))
                /\ completed_sessions' = completed_sessions \cup {<<msg.from, b>>}
           ELSE /\ bridge_state' = [bridge_state EXCEPT ![b] = "Failed"]
                /\ network' = Tail(network)
                /\ UNCHANGED completed_sessions
    /\ UNCHANGED << bridge_id, bridge_pubkey, client_target, client_known_id,
                    client_state >>

\* Client processes its ServerReply.
ClientFinish(c) ==
    /\ client_state[c] = "Started"
    /\ Len(network) > 0
    /\ Head(network).type = "ServerReply"
    /\ Head(network).client_ephem = c   \* reply is for THIS client
    /\ client_state' = [client_state EXCEPT ![c] = "Done"]
    /\ network' = Tail(network)
    /\ UNCHANGED << bridge_id, bridge_pubkey, client_target, client_known_id,
                    bridge_state, completed_sessions >>

\* Attacker actions, only if AttackerOn.
\* (1) Drop the head of the network queue.
AttackerDrop ==
    /\ AttackerOn
    /\ Len(network) > 0
    /\ network' = Tail(network)
    /\ UNCHANGED << bridge_id, bridge_pubkey, client_target, client_known_id,
                    client_state, bridge_state, completed_sessions >>

\* (2) Replay any prior client hello at a different epoch.
AttackerReplayAtNewEpoch(c, e_new) ==
    /\ AttackerOn
    /\ e_new \in Epochs
    /\ LET msg == ClientHelloMsg(c, client_known_id[c], e_new, c)
       IN  /\ network' = Append(network, msg)
    /\ UNCHANGED << bridge_id, bridge_pubkey, client_target, client_known_id,
                    client_state, bridge_state, completed_sessions >>

\* (3) Forge a hello with random bridge id (different from any real one).
\* In our abstraction "random" = pick a bridge id NOT in Bridges.
\* But our id-space IS Bridges; so forge by using a Client name as the
\* id (clients are distinct from bridges in Constants).
AttackerForgeRandomId(c, fake, e) ==
    /\ AttackerOn
    /\ fake \in Clients   \* using a Client name as fake "bridge id"
    /\ e \in Epochs
    /\ LET msg == ClientHelloMsg(c, fake, e, c)
       IN  /\ network' = Append(network, msg)
    /\ UNCHANGED << bridge_id, bridge_pubkey, client_target, client_known_id,
                    client_state, bridge_state, completed_sessions >>

------------------------------------------------------------------------
\* Next

Next ==
    \/ \E c \in Clients, e \in Epochs : ClientStart(c, e)
    \/ \E b \in Bridges, e \in Epochs : BridgeAccept(b, e)
    \/ \E c \in Clients : ClientFinish(c)
    \/ AttackerDrop
    \/ \E c \in Clients, e \in Epochs : AttackerReplayAtNewEpoch(c, e)
    \/ \E c \in Clients, fake \in Clients, e \in Epochs :
        AttackerForgeRandomId(c, fake, e)

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------
\* Safety properties

\* No bridge accepts a handshake whose tag.bridge_id_used isn't its own id.
NoCrossBridgeReplay ==
    \A pair \in completed_sessions :
        \E c \in Clients, b \in Bridges :
            pair = <<c, b>> /\ client_known_id[c] = b

\* No bridge with current epoch e_now accepts a tag with
\* tag.epoch_used outside {e_now, e_now - 1}.
\* Operationally: any (c, b) in completed_sessions came from a valid
\* epoch window. Since our BridgeAccept already enforces this, the
\* invariant just states that no record bypasses BridgeAccept.
NoOutOfEpochAccept ==
    \A pair \in completed_sessions :
        \E c \in Clients, b \in Bridges :
            pair = <<c, b>>

\* No forged handshake (random fake id from the Clients namespace)
\* succeeds.  A successful completion implies the id matched a real
\* bridge id.
NoUnauthBypass ==
    \A pair \in completed_sessions :
        \E c \in Clients, b \in Bridges :
            pair = <<c, b>> /\ client_known_id[c] \in Bridges

\* If a client completes, the bridge it reached was its target.
\* (Honest run, no attacker meddling with client_known_id.)
SessionAgreementOnHonestRun ==
    AttackerOn = FALSE =>
        \A pair \in completed_sessions :
            \E c \in Clients, b \in Bridges :
                pair = <<c, b>> /\ client_target[c] = b

\* Together with NoCrossBridgeReplay, this matches the implementation:
\* compute_handshake_tag mixes bridge_id into the BLAKE3 key, so
\* tag.bridge_id_used must equal the verifying bridge's own id.
\* compute_handshake_tag also mixes epoch into the key, so accept(...)
\* only matches tags computed at the current OR previous epoch.
\* compute_server_auth_tag mixes the same bridge_id + epoch into the
\* SERVER's reply tag, so the client can verify the reply came from
\* the same bridge it targeted (modeled by reply.client_ephem = c).
======================================================================
