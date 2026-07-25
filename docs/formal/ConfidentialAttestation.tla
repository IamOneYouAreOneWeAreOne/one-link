-------------------- MODULE ConfidentialAttestation --------------------
(*
 * Design-time formal model for Row 10 — confidential-compute daemon
 * attestation protocol.
 *
 * The model is a state machine over master identities + peer
 * challenges + attestation docs. Each transition mirrors a real-code
 * operation in `ol_confidential::attestation`:
 *
 *   sign_attestation(...)   →  IssueAttestation
 *   verify_attestation(...) →  VerifyAtPeer
 *
 * The four invariants below are CHECKED by TLC against the model:
 *
 *  - INV_freshness_in_policy:
 *      every issued doc satisfies issued_unix < deadline_unix ≤
 *      issued_unix + FRESHNESS_WIN_SEC.
 *
 *  - INV_no_past_deadline:
 *      every doc accepted by a verifier has now_unix ≤
 *      deadline_unix at acceptance time.
 *
 *  - INV_nonce_at_most_once:
 *      a peer that issued nonce N accepts at most one doc carrying N.
 *      (Replay protection.)
 *
 *  - INV_no_cross_master_forgery:
 *      no verifier accepts a doc claiming master_vk = M when the
 *      signature was issued by a different master M' ≠ M.
 *)

EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Masters,            \* set of master identities present in the world
    ProviderTags,       \* {Software, WindowsTpm, ...}
    Nonces,             \* finite challenge domain explored by TLC
    Witnesses,          \* set of field witnesses
    DocSlots,           \* maximum concurrent signed/forged documents
    FRESHNESS_WIN_SEC,  \* policy maximum window
    MAX_TIME            \* model checker bound on wall clock

VARIABLES
    now,                \* current wall-clock seconds
    issued_docs,        \* set of all docs ever signed
    accepted_docs,      \* set of (verifier, doc, accepted_at) triples
    challenge_nonces    \* function: verifier -> set of nonces it has issued

vars == << now, issued_docs, accepted_docs, challenge_nonces >>

NoWitness == "NoWitness"

(* A doc is a record of every signed field plus the master that signed it.
   Keeping signer separate from the claimed master makes the
   no-cross-master-forgery invariant executable instead of tautological. *)
Docs ==
    [ master   : Masters,
      signer   : Masters,
      provider : ProviderTags,
      nonce    : Nonces,
      issued   : 0..MAX_TIME,
      deadline : 0..MAX_TIME,
      witness  : {NoWitness} \cup Witnesses ]

\* Model: a witness commitment is a tag-bound function of (provider, witness).
\* TLC just needs the function to be injective in the witness arg, so we use
\* the witness itself as the "commitment" — collisions across witnesses are
\* what would break field-binding, and the spec asserts they don't occur.

Init ==
    /\ now = 0
    /\ issued_docs = {}
    /\ accepted_docs = {}
    /\ challenge_nonces = [v \in Masters |-> {}]

TypeOK ==
    /\ now \in 0..MAX_TIME
    /\ issued_docs \subseteq Docs
    /\ Cardinality(issued_docs) <= Cardinality(DocSlots)
    /\ accepted_docs \subseteq (Masters \X Docs \X (0..MAX_TIME))
    /\ challenge_nonces \in [Masters -> SUBSET Nonces]

\* Time advances by 1 second. Bounded so TLC can finish.
AdvanceTime ==
    /\ now < MAX_TIME
    /\ now' = now + 1
    /\ UNCHANGED << issued_docs, accepted_docs, challenge_nonces >>

\* The bounded model permits the daemon to remain quiescent after the model
\* clock reaches its ceiling. This is an explicit service-idle transition,
\* not a disabled deadlock check.
Quiesce ==
    /\ now = MAX_TIME
    /\ UNCHANGED vars

\* A verifier (a "master" in the model = a process holding a long-term
\* identity) issues a fresh challenge nonce.
IssueChallenge(v, n) ==
    /\ v \in Masters
    /\ n \in Nonces
    /\ n \notin challenge_nonces[v]
    /\ challenge_nonces' = [challenge_nonces EXCEPT ![v] = @ \cup {n}]
    /\ UNCHANGED << now, issued_docs, accepted_docs >>

\* The prover (master m) signs an attestation doc binding the challenge.
IssueAttestation(m, p, n, w, deadline) ==
    /\ m \in Masters
    /\ p \in ProviderTags
    /\ n \in Nonces
    /\ w \in {NoWitness} \cup Witnesses
    /\ deadline \in 0..MAX_TIME
    /\ now < deadline
    /\ deadline <= now + FRESHNESS_WIN_SEC
    /\ Cardinality(issued_docs) < Cardinality(DocSlots)
    /\ LET d == [ master |-> m, signer |-> m,
                  provider |-> p, nonce |-> n,
                  issued |-> now, deadline |-> deadline,
                  witness |-> w ]
       IN  /\ d \notin issued_docs
           /\ issued_docs' = issued_docs \cup {d}
    /\ UNCHANGED << now, accepted_docs, challenge_nonces >>

\* An active attacker can submit a document whose signed bytes identify one
\* signer while the public claim names another master. This makes the
\* cross-master invariant adversarial and non-vacuous: VerifyAtPeer must
\* reject every such document.
InjectForgedAttestation(claimed, signer, p, n, w, deadline) ==
    /\ claimed \in Masters
    /\ signer \in Masters
    /\ claimed /= signer
    /\ p \in ProviderTags
    /\ n \in Nonces
    /\ w \in {NoWitness} \cup Witnesses
    /\ deadline \in 0..MAX_TIME
    /\ now < deadline
    /\ deadline <= now + FRESHNESS_WIN_SEC
    /\ Cardinality(issued_docs) < Cardinality(DocSlots)
    /\ LET d == [ master |-> claimed, signer |-> signer,
                  provider |-> p, nonce |-> n,
                  issued |-> now, deadline |-> deadline,
                  witness |-> w ]
       IN  /\ d \notin issued_docs
           /\ issued_docs' = issued_docs \cup {d}
    /\ UNCHANGED << now, accepted_docs, challenge_nonces >>

\* A verifier v accepts doc d issued by prover m IFF:
\*   - d.nonce was a challenge v previously issued
\*   - now ≤ d.deadline
\*   - the doc was actually signed by m (modeled: the doc carries its issuer)
VerifyAtPeer(v, d) ==
    /\ v \in Masters
    /\ d \in issued_docs
    /\ d.signer = d.master
    /\ d.nonce \in challenge_nonces[v]
    /\ now <= d.deadline
    /\ ~ \E acc \in accepted_docs :
              acc[1] = v /\ acc[2].nonce = d.nonce
    /\ accepted_docs' = accepted_docs \cup {<<v, d, now>>}
    /\ UNCHANGED << now, issued_docs, challenge_nonces >>

Next ==
    \/ AdvanceTime
    \/ Quiesce
    \/ \E v \in Masters, n \in Nonces : IssueChallenge(v, n)
    \/ \E m \in Masters, p \in ProviderTags, n \in Nonces,
         w \in {NoWitness} \cup Witnesses, d \in 0..MAX_TIME :
            IssueAttestation(m, p, n, w, d)
    \/ \E claimed \in Masters, signer \in Masters,
          p \in ProviderTags, n \in Nonces,
          w \in {NoWitness} \cup Witnesses, d \in 0..MAX_TIME :
            InjectForgedAttestation(claimed, signer, p, n, w, d)
    \/ \E v \in Masters, d \in issued_docs : VerifyAtPeer(v, d)

Spec == Init /\ [][Next]_vars

(* ── Invariants ───────────────────────────────────────────────── *)

INV_freshness_in_policy ==
    \A d \in issued_docs :
        /\ d.issued < d.deadline
        /\ d.deadline <= d.issued + FRESHNESS_WIN_SEC

INV_no_past_deadline ==
    \A acc \in accepted_docs :
        acc[3] <= acc[2].deadline

INV_nonce_at_most_once ==
    \A v \in Masters, n \in Nonces :
        Cardinality({ acc \in accepted_docs :
                        acc[1] = v /\ acc[2].nonce = n }) <= 1

INV_no_cross_master_forgery ==
    \A acc \in accepted_docs :
        \* The forged-document action can put signer /= master records into
        \* issued_docs. The verifier's signer/claim equality check keeps every
        \* such record out of accepted_docs.
        /\ acc[2] \in issued_docs
        /\ acc[2].signer = acc[2].master

=============================================================================
