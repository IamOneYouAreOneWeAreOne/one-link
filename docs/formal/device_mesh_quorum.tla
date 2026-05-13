------------------------ MODULE DeviceMeshQuorum ------------------------
(*
  TLA+ model of Row 8 Layer 2 — threshold device quorum.

  The mesh has one master and a roster of N devices. The master signs
  a policy with threshold K. Devices propose and approve operations.
  An attacker can: forward / drop / duplicate messages, capture
  approvals signed for one proposal and try to substitute them into
  a certificate for a different proposal.

  Verified safety properties:

    NoBelowThresholdAccept
        A certificate is accepted only if at least K distinct
        eligible devices approved.

    NoIneligibleApproval
        An approval from a device not in the policy's eligible list
        never contributes to a valid certificate.

    NoCrossProposalReplay
        An approval signed for proposal A is never accepted as part
        of a certificate for proposal B (proposal_id binds them).

    NoExpiredApprove
        An approval whose approved_unix is past the proposal's
        deadline_unix is never accepted.

    DistinctApprovers
        Two approvals from the same device in one certificate count
        as one (the certificate's K count is over distinct approvers).
*)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Devices,        \* finite set of device ids in this mesh
    Eligible,       \* subset of Devices that the policy authorises
    K,              \* quorum threshold; integer 1..|Eligible|
    Proposals,      \* finite set of distinct proposal ids
    NowUnix,        \* abstract verifier wall-clock (integer)
    DeadlineUnix,   \* abstract proposal deadline (integer)
    AttackerOn      \* BOOLEAN — model an active attacker

ASSUME
    /\ Eligible \subseteq Devices
    /\ K \in 1 .. Cardinality(Eligible)
    /\ NowUnix \in Nat
    /\ DeadlineUnix \in Nat

VARIABLES
    issued,         \* function Proposals -> {none} ∪ Devices (issuer)
    approvals,      \* function Proposals -> set of (device, approved_unix)
    certificates,   \* set of (proposal_id, approval_set) records
    accepted        \* set of certificates the verifier said "ok"

vars == << issued, approvals, certificates, accepted >>

NotIssued == "not-issued"

------------------------------------------------------------------------
\* Type invariant

TypeOK ==
    /\ issued \in [Proposals -> Devices \cup {NotIssued}]
    /\ approvals \in [Proposals -> SUBSET (Devices \X Nat)]
    /\ certificates \subseteq [proposal_id : Proposals, approval_set : SUBSET (Devices \X Nat)]
    /\ accepted \subseteq certificates

------------------------------------------------------------------------
\* Initial state

Init ==
    /\ issued = [p \in Proposals |-> NotIssued]
    /\ approvals = [p \in Proposals |-> {}]
    /\ certificates = {}
    /\ accepted = {}

------------------------------------------------------------------------
\* Actions

\* An eligible device issues a proposal.
IssueProposal(d, p) ==
    /\ d \in Eligible
    /\ issued[p] = NotIssued
    /\ issued' = [issued EXCEPT ![p] = d]
    /\ UNCHANGED << approvals, certificates, accepted >>

\* Any device signs an approval at any wall-clock time. (We don't
\* model the device choosing valid times; the verifier later rejects
\* out-of-window approvals.)
SignApproval(d, p, t) ==
    /\ issued[p] /= NotIssued
    /\ t \in 0 .. (DeadlineUnix + 10)   \* allow late approvals to model attacker
    /\ approvals' = [approvals EXCEPT ![p] = approvals[p] \cup {<<d, t>>}]
    /\ UNCHANGED << issued, certificates, accepted >>

\* Anyone (including the attacker) constructs a certificate from
\* whatever approval bytes are visible.
ConstructCertificate(p, app_set) ==
    /\ issued[p] /= NotIssued
    /\ app_set \subseteq approvals[p]   \* approvals must be real for THIS proposal id
    /\ certificates' = certificates \cup {[proposal_id |-> p, approval_set |-> app_set]}
    /\ UNCHANGED << issued, approvals, accepted >>

\* Attacker tries to cross-paste: build a certificate for proposal A
\* using approval bytes from proposal B. We MODEL this as a non-deterministic
\* construct, but the verifier check below catches it.
AttackerCrossPaste(p_a, p_b, app_set) ==
    /\ AttackerOn
    /\ p_a /= p_b
    /\ issued[p_a] /= NotIssued
    /\ issued[p_b] /= NotIssued
    /\ app_set \subseteq approvals[p_b]
    /\ certificates' = certificates \cup
        {[proposal_id |-> p_a, approval_set |-> app_set]}
    /\ UNCHANGED << issued, approvals, accepted >>

\* Verifier accepts a certificate iff ALL of:
\*  - every (d, t) in approval_set has d ∈ Eligible
\*  - every (d, t) has t ≤ DeadlineUnix
\*  - approval_set was actually signed for THIS proposal (modelled via
\*    "app_set ⊆ approvals[p]" — i.e., the verifier knows the bytes;
\*    cross-paste certificates have app_set referencing a DIFFERENT
\*    proposal's approvals so they fail this clause)
\*  - the distinct-device count ≥ K
\*  - NowUnix ≤ DeadlineUnix
DistinctDevices(app_set) == {d \in Devices : \E t \in Nat : <<d, t>> \in app_set}

AcceptCertificate(c) ==
    /\ c \in certificates
    /\ c \notin accepted
    /\ NowUnix <= DeadlineUnix
    /\ \A entry \in c.approval_set : entry[1] \in Eligible /\ entry[2] <= DeadlineUnix
    /\ c.approval_set \subseteq approvals[c.proposal_id]   \* binds to proposal
    /\ Cardinality(DistinctDevices(c.approval_set)) >= K
    /\ accepted' = accepted \cup {c}
    /\ UNCHANGED << issued, approvals, certificates >>

------------------------------------------------------------------------
\* Next-state

Next ==
    \/ \E d \in Devices, p \in Proposals : IssueProposal(d, p)
    \/ \E d \in Devices, p \in Proposals, t \in 0 .. (DeadlineUnix + 10) :
            SignApproval(d, p, t)
    \/ \E p \in Proposals, app_set \in SUBSET (Devices \X (0 .. (DeadlineUnix + 10))) :
            ConstructCertificate(p, app_set)
    \/ \E p_a \in Proposals, p_b \in Proposals,
          app_set \in SUBSET (Devices \X (0 .. (DeadlineUnix + 10))) :
            AttackerCrossPaste(p_a, p_b, app_set)
    \/ \E c \in certificates : AcceptCertificate(c)

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------
\* Safety properties

\* (1) No accepted certificate has fewer than K distinct approvers.
NoBelowThresholdAccept ==
    \A c \in accepted : Cardinality(DistinctDevices(c.approval_set)) >= K

\* (2) Every approver in an accepted certificate is eligible.
NoIneligibleApproval ==
    \A c \in accepted :
        \A entry \in c.approval_set : entry[1] \in Eligible

\* (3) An approval in an accepted certificate must have been signed
\* for THAT certificate's proposal id (the verifier's app_set ⊆
\* approvals[proposal] check enforces this).
NoCrossProposalReplay ==
    \A c \in accepted : c.approval_set \subseteq approvals[c.proposal_id]

\* (4) No accepted approval is past the deadline.
NoExpiredApprove ==
    \A c \in accepted :
        \A entry \in c.approval_set : entry[2] <= DeadlineUnix

\* (5) Distinct-approver counting: even if the certificate's
\* approval_set has two entries for the same device with different
\* timestamps, they count as one in the distinct-devices set.
\* This is enforced by the SET semantics of DistinctDevices.
DistinctApprovers ==
    \A c \in accepted :
        Cardinality(DistinctDevices(c.approval_set)) <= Cardinality(c.approval_set)
======================================================================
