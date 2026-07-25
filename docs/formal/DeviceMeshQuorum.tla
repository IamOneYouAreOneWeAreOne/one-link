--------------------------- MODULE DeviceMeshQuorum ---------------------------
(*
  Finite-state model of threshold device quorum verification.

  This is a sound safety abstraction of the runtime protocol, not a performance
  model.  Proposal issuance is represented as a set because the issuer identity
  does not participate in any certificate-verification decision.  A single
  candidate certificate is retained at a time: every candidate is still explored
  nondeterministically, and once a candidate is accepted it is frozen so the
  invariants remain bound to the exact object the verifier accepted.  Approval
  timestamps are partitioned into finite timely/late equivalence classes.

  MaxApprovalEntries is an explicit finite-model bound.  The checked instance
  includes enough entries to exercise a K-of-N acceptance, duplicate-device
  counting, an ineligible signer, and a late signer in adversarial combinations.
*)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Devices,             \* finite set of device ids
    Eligible,            \* policy-authorised subset of Devices
    K,                   \* quorum threshold
    Proposals,           \* finite set of proposal ids
    ApprovalTimes,       \* finite timestamp equivalence classes
    TimelyTimes,         \* classes at or before the proposal deadline
    MaxApprovalEntries,  \* per-proposal finite exploration bound
    NullProposal,        \* typed sentinel outside Proposals
    NowUnix,             \* verifier wall clock
    DeadlineUnix,        \* proposal deadline
    AttackerOn           \* whether cross-proposal construction is explored

ASSUME
    /\ Eligible \subseteq Devices
    /\ K \in 1 .. Cardinality(Eligible)
    /\ Proposals # {}
    /\ NullProposal \notin Proposals
    /\ ApprovalTimes # {}
    /\ TimelyTimes \subseteq ApprovalTimes
    /\ ApprovalTimes \ TimelyTimes # {}
    /\ MaxApprovalEntries \in 1 .. Cardinality(Devices \X ApprovalTimes)
    /\ NowUnix \in Nat
    /\ DeadlineUnix \in Nat

ApprovalUniverse == Devices \X ApprovalTimes
NoCertificate == [proposal_id |-> NullProposal, approval_set |-> {}]

VARIABLES
    issued,       \* set of issued proposal ids
    approvals,    \* function Proposals -> set of <<device, time-class>>
    certificate,  \* the currently presented candidate, or NoCertificate
    accepted      \* TRUE only after this exact candidate passed verification

vars == <<issued, approvals, certificate, accepted>>

CertificateType ==
    [proposal_id : Proposals \cup {NullProposal},
     approval_set : SUBSET ApprovalUniverse]

TypeOK ==
    /\ issued \subseteq Proposals
    /\ approvals \in [Proposals -> SUBSET ApprovalUniverse]
    /\ \A p \in Proposals : Cardinality(approvals[p]) <= MaxApprovalEntries
    /\ certificate \in {NoCertificate} \cup CertificateType
    /\ accepted \in BOOLEAN
    /\ accepted => certificate # NoCertificate

Init ==
    /\ issued = {}
    /\ approvals = [p \in Proposals |-> {}]
    /\ certificate = NoCertificate
    /\ accepted = FALSE

IssueProposal(p) ==
    /\ p \notin issued
    /\ issued' = issued \cup {p}
    /\ UNCHANGED <<approvals, certificate, accepted>>

SignApproval(d, p, t) ==
    /\ p \in issued
    /\ <<d, t>> \notin approvals[p]
    /\ Cardinality(approvals[p]) < MaxApprovalEntries
    /\ approvals' = [approvals EXCEPT ![p] = @ \cup {<<d, t>>}]
    /\ UNCHANGED <<issued, certificate, accepted>>

Candidate(p, app_set) ==
    [proposal_id |-> p, approval_set |-> app_set]

ConstructCertificate(p, app_set) ==
    LET candidate == Candidate(p, app_set) IN
    /\ ~accepted
    /\ p \in issued
    /\ app_set \subseteq approvals[p]
    /\ certificate # candidate
    /\ certificate' = candidate
    /\ UNCHANGED <<issued, approvals, accepted>>

(* Model an attacker presenting approval bytes observed under another proposal. *)
AttackerCrossPaste(p_a, p_b, app_set) ==
    LET candidate == Candidate(p_a, app_set) IN
    /\ AttackerOn
    /\ ~accepted
    /\ p_a # p_b
    /\ p_a \in issued
    /\ p_b \in issued
    /\ app_set \subseteq approvals[p_b]
    /\ certificate # candidate
    /\ certificate' = candidate
    /\ UNCHANGED <<issued, approvals, accepted>>

DistinctDevices(app_set) ==
    {d \in Devices : \E t \in ApprovalTimes : <<d, t>> \in app_set}

AcceptCertificate ==
    /\ ~accepted
    /\ certificate # NoCertificate
    /\ NowUnix <= DeadlineUnix
    /\ \A entry \in certificate.approval_set :
           /\ entry[1] \in Eligible
           /\ entry[2] \in TimelyTimes
    /\ certificate.approval_set \subseteq approvals[certificate.proposal_id]
    /\ Cardinality(DistinctDevices(certificate.approval_set)) >= K
    /\ accepted' = TRUE
    /\ UNCHANGED <<issued, approvals, certificate>>

Next ==
    \/ \E p \in Proposals : IssueProposal(p)
    \/ \E d \in Devices, p \in Proposals, t \in ApprovalTimes :
           SignApproval(d, p, t)
    \/ \E p \in Proposals :
           \E app_set \in SUBSET approvals[p] :
               ConstructCertificate(p, app_set)
    \/ \E p_a \in Proposals, p_b \in Proposals :
           \E app_set \in SUBSET approvals[p_b] :
               AttackerCrossPaste(p_a, p_b, app_set)
    \/ AcceptCertificate

Spec == Init /\ [][Next]_vars

AcceptedProperty(predicate) == IF accepted THEN predicate ELSE TRUE

NoBelowThresholdAccept ==
    AcceptedProperty(
        Cardinality(DistinctDevices(certificate.approval_set)) >= K
    )

NoIneligibleApproval ==
    AcceptedProperty(
        \A entry \in certificate.approval_set : entry[1] \in Eligible
    )

NoCrossProposalReplay ==
    AcceptedProperty(
        certificate.approval_set \subseteq approvals[certificate.proposal_id]
    )

NoExpiredApprove ==
    AcceptedProperty(
        \A entry \in certificate.approval_set : entry[2] \in TimelyTimes
    )

DistinctApprovers ==
    AcceptedProperty(
        Cardinality(DistinctDevices(certificate.approval_set))
            <= Cardinality(certificate.approval_set)
    )

(* Preserve semantic partitions while reducing interchangeable model values. *)
Symmetry ==
    Permutations(Eligible)
    \cup Permutations(Devices \ Eligible)
    \cup Permutations(Proposals)
    \cup Permutations(TimelyTimes)
    \cup Permutations(ApprovalTimes \ TimelyTimes)
=============================================================================
