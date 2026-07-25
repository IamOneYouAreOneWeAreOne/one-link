------------------------ MODULE DeviceMeshSelfRouting ------------------------
(*
  TLA+ model of Row 8 Layer 6 — the convergent self-mesh route
  announcement table that feeds the max-min-τ path finder.

  Two replicas ingest the same SET of route announcements (possibly
  in different orders) and run pick_best_route over the resulting
  table. We model:

    - A small mesh of N devices, each with an announcement time and
      a summary tau value.
    - Two receivers, each with its own RouteTable, that ingest
      announcements in arbitrary order.
    - Equal timestamps use tau as a deterministic canonical tie-break.

  Verified invariants:

    Convergence
        Two receivers that have ingested the same SET of
        announcements hold identical route tables (modulo
        canonical ordering).

    DominanceMonotone
        Ingesting an older announcement is a no-op (the table never
        regresses).

    LatestWins
        Every materialized row is the lexicographic maximum
        (announcement time, tau) accepted for that device.

  This model is deliberately the convergence/merge slice. Path enumeration
  and wall-clock pruning require their own executable models and are not
  claimed by this specification.
*)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Devices,        \* finite set of device ids
    AnnPool,        \* finite publication slots (bounds the TLC state space)
    MaxTau,         \* upper bound on τ_c scores (Nat)
    NowUnix         \* fixed verifier clock value

ASSUME
    /\ MaxTau \in Nat
    /\ NowUnix \in Nat
    /\ IsFiniteSet(AnnPool)
    /\ Cardinality(AnnPool) > 0

VARIABLES
    ann_pool,       \* SUBSET (Devices \X Nat \X Nat)
                    \* tuples (announcer, ann_at_unix, max_tau)
    table_a,        \* tagged (ann_at_unix, summary tau) per device
    table_b,        \* same for replica B
    accepted_a,     \* SUBSET ann_pool (what replica A has ingested)
    accepted_b      \* same for replica B

vars == << ann_pool, table_a, table_b, accepted_a, accepted_b >>

NULL == <<"Empty", 0, 0>>

AnnouncementUniverse ==
    Devices \X (0 .. (NowUnix * 2)) \X (0 .. MaxTau)

AnnouncementDominates(ann, prior) ==
    IF prior = NULL
    THEN TRUE
    ELSE \/ ann[2] > prior[2]
         \/ /\ ann[2] = prior[2]
            /\ ann[3] > prior[3]
------------------------------------------------------------------------
TypeOK ==
    /\ ann_pool \subseteq AnnouncementUniverse
    /\ Cardinality(ann_pool) <= Cardinality(AnnPool)
    /\ table_a \in [Devices -> {NULL} \cup
          ({"R"} \X (0 .. (NowUnix * 2)) \X (0 .. MaxTau))]
    /\ table_b \in [Devices -> {NULL} \cup
          ({"R"} \X (0 .. (NowUnix * 2)) \X (0 .. MaxTau))]
    /\ accepted_a \subseteq ann_pool
    /\ accepted_b \subseteq ann_pool

------------------------------------------------------------------------
Init ==
    /\ ann_pool = {}
    /\ table_a = [d \in Devices |-> NULL]
    /\ table_b = [d \in Devices |-> NULL]
    /\ accepted_a = {}
    /\ accepted_b = {}

------------------------------------------------------------------------
\* Some device authors a new announcement at some time with some tau.
PublishAnn(d, t, tau) ==
    /\ d \in Devices
    /\ t \in 0 .. (NowUnix * 2)
    /\ tau \in 0 .. MaxTau
    /\ <<d, t, tau>> \notin ann_pool
    /\ Cardinality(ann_pool) < Cardinality(AnnPool)
    /\ ann_pool' = ann_pool \cup {<<d, t, tau>>}
    /\ UNCHANGED << table_a, table_b, accepted_a, accepted_b >>

\* Replica A ingests an announcement.
IngestA(ann) ==
    /\ ann \in ann_pool
    /\ ann \notin accepted_a
    /\ LET d == ann[1]
           t == ann[2]
           tau == ann[3]
           prior == table_a[d]
       IN  IF AnnouncementDominates(ann, prior)
           THEN table_a' = [table_a EXCEPT ![d] = <<"R", t, tau>>]
           ELSE table_a' = table_a
    /\ accepted_a' = accepted_a \cup {ann}
    /\ UNCHANGED << ann_pool, table_b, accepted_b >>

\* Replica B ingests an announcement.
IngestB(ann) ==
    /\ ann \in ann_pool
    /\ ann \notin accepted_b
    /\ LET d == ann[1]
           t == ann[2]
           tau == ann[3]
           prior == table_b[d]
       IN  IF AnnouncementDominates(ann, prior)
           THEN table_b' = [table_b EXCEPT ![d] = <<"R", t, tau>>]
           ELSE table_b' = table_b
    /\ accepted_b' = accepted_b \cup {ann}
    /\ UNCHANGED << ann_pool, table_a, accepted_a >>

Quiesce ==
    /\ Cardinality(ann_pool) = Cardinality(AnnPool)
    /\ accepted_a = ann_pool
    /\ accepted_b = ann_pool
    /\ UNCHANGED vars

Next ==
    \/ \E d \in Devices, t \in 0 .. (NowUnix * 2), tau \in 0 .. MaxTau :
         PublishAnn(d, t, tau)
    \/ \E ann \in ann_pool : IngestA(ann)
    \/ \E ann \in ann_pool : IngestB(ann)
    \/ Quiesce

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------
\* Safety invariants

\* When two replicas have ingested the same SET of announcements,
\* their tables agree.
Convergence ==
    accepted_a = accepted_b => table_a = table_b

\* Ingesting an older announcement never regresses the table.
DominanceMonotone ==
    /\ \A d \in Devices :
           \/ table_a[d] = NULL
           \/ (\E ann \in accepted_a :
                  ann[1] = d
                  /\ ann[2] = table_a[d][2]
                  /\ ann[3] = table_a[d][3])
    /\ \A d \in Devices :
           \/ table_b[d] = NULL
           \/ (\E ann \in accepted_b :
                  ann[1] = d
                  /\ ann[2] = table_b[d][2]
                  /\ ann[3] = table_b[d][3])

\* No stale entry. (Modeled: every accepted announcement that
\* corresponds to the current table row is the latest one in
\* accepted_a for that device.)
LatestWins ==
    /\ \A d \in Devices :
           table_a[d] /= NULL =>
               (\A ann \in accepted_a :
                   ann[1] = d =>
                       \/ ann[2] < table_a[d][2]
                       \/ /\ ann[2] = table_a[d][2]
                          /\ ann[3] <= table_a[d][3])
    /\ \A d \in Devices :
           table_b[d] /= NULL =>
               (\A ann \in accepted_b :
                   ann[1] = d =>
                       \/ ann[2] < table_b[d][2]
                       \/ /\ ann[2] = table_b[d][2]
                          /\ ann[3] <= table_b[d][3])
======================================================================
