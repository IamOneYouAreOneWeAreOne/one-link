------------------------------ MODULE Capability ------------------------------
(*
  Capability grant, attenuation, key-rotation, revocation, and validation
  state machine.  This model checks the four Phase-D safety families against
  every state reachable within the explicit finite bounds in Capability.cfg:

    NoDoubleGrant
      Two simultaneously live capability ids cannot represent the same
      (granter, subject, root-rights) grant.

    NoKeyReuse
      Root keys are globally unique while active, and a retired root key can
      never become active again.

    NoDowngrade
      Attenuation only removes rights: every effective-right set remains a
      subset of the immutable root-right set.

    NoReplay
      Presenting a revoked or never-minted capability cannot produce an
      accepted validation decision, including after a prior acceptance.

  Rights are represented as sets of opaque Scopes.  This is the finite safety
  abstraction of the runtime's conjunctive macaroon caveats: adding a caveat
  intersects the set of accepted contexts and therefore cannot add rights.
  Cryptographic unforgeability and wire parsing remain native-code properties.
*)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Granters,
    Subjects,
    Scopes,
    RootKeys,
    CapIds,
    NoGranter,
    NoSubject,
    NoKey,
    MaxMinted

ASSUME
    /\ Granters # {}
    /\ Subjects # {}
    /\ Scopes # {}
    /\ Cardinality(RootKeys) > Cardinality(Granters)
    /\ CapIds # {}
    /\ NoGranter \notin Granters
    /\ NoSubject \notin Subjects
    /\ NoKey \notin RootKeys
    /\ MaxMinted \in 1 .. Cardinality(CapIds)

VARIABLES
    minted,               \* all capability ids ever minted
    grant_granter,        \* CapIds -> Granters or sentinel
    grant_subject,        \* CapIds -> Subjects or sentinel
    grant_key,            \* CapIds -> mint-time RootKey or sentinel
    root_rights,          \* immutable rights at mint
    effective_rights,     \* rights after zero or more attenuations
    current_key,          \* active root key per granter
    used_keys,            \* all root keys ever activated
    retired_keys,         \* keys that may never become active again
    revoked,              \* revoked capability ids
    validation_target,    \* empty or singleton last presented CapId
    validation_accepted   \* result of validating that presentation

vars == <<minted, grant_granter, grant_subject, grant_key, root_rights,
          effective_rights, current_key, used_keys, retired_keys, revoked,
          validation_target, validation_accepted>>

ActiveCaps == minted \ revoked
CurrentKeys == {current_key[g] : g \in Granters}

TypeOK ==
    /\ minted \subseteq CapIds
    /\ Cardinality(minted) <= MaxMinted
    /\ grant_granter \in [CapIds -> Granters \cup {NoGranter}]
    /\ grant_subject \in [CapIds -> Subjects \cup {NoSubject}]
    /\ grant_key \in [CapIds -> RootKeys \cup {NoKey}]
    /\ root_rights \in [CapIds -> SUBSET Scopes]
    /\ effective_rights \in [CapIds -> SUBSET Scopes]
    /\ current_key \in [Granters -> RootKeys]
    /\ used_keys \subseteq RootKeys
    /\ retired_keys \subseteq used_keys
    /\ revoked \subseteq minted
    /\ validation_target \subseteq CapIds
    /\ Cardinality(validation_target) <= 1
    /\ validation_accepted \in BOOLEAN

Init ==
    /\ minted = {}
    /\ grant_granter = [cap \in CapIds |-> NoGranter]
    /\ grant_subject = [cap \in CapIds |-> NoSubject]
    /\ grant_key = [cap \in CapIds |-> NoKey]
    /\ root_rights = [cap \in CapIds |-> {}]
    /\ effective_rights = [cap \in CapIds |-> {}]
    /\ current_key \in [Granters -> RootKeys]
    /\ Cardinality(CurrentKeys) = Cardinality(Granters)
    /\ used_keys = CurrentKeys
    /\ retired_keys = {}
    /\ revoked = {}
    /\ validation_target = {}
    /\ validation_accepted = FALSE

DuplicateLiveGrant(g, s, rights) ==
    \E cap \in ActiveCaps :
        /\ grant_granter[cap] = g
        /\ grant_subject[cap] = s
        /\ root_rights[cap] = rights

IssueGrant(g, s, rights, cap) ==
    /\ cap \notin minted
    /\ Cardinality(minted) < MaxMinted
    /\ rights # {}
    /\ ~DuplicateLiveGrant(g, s, rights)
    /\ minted' = minted \cup {cap}
    /\ grant_granter' = [grant_granter EXCEPT ![cap] = g]
    /\ grant_subject' = [grant_subject EXCEPT ![cap] = s]
    /\ grant_key' = [grant_key EXCEPT ![cap] = current_key[g]]
    /\ root_rights' = [root_rights EXCEPT ![cap] = rights]
    /\ effective_rights' = [effective_rights EXCEPT ![cap] = rights]
    /\ UNCHANGED <<current_key, used_keys, retired_keys, revoked,
                   validation_target, validation_accepted>>

Attenuate(cap, narrowed_rights) ==
    /\ cap \in ActiveCaps
    /\ narrowed_rights \subseteq effective_rights[cap]
    /\ narrowed_rights # effective_rights[cap]
    /\ effective_rights' =
           [effective_rights EXCEPT ![cap] = narrowed_rights]
    /\ UNCHANGED <<minted, grant_granter, grant_subject, grant_key,
                   root_rights, current_key, used_keys, retired_keys, revoked,
                   validation_target, validation_accepted>>

RotateRootKey(g, fresh_key) ==
    /\ fresh_key \notin used_keys
    /\ current_key' = [current_key EXCEPT ![g] = fresh_key]
    /\ used_keys' = used_keys \cup {fresh_key}
    /\ retired_keys' = retired_keys \cup {current_key[g]}
    /\ UNCHANGED <<minted, grant_granter, grant_subject, grant_key,
                   root_rights, effective_rights, revoked,
                   validation_target, validation_accepted>>

Revoke(cap) ==
    /\ cap \in ActiveCaps
    /\ revoked' = revoked \cup {cap}
    /\ validation_accepted' =
           IF validation_target = {cap} THEN FALSE ELSE validation_accepted
    /\ UNCHANGED <<minted, grant_granter, grant_subject, grant_key,
                   root_rights, effective_rights, current_key, used_keys,
                   retired_keys, validation_target>>

PresentForValidation(cap) ==
    /\ \/ validation_target # {cap}
       \/ validation_accepted # (cap \in ActiveCaps)
    /\ validation_target' = {cap}
    /\ validation_accepted' = (cap \in ActiveCaps)
    /\ UNCHANGED <<minted, grant_granter, grant_subject, grant_key,
                   root_rights, effective_rights, current_key, used_keys,
                   retired_keys, revoked>>

Next ==
    \/ \E g \in Granters, s \in Subjects, rights \in SUBSET Scopes,
          cap \in CapIds : IssueGrant(g, s, rights, cap)
    \/ \E cap \in CapIds, narrowed \in SUBSET Scopes :
           Attenuate(cap, narrowed)
    \/ \E g \in Granters, key \in RootKeys : RotateRootKey(g, key)
    \/ \E cap \in CapIds : Revoke(cap)
    \/ \E cap \in CapIds : PresentForValidation(cap)

Spec == Init /\ [][Next]_vars

NoDoubleGrant ==
    \A cap1, cap2 \in ActiveCaps :
        /\ grant_granter[cap1] = grant_granter[cap2]
        /\ grant_subject[cap1] = grant_subject[cap2]
        /\ root_rights[cap1] = root_rights[cap2]
        => cap1 = cap2

NoKeyReuse ==
    /\ Cardinality(CurrentKeys) = Cardinality(Granters)
    /\ CurrentKeys \cap retired_keys = {}
    /\ used_keys = CurrentKeys \cup retired_keys

NoDowngrade ==
    \A cap \in minted : effective_rights[cap] \subseteq root_rights[cap]

NoReplay ==
    validation_accepted => validation_target \subseteq ActiveCaps

MintMetadataComplete ==
    \A cap \in CapIds :
        IF cap \in minted
        THEN
            /\ grant_granter[cap] \in Granters
            /\ grant_subject[cap] \in Subjects
            /\ grant_key[cap] \in RootKeys
            /\ root_rights[cap] # {}
        ELSE
            /\ grant_granter[cap] = NoGranter
            /\ grant_subject[cap] = NoSubject
            /\ grant_key[cap] = NoKey
            /\ root_rights[cap] = {}
            /\ effective_rights[cap] = {}

SafetyInvariants ==
    /\ TypeOK
    /\ NoDoubleGrant
    /\ NoKeyReuse
    /\ NoDowngrade
    /\ NoReplay
    /\ MintMetadataComplete

Symmetry ==
    Permutations(Granters)
    \cup Permutations(Subjects)
    \cup Permutations(Scopes)
    \cup Permutations(RootKeys)
    \cup Permutations(CapIds)
=============================================================================
