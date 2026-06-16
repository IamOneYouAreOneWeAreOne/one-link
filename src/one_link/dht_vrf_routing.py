"""VRF-routed DHT — eclipse-resistant lookup via verifiable random scoring.

Vanilla Kademlia (Bundle 36) ranks lookup candidates by raw XOR
distance to the target. An adversary who controls many node IDs
near the target can bias the routing: they pre-compute IDs that
sit close in XOR distance and reliably attract queries, eclipsing
honest nodes from the requester's view.

Standard hardening: **VRF-based scoring**. Instead of comparing
``XOR(target_id, candidate_id)``, the requester scores each
candidate by

    score = VRF(self_priv, target_id || candidate_id)

The score is:
  - **Pseudorandom** to anyone without the requester's secret key,
    so an adversary planning their node IDs cannot pre-bias
    against a specific target.
  - **Deterministic per (self_priv, target, candidate)**, so the
    requester's lookup is reproducible + auditable.
  - **Verifiable** by anyone with the requester's pubkey (the VRF
    proof comes alongside the score), so the candidate set the
    requester actually queried is publicly checkable.

This module wraps Bundle 36's RoutingTable + Bundle 47's VRF into
a routing primitive. The lookup loop in dht.py stays unchanged
(iterative_lookup with α + max_rounds + transport hook); we
substitute the candidate-ranking step.

API
---

  vrf_score_candidates(priv_seed, target_id, candidates) →
      list of (Contact, score, proof)
  vrf_routed_lookup(self_id, priv_seed, target_id, table,
                    rpc_find_node, ...) → LookupResult

The lookup returns the same shape as ``dht.iterative_lookup`` but
with the ordering driven by VRF scores instead of XOR distance.
The transport-side rpc_find_node hook is unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass

from one_link import dht, vrf


@dataclass(frozen=True)
class ScoredContact:
    contact: dht.Contact
    score: int           # 256-bit integer derived from the VRF output
    proof: bytes


def _score_to_int(out: bytes) -> int:
    """Convert a 32-byte VRF output to a 256-bit integer for ordering."""
    return int.from_bytes(out, "big")


def vrf_score_candidates(
    *,
    priv_seed: bytes,
    target_id: dht.NodeID,
    candidates: list[dht.Contact],
) -> list[ScoredContact]:
    """Score every candidate via VRF(priv_seed, target_id ||
    candidate_id). Returns the candidates with their scores +
    proofs, sorted by ascending score (lowest = "closest" by this
    metric)."""
    out: list[ScoredContact] = []
    for c in candidates:
        input_bytes = target_id.raw + c.id.raw
        v = vrf.prove(priv_seed=priv_seed, input_bytes=input_bytes)
        out.append(ScoredContact(
            contact=c, score=_score_to_int(v.output), proof=v.proof,
        ))
    out.sort(key=lambda s: s.score)
    return out


def verify_vrf_score(
    *,
    public_key: bytes,
    target_id: dht.NodeID,
    candidate_id: dht.NodeID,
    score: int,
    proof: bytes,
) -> bool:
    """Auditor-side: verify a (target, candidate, score, proof)
    tuple against the requester's pubkey. Returns True iff the
    score was correctly computed by the holder of the matching
    private key."""
    input_bytes = target_id.raw + candidate_id.raw
    expected_output = score.to_bytes(32, "big")
    return vrf.verify(
        public_key=public_key,
        input_bytes=input_bytes,
        output=expected_output,
        proof=proof,
    )


def vrf_routed_lookup(
    *,
    self_id: dht.NodeID,
    priv_seed: bytes,
    target_id: dht.NodeID,
    table: dht.RoutingTable,
    rpc_find_node,
    k: int = dht.DEFAULT_K,
    alpha: int = dht.DEFAULT_ALPHA,
    max_rounds: int = 20,
) -> dht.LookupResult:
    """Run an iterative DHT lookup but rank candidates by VRF score
    instead of XOR distance. Returns the top-K contacts by VRF
    score on convergence.

    The transport hook ``rpc_find_node(contact, target_id) →
    list[Contact]`` is unchanged from dht.iterative_lookup; the
    contacted nodes still return contacts they consider closest by
    XOR (since they don't know our priv_seed). We re-score the
    union of (our shortlist + their responses) by VRF on every
    round.

    Convergence: a round in which no newly-discovered candidate
    has a strictly smaller VRF score than the round's best
    queried node ends the lookup."""
    queried: set[dht.NodeID] = set()
    initial = list(table.find_closest(target_id, n=k * 2))
    if not initial:
        return dht.LookupResult(
            target_id=target_id, closest=[], queried=0,
        )
    scored = vrf_score_candidates(
        priv_seed=priv_seed, target_id=target_id, candidates=initial,
    )
    shortlist = scored[:k]
    best_score = shortlist[0].score

    for _ in range(max_rounds):
        candidates = [
            sc.contact for sc in shortlist
            if sc.contact.id not in queried and sc.contact.id != self_id
        ][:alpha]
        if not candidates:
            break
        new_contacts: list[dht.Contact] = []
        for c in candidates:
            queried.add(c.id)
            try:
                rsp = rpc_find_node(c, target_id) or []
            except Exception:
                rsp = []
            for rc in rsp:
                if rc.id == self_id:
                    continue
                new_contacts.append(rc)
                table.add(rc)
        # Re-score the union of (existing shortlist + new contacts).
        existing_ids = {sc.contact.id for sc in shortlist}
        all_contacts = [sc.contact for sc in shortlist]
        for nc in new_contacts:
            if nc.id not in existing_ids:
                all_contacts.append(nc)
                existing_ids.add(nc.id)
        rescored = vrf_score_candidates(
            priv_seed=priv_seed, target_id=target_id,
            candidates=all_contacts,
        )
        shortlist = rescored[:k]
        cur_best = shortlist[0].score
        if cur_best >= best_score and all(
            sc.contact.id in queried for sc in shortlist[:alpha]
        ):
            break
        best_score = min(best_score, cur_best)

    return dht.LookupResult(
        target_id=target_id,
        closest=[sc.contact for sc in shortlist],
        queried=len(queried),
    )
