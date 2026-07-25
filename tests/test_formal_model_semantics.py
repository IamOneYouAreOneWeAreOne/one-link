"""Executable-semantics regressions for the repaired TLA+ models."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from scripts.run_formal_models import (
    TLC_SUCCESS_MARKER,
    Manifest,
    load_manifest,
    run_models,
)


ROOT = Path(__file__).resolve().parents[1]
FORMAL = ROOT / "docs" / "formal"
MANIFEST_PATH = FORMAL / "models.json"
REPAIRED_MODEL_IDS = {
    "confidential-attestation",
    "device-mesh-self-routing",
    "device-mesh-state",
    "onion",
    "pair-qr",
}


def _read(name: str) -> str:
    return (FORMAL / name).read_text(encoding="utf-8")


def test_repaired_models_use_canonical_module_and_config_names() -> None:
    manifest = load_manifest(MANIFEST_PATH)
    files = {
        model.model_id: (model.spec.name, model.config.name)
        for model in manifest.models
        if model.model_id in REPAIRED_MODEL_IDS
    }
    assert files == {
        "confidential-attestation": (
            "ConfidentialAttestation.tla",
            "ConfidentialAttestation.cfg",
        ),
        "device-mesh-self-routing": (
            "DeviceMeshSelfRouting.tla",
            "DeviceMeshSelfRouting.cfg",
        ),
        "device-mesh-state": ("DeviceMeshState.tla", "DeviceMeshState.cfg"),
        "onion": ("Onion.tla", "Onion.cfg"),
        "pair-qr": ("PairQr.tla", "PairQr.cfg"),
    }
    assert not (FORMAL / "confidential_attestation.tla").exists()
    assert not (FORMAL / "confidential_attestation.cfg").exists()


def test_attestation_deadline_and_nonce_invariants_are_non_vacuous() -> None:
    spec = _read("ConfidentialAttestation.tla")
    config = _read("ConfidentialAttestation.cfg")
    assert "EXTENDS Naturals, Sequences, FiniteSets, TLC" in spec
    assert spec.index('NoWitness == "NoWitness"') < spec.index("Docs ==")
    assert "acc[3] <= acc[2].deadline" in spec
    assert "acc[1] = v /\\ acc[2].nonce = d.nonce" in spec
    assert "d.signer = d.master" in spec
    assert "InjectForgedAttestation" in spec
    assert "claimed /= signer" in spec
    assert "Cardinality(issued_docs) < Cardinality(DocSlots)" in spec
    assert "Quiesce" in spec
    assert "TypeOK" in config
    assert "MAX_TIME        = 2" in config


def test_routing_model_parenthesizes_domains_and_breaks_timestamp_ties() -> None:
    spec = _read("DeviceMeshSelfRouting.tla")
    assert "0 .. NowUnix * 2" not in spec
    assert "Devices \\X (0 .. (NowUnix * 2)) \\X (0 .. MaxTau)" in spec
    assert "AnnouncementDominates(ann, prior)" in spec
    assert "/\\ ann[2] = prior[2]" in spec
    assert "/\\ ann[3] > prior[3]" in spec
    assert "Cardinality(ann_pool) < Cardinality(AnnPool)" in spec
    assert "accepted_b" in spec[spec.index("DominanceMonotone ==") :]


def test_mesh_state_has_finite_replay_and_typed_tuple_domains() -> None:
    spec = _read("DeviceMeshState.tla")
    config = _read("DeviceMeshState.cfg")
    tuple_domain = "SUBSET (Devices \\X (1 .. MaxSeq))"
    assert spec.count(tuple_domain) == 2
    assert spec.count("Len(network) < Cardinality(OpsPool)") == 2
    assert "SignatureRequired ==" in spec
    assert "op[2] \\in 1 .. local_max_seq[op[1]]" in spec
    assert "SignatureRequired" in config


def test_onion_model_uses_an_executable_fixed_three_relay_circuit() -> None:
    spec = _read("Onion.tla")
    config = _read("Onion.cfg")
    assert "<<\\E" not in spec
    assert "Hops == {Relay1, Relay2, Relay3, Destination}" in spec
    assert "NextHop(h) ==" in spec
    assert 'peeled[at_hop] = "None"' in spec
    assert 'peeled[Destination] = "None"' in spec
    assert "TypeOK" in config
    for name in ("Relay1", "Relay2", "Relay3", "Destination"):
        assert name in config


def test_pairing_model_binds_each_response_to_its_issuing_inviter() -> None:
    spec = _read("PairQr.tla")
    assert "Unknown operator" not in spec
    assert "inviter_invite \\in [Inviters -> Invites]" in spec
    assert "inv = inviter_invite[i]" in spec
    assert "scanner_has_scanned" in spec
    assert (
        'ScannerStates == {"AwaitingConfirm", "Done", "Aborted"}'
        in spec
    )
    assert "\\E inv \\in Invites, s \\in Scanners, t \\in" not in spec
    assert "\\E i \\in Inviters, inv \\in Invites, s \\in Scanners, t \\in" not in spec


@pytest.mark.skipif(
    not os.environ.get("ONE_LINK_TLA2TOOLS_JAR"),
    reason="set ONE_LINK_TLA2TOOLS_JAR to run the pinned TLC integration gate",
)
def test_repaired_models_complete_under_authorized_tlc(tmp_path: Path) -> None:
    """Run the exact five models when the pinned jar is provisioned locally."""

    manifest = load_manifest(MANIFEST_PATH)
    selected = tuple(
        model for model in manifest.models if model.model_id in REPAIRED_MODEL_IDS
    )
    assert len(selected) == len(REPAIRED_MODEL_IDS)
    scoped = Manifest(
        path=manifest.path,
        formal_dir=manifest.formal_dir,
        tool=manifest.tool,
        models=selected,
    )
    summary = run_models(
        scoped,
        jar=Path(os.environ["ONE_LINK_TLA2TOOLS_JAR"]),
        java=os.environ.get("ONE_LINK_JAVA", "java"),
        output_dir=tmp_path / "evidence",
        workers=2,
        repo_root=ROOT,
    )
    assert summary["status"] == "passed"
    assert {row["id"] for row in summary["models"]} == REPAIRED_MODEL_IDS
    for row in summary["models"]:
        assert row["status"] == "passed"
        assert row["success_marker"] is True
        log = (tmp_path / "evidence" / row["log"]).read_text(encoding="utf-8")
        assert TLC_SUCCESS_MARKER in log
