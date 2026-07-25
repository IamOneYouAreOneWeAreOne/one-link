"""Externally visible product copy must match the active network model."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _claim_text(relative: str) -> str:
    """Normalize Markdown/Rust doc-comment wrapping for copy assertions."""
    text = (
        _read(relative)
        .replace("//!", " ")
        .replace("///", " ")
        .replace("\n> ", "\n")
    )
    return " ".join(text.split())


def test_desktop_about_copy_discloses_optional_infrastructure() -> None:
    text = _read("src/one_link/web/index.html")

    assert "No account or central message store is" in text
    assert "Optional" in text and "rendezvous discovers routes" in text
    assert "an optional relay may carry" in text
    assert "No account, no server, no telemetry" not in text
    assert "Phones rely on the OS Secure Enclave" not in text
    assert "Recent instrumented outside events" in text
    assert "not proof that no network connection occurred" in text
    assert "hasn't made any outside connections since it started" not in text


def test_rendezvous_help_distinguishes_discovery_from_payload_relay() -> None:
    text = _read("src/one_link/web/index.html")

    assert "signed reachability records" in text
    assert "optional relay can carry end-to-end encrypted payloads" in text
    assert "It only carries signed presence beacons" not in text


def test_browser_peer_copy_discloses_metadata_and_route_limits() -> None:
    text = _read("src/one_link/web/peer.html")

    assert "connects directly over host or configured STUN-discovered" in text
    assert "This QR flow does not use One Link's relay" in text
    assert "if no direct route" in text and "it fails clearly" in text
    assert "meeting point sees presence and" in text
    assert "network metadata, but not plaintext messages, files, or private keys" in text
    assert "meeting point only knows you're" not in text
    assert "Chromium and Firefox are tested" in text
    assert "WebKit/Safari remains a" in text
    assert "Try Chrome / Edge / Safari 17+" not in text


def test_uncapped_setting_does_not_claim_infinite_bandwidth() -> None:
    text = _read("src/one_link/web/index.html")

    assert '<option value="0">No One Link cap</option>' in text
    assert '<option value="0">Unlimited</option>' not in text


def test_project_home_does_not_claim_unmeasured_demo_coverage() -> None:
    text = " ".join(_read("README.md").split())

    assert "demonstrations of selected primitives" in text
    assert "demos of every cryptographic primitive" not in text


def test_public_site_metadata_discloses_route_and_infrastructure_limits() -> None:
    text = " ".join(_read("docs/site/index.html").split())

    assert "no account or central message store" in text
    assert "connect directly when routes permit" in text
    assert "optional discovery and encrypted relay infrastructure" in text
    assert "No accounts, no servers, no cloud" not in text
    assert "talk directly" not in text


def test_public_invite_landing_does_not_make_absolute_no_cloud_claim() -> None:
    text = " ".join(_read("src/one_link/server.py").split())

    assert "needs no account or central message store" in text
    assert "Optional discovery and encrypted relay infrastructure" in text
    assert "No accounts, no tracking, no cloud" not in text


def test_packaging_metadata_discloses_optional_connectivity_services() -> None:
    linux = _read("packaging/linux/one-link.desktop")
    windows = _read("packaging/windows/one-link.iss")
    manifest = _read("src/one_link/web/manifest.json")
    project = _read("pyproject.toml")

    for text in (linux, windows):
        normalized = text.lower()
        assert "no required account" in normalized
        assert "direct-first with optional discovery and relay" in normalized
        assert "no servers" not in normalized

    manifest_normalized = manifest.lower()
    assert "optional discovery and relay services" in manifest_normalized
    assert "no required account or product analytics" in manifest_normalized
    assert "no server" not in manifest_normalized
    assert "Direct-first encrypted chat, calls, resilient file transfer" in project
    assert "optional discovery and relay" in project


def test_license_charter_and_contributor_policy_disclose_network_services() -> None:
    notice = " ".join(_read("NOTICE").split())
    contributing = " ".join(_read("CONTRIBUTING.md").split())

    assert "requires no user account and ships no product analytics" in notice
    assert "optional discovery and encrypted relay services" in notice
    assert "necessarily process the network metadata" in notice
    assert "never receives message/file plaintext or end-to-end keys" in notice
    assert "presence, address, timing, size, and route metadata" in notice
    assert "without servers" not in notice
    assert "There is no user data on any server" not in notice
    assert "No product analytics, advertising telemetry" in contributing
    assert "user-configured discovery/relay" in contributing
    assert "covert phone-home" in contributing
    assert "phone-home of any kind" not in contributing


def test_install_verification_copy_does_not_treat_local_hash_as_authenticity() -> None:
    text = " ".join(_read("src/one_link/web/index.html").lower().split())

    assert "local hashes alone do not prove authenticity" in text
    assert "--expected-rollup" in text
    assert "wildcard publisher identities are never accepted" in text
    assert "verify the binary is exactly what we published" not in text


def test_pairing_copy_matches_the_active_daemon_ceremony() -> None:
    text = " ".join(_read("README.md").split())

    assert "transcript-bound five-word safety phrase" in text
    assert "current pairing path uses ML-DSA" in text
    assert "Pair-by-QR with Ed25519+ML-DSA hybrid signatures" not in text
    assert "numeric value remains visible only" in text

    setup = " ".join(_read("docs/ONE_SETUP_FIRST_RUN_EXPERIENCE.md").split())
    phone = " ".join(_read("docs/PHONE_TIER.md").split())
    assert "five-word transcript-bound safety phrase" in setup
    assert "Both devices should show the same five words" in setup
    assert "six-digit SAS" not in setup
    assert "Codes match" not in setup
    assert "Five-word transcript-bound SAS" in phone
    assert "mixed-version peer" in phone
    assert "6-digit SAS digits" not in phone


def test_public_site_scopes_at_rest_and_telemetry_badges() -> None:
    text = _read("docs/site/index.html")

    assert "SQLCipher state DB by default" in text
    assert "no product analytics" in text
    assert "at-rest encryption by default" not in text


def test_desktop_truth_matrix_does_not_promote_scaffolds() -> None:
    text = _read("src/one_link/web/index.html")

    assert 'api.get("/api/audit"' in text
    assert "audit?.feature_truth" in text
    assert "Runtime truth unavailable" in text
    assert "const TRUTH_MATRIX" not in text

    from one_link.server import _feature_truth_matrix

    rows = {row["id"]: row for row in _feature_truth_matrix()}
    for feature_id in (
        "browser_peer", "pq_kem", "mls", "onion", "sealed_sender",
        "cover_frames", "updates", "filesystem_mount",
    ):
        assert feature_id in rows

    assert rows["pq_kem"]["name"] == "Hybrid post-quantum peer channel"
    assert rows["pq_kem"]["ui_exposed"] == "partial"
    assert rows["quic"]["name"] == "Native QUIC file lanes"
    assert "does not replace the daemon control/message channel" in rows["quic"][
        "limitation"
    ]
    assert rows["mls"]["name"] == "MLS groups"
    assert rows["mls"]["daemon_wired"] == "absent"
    assert rows["sealed_sender"]["name"] == "Pairwise-blinded relay first flights"
    assert rows["sealed_sender"]["ui_exposed"] == "absent"
    assert rows["sealed_sender"]["runtime"]["status"] == "not_observed"
    assert "not sender anonymity or traffic-analysis resistance" in rows[
        "sealed_sender"
    ]["limitation"]
    assert rows["cover_frames"]["name"] == "Cover-frame emission (not traffic shaping)"
    assert rows["cover_frames"]["daemon_wired"] == "partial"
    assert "not proof of an anonymity system" in rows["cover_frames"]["limitation"]
    assert rows["onion"]["name"] == "Onion/Sphinx routing"
    assert rows["onion"]["daemon_wired"] == "absent"
    assert rows["browser_peer"]["name"] == "Direct browser peer"
    assert rows["updates"]["name"] == "Authenticated one-click transactional updates"
    assert "Unattended/background automatic installation remains disabled" in rows[
        "updates"
    ]["limitation"]
    assert "Source, pip, development, incomplete, moved, or modified installs fail" in rows[
        "updates"
    ]["limitation"]
    assert rows["filesystem_mount"]["primitive_proven"] == "proven"
    assert rows["filesystem_mount"]["ui_exposed"] == "partial"
    assert "Windows WinFsp/Dokan and macOS FSKit adapters are not implemented" in rows[
        "filesystem_mount"
    ]["limitation"]


def test_browser_double_ratchet_primitive_is_not_claimed_as_live_wiring() -> None:
    module = _read("src/one_link/web/dr.js")
    peer = _read("src/one_link/web/peer.html")
    desktop = _read("src/one_link/web/index.html")
    server = _read("src/one_link/server.py")

    assert "standalone primitive and self-test dependency" in module
    assert "browser-as-peer DataChannels do NOT inherit" in module
    assert "repository presence is not a WebKit" in module
    assert "This module closes that gap" not in module
    assert "Safari 17+" not in module
    assert 'from "./dr.js"' not in peer
    assert 'from "./dr.js"' not in desktop
    assert "the active peer shells do not" in server
    assert "self-test-only rather than imported by peer.html/index.html" in server


def test_public_claims_preserve_implemented_relay_pq_browser_and_update_scope() -> None:
    readme = " ".join(_read("README.md").split())
    site = " ".join(_read("docs/site/index.html").split())
    architecture = " ".join(_read("docs/ARCHITECTURE.md").split())
    mesh = " ".join(_read("docs/COHERENCE_MESH_PLAN.md").split())

    for text in (readme, site):
        assert "rotating pairwise" in text
        assert "identity" in text and "first flights" in text
        assert "timing" in text and "size" in text
        assert "ML-KEM-768" in text
        assert "browser/WebRTC" in text
        assert "one-click transactional installation" in text
        assert "frozen standalone bundle" in text
        assert "Unattended/background" in text
        assert "installation remains disabled" in text

    assert "no live message/file path uses onion routing" in readme.lower()
    assert "not sender anonymity" in architecture
    assert "no live message/file route" in mesh
    assert "mix-net" in architecture and "not implemented" in architecture


def test_alpha_warning_and_version_help_do_not_invent_an_installer() -> None:
    text = " ".join(_read("src/one_link/web/index.html").split())

    assert "No verified public installer is currently available" in text
    assert "source availability alone does not authenticate the bytes" in text
    assert "latest installer" not in text.lower()
    assert "no company has the power to revoke your right" not in text


def test_cli_help_scopes_file_size_and_network_audit() -> None:
    text = " ".join(_read("src/one_link/cli.py").split())

    assert "disk, filesystem, memory, transport, route, and peer-policy" in text
    assert "Send a file to PEER. Any size." not in text
    assert "This inventory is not a packet-capture attestation" in text


def test_current_status_docs_mark_roadmap_and_mount_boundaries() -> None:
    sovereignty = " ".join(_read("docs/SOVEREIGNTY.md").split())
    mesh = " ".join(_read("docs/COHERENCE_MESH_PLAN.md").split())
    engine = " ".join(_read("docs/FILE_ENGINE_V2_PLAN.md").split())

    assert "roadmap/design specification; not a current capability inventory" in sovereignty
    assert "signed, key-confirmed v3 X25519 + ML-KEM-768 handshake" in mesh
    assert "migration override and is reported as non-PQ" in mesh
    assert "does **not** establish" in mesh
    assert "post-quantum signatures/identity" in mesh
    assert "macOS FSKit and Windows WinFsp/Dokan adapters are unimplemented" in engine
    assert "| `ol_fuse` | partial; Linux app binding implemented |" in engine
    assert "Packaged `/dev/fuse`" in engine


def test_plans_and_history_do_not_read_as_current_network_proof() -> None:
    root_roadmap = " ".join(_read("ROADMAP.md").split())
    changelog = " ".join(_read("CHANGELOG.md").split())
    engine = " ".join(_read("docs/FILE_ENGINE_V2_PLAN.md").split())
    quic_adr = " ".join(_read("docs/decisions/0009-quic-transport.md").split())
    mesh = " ".join(_read("docs/COHERENCE_MESH_PLAN.md").split())

    assert "this is a target roadmap, not release evidence" in root_roadmap
    assert "historical source snapshot" in root_roadmap.lower()
    assert "do not establish a whole-session cutover" in changelog
    assert "Current boundary:" in engine
    assert "has not replaced the daemon control/message channel" in engine
    assert "not proof that every listed property is active" in quic_adr
    assert "there's no metadata to hide" not in mesh
    assert "Onion routing hides who-talks-to-whom" not in mesh


def test_readme_matches_current_ui_and_standalone_bundle_contracts() -> None:
    text = _read("README.md")
    normalized = " ".join(text.split())

    assert "`http://127.0.0.1:7117`" in text
    assert "`http://127.0.0.1:8765`" not in text
    assert "one-link.app/Contents/MacOS/one-link" in text
    macos_row = next(
        line for line in text.splitlines() if line.startswith("| macOS | arm64")
    )
    assert "chmod +x one-link/one-link && ./one-link/one-link" not in macos_row

    assert (
        "plain loopback HTTP authenticates API calls with an origin-scoped Bearer"
        in normalized
    )
    assert (
        "Owner cookies are accepted only when the live request transport is TLS"
        in normalized
    )
    assert "Explicit `one-link app --lan` mode" in normalized
    assert (
        "remote plaintext requests cannot use owner Bearer/session credentials"
        in normalized
    )
    assert "The daemon does not listen on any external interface for HTTP" not in text


def test_native_onion_documents_do_not_promote_packet_primitives_to_anonymity() -> None:
    design = _claim_text("native/ol_onion/SPHINX_COHERENCE_DESIGN.md")
    onion = _claim_text("native/ol_onion/src/lib.rs")
    sphinx_cover = _claim_text("native/ol_onion/src/sphinx/cover.rs")
    nested_cover = _claim_text("native/ol_onion/src/cover.rs")
    pq = _claim_text("native/ol_onion/src/sphinx/pq.rs")
    field = _claim_text("native/ol_onion/src/sphinx/field.rs")
    bindings = _claim_text("native/one_link_native/src/lib.rs")

    assert "does **not** contain a live One Link" in design
    assert "**Not defeated.** Alpha blinding" in design
    assert "must not claim that this stack defeats every" in design
    assert "defeats every known onion-routing attack class" not in design
    assert "posterior over \"who's talking to whom\"" not in design
    assert "not forward secrecy against later" in onion
    assert "cover primitives do not" in onion
    assert "does not close that correlation gap" in sphinx_cover
    assert "does not establish" in nested_cover
    assert "observer sees no signal" not in sphinx_cover.lower()
    assert "changing_pq_component_changes_hybrid_output" in pq
    assert "quantum_adversary_cannot_reproduce" not in pq
    assert "public or low-entropy field digest" in field
    assert "do not defeat a global observer" in bindings


def test_native_field_confidential_and_duress_copy_states_real_boundaries() -> None:
    threshold = _claim_text("native/ol_threshold_recovery/src/lib.rs")
    threshold_impl = _claim_text("native/ol_threshold_recovery/src/field_bound.rs")
    confidential = _claim_text("native/ol_confidential/README.md")
    confidential_lib = _claim_text("native/ol_confidential/src/lib.rs")
    attestation = _claim_text("native/ol_confidential/src/attestation.rs")
    windows_tpm = _claim_text("native/ol_confidential/src/windows_tpm.rs")
    duress = _claim_text("native/ol_duress/src/lib.rs")

    assert "separately generated, CSPRNG-grade secret binding key" in threshold
    assert "does not make brute force impossible" in threshold
    assert "public field-solver output is context" in threshold_impl
    assert "does not place the daemon" in confidential
    assert "master identity inside an enclave" in confidential
    assert "same-user malware able to inspect/inject" in confidential.lower()
    assert "does not place the One Link daemon inside" in confidential_lib
    assert "provider tag is self-asserted" in attestation.lower()
    assert "not physical origin" in attestation
    assert "no EK/vendor certificate or standard TPM quote" in windows_tpm
    assert "does not provide plausible deniability" in duress
    assert "does not place it on a wire" in duress


def test_native_crypto_copy_does_not_turn_conditional_invariants_into_proofs() -> None:
    aead = _claim_text("native/ol_aead/src/nonce.rs")
    ratchet = _claim_text("native/ol_ratchet/src/lib.rs")
    device_mesh = _claim_text("native/ol_device_mesh/src/lib.rs")
    pqkem = _claim_text("native/ol_pqkem/src/lib.rs")
    pqsig = _claim_text("native/ol_pqsig/src/lib.rs")

    assert "64-bit prefix can collide" in aead
    assert "reuse-impossible by design" not in aead
    assert "Replay is out of scope" in ratchet
    assert "replays decrypt as garbage" not in ratchet
    assert "does not guarantee device-count privacy" in device_mesh
    assert "does not inherit the X-Wing" in pqkem
    assert "Repository presence does not make every daemon" in pqkem
    assert "does not mean current One Link daemon" in pqsig

    aead_adr = _claim_text("docs/decisions/0002-aead-frame.md")
    assert "64-bit chunk prefix is not globally unique" in aead_adr
    assert "reuse as impossible" in aead_adr
    assert "Reuse-impossible by construction" not in aead_adr


def test_updater_copy_matches_the_qualified_manual_handoff_boundary() -> None:
    server = _claim_text("src/one_link/server.py")
    ui = _claim_text("src/one_link/web/index.html")
    documents = (
        "README.md",
        "ROADMAP.md",
        "docs/ROADMAP.md",
        "docs/SOVEREIGNTY.md",
        "docs/site/index.html",
        "docs/UX_AUDIT_2026-05-17.md",
        "docs/TRANSFER_RELIABILITY_AUDIT_2026-07-21.md",
    )

    assert "Authenticated one-click transactional updates" in server
    assert "complete local frozen bundle" in server
    assert "Unattended/background automatic installation remains disabled" in server
    assert "Install verified update" in ui
    assert "qualifying frozen bundle" in ui
    assert "Background installation is unavailable" in ui
    assert "in-place replacement is unavailable" not in ui

    for relative in documents:
        text = _claim_text(relative)
        assert "owner-confirmed" in text, relative
        assert "frozen" in text and "bundle" in text, relative
        assert "unattended/background" in text.lower(), relative
        assert "automatic installation remains" in text.lower(), relative


def test_python_primitive_docs_do_not_promote_scaffolds_to_live_guarantees() -> None:
    onion = _claim_text("src/one_link/onion_native.py")
    dht = _claim_text("src/one_link/dht.py")
    compat = _claim_text("src/one_link/protocol_compat.py")
    discovery = _claim_text("src/one_link/lan_discovery.py")
    threshold = _claim_text("src/one_link/threshold_recovery_native.py")
    confidential = _claim_text("src/one_link/confidential_native.py")
    ui = _claim_text("src/one_link/web/index.html")

    assert "No active One Link daemon message or file route" in onion
    assert "one encoded length" in onion
    assert "Hop count and payload size are invisible" not in onion
    assert "not the current product rendezvous path" in dht
    assert "decentralization does not imply no operators or no logs" in dht
    assert "contained plumbing change" in dht
    assert "different versions ALWAYS work" not in compat
    assert "not proof that arbitrary historical/future builds" in compat
    assert "No discovery method can enumerate every local device" in discovery
    assert "not packet-capture proof" in discovery
    assert "finds EVERY device" not in discovery
    assert "best-effort local scan" in ui
    assert "Send an invite to any device" not in ui
    assert "public field output is context, not secret entropy" in threshold
    assert "binding_key = secrets.token_bytes(32)" in threshold
    assert "same-user malware able to inspect or inject" in confidential
    assert "no EK/vendor certificate chain or standard TPM quote" in confidential
    assert "provider tag alone is self-asserted" in confidential
    assert "hold the master inside a hardware secure element" not in confidential

    sphinx = _claim_text("src/one_link/sphinx_native.py")
    cover = _claim_text("src/one_link/cover_traffic.py")
    layered = _claim_text("src/one_link/onion.py")
    shamir = _claim_text("src/one_link/threshold.py")
    assert "No active One Link message/file route uses this adapter" in sphinx
    assert "no whole-route post-quantum proof" in sphinx
    assert "does not prove indistinguishability" in sphinx
    assert "It does not schedule or shape real traffic" in sphinx
    assert "does not shape normal message/file traffic" in cover
    assert "not an anonymity guarantee" in cover
    assert "No active One Link daemon message/file route imports this module" in layered
    assert "does not by itself establish that no operator sees both endpoints" in layered
    assert "pure-Python implementation is not constant-time" in shamir
    assert "not a formal zero-knowledge proof" in shamir
    assert "cannot detect too few otherwise well-formed shares" in shamir

    wire = _claim_text("docs/WIRE_COMPATIBILITY.md")
    assert "not proof that any two historical or future builds interoperate" in wire
    assert "not end-to-end proof" in wire
    assert "Any two One Link builds can always" not in wire
