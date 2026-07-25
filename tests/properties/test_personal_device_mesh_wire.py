"""Property and hostile-input coverage for personal-mesh command envelopes."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import HealthCheck, given, settings, strategies as st

from one_link.identity_dag import encode_device_cert
from one_link.personal_device_mesh import (
    MAX_REMOTE_INSTRUCTION_BYTES,
    RemoteInstruction,
    sign_remote_instruction,
    verify_remote_instruction,
)


_ROOT_PRIVATE = Ed25519PrivateKey.generate()
_ROOT_SEED = _ROOT_PRIVATE.private_bytes_raw()
_ROOT_PUBLIC = _ROOT_PRIVATE.public_key().public_bytes_raw()
_CONTROLLER_PRIVATE = Ed25519PrivateKey.generate()
_CONTROLLER_SEED = _CONTROLLER_PRIVATE.private_bytes_raw()
_CONTROLLER_PUBLIC = _CONTROLLER_PRIVATE.public_key().public_bytes_raw()
_TARGET_PUBLIC = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
_CONTROLLER_CERT = encode_device_cert(
    root_priv_seed=_ROOT_SEED,
    root_pub=_ROOT_PUBLIC,
    device_pub=_CONTROLLER_PUBLIC,
    device_kind="property-controller",
    added_ms=1_000,
)

_SAFE_TEXT = st.text(
    alphabet=st.characters(
        min_codepoint=0x20,
        max_codepoint=0x7E,
        blacklist_characters="\x7f",
    ),
    max_size=32,
)
_SAFE_KEY = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789_",
    min_size=1,
    max_size=20,
)
_JSON_VALUE = st.recursive(
    st.none() | st.booleans() | st.integers(min_value=-(2**63), max_value=2**63 - 1) | _SAFE_TEXT,
    lambda children: (
        st.lists(children, max_size=8) | st.dictionaries(_SAFE_KEY, children, max_size=8)
    ),
    max_leaves=40,
)
_SCOPE = st.dictionaries(_SAFE_KEY, _JSON_VALUE, max_size=10)


@settings(
    max_examples=250,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(scope=_SCOPE)
def test_remote_instruction_scope_round_trip_is_canonical(scope):
    wire = sign_remote_instruction(
        controller_device_seed=_CONTROLLER_SEED,
        controller_cert=_CONTROLLER_CERT,
        target_device_pub=_TARGET_PUBLIC,
        action="pull_file_manifest",
        scope=scope,
        created_ms=10_000,
        expires_ms=20_000,
        nonce=b"p" * 16,
    )

    parsed = verify_remote_instruction(
        wire,
        expected_root_pub=_ROOT_PUBLIC,
        expected_target_device_pub=_TARGET_PUBLIC,
        now_ms=15_000,
    )

    assert isinstance(parsed, RemoteInstruction)
    assert parsed.scope == scope
    assert parsed.encoded == wire


@settings(max_examples=500, deadline=None)
@given(st.binary(max_size=MAX_REMOTE_INSTRUCTION_BYTES + 1024))
def test_arbitrary_remote_instruction_bytes_fail_closed_without_crashing(wire):
    try:
        parsed = verify_remote_instruction(
            wire,
            expected_root_pub=_ROOT_PUBLIC,
            expected_target_device_pub=_TARGET_PUBLIC,
            now_ms=15_000,
        )
    except ValueError:
        return
    pytest.fail(f"arbitrary input unexpectedly verified: {parsed.command_id}")


@settings(max_examples=250, deadline=None)
@given(suffix=st.binary(min_size=1, max_size=32))
def test_canonical_wire_rejects_every_trailing_byte_sequence(suffix):
    wire = sign_remote_instruction(
        controller_device_seed=_CONTROLLER_SEED,
        controller_cert=_CONTROLLER_CERT,
        target_device_pub=_TARGET_PUBLIC,
        action="pull_file_manifest",
        scope={"path": "C:/safe/file.txt"},
        created_ms=10_000,
        expires_ms=20_000,
        nonce=b"p" * 16,
    )

    with pytest.raises(ValueError):
        verify_remote_instruction(
            wire + suffix,
            expected_root_pub=_ROOT_PUBLIC,
            expected_target_device_pub=_TARGET_PUBLIC,
            now_ms=15_000,
        )
