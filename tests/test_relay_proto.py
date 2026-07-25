"""Unit tests for the relay wire protocol (`one_link.relay_proto`)."""
from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.relay_proto import (
    DATA_FRAME_MAX_BYTES,
    FRAME_CLOSE,
    FRAME_DATA,
    REPLAY_WINDOW_MS,
    SESSION_ID_BYTES,
    ListenAuth,
    bounded_json_loads,
    decode_frame,
    encode_close_frame,
    encode_data_frame,
    make_incoming_msg,
    make_ready_msg,
    make_session_closed_msg,
    new_session_id,
    parse_session_id_from_msg,
    sign_listen_auth,
    timestamp_within_replay_window,
)


def _new_key() -> tuple[Ed25519PrivateKey, bytes]:
    sk = Ed25519PrivateKey.generate()
    return sk, sk.public_key().public_bytes_raw()


def test_bounded_json_parser_rejects_ambiguity_and_resource_bombs():
    assert bounded_json_loads('{"t":"ready","session_id":"0011223344556677"}') == {
        "t": "ready",
        "session_id": "0011223344556677",
    }
    with pytest.raises(ValueError, match="duplicate"):
        bounded_json_loads('{"t":"ready","t":"incoming"}')
    with pytest.raises(ValueError, match="nesting"):
        bounded_json_loads("[" * 65 + "0" + "]" * 65)
    with pytest.raises(ValueError, match="non-finite"):
        bounded_json_loads('{"value":NaN}')


# ─── ListenAuth sign/verify ────────────────────────────────────────

def test_listen_auth_sign_and_verify_round_trip():
    sk, pk = _new_key()
    auth = sign_listen_auth(private_key=sk, pubkey=pk)
    auth.verify()


def test_listen_auth_rejects_tampered_pubkey():
    sk1, pk1 = _new_key()
    _, pk2 = _new_key()
    auth = sign_listen_auth(private_key=sk1, pubkey=pk1)
    auth.pubkey = pk2
    with pytest.raises(ValueError, match="signature"):
        auth.verify()


def test_listen_auth_rejects_tampered_timestamp():
    sk, pk = _new_key()
    auth = sign_listen_auth(private_key=sk, pubkey=pk, timestamp_ms=1_700_000_000_000)
    auth.timestamp_ms = 1_800_000_000_000
    with pytest.raises(ValueError, match="signature"):
        auth.verify()


def test_listen_auth_rejects_tampered_nonce():
    sk, pk = _new_key()
    auth = sign_listen_auth(private_key=sk, pubkey=pk)
    auth.nonce = b"\x00" * 16
    with pytest.raises(ValueError, match="signature"):
        auth.verify()


def test_listen_auth_rejects_signature_from_other_key():
    sk1, _ = _new_key()
    _, pk2 = _new_key()
    with pytest.raises(ValueError, match="does not match"):
        sign_listen_auth(private_key=sk1, pubkey=pk2)


# ─── ListenAuth wire round-trip ────────────────────────────────────

def test_listen_auth_to_wire_and_back():
    sk, pk = _new_key()
    auth = sign_listen_auth(private_key=sk, pubkey=pk)
    parsed = ListenAuth.from_wire(json.loads(json.dumps(auth.to_wire())))
    parsed.verify()
    assert parsed.pubkey == pk


def test_listen_auth_rejects_wrong_protocol_version():
    sk, pk = _new_key()
    auth = sign_listen_auth(private_key=sk, pubkey=pk)
    wire = auth.to_wire()
    wire["v"] = "OL-RELAY-99"
    with pytest.raises(ValueError, match="protocol version"):
        ListenAuth.from_wire(wire)


def test_listen_auth_rejects_wrong_type():
    sk, pk = _new_key()
    auth = sign_listen_auth(private_key=sk, pubkey=pk)
    wire = auth.to_wire()
    wire["t"] = "register"
    with pytest.raises(ValueError, match="type"):
        ListenAuth.from_wire(wire)


def test_listen_auth_rejects_wrong_pubkey_length():
    sk, pk = _new_key()
    auth = sign_listen_auth(private_key=sk, pubkey=pk)
    wire = auth.to_wire()
    wire["pubkey_b64"] = wire["pubkey_b64"][:8]  # truncated
    with pytest.raises(ValueError):
        ListenAuth.from_wire(wire)


def test_listen_auth_rejects_wrong_nonce_length():
    sk, pk = _new_key()
    auth = sign_listen_auth(private_key=sk, pubkey=pk)
    wire = auth.to_wire()
    wire["nonce_b64"] = "AAAA"  # 3 bytes decoded
    with pytest.raises(ValueError, match="nonce"):
        ListenAuth.from_wire(wire)


# ─── frame encoding ────────────────────────────────────────────────

def test_data_frame_round_trip():
    sid = new_session_id()
    payload = b"hello"
    raw = encode_data_frame(sid, payload)
    parsed = decode_frame(raw)
    assert parsed.type == FRAME_DATA
    assert parsed.session_id == sid
    assert parsed.payload == payload


def test_close_frame_round_trip():
    sid = new_session_id()
    raw = encode_close_frame(sid)
    parsed = decode_frame(raw)
    assert parsed.type == FRAME_CLOSE
    assert parsed.session_id == sid
    assert parsed.payload == b""


def test_decode_rejects_unknown_type():
    sid = new_session_id()
    raw = bytes([0x99]) + sid
    with pytest.raises(ValueError, match="frame type"):
        decode_frame(raw)


def test_decode_rejects_short_frame():
    with pytest.raises(ValueError, match="too short"):
        decode_frame(b"\x01")  # type byte but no session_id


def test_decode_rejects_close_with_payload():
    sid = new_session_id()
    raw = bytes([FRAME_CLOSE]) + sid + b"payload"
    with pytest.raises(ValueError, match="close frame"):
        decode_frame(raw)


def test_encode_data_rejects_oversize_payload():
    sid = new_session_id()
    with pytest.raises(ValueError, match="too large"):
        encode_data_frame(sid, b"\x00" * (DATA_FRAME_MAX_BYTES + 1))


def test_encode_rejects_wrong_session_id_length():
    with pytest.raises(ValueError, match="session_id"):
        encode_data_frame(b"\x00" * 4, b"hi")
    with pytest.raises(ValueError, match="session_id"):
        encode_close_frame(b"\x00" * 4)


def test_decode_rejects_oversize_data_payload():
    """Server already truncates at WS layer, but defense-in-depth
    here catches anything that slipped through."""
    sid = new_session_id()
    raw = bytes([FRAME_DATA]) + sid + b"\x00" * (DATA_FRAME_MAX_BYTES + 1)
    with pytest.raises(ValueError, match="too large"):
        decode_frame(raw)


# ─── session ids ───────────────────────────────────────────────────

def test_new_session_id_correct_length():
    assert len(new_session_id()) == SESSION_ID_BYTES


def test_new_session_ids_are_unique_in_practice():
    """Birthday-paradox is ~2^32 for 8-byte IDs, so 1000 IDs almost
    surely don't collide. Test pins this."""
    ids = {new_session_id() for _ in range(1000)}
    assert len(ids) == 1000


# ─── control message helpers ───────────────────────────────────────

def test_control_message_round_trip():
    sid = new_session_id()
    inc = make_incoming_msg(sid)
    closed = make_session_closed_msg(sid)
    ready = make_ready_msg(sid)
    assert parse_session_id_from_msg(inc) == sid
    assert parse_session_id_from_msg(closed) == sid
    assert parse_session_id_from_msg(ready) == sid


def test_parse_session_id_rejects_wrong_length():
    with pytest.raises(ValueError):
        parse_session_id_from_msg({"t": "incoming", "session_id": "abcd"})


def test_parse_session_id_rejects_non_hex():
    with pytest.raises(ValueError):
        parse_session_id_from_msg({"t": "incoming", "session_id": "z" * 16})


def test_listen_auth_rejects_unknown_missing_and_padded_fields():
    sk, pk = _new_key()
    baseline = sign_listen_auth(private_key=sk, pubkey=pk).to_wire()

    unknown = dict(baseline, ignored="parser-confusion")
    with pytest.raises(ValueError, match="fields invalid"):
        ListenAuth.from_wire(unknown)

    missing = dict(baseline)
    del missing["nonce_b64"]
    with pytest.raises(ValueError, match="fields invalid"):
        ListenAuth.from_wire(missing)

    for field in ("pubkey_b64", "nonce_b64", "signature"):
        padded = dict(baseline)
        padded[field] += "="
        with pytest.raises(ValueError, match=field if field != "nonce_b64" else "nonce"):
            ListenAuth.from_wire(padded)


def test_listen_auth_rejects_boolean_and_out_of_range_timestamps():
    sk, pk = _new_key()
    baseline = sign_listen_auth(private_key=sk, pubkey=pk).to_wire()
    for timestamp in (True, -1, 1 << 63, "123"):
        wire = dict(baseline)
        wire["timestamp_ms"] = timestamp
        with pytest.raises(ValueError, match="timestamp_ms"):
            ListenAuth.from_wire(wire)


def test_control_message_parser_rejects_ambiguous_schema_and_type():
    sid_hex = new_session_id().hex()
    with pytest.raises(ValueError, match="fields invalid"):
        parse_session_id_from_msg(
            {"t": "incoming", "session_id": sid_hex, "ignored": True}
        )
    with pytest.raises(ValueError, match="control type"):
        parse_session_id_from_msg({"t": "surprise", "session_id": sid_hex})
    with pytest.raises(ValueError, match="lowercase"):
        parse_session_id_from_msg({"t": "incoming", "session_id": sid_hex.upper()})


def test_frame_encoders_reject_coercive_types():
    sid = new_session_id()
    with pytest.raises(ValueError, match="session_id"):
        encode_data_frame(bytearray(sid), b"payload")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="payload"):
        encode_data_frame(sid, bytearray(b"payload"))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="session_id"):
        make_ready_msg(bytearray(sid))  # type: ignore[arg-type]


def test_relay_replay_window_fails_closed_on_invalid_inputs():
    now = 1_700_000_000_000
    assert not timestamp_within_replay_window(True, server_now_ms=now)
    assert not timestamp_within_replay_window(str(now), server_now_ms=now)  # type: ignore[arg-type]
    assert not timestamp_within_replay_window(now, server_now_ms=True)
    assert not timestamp_within_replay_window(now, server_now_ms=now, window_ms=-1)


# ─── replay window ─────────────────────────────────────────────────

def test_replay_window_accepts_recent():
    now = 1_700_000_000_000
    assert timestamp_within_replay_window(now - 1_000, server_now_ms=now)
    assert timestamp_within_replay_window(now + 1_000, server_now_ms=now)


def test_replay_window_rejects_old():
    now = 1_700_000_000_000
    assert not timestamp_within_replay_window(
        now - REPLAY_WINDOW_MS - 1, server_now_ms=now
    )


def test_replay_window_rejects_future():
    now = 1_700_000_000_000
    assert not timestamp_within_replay_window(
        now + REPLAY_WINDOW_MS + 1, server_now_ms=now
    )
