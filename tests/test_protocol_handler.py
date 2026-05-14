import pytest

from one_link.protocol_handler import (
    local_ui_url_for_deep_link,
    peer_path_for_deep_link,
)


def test_self_mesh_enroll_deep_link_maps_to_peer_shell():
    token = "abc123_Invite-Token"
    path = peer_path_for_deep_link(
        f"one-link://self-mesh/enroll?token={token}"
    )
    assert path == f"/peer?self_mesh_invite={token}"


def test_self_mesh_enroll_deep_link_requires_token():
    with pytest.raises(ValueError, match="missing token"):
        peer_path_for_deep_link("one-link://self-mesh/enroll")


def test_unknown_deep_link_route_rejected():
    with pytest.raises(ValueError, match="unsupported"):
        peer_path_for_deep_link("one-link://files/open?x=1")


def test_self_mesh_enroll_rejects_malformed_token():
    with pytest.raises(ValueError, match="malformed"):
        peer_path_for_deep_link("one-link://self-mesh/enroll?token=bad%20token")


def test_self_mesh_enroll_rejects_oversized_token():
    token = "a" * 8193
    with pytest.raises(ValueError, match="malformed"):
        peer_path_for_deep_link(f"one-link://self-mesh/enroll?token={token}")


def test_local_ui_url_adds_auth_token():
    url = local_ui_url_for_deep_link(
        "one-link://self-mesh/enroll?token=invite-token-1234",
        port=8123,
        token="ui-token",
    )
    assert url == (
        "http://127.0.0.1:8123/peer?"
        "self_mesh_invite=invite-token-1234&t=ui-token"
    )
