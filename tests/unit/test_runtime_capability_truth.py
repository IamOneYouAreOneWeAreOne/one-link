"""Runtime capability frames must not advertise unavailable native paths."""

from one_link import bloom_init, native_transfer, peer_quic
from one_link.capabilities import (
    BLOOM_INIT_EXACT_V2,
    BLOOM_INIT_V1,
    NATIVE_TRANSFER_INDEXED_V1,
    QUIC_TRANSPORT_V1,
    advertised_capabilities,
)


def test_native_backed_capabilities_match_authenticated_runtime() -> None:
    advertised = set(advertised_capabilities())
    assert (BLOOM_INIT_V1 in advertised) is bool(bloom_init.HAS_NATIVE)
    assert (BLOOM_INIT_EXACT_V2 in advertised) is bool(bloom_init.HAS_NATIVE)
    assert (QUIC_TRANSPORT_V1 in advertised) is bool(peer_quic.HAS_NATIVE)
    assert (NATIVE_TRANSFER_INDEXED_V1 in advertised) is bool(
        native_transfer.HAS_NATIVE
    )


def test_daemon_caps_frame_uses_runtime_capabilities() -> None:
    from one_link.daemon import CAPS_FEATURES

    frame = set(CAPS_FEATURES)
    runtime = set(advertised_capabilities())
    assert runtime <= frame
    for capability in (
        BLOOM_INIT_EXACT_V2,
        BLOOM_INIT_V1,
        QUIC_TRANSPORT_V1,
        NATIVE_TRANSFER_INDEXED_V1,
    ):
        assert (capability in frame) is (capability in runtime)
