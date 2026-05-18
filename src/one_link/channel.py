"""Encrypted bidirectional channel between two peers.

Handshake (Noise-IK-flavored, simplified):
    1. Initiator -> Responder
       HELLO = init_pub_ed25519 || init_pub_x25519 || nonce_init || sig_init
       sig_init signs: "OL1|HELLO|" + init_pub_ed25519 + init_pub_x25519 + nonce_init
    2. Responder -> Initiator
       REPLY = resp_pub_ed25519 || resp_pub_x25519 || nonce_resp || sig_resp
       sig_resp signs: "OL1|REPLY|" + nonce_init + resp_pub_ed25519 + resp_pub_x25519 + nonce_resp

After both sides verify the other's signature, they:
    shared = X25519(my_x25519_priv, peer_x25519_pub)
    salt   = nonce_init || nonce_resp
    transcript = SHA256(HELLO || REPLY)
    keys   = HKDF(shared, salt, info="OL1/keys|" + transcript, L=64)
    tx_key = keys[0:32]   # initiator -> responder
    rx_key = keys[32:64]  # responder -> initiator

Each side keeps a 64-bit send counter (starts at 0) used as the ChaCha20-Poly1305 nonce
(little-endian, padded to 12 bytes). AAD = "OL1/data|" + transcript.

v0.8.2 Double Ratchet activation
================================

The legacy mode above uses a STATIC tx/rx key pair for the lifetime
of the channel. v0.7.2 shipped an audited Signal-style Double Ratchet
primitive (one_link.double_ratchet); v0.8.2 wires it in.

Activation flow:
  1. Handshake completes as before. Channel stashes the X25519 ephemeral
     PRIVATE key and the peer's X25519 ephemeral PUBLIC key for ratchet
     bootstrap (these were previously discarded after key derivation).
  2. Both sides exchange CAPS frames (legacy-encrypted). Daemon notes
     `note_caps_sent()` after sending CAPS and `note_caps_received(features)`
     when CAPS arrives.
  3. When BOTH flags are set AND both feature lists contain
     DOUBLE_RATCHET_V1, `maybe_activate_ratchet(role)` initialises the
     ratchet state from the handshake bootstrap — and from that point
     forward every send/recv goes through the ratchet, providing forward
     secrecy + post-compromise security.

Atomicity: activation flips BOTH directions at the same logical
boundary. Sending side: switch happens after the local CAPS frame
is written. Receiving side: switch happens after the peer's CAPS
frame is parsed. Each side's recv loop is single-threaded so there
is no in-flight frame between the CAPS frame and the next frame.

Wire-format on the ratchet path:
    [length-prefix, unchanged] [42-byte Header.encode()] [ciphertext]

AAD = header.encode() || transcript_hash. Splicing a ratchet frame
across channels fails AEAD (different transcript_hash).

Backward compatibility: peers that don't advertise DOUBLE_RATCHET_V1
stay on legacy. The activation is symmetric — either both speak
ratchet or both stay legacy.
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from one_link.double_ratchet import RatchetState

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from one_link.identity import Identity, fingerprint_of, verify
from one_link.wire import read_frame, write_frame, write_frame_nowait

log = logging.getLogger(__name__)

# External audit 2026-05-18 ES-1: per-peer counter of v1-fallback
# HELLO sig acceptances. The flag-day plan is a CAPS-advertised
# `uks_v2_only` after which v1 acceptance becomes a hard reject;
# until then, ops grep this counter to spot peers stuck on v1 (or
# attackers trying to splice).
_v1_sig_fallback_counts: dict[bytes, int] = {}

def _bump_v1_sig_counter(peer_ed_pub: bytes) -> int:
    """Increment + return the v1-fallback count for this peer's
    Ed25519 pubkey. Module-local; bounded by the number of distinct
    peers, which is itself bounded by paired-peer count."""
    n = _v1_sig_fallback_counts.get(peer_ed_pub, 0) + 1
    _v1_sig_fallback_counts[peer_ed_pub] = n
    return n


def v1_sig_fallback_summary() -> dict[str, int]:
    """Diagnostic surface: peer-fingerprint-prefix -> v1 fallback
    count. Read by the One Link Doctor health check and the
    Truth Dashboard."""
    return {pk.hex()[:16]: n for pk, n in _v1_sig_fallback_counts.items()}


PROTO = b"OL1"
NONCE_LEN = 16
HELLO_TAG = b"OL1|HELLO|"
REPLY_TAG = b"OL1|REPLY|"
AAD_PREFIX = b"OL1/data|"
# v0.8.2: capability tag both peers must advertise to enable ratchet.
DR_CAP = "double_ratchet_v1"
# Phase C-3 (ADR-0026): capability tag both peers must advertise to
# enable the native chunk-store transport (FILE_NATIVE_CHUNK messages).
# Keep in sync with `capabilities.NATIVE_TRANSFER_V1`.
NATIVE_TRANSFER_CAP = "native_transfer_v1"
# v0.8.2: HKDF info label for the ratchet-bootstrap root key. Distinct
# from the legacy session-key derivation so the two are independent;
# even if the legacy AEAD keys leak, they don't reveal the ratchet
# root_key (and vice versa).
DR_ROOT_INFO = b"OL1/dr/root_seed|"
DR_HEADER_LEN = 42  # Header.encode() output length


@dataclass
class Channel:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    peer_ed_pub: bytes
    peer_short_id: str
    tx_aead: ChaCha20Poly1305
    rx_aead: ChaCha20Poly1305
    tx_seq: int = 0
    rx_seq: int = 0
    transcript_hash: bytes = b""
    # Set after CAPS exchange (post-handshake first encrypted message).
    # None = peer hasn't sent CAPS yet (legacy or pre-CAPS).
    peer_caps: dict | None = None

    # v0.8.2: Double Ratchet bootstrap material — kept alive
    # post-handshake so we can activate the ratchet later if both
    # peers advertise DOUBLE_RATCHET_V1. Set by initiate / respond.
    _dr_role: Optional[str] = None      # "alice" | "bob"
    _dr_x_priv: Optional[X25519PrivateKey] = None
    _dr_peer_x_pub: Optional[bytes] = None
    _dr_shared: Optional[bytes] = None  # raw 32-byte ECDH output
    # Activation tracking. Both must be True before we attempt to
    # negotiate the ratchet. _peer_dr_capable is the latest known
    # state of the peer's DOUBLE_RATCHET_V1 advertisement.
    _caps_sent: bool = False
    _caps_received: bool = False
    _peer_dr_capable: bool = False
    # Phase C-3 (ADR-0026): native transfer capability tracking.
    # True iff the peer's CAPS frame included NATIVE_TRANSFER_V1.
    # Independent of ratchet status — the native pipeline derives
    # its own session secret from the DR-bootstrap material via
    # `derive_native_transfer_secret`, so we don't gate on DR
    # activation.
    _peer_native_transfer_capable: bool = False
    # When non-None, channel is in ratchet mode. send/recv branch
    # to the ratchet path and the legacy AEADs go unused. Set
    # exactly once per channel by maybe_activate_ratchet.
    # Lazy-imported under TYPE_CHECKING so we don't pull
    # double_ratchet at module import time (it pulls cryptography
    # primitives). Runtime contract: None until
    # maybe_activate_ratchet flips it, then a RatchetState until
    # close().
    _dr_state: Optional["RatchetState"] = None
    # Phase C-3 (ADR-0026): cached native transfer session for
    # FILE_NATIVE_CHUNK encrypt/decrypt. Lazily built by the daemon
    # on first chunk; sender and receiver hold MATCHED instances
    # because both sides derive the same secret via
    # `derive_native_transfer_secret`.
    _native_transfer_session: object = None  # NativeTransferSession

    def _nonce(self, seq: int) -> bytes:
        return seq.to_bytes(12, "little")

    @property
    def transcript_hex(self) -> str:
        return self.transcript_hash.hex()

    def _aad(self) -> bytes:
        return AAD_PREFIX + self.transcript_hash

    # ─── Phase C-3 native transfer integration (ADR-0025) ─────────────
    def derive_native_transfer_secret(self) -> bytes:
        """Derive a 32-byte session secret suitable for seeding a
        :class:`one_link.native_transfer.NativeTransferSession`.

        The native pipeline (ChunkRatchet + per-chunk AEAD) needs a
        distinct 32-byte secret separate from this channel's
        legacy AEAD keys and from the Double Ratchet root seed. We
        derive via HKDF with a fresh info tag so each domain has
        its own derived material — leaking either the legacy
        channel keys or the DR root doesn't compromise the native
        transfer secret.

        The same derivation runs on both peers (deterministic from
        ``transcript_hash`` + the DR bootstrap shared secret), so
        sender + receiver hold matching native sessions without
        any wire-format change."""
        if self._dr_shared is None:
            raise RuntimeError(
                "channel cannot derive native transfer secret: DR "
                "bootstrap material missing (handshake incomplete)"
            )
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.transcript_hash,
            info=b"OL1/native-transfer/seed|v1",
        ).derive(self._dr_shared)

    def get_or_create_native_transfer_session(
        self,
        *,
        cipher_backend: str = "fast",
        store_root: "Path | None" = None,
    ):
        """Lazy, cached version of :meth:`establish_native_transfer`.

        Daemon callers invoke this on every chunk — the session is
        built once on first call and reused for the rest of the
        channel's lifetime. Sender and receiver each cache their
        own instance; matched derivation makes them line up."""
        if self._native_transfer_session is None:
            self._native_transfer_session = self.establish_native_transfer(
                cipher_backend=cipher_backend,
                store_root=store_root,
            )
        return self._native_transfer_session

    def establish_native_transfer(
        self,
        *,
        cipher_backend: str = "fast",
        store_root: "Path | None" = None,
    ):
        """Build a :class:`NativeTransferSession` from this channel's
        derived native-transfer secret.

        The daemon's ``send_file`` / chunk-store transport call sites
        invoke this once per channel and reuse the returned session
        across all chunks of that channel. The session is matched on
        both peers (same shared secret, deterministic derivation), so
        the receiver's instance decrypts what the sender's produces.

        ``cipher_backend`` defaults to ``"fast"`` (cryptography.hazmat
        BoringSSL); pass ``"native"`` for the ring-backed
        ``ol_aead.AeadCipher`` multi-frame layout (use when partial-
        chunk integrity is needed)."""
        from one_link import native_transfer as _native_transfer

        if not _native_transfer.HAS_NATIVE:
            raise RuntimeError(
                "channel.establish_native_transfer requires "
                "one_link_native; build via `cd native && maturin "
                "develop --release`"
            )
        secret = self.derive_native_transfer_secret()
        return _native_transfer.session_from_shared_secret(
            secret,
            cipher_backend=cipher_backend,
            store_root=store_root,
        )

    @property
    def is_ratchet_active(self) -> bool:
        """v0.8.2: True after both sides exchanged CAPS containing
        DOUBLE_RATCHET_V1 and the ratchet state was successfully
        bootstrapped. Read-only — flipped exactly once."""
        return self._dr_state is not None

    # ─── v0.8.2: caps-driven ratchet activation ────────────────────

    def note_caps_sent(self) -> None:
        """Daemon calls this immediately after writing the local
        CAPS frame. Marks the send-side ready for ratchet flip."""
        self._caps_sent = True

    def note_caps_received(self, features: list[str] | tuple[str, ...] | set[str]) -> None:
        """Daemon calls this immediately after parsing the peer's
        CAPS frame. Records DR + native-transfer capabilities, marks
        recv-side ready."""
        if features is None:
            features = []
        # Normalize to a set once so membership checks are O(1).
        feature_set = set(features)
        self._peer_dr_capable = DR_CAP in feature_set
        self._peer_native_transfer_capable = NATIVE_TRANSFER_CAP in feature_set
        self._caps_received = True

    @property
    def peer_native_transfer_capable(self) -> bool:
        """True iff the peer's CAPS frame advertised
        ``NATIVE_TRANSFER_V1`` (ADR-0026). Read-only — set by
        :meth:`note_caps_received`."""
        return self._peer_native_transfer_capable

    def maybe_activate_ratchet(self) -> bool:
        """If both sides have exchanged CAPS, both advertise
        DOUBLE_RATCHET_V1, and we have the bootstrap material from
        the handshake, initialise the ratchet state and flip the
        channel to ratchet mode.

        Returns True iff the channel just transitioned to ratchet
        mode on this call. Idempotent on subsequent calls.
        """
        if self._dr_state is not None:
            return False  # already active
        if not (self._caps_sent and self._caps_received):
            return False
        if not self._peer_dr_capable:
            return False  # peer doesn't speak DR
        if (
            self._dr_role is None
            or self._dr_shared is None
            or self._dr_peer_x_pub is None
            or self._dr_x_priv is None
        ):
            log.warning(
                "channel ratchet activation requested but bootstrap "
                "material missing for peer %s — staying on legacy",
                self.peer_short_id,
            )
            return False
        try:
            from one_link.double_ratchet import (
                init_alice, init_bob,
            )
            # Derive a root_key distinct from the legacy AEAD keys.
            # If legacy keys leak, the DR bootstrap stays safe; if
            # the bootstrap leaks, legacy still has its own keys.
            root_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.transcript_hash,
                info=DR_ROOT_INFO,
            ).derive(self._dr_shared)
            if self._dr_role == "alice":
                self._dr_state = init_alice(
                    shared_secret=root_key,
                    peer_pub=self._dr_peer_x_pub,
                )
            elif self._dr_role == "bob":
                self._dr_state = init_bob(
                    shared_secret=root_key,
                    dh_priv=self._dr_x_priv,
                )
            else:
                log.warning(
                    "channel ratchet: unknown role %r for %s",
                    self._dr_role, self.peer_short_id,
                )
                return False
            log.info(
                "channel ratchet activated for peer %s as %s",
                self.peer_short_id, self._dr_role,
            )
            # Drop the legacy bootstrap material — we no longer need
            # the X25519 priv key once the ratchet is rolling.
            self._dr_x_priv = None
            self._dr_shared = None
            self._dr_peer_x_pub = None
            return True
        except Exception as e:
            log.warning(
                "channel ratchet activation FAILED for %s: %s — "
                "falling back to legacy AEAD",
                self.peer_short_id, e,
            )
            self._dr_state = None
            return False

    # ─── send / recv ───────────────────────────────────────────────

    def _can_send_ratchet(self) -> bool:
        """v0.20.7 (security audit C4 send-side race fix): True only
        when DR is active AND we have a usable send chain.

        After both sides exchange CAPS and call maybe_activate_ratchet,
        Alice's RatchetState has send_chain_key set (init_alice runs
        an immediate root step). Bob's RatchetState is intentionally
        send-empty until Alice's first message arrives — that's the
        Signal Double Ratchet specification: Bob can't send before
        receiving Alice's first ratchet message because his
        send_chain_key is derived during the DH ratchet that
        Alice's first frame triggers.

        For us that means there's a brief window where Bob has
        DR active but cannot encrypt outbound. Legacy AEAD keys are
        still alive (the recv-side race tolerance keeps them around);
        falling back to legacy for that window keeps the channel
        bidirectional and matches the symmetry of the recv-side
        DR-then-legacy fallback in recv(). Once Bob receives Alice's
        first DR frame, his send_chain_key gets set and subsequent
        sends go through the ratchet.
        """
        if self._dr_state is None:
            return False
        return getattr(self._dr_state, "send_chain_key", None) is not None

    async def send(self, plaintext: bytes) -> None:
        if self._can_send_ratchet():
            await self._send_ratchet(plaintext)
            return
        # Legacy path (also used by Bob immediately post-activation
        # until Alice's first DR frame seeds his send chain).
        nonce = self._nonce(self.tx_seq)
        self.tx_seq += 1
        ct = self.tx_aead.encrypt(nonce, plaintext, self._aad())
        await write_frame(self.writer, ct)

    async def queue_send(self, plaintext: bytes) -> None:
        """Encrypt and write a frame without awaiting socket drain.

        File transfer callers use this for bounded windows: write several
        chunks, then call ``flush`` before awaiting ACKs. Normal chat/control
        paths keep using ``send`` so small messages retain immediate
        backpressure and error visibility.
        """
        if self._can_send_ratchet():
            self._queue_send_ratchet(plaintext)
            return
        nonce = self._nonce(self.tx_seq)
        self.tx_seq += 1
        ct = self.tx_aead.encrypt(nonce, plaintext, self._aad())
        write_frame_nowait(self.writer, ct)

    async def flush(self) -> None:
        await self.writer.drain()

    async def recv(self) -> bytes:
        # v0.9.6: ratchet activation race tolerance. The two sides
        # flip _dr_state independently as caps_sent + caps_received
        # complete on each end. There's a brief window where WE've
        # activated DR but the peer's NEXT outbound frame was queued
        # BEFORE peer activated → peer's frame is legacy AEAD. Decoding
        # a legacy ciphertext as a DR header reads a uniformly-random
        # first byte and raises "unsupported ratchet header version".
        #
        # The fix: when DR is active, try DR first; on header-parse
        # failure, fall back to legacy. Both paths use different keys,
        # so a successful decryption under either is unambiguous —
        # an attacker forging a legacy frame to bypass DR can't
        # succeed because the legacy AEAD key would also fail
        # without authentic ciphertext.
        if self._dr_state is not None:
            payload = await read_frame(self.reader)
            try:
                return self._decode_ratchet_payload(payload)
            except (ValueError, RuntimeError) as dr_err:
                # Activation-race fingerprints: the bytes we just read
                # were encrypted by the peer's send-side BEFORE peer
                # activated DR (i.e. legacy AEAD ciphertext arriving
                # AFTER our local activation). DR-parsing legacy
                # bytes can fail in several ways:
                #   - "header too short" / "ratchet frame too short"
                #   - "ratchet header version" (the version byte
                #     isn't 1)
                #   - "too many skipped messages" (random middle
                #     bytes interpreted as header.n)
                #   - "low-order point" (M5: random ECDH bytes)
                #   - "out-of-order delivery on current chain"
                #   - AEAD InvalidTag (random keystream mismatch)
                # All of these mean "this wasn't DR." Fall back to
                # legacy AEAD on the same bytes; keys are disjoint
                # so a wrong-path decrypt cannot accidentally
                # succeed. If legacy also fails, surface the
                # original DR error so the channel tears down on
                # genuine corruption. v0.20.7 (security audit C4):
                # broaden the fingerprint list so the activation-
                # race window doesn't spuriously kill channels.
                msg = str(dr_err)
                race_indicators = (
                    "ratchet header version",
                    "ratchet frame too short",
                    "header too short",
                    "too many skipped messages",
                    "low-order point",
                    "out-of-order delivery on current chain",
                    "replayed message",
                )
                if not any(ind in msg for ind in race_indicators):
                    # AEAD InvalidTag from dr_decrypt is a
                    # cryptography library exception; re-classify it
                    # as a race-fallback candidate too.
                    from cryptography.exceptions import InvalidTag
                    if not isinstance(dr_err, InvalidTag):
                        raise
                try:
                    nonce = self._nonce(self.rx_seq)
                    pt = self.rx_aead.decrypt(nonce, payload, self._aad())
                    self.rx_seq += 1
                    return pt
                except Exception:
                    raise dr_err
        # Legacy path.
        # v0.20.7 (security audit M2): increment rx_seq AFTER successful
        # decrypt so a single bit-flip / injected garbage frame does not
        # permanently desync the channel. The DR fallback path above
        # already follows this pattern; this brings the legacy path in
        # line. On decrypt failure the exception propagates and the
        # channel is closed by the caller, so leaving rx_seq unmodified
        # is safe (the channel will not be reused).
        ct = await read_frame(self.reader)
        nonce = self._nonce(self.rx_seq)
        pt = self.rx_aead.decrypt(nonce, ct, self._aad())
        self.rx_seq += 1
        return pt

    def _decode_ratchet_payload(self, payload: bytes) -> bytes:
        """Synchronous DR-decrypt of an already-read frame payload.
        Split out from _recv_ratchet so recv() can try-DR-then-legacy
        on the same buffered bytes (one read_frame, two decode
        attempts)."""
        from one_link.double_ratchet import (
            Header as DRHeader, decrypt as dr_decrypt,
        )
        # All four ratchet methods are only reached after
        # ``is_ratcheting`` returns True, which guarantees
        # ``_dr_state is not None``. The asserts encode that
        # invariant for the type checker.
        assert self._dr_state is not None, "ratchet not yet activated"
        if len(payload) < DR_HEADER_LEN:
            raise RuntimeError(
                f"ratchet frame too short: {len(payload)} bytes "
                f"(need at least {DR_HEADER_LEN} for header)"
            )
        header = DRHeader.decode(payload[:DR_HEADER_LEN])
        ct = payload[DR_HEADER_LEN:]
        return dr_decrypt(
            self._dr_state, header, ct, ad=self.transcript_hash,
        )

    async def _send_ratchet(self, plaintext: bytes) -> None:
        from one_link.double_ratchet import encrypt as dr_encrypt
        assert self._dr_state is not None, "ratchet not yet activated"
        header, ct = dr_encrypt(
            self._dr_state, plaintext, ad=self.transcript_hash,
        )
        # Wire layout: [Header (DR_HEADER_LEN bytes)][ciphertext]
        await write_frame(self.writer, header.encode() + ct)

    def _queue_send_ratchet(self, plaintext: bytes) -> None:
        from one_link.double_ratchet import encrypt as dr_encrypt
        assert self._dr_state is not None, "ratchet not yet activated"
        header, ct = dr_encrypt(
            self._dr_state, plaintext, ad=self.transcript_hash,
        )
        write_frame_nowait(self.writer, header.encode() + ct)

    async def _recv_ratchet(self) -> bytes:
        from one_link.double_ratchet import (
            Header as DRHeader, decrypt as dr_decrypt,
        )
        assert self._dr_state is not None, "ratchet not yet activated"
        payload = await read_frame(self.reader)
        if len(payload) < DR_HEADER_LEN:
            raise RuntimeError(
                f"ratchet frame too short: {len(payload)} bytes "
                f"(need at least {DR_HEADER_LEN} for header)"
            )
        header = DRHeader.decode(payload[:DR_HEADER_LEN])
        ct = payload[DR_HEADER_LEN:]
        return dr_decrypt(
            self._dr_state, header, ct, ad=self.transcript_hash,
        )

    async def close(self) -> None:
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass


def _x25519_keypair() -> tuple[X25519PrivateKey, bytes]:
    priv = X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub


def _sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def _derive_keys(
    shared: bytes, salt: bytes, transcript_hash: bytes,
) -> tuple[bytes, bytes]:
    out = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        info=b"OL1/keys|" + transcript_hash,
    ).derive(shared)
    return out[:32], out[32:64]


async def initiate(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    me: Identity,
    *,
    expected_responder_ed_pub: Optional[bytes] = None,
) -> Channel:
    """Open an outbound encrypted channel.

    v0.20.7 (security audit M1): when ``expected_responder_ed_pub`` is
    provided, the initiator binds it into the HELLO signature
    (``sig_i = me.sign(HELLO_TAG + me_pub + x_pub + nonce_i + resp_pub)``)
    AND strictly equality-checks the actual REPLY's responder pubkey
    against the claim. Together these defeat the unknown-key-share
    attack: an attacker who re-routes the HELLO to a different
    (paired) responder C cannot get C to verify the sig (the bound
    pubkey identifies the original target), and even if C did
    somehow accept, the initiator catches the redirect at the REPLY
    pubkey check.

    For TOFU first-meet flows where the responder pubkey isn't yet
    known, leave ``expected_responder_ed_pub`` as None — the legacy
    sig material is used and the responder side accepts both v1 and
    v2 sigs. This is a soft transition: callers wire in the bind as
    knowledge of the target identity becomes available.
    """
    if (
        expected_responder_ed_pub is not None
        and len(expected_responder_ed_pub) != 32
    ):
        raise ValueError(
            f"expected_responder_ed_pub must be 32 bytes, "
            f"got {len(expected_responder_ed_pub)}"
        )
    x_priv, x_pub = _x25519_keypair()
    nonce_i = os.urandom(NONCE_LEN)
    if expected_responder_ed_pub is not None:
        sig_i = me.sign(
            HELLO_TAG + me.public_bytes + x_pub + nonce_i
            + expected_responder_ed_pub
        )
    else:
        sig_i = me.sign(HELLO_TAG + me.public_bytes + x_pub + nonce_i)
    hello = me.public_bytes + x_pub + nonce_i + sig_i
    await write_frame(writer, hello)

    reply = await read_frame(reader)
    if len(reply) != 32 + 32 + NONCE_LEN + 64:
        raise RuntimeError(f"bad REPLY length: {len(reply)}")
    r_ed = reply[0:32]
    r_x = reply[32:64]
    nonce_r = reply[64 : 64 + NONCE_LEN]
    sig_r = reply[64 + NONCE_LEN :]
    if not verify(r_ed, sig_r, REPLY_TAG + nonce_i + r_ed + r_x + nonce_r):
        raise RuntimeError("REPLY signature invalid")
    # v0.20.7 (M1): catch UKS redirect where attacker re-routes our
    # HELLO to a different responder. If we didn't know who we were
    # talking to (TOFU), the bind step above used legacy material and
    # this check is skipped.
    if (
        expected_responder_ed_pub is not None
        and r_ed != expected_responder_ed_pub
    ):
        raise RuntimeError(
            "REPLY pubkey does not match expected responder identity "
            "(possible unknown-key-share redirect)"
        )

    transcript_hash = _sha256(hello + reply)
    shared = x_priv.exchange(X25519PublicKey.from_public_bytes(r_x))
    k_i_to_r, k_r_to_i = _derive_keys(shared, nonce_i + nonce_r, transcript_hash)
    return Channel(
        reader=reader,
        writer=writer,
        peer_ed_pub=r_ed,
        peer_short_id=fingerprint_of(r_ed)[:8],
        tx_aead=ChaCha20Poly1305(k_i_to_r),
        rx_aead=ChaCha20Poly1305(k_r_to_i),
        transcript_hash=transcript_hash,
        # v0.8.2: ratchet-bootstrap material. Held until
        # maybe_activate_ratchet seeds the RatchetState; cleared
        # afterwards.
        _dr_role="alice",
        _dr_x_priv=x_priv,
        _dr_peer_x_pub=r_x,
        _dr_shared=shared,
    )


async def respond(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    me: Identity,
) -> Channel:
    hello = await read_frame(reader)
    if len(hello) != 32 + 32 + NONCE_LEN + 64:
        raise RuntimeError(f"bad HELLO length: {len(hello)}")
    i_ed = hello[0:32]
    i_x = hello[32:64]
    nonce_i = hello[64 : 64 + NONCE_LEN]
    sig_i = hello[64 + NONCE_LEN :]
    # v0.20.7 (security audit M1): try the v2 sig (with our pubkey
    # bound in) first to defeat unknown-key-share. Fall back to the
    # v1 sig material only if v2 fails — that's the rolling-upgrade
    # hatch for initiators who don't yet know our identity (TOFU
    # first-meet) and signed without the bind.
    sig_v2_material = (
        HELLO_TAG + i_ed + i_x + nonce_i + me.public_bytes
    )
    sig_v1_material = HELLO_TAG + i_ed + i_x + nonce_i
    if verify(i_ed, sig_i, sig_v2_material):
        pass  # v2 sig — UKS-defended path, the common case once peers upgrade.
    elif verify(i_ed, sig_i, sig_v1_material):
        # External audit 2026-05-18 ES-1: this fallback was added as
        # a rolling-upgrade hatch (audit M1) but at v0.20.7 it's still
        # universally accepted. An attacker on a hostile LAN who MITMs
        # a TOFU first-meet between two paired peers (A and C, both
        # paired with B) can splice their HELLO/REPLY because v1 sig
        # doesn't bind the responder's pubkey. The flag-day cleanup
        # is a CAPS-advertised `uks_v2_only` flag after which v1
        # acceptance becomes a hard reject.
        #
        # Until that ships: log at WARNING (not INFO) so ops can
        # actually grep for it, and increment a per-pubkey counter so
        # a sudden spike of v1-fallback from a known-upgraded peer
        # surfaces as suspicious behaviour.
        v1_count = _bump_v1_sig_counter(i_ed)
        log.warning(
            "channel.respond: peer %s used legacy v1 HELLO sig "
            "(no responder-pubkey binding). UKS defence NOT active "
            "for this handshake. v1-fallback count for this peer: %d. "
            "Fix: upgrade the other side so it signs the v2 transcript.",
            i_ed.hex()[:16],
            v1_count,
        )
    else:
        raise RuntimeError("HELLO signature invalid")

    x_priv, x_pub = _x25519_keypair()
    nonce_r = os.urandom(NONCE_LEN)
    sig_r = me.sign(REPLY_TAG + nonce_i + me.public_bytes + x_pub + nonce_r)
    reply = me.public_bytes + x_pub + nonce_r + sig_r
    await write_frame(writer, reply)

    transcript_hash = _sha256(hello + reply)
    shared = x_priv.exchange(X25519PublicKey.from_public_bytes(i_x))
    k_i_to_r, k_r_to_i = _derive_keys(shared, nonce_i + nonce_r, transcript_hash)
    return Channel(
        reader=reader,
        writer=writer,
        peer_ed_pub=i_ed,
        peer_short_id=fingerprint_of(i_ed)[:8],
        tx_aead=ChaCha20Poly1305(k_r_to_i),
        rx_aead=ChaCha20Poly1305(k_i_to_r),
        transcript_hash=transcript_hash,
        # v0.8.2: bob-side ratchet bootstrap. Bob's x_priv is the
        # initial dh_send for init_bob; first ratchet ratchet-step
        # happens when alice's first ratchet message arrives.
        _dr_role="bob",
        _dr_x_priv=x_priv,
        _dr_peer_x_pub=i_x,
        _dr_shared=shared,
    )
