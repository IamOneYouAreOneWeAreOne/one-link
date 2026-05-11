"""Post-quantum hybrid KEM — defense against harvest-now-decrypt-later.

A sufficiently powerful quantum computer running Shor's algorithm
breaks Curve25519 (and every other discrete-log curve) in
polynomial time. State actors today record encrypted traffic
they can't read NOW, betting they'll be able to read it
LATER when the quantum hardware arrives. This is the
"harvest-now-decrypt-later" threat (HNDL): every X25519 frame
on the wire today is a potential plaintext for whoever has
storage + patience.

The standard mitigation is a **hybrid KEM**: combine a classical
KEM (X25519) with a post-quantum KEM (ML-KEM-768, formerly Kyber)
such that the resulting shared secret is secure unless BOTH KEMs
are broken. The PQ side covers HNDL; the classical side covers
the (currently real) possibility that a brand-new PQ scheme has
a structural flaw not yet found.

Bundle 37 ships the **hybrid combine architecture**:

  - A KEM Protocol interface (keypair / encapsulate / decapsulate)
  - X25519 as a KEM, using the standard "ephemeral pubkey +
    ECDH-shared-secret" trick so it slots into the same protocol
  - A NullKEM placeholder for the PQ slot — emits empty bytes,
    contributes zero entropy to the combine. ML-KEM-768 will
    replace this when ``cryptography`` ships it (FIPS 203, finalized
    August 2024; the Python ``cryptography`` library hasn't shipped
    bindings as of v42). The wire format already has the slot, so
    a rolling upgrade just swaps the import.
  - HybridKEM that runs both KEMs in parallel, concatenates
    ciphertexts, HKDF-combines shared secrets with a domain-
    separation tag (``OL/hybrid-kem|v1``).

Why ship NullKEM today?

  - Wire-format compatibility: encoded HybridKEM ciphertexts are
    serialized with explicit ``pq_ct_len``. When ML-KEM lands and
    pq_ct grows from 0 to 1088 bytes (ML-KEM-768 ct size), old
    peers receive frames they can't decapsulate the PQ half of —
    BUT the daemon's negotiation layer can detect "peer doesn't
    advertise pq=ml-kem-768" and fall back to NullKEM = X25519-only.
    Today's wire format pre-allocates the slot.

  - HKDF-combine logic: the security argument for the hybrid
    rests on the combine function. We pin the combine semantics
    today (HKDF-Extract over classical_ss || pq_ss with a fixed
    info string) so when the PQ slot lights up, the security
    proof transfers cleanly.

  - Test surface: the combine logic, the wire format, the KEM
    Protocol — all unit-testable today. ML-KEM proper has its own
    huge test surface (KAT vectors) which lives with the
    eventual implementation.

Future bundle: replace NullKEM with a real ML-KEM-768 — either via
``cryptography``'s bindings (when shipped), the ``kyber-py`` pure-
Python reference, or a from-scratch FIPS 203 implementation. The
HybridKEM caller surface stays identical.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ── KEM Protocol ───────────────────────────────────────────────────


class KEM(Protocol):
    """Key Encapsulation Mechanism — the abstract interface every
    classical and post-quantum primitive in this module conforms to.

      * ``keypair()``: mint a fresh (priv, pub) tuple. priv is opaque
        to the protocol layer; transport never sees it. pub is bytes
        suitable for embedding in a wire frame.
      * ``encapsulate(peer_pub) -> (ciphertext, shared_secret)``: the
        SENDER side. Generate a fresh shared secret, encapsulate it
        under peer_pub, return both. Caller transmits ciphertext to
        the receiver and uses shared_secret as the symmetric-key
        seed.
      * ``decapsulate(ciphertext, my_priv) -> shared_secret``: the
        RECEIVER side. Recover the shared secret from the ciphertext
        + own private key. MUST equal the sender's shared_secret.
    """

    name: str

    def keypair(self) -> tuple[bytes, bytes]: ...
    def encapsulate(self, peer_pub: bytes) -> tuple[bytes, bytes]: ...
    def decapsulate(self, ciphertext: bytes, my_priv: bytes) -> bytes: ...


# ── X25519 KEM ─────────────────────────────────────────────────────


class X25519KEM:
    """X25519 dressed up as a KEM. The ciphertext is the sender's
    ephemeral X25519 public key; the shared secret is the ECDH
    output. Same algorithm Signal / Noise / TLS-1.3 use under the
    hood, just structured to fit the KEM Protocol surface."""

    name = "X25519"
    pub_size = 32
    priv_size = 32
    ct_size = 32  # ciphertext is the ephemeral public
    ss_size = 32  # shared-secret length

    def keypair(self) -> tuple[bytes, bytes]:
        priv = X25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw()
        # Export raw 32-byte priv via the cryptography API:
        priv_bytes = priv.private_bytes_raw()
        return priv_bytes, pub

    def encapsulate(self, peer_pub: bytes) -> tuple[bytes, bytes]:
        if len(peer_pub) != self.pub_size:
            raise ValueError(
                f"peer_pub must be {self.pub_size} bytes, got {len(peer_pub)}"
            )
        eph_priv = X25519PrivateKey.generate()
        eph_pub = eph_priv.public_key().public_bytes_raw()
        peer_pub_obj = X25519PublicKey.from_public_bytes(peer_pub)
        shared = eph_priv.exchange(peer_pub_obj)
        if shared == b"\x00" * 32:
            raise ValueError(
                "X25519 produced zero shared secret (small-order pubkey)"
            )
        # The ciphertext we ship to the peer is the ephemeral pubkey;
        # they'll ECDH it with their long-term priv.
        return eph_pub, shared

    def decapsulate(self, ciphertext: bytes, my_priv: bytes) -> bytes:
        if len(ciphertext) != self.ct_size:
            raise ValueError(
                f"ciphertext must be {self.ct_size} bytes, got {len(ciphertext)}"
            )
        if len(my_priv) != self.priv_size:
            raise ValueError(
                f"my_priv must be {self.priv_size} bytes, got {len(my_priv)}"
            )
        priv_obj = X25519PrivateKey.from_private_bytes(my_priv)
        peer_pub_obj = X25519PublicKey.from_public_bytes(ciphertext)
        shared = priv_obj.exchange(peer_pub_obj)
        if shared == b"\x00" * 32:
            raise ValueError(
                "X25519 produced zero shared secret (small-order eph pubkey)"
            )
        return shared


# ── NullKEM (placeholder for ML-KEM-768) ───────────────────────────


class NullKEM:
    """Placeholder PQ KEM that contributes zero entropy. Used until
    ML-KEM-768 lands in the ``cryptography`` library (or we vendor
    a pure-Python ref). The hybrid combine HKDF-extracts over
    (classical_ss || empty), which is mathematically equivalent to
    HKDF-extracting over classical_ss alone — so the security level
    today is exactly X25519's, with the wire format slot
    pre-allocated for the day the PQ side lights up.

    A real ML-KEM-768 implementation will replace this by supplying:
      - pub_size = 1184 (ML-KEM-768 public key length)
      - ct_size  = 1088 (ML-KEM-768 ciphertext length)
      - priv_size = 2400
      - ss_size = 32
    The HybridKEM combine logic does NOT change; it just starts
    consuming non-empty pq_ss bytes."""

    name = "Null"
    pub_size = 0
    priv_size = 0
    ct_size = 0
    ss_size = 0

    def keypair(self) -> tuple[bytes, bytes]:
        return b"", b""

    def encapsulate(self, peer_pub: bytes) -> tuple[bytes, bytes]:
        if peer_pub != b"":
            raise ValueError(
                "NullKEM peer_pub must be empty bytes; non-empty input "
                "implies the peer expects a real PQ KEM here"
            )
        return b"", b""

    def decapsulate(self, ciphertext: bytes, my_priv: bytes) -> bytes:
        if ciphertext != b"" or my_priv != b"":
            raise ValueError(
                "NullKEM decapsulate requires empty ciphertext + priv"
            )
        return b""


# ── Hybrid combine ─────────────────────────────────────────────────


HKDF_INFO_HYBRID = b"OL/hybrid-kem|v1"


def hkdf_combine(
    classical_ss: bytes,
    pq_ss: bytes,
    *,
    classical_name: str,
    pq_name: str,
    transcript: bytes = b"",
    out_len: int = 32,
) -> bytes:
    """Combine two shared secrets into one via HKDF-Extract+Expand.

    The combiner construction follows the IETF draft
    ``draft-ietf-tls-hybrid-design`` style: concatenate the two
    secrets in a fixed order, run them through HKDF with a domain-
    separation info that includes both KEM names + an optional
    transcript binder. The result is secure as long as AT LEAST ONE
    of the input secrets is secure — which is exactly the property
    we want.

    The transcript binder (typically the channel handshake's
    SHA-256 of HELLO || REPLY) ties the resulting key to its
    session, so a hybrid KEM output reused across sessions
    produces different keys."""
    info = (
        HKDF_INFO_HYBRID
        + b"|" + classical_name.encode("ascii")
        + b"|" + pq_name.encode("ascii")
        + b"|" + transcript
    )
    return HKDF(
        algorithm=hashes.SHA256(),
        length=out_len,
        salt=None,
        info=info,
    ).derive(classical_ss + pq_ss)


# ── HybridKEM ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class HybridKey:
    """Hybrid public/private key: concatenation of classical and PQ
    halves with an explicit length prefix so on-wire parsing is
    unambiguous as the PQ half resizes (today 0, tomorrow 1184)."""
    classical: bytes
    pq: bytes

    def encode(self) -> bytes:
        # ``len(classical) || classical || len(pq) || pq``. u16 lens
        # cap each half at 65535 bytes; ample for ML-KEM-768 (1184).
        return (
            struct.pack(">H", len(self.classical)) + self.classical
            + struct.pack(">H", len(self.pq)) + self.pq
        )

    @classmethod
    def decode(cls, raw: bytes) -> "HybridKey":
        off = 0
        if len(raw) < 2:
            raise ValueError("hybrid key truncated at classical length")
        clen = struct.unpack(">H", raw[off:off + 2])[0]
        off += 2
        if off + clen > len(raw):
            raise ValueError("hybrid key truncated at classical body")
        classical = raw[off:off + clen]
        off += clen
        if off + 2 > len(raw):
            raise ValueError("hybrid key truncated at pq length")
        pqlen = struct.unpack(">H", raw[off:off + 2])[0]
        off += 2
        if off + pqlen > len(raw):
            raise ValueError("hybrid key truncated at pq body")
        pq = raw[off:off + pqlen]
        return cls(classical=classical, pq=pq)


class HybridKEM:
    """Combines a classical KEM with a PQ KEM. The PQ slot is NullKEM
    by default (zero bytes, zero contribution) for wire-format
    compatibility with peers that haven't enabled ML-KEM-768. New
    peers should use :func:`default_kem` which returns a native ML-KEM-
    backed implementation when available; that path produces non-empty
    pq_ss bytes and provides actual HNDL resistance.

    Wire-format compatibility: the encoded ``HybridKey`` always
    length-prefixes both halves, so a Python ``HybridKEM(NullKEM)``
    peer and a ``NativeHybridKEM`` peer can negotiate via the
    daemon's capability advertisement layer without breaking the
    framing."""

    def __init__(
        self, *,
        classical: KEM | None = None,
        pq: KEM | None = None,
    ):
        self.classical = classical or X25519KEM()
        self.pq = pq or NullKEM()
        self.name = f"{self.classical.name}+{self.pq.name}"

    def keypair(self) -> tuple[HybridKey, HybridKey]:
        c_priv, c_pub = self.classical.keypair()
        p_priv, p_pub = self.pq.keypair()
        return (
            HybridKey(classical=c_priv, pq=p_priv),
            HybridKey(classical=c_pub, pq=p_pub),
        )

    def encapsulate(
        self, peer_pub: HybridKey, *, transcript: bytes = b"",
    ) -> tuple[HybridKey, bytes]:
        c_ct, c_ss = self.classical.encapsulate(peer_pub.classical)
        p_ct, p_ss = self.pq.encapsulate(peer_pub.pq)
        ss = hkdf_combine(
            c_ss, p_ss,
            classical_name=self.classical.name,
            pq_name=self.pq.name,
            transcript=transcript,
        )
        return HybridKey(classical=c_ct, pq=p_ct), ss

    def decapsulate(
        self, ciphertext: HybridKey, my_priv: HybridKey,
        *, transcript: bytes = b"",
    ) -> bytes:
        c_ss = self.classical.decapsulate(ciphertext.classical, my_priv.classical)
        p_ss = self.pq.decapsulate(ciphertext.pq, my_priv.pq)
        return hkdf_combine(
            c_ss, p_ss,
            classical_name=self.classical.name,
            pq_name=self.pq.name,
            transcript=transcript,
        )


# ── NativeHybridKEM (ML-KEM-768 + X25519 via one_link_native) ─────


class NativeHybridKEM:
    """ML-KEM-768 + X25519 hybrid backed by ``ol_pqkem`` (ADR-0017).

    Same outer surface as :class:`HybridKEM` (``keypair`` /
    ``encapsulate`` / ``decapsulate`` returning a 32-byte
    ``shared_secret``), but the wire format is the native crate's
    combined-hybrid bytes, not Python's length-prefixed split. Use
    :func:`default_kem` to pick the best-available backend.

    The native primitive does the X-Wing-style BLAKE3 combine
    internally; the Python-side ``hkdf_combine`` is NOT invoked.
    Callers that need to bind a transcript should do so via a
    second HKDF over the returned shared_secret.
    """

    name = "X25519+ML-KEM-768/native"

    # Sizes mirrored from one_link_native.pqkem at module load time
    # so callers don't need to import the native module to inspect.
    classical_pub_size = 32
    pq_pub_size = 1184
    classical_ct_size = 32
    pq_ct_size = 1088
    ss_size = 32

    def __init__(self) -> None:
        from . import pqkem_native

        if not pqkem_native.HAS_NATIVE:
            raise RuntimeError(
                "NativeHybridKEM requires one_link_native.pqkem; build via "
                "`cd native && maturin develop --release`"
            )
        self._native = pqkem_native

    def keypair(self) -> tuple[HybridKey, HybridKey]:
        """Generate a fresh hybrid keypair. Returns ``(priv, pub)``
        with each half wrapped in a :class:`HybridKey` so the surface
        matches :class:`HybridKEM`."""
        pk, sk = self._native.keypair()
        pk_bytes = bytes(pk.to_bytes())
        sk_bytes = bytes(sk.to_bytes())
        # The native crate produces atomic pk/sk byte blobs; we expose
        # them as a single "classical" half with empty pq half to
        # preserve the HybridKey shape. Callers reading native peers
        # decode by calling NativeHybridKEM.parse_*.
        return (
            HybridKey(classical=sk_bytes, pq=b""),
            HybridKey(classical=pk_bytes, pq=b""),
        )

    def encapsulate(
        self,
        peer_pub: HybridKey,
        *,
        transcript: bytes = b"",
    ) -> tuple[HybridKey, bytes]:
        """Encapsulate against ``peer_pub``. Returns
        ``(ciphertext, shared_secret)``. ``transcript`` is mixed in
        via an HKDF post-hash so two sessions with the same hybrid
        ciphertext but different transcripts derive distinct keys."""
        pk = self._native.public_key_from_bytes(peer_pub.classical)
        ct, ss = self._native.encapsulate(pk)
        ss_bytes = bytes(ss)
        if transcript:
            ss_bytes = _post_bind_transcript(ss_bytes, transcript)
        return HybridKey(classical=bytes(ct.to_bytes()), pq=b""), ss_bytes

    def decapsulate(
        self,
        ciphertext: HybridKey,
        my_priv: HybridKey,
        *,
        transcript: bytes = b"",
    ) -> bytes:
        """Decapsulate ``ciphertext`` with ``my_priv``."""
        sk = self._native.secret_key_from_bytes(my_priv.classical)
        ct = self._native.ciphertext_from_bytes(ciphertext.classical)
        ss = bytes(self._native.decapsulate(sk, ct))
        if transcript:
            ss = _post_bind_transcript(ss, transcript)
        return ss


def _post_bind_transcript(shared_secret: bytes, transcript: bytes) -> bytes:
    """Mix ``transcript`` into ``shared_secret`` via HKDF-Expand. Used
    by :class:`NativeHybridKEM` so callers get the same session-
    binding semantics they have with :class:`HybridKEM` + the
    Python-side ``hkdf_combine``."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"OL/native-hybrid-transcript|v1|" + transcript,
    ).derive(shared_secret)


# ── default_kem factory ───────────────────────────────────────────


def default_kem() -> HybridKEM | NativeHybridKEM:
    """Pick the best-available hybrid KEM at runtime.

    Returns :class:`NativeHybridKEM` when ``one_link_native.pqkem``
    is installed; otherwise :class:`HybridKEM` with the X25519 +
    NullKEM placeholder. New code should call this rather than
    instantiating ``HybridKEM`` directly so daemons running on
    machines with the native engine installed automatically get
    real PQ protection.

    The negotiation layer is the daemon's responsibility — if a peer
    advertises only the Python placeholder, the local daemon
    downgrades to ``HybridKEM(NullKEM)`` for that channel."""
    from . import pqkem_native

    if pqkem_native.HAS_NATIVE:
        return NativeHybridKEM()
    return HybridKEM()
