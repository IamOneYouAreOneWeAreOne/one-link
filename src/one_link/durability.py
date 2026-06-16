"""Local erasure-coded chunk durability (ADR-0018 — Phase C item 2).

Wires `ol_erasure` into the chunk-store side of the daemon so a chunk
can survive partial disk corruption / bit-rot / accidental shard
deletion. Each replicated chunk is encoded into ``k + m`` shards via
Reed-Solomon over GF(2^8); any ``k`` of the ``k+m`` shards
reconstruct the original plaintext. Shards live in a
``.shards/<stripe_id>/`` directory under the chunk-store root.

Profiles ship from ``ol_erasure``:

  - ``EPHEMERAL``  — k=4, m=2 (1.5× overhead). For ephemeral caches.
  - ``STANDARD``   — k=10, m=4 (1.4× overhead). The default.
  - ``ARCHIVAL``   — k=8, m=8 (2.0× overhead). For long-term storage.

The Phase D long-term direction extends this to CROSS-PEER
distribution (your shards land on N trusted peers' devices, you
survive M of them going offline). This module ships the local
half today; the daemon's auto-replication scheduler will plug into
``replicate_chunk_locally`` once the multi-peer wire protocol lands.

Usage
-----

    from one_link import durability as d

    store = d.LocalStripeStore(chunks_dir="/path/to/chunks")
    stripe_id = store.replicate_chunk_locally(
        chunk_bytes=plaintext, profile="standard",
    )
    # Disaster simulation: drop some shards.
    store.delete_shard(stripe_id, 0)
    store.delete_shard(stripe_id, 1)
    store.delete_shard(stripe_id, 5)
    # Recovery: works as long as <= m shards are missing.
    recovered = store.recover_chunk_locally(stripe_id)
    assert recovered == plaintext
"""
from __future__ import annotations

import logging
import os
import pathlib
import shutil
from dataclasses import dataclass
from typing import Literal, Optional

log = logging.getLogger(__name__)

# The native primitives are required; this module ships ONLY the
# adapter / file-layout side. If the wheel isn't built, callers get a
# clear RuntimeError.
from one_link import erasure_native as _en

Profile = Literal["ephemeral", "standard", "archival"]


def _profile_params(profile: Profile):
    """Resolve a profile name to a `ol_erasure.StripeParams`."""
    _en._require_native()
    if profile == "ephemeral":
        return _en.EPHEMERAL
    if profile == "standard":
        return _en.STANDARD
    if profile == "archival":
        return _en.ARCHIVAL
    raise ValueError(
        f"unknown durability profile {profile!r}; "
        f"expected one of: ephemeral, standard, archival"
    )


@dataclass(frozen=True)
class StripeManifest:
    """What the caller needs to recover a stripe later.

    Stored alongside each stripe so recovery doesn't depend on the
    caller remembering the params used.
    """
    stripe_id: bytes  # 32-byte ol_erasure canonical id
    k: int
    m: int
    plaintext_len: int
    profile: Profile


class LocalStripeStore:
    """Directory-rooted erasure-coded chunk store.

    Layout under ``chunks_dir``::

        .shards/
          <stripe_id_hex>/
            manifest.txt         # k, m, plaintext_len, profile
            shard_00.bin         # shard 0 (data) raw bytes
            shard_01.bin         # shard 1 (data)
            ...
            shard_<k+m-1>.bin    # shard k+m-1 (parity)

    The manifest is plain-text not JSON so a future operator can
    `cat` and read it without tooling. Manifest is one
    ``key=value`` line per field; the parser is permissive on
    trailing whitespace + unknown fields.
    """

    SHARDS_SUBDIR = ".shards"
    SHARD_FILENAME = "shard_{index:02d}.bin"
    MANIFEST_FILENAME = "manifest.txt"

    def __init__(self, chunks_dir: str | os.PathLike[str]):
        self.chunks_dir = pathlib.Path(chunks_dir)
        self.shards_root = self.chunks_dir / self.SHARDS_SUBDIR

    # ── Replicate ───────────────────────────────────────────────────

    def replicate_chunk_locally(
        self,
        chunk_bytes: bytes,
        *,
        profile: Profile = "standard",
    ) -> bytes:
        """Encode ``chunk_bytes`` into k+m shards under
        ``.shards/<stripe_id_hex>/``. Returns the 32-byte stripe_id.

        Idempotent: if the directory already exists with the same
        stripe_id (deterministic for a given plaintext+params), the
        existing shards are left in place and the call is a no-op
        beyond a metadata refresh.
        """
        if not isinstance(chunk_bytes, (bytes, bytearray, memoryview)):
            raise TypeError("chunk_bytes must be bytes-like")
        params = _profile_params(profile)
        shards = _en.encode(bytes(chunk_bytes), params)
        if not shards:
            raise RuntimeError("erasure encode returned no shards")
        stripe_id = shards[0].stripe_id
        manifest = StripeManifest(
            stripe_id=stripe_id,
            k=params.k,
            m=params.m,
            plaintext_len=len(chunk_bytes),
            profile=profile,
        )
        stripe_dir = self.shards_root / stripe_id.hex()
        stripe_dir.mkdir(parents=True, exist_ok=True)
        self._write_manifest(stripe_dir, manifest)
        for shard in shards:
            # The native crate gives index per-role (0..k for data,
            # 0..m for parity). Flatten to a stripe-wide position so
            # the on-disk filenames don't collide.
            position = shard.index if shard.role == "data" else params.k + shard.index
            target = stripe_dir / self.SHARD_FILENAME.format(index=position)
            # Atomic-ish write: write to a sibling .tmp then rename.
            tmp = target.with_suffix(".bin.tmp")
            tmp.write_bytes(shard.bytes)
            tmp.replace(target)
        log.debug(
            "durability.replicate stripe_id=%s profile=%s k=%d m=%d plaintext_len=%d",
            stripe_id.hex()[:16], profile, params.k, params.m, len(chunk_bytes),
        )
        return stripe_id

    # ── Recover ─────────────────────────────────────────────────────

    def recover_chunk_locally(self, stripe_id: bytes) -> bytes:
        """Reconstruct the original chunk from the stored shards.
        Tolerates up to ``m`` missing/corrupt shards. Raises
        ``FileNotFoundError`` if the stripe directory is missing
        and ``RuntimeError`` if too many shards are missing for
        recovery (i.e. fewer than ``k`` survive)."""
        manifest, present = self._load_stripe(stripe_id)
        params = _en.params(manifest.k, manifest.m)
        if sum(1 for s in present if s is not None) < manifest.k:
            raise RuntimeError(
                f"stripe {stripe_id.hex()[:16]}: only "
                f"{sum(1 for s in present if s is not None)} of {manifest.k} shards "
                f"available; cannot reconstruct"
            )
        plaintext = _en.decode(params, present)
        # ol_erasure returns the original plaintext exactly; trim
        # paranoid here to make sure we don't surface trailing pad
        # bytes from the stripe encoding.
        return plaintext[: manifest.plaintext_len]

    def stripe_exists(self, stripe_id: bytes) -> bool:
        return (self.shards_root / stripe_id.hex()).is_dir()

    def stripe_health(self, stripe_id: bytes) -> dict:
        """Returns a dict with ``shards_present``, ``shards_missing``,
        ``recoverable`` (bool), and ``manifest`` (dict)."""
        try:
            manifest, present = self._load_stripe(stripe_id)
        except FileNotFoundError:
            return {
                "exists": False,
                "shards_present": 0,
                "shards_missing": 0,
                "recoverable": False,
            }
        n_present = sum(1 for s in present if s is not None)
        n_missing = len(present) - n_present
        return {
            "exists": True,
            "shards_present": n_present,
            "shards_missing": n_missing,
            "recoverable": n_present >= manifest.k,
            "manifest": {
                "stripe_id": manifest.stripe_id.hex(),
                "k": manifest.k,
                "m": manifest.m,
                "plaintext_len": manifest.plaintext_len,
                "profile": manifest.profile,
            },
        }

    # ── Maintenance ────────────────────────────────────────────────

    def delete_shard(self, stripe_id: bytes, shard_index: int) -> bool:
        """Delete a single shard. Returns True iff the shard existed.

        Used by the recovery test harness AND by the daemon's
        auto-repair scheduler to drop corrupted shards before
        re-encoding from survivors.
        """
        path = (
            self.shards_root
            / stripe_id.hex()
            / self.SHARD_FILENAME.format(index=shard_index)
        )
        if not path.exists():
            return False
        path.unlink()
        return True

    def delete_stripe(self, stripe_id: bytes) -> bool:
        """Drop every shard + manifest for ``stripe_id``."""
        path = self.shards_root / stripe_id.hex()
        if not path.is_dir():
            return False
        shutil.rmtree(path)
        return True

    def list_stripes(self) -> list[bytes]:
        """Enumerate every locally-stored stripe by id."""
        if not self.shards_root.is_dir():
            return []
        out = []
        for child in self.shards_root.iterdir():
            if not child.is_dir():
                continue
            try:
                out.append(bytes.fromhex(child.name))
            except ValueError:
                # Stray directory; ignore.
                continue
        return out

    # ── Repair (future hook for auto-replication) ──────────────────

    def repair_stripe(self, stripe_id: bytes) -> int:
        """Re-encode missing shards from survivors. Returns the
        count of shards re-written. Cheap when the stripe is intact
        (zero shards re-written)."""
        manifest, present = self._load_stripe(stripe_id)
        if sum(1 for s in present if s is not None) >= len(present):
            return 0
        recovered = self.recover_chunk_locally(stripe_id)
        # Re-encode from the recovered plaintext.
        params = _en.params(manifest.k, manifest.m)
        shards = _en.encode(recovered, params)
        stripe_dir = self.shards_root / stripe_id.hex()
        rewritten = 0
        for shard in shards:
            # Same position-flatten as replicate_chunk_locally.
            position = shard.index if shard.role == "data" else params.k + shard.index
            target = stripe_dir / self.SHARD_FILENAME.format(index=position)
            if target.exists():
                continue
            tmp = target.with_suffix(".bin.tmp")
            tmp.write_bytes(shard.bytes)
            tmp.replace(target)
            rewritten += 1
        return rewritten

    # ── Internals ──────────────────────────────────────────────────

    def _write_manifest(self, stripe_dir: pathlib.Path, manifest: StripeManifest) -> None:
        body = (
            f"stripe_id={manifest.stripe_id.hex()}\n"
            f"k={manifest.k}\n"
            f"m={manifest.m}\n"
            f"plaintext_len={manifest.plaintext_len}\n"
            f"profile={manifest.profile}\n"
        )
        tmp = stripe_dir / (self.MANIFEST_FILENAME + ".tmp")
        tmp.write_text(body, encoding="utf-8")
        tmp.replace(stripe_dir / self.MANIFEST_FILENAME)

    def _read_manifest(self, stripe_dir: pathlib.Path) -> StripeManifest:
        text = (stripe_dir / self.MANIFEST_FILENAME).read_text(encoding="utf-8")
        fields: dict[str, str] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue
            k, v = line.split("=", 1)
            fields[k.strip()] = v.strip()
        return StripeManifest(
            stripe_id=bytes.fromhex(fields["stripe_id"]),
            k=int(fields["k"]),
            m=int(fields["m"]),
            plaintext_len=int(fields["plaintext_len"]),
            profile=fields.get("profile", "standard"),  # type: ignore[arg-type]
        )

    def _load_stripe(
        self, stripe_id: bytes,
    ) -> tuple[StripeManifest, list[Optional[object]]]:
        stripe_dir = self.shards_root / stripe_id.hex()
        if not stripe_dir.is_dir():
            raise FileNotFoundError(
                f"stripe {stripe_id.hex()[:16]} not present locally"
            )
        manifest = self._read_manifest(stripe_dir)
        params = _en.params(manifest.k, manifest.m)
        total = manifest.k + manifest.m
        present: list[Optional[object]] = []
        for position in range(total):
            path = stripe_dir / self.SHARD_FILENAME.format(index=position)
            if not path.exists():
                present.append(None)
                continue
            shard_bytes = path.read_bytes()
            # Reconstruct a Shard object so decode_stripe receives
            # the same type encode produced. The native crate uses
            # per-role indices (data: 0..k, parity: 0..m), so we
            # reverse the position → (role, index) mapping that
            # `replicate_chunk_locally` baked into the filename.
            if position < manifest.k:
                role = "data"
                role_index = position
            else:
                role = "parity"
                role_index = position - manifest.k
            present.append(_native_make_shard(
                stripe_id=manifest.stripe_id,
                index=role_index,
                role=role,
                plaintext_len=manifest.plaintext_len,
                shard_bytes=shard_bytes,
            ))
        return manifest, present


def _native_make_shard(
    *,
    stripe_id: bytes,
    index: int,
    role: str,
    plaintext_len: int,
    shard_bytes: bytes,
):
    """Reconstruct an ``ol_erasure.Shard`` from on-disk bytes.

    The native crate exposes a constructor when available; otherwise
    we fall back to the wire-level reconstruction helper if shipped.
    Today the native module exposes ``Shard.from_bytes`` (preferred)
    OR a positional ctor — try both.
    """
    _en._require_native()
    from one_link_native import erasure as _native_erasure  # type: ignore[import-not-found]
    Shard = _native_erasure.Shard
    # Preferred surface: kwargs constructor (matches the crate's
    # PyClass new method shape).
    try:
        return Shard(
            stripe_id=stripe_id,
            index=index,
            role=role,
            plaintext_len=plaintext_len,
            bytes=shard_bytes,
        )
    except TypeError:
        # Older surface: positional ctor.
        return Shard(stripe_id, index, role, plaintext_len, shard_bytes)
