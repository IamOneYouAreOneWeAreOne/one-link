"""The peer row is drawn from a PROVEN renderer — and this module is why that can ship.

One Link tells a user what to trust over a channel whose other end is a stranger. The row that says
so is ordinary UI code: a badge, a name, a width. In every app ever shipped, "the verified badge only
appears for verified peers" is a convention enforced by code review, and the failure mode is silent.

Here it is a theorem. Three laws are discharged over **every integer input** by the Coherence prover
in the `idem` repo, at build time:

    the-verified-glyph-requires-verified-trust    scope: exact
    the-name-never-runs-under-the-badge           scope: exact
    nothing-is-drawn-outside-the-row              scope: exact

WHY A TABLE AND NOT A PROVER. One Link ships as a PyInstaller bundle. Importing the prover would drag
in a research checkout, a solver, and `coherence_lang` to put a badge on a row — so the proof stays
at build time and what ships is its ANSWERS: `data/certified/peer_row.json`, a table over the
declared state space, with a digest. This module is the whole runtime cost: stdlib only, no
network, no `idem`, no `coherence_lang`.

WHAT THE LAWS BOUGHT, CONCRETELY. The first version of that renderer clamped only the high side of
the name width — the clamp anybody writes, because the failure you picture is a long name
overflowing. `nothing-is-drawn-outside-the-row` came back **refuted** and the emitter refused to
produce a table at all. The witness: a negative `name_len`, or one large enough that `name_len * 8`
wraps in i64, yields a **negative width**. No test written against plausible names would have found
it, and no reviewer would have looked.

FAIL CLOSED, AND SAY SO. A table whose digest does not match its rows, or that is missing a point of
its declared space, is REFUSED at load — `available()` goes False and the UI falls back to its
ordinary rendering path. A surface that silently drew from an unverified table would be worse than
one that never claimed anything, because the claim is the product.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("one_link.certified_surface")

SCHEMA = "idem-certified-view/v1"

#: Lives under `data/` because that subtree is ALREADY inside the packaging contract: the wheel's
#: package-data list, PyInstaller's `--add-data`, and `validate_python_distributions.py`'s source
#: scan (which walks exactly `data` and `web`). A new top-level directory would have been
#: invisible to that scan and shipped in a wheel that looked valid.
DEFAULT_ARTIFACT = Path(__file__).resolve().parent / "data" / "certified" / "peer_row.json"

#: The glyph the whole security argument is about. Named here so a reader of THIS file can see what
#: the law protects without opening the prover repo.
GLYPH_VERIFIED = 7

#: WHO IS ALLOWED TO HAVE PRODUCED THIS TABLE.
#:
#: The digest binds the artifact to ITSELF: edit an answer and it stops matching. But an adversary
#: who edits an answer AND recomputes the digest produces a perfectly self-consistent file, because
#: a hash is not an identity. Only a signature makes FABRICATION fail rather than merely editing —
#: and only a PINNED signer makes the signature mean anything, since verifying against whatever key
#: the artifact names is verifying against its author.
#:
#: ⚠ THIS IS A DEVELOPMENT KEY. It is derived from a published phrase
#: (`one-link/certified-view/DEVELOPMENT-KEY/not-for-release/v1`), so anyone can produce a table
#: this build accepts. That is deliberate and temporary: it makes the whole path — sign, pin,
#: verify, fail closed — real and testable now, instead of a TODO. `test_certified_surface.py`
#: FAILS THE BUILD if a non-alpha version still pins it, so the key cannot quietly ride into a
#: release. Replace with the release role pubkey and drop this entry.
DEVELOPMENT_SIGNER = "6c73b5addfbc1dcd82adb15738c954b2fa0e0e49ae92a93451ae7c9f2ff9df51"

TRUSTED_VIEW_SIGNERS: frozenset = frozenset({DEVELOPMENT_SIGNER})

#: Domain separator for the signed bytes. Must match `idem/certified_view.py::_signable` exactly —
#: a divergence here does not fail loudly, it simply rejects every honest artifact.
_SIG_DOMAIN = b"idem-view-sig/v1\x00"


def _canon(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def table_digest(rows: Any) -> str:
    """Re-derive the table's content address.

    Byte-for-byte the producer's rule (`idem/certified_view.py::table_digest`). It hashes the ROWS
    ALONE — not the provenance beside them — so the number stays a statement about what is drawn and
    does not move when a comment does.
    """
    d = hashlib.sha256()
    d.update(b"idem-view-table/v1")
    d.update(_canon(list(rows)))
    return d.hexdigest()


#: What a screen reader says, as ids the PROOF chose. The words are the product's; the CHOICE is
#: a theorem. `the-spoken-label-cannot-contradict-the-pixel` is discharged over every integer input,
#: so a row showing the verified glyph and a row announcing "verified" are the same rows -- not by
#: construction, and not by review, but because the renderer emitting one emits the other.
LABEL_NONE, LABEL_KNOWN, LABEL_VERIFIED = 0, 1, 2

LABEL_TEXT = {
    LABEL_NONE: "Unverified device",
    LABEL_KNOWN: "Paired, not verified in person",
    LABEL_VERIFIED: "Verified in person",
}


@dataclass(frozen=True)
class CertifiedRow:
    """What the renderer proved it draws for one peer -- seen AND spoken."""
    glyph: int
    name_w: int
    badge_x: int
    label: int

    def shows_verified(self) -> bool:
        return self.glyph == GLYPH_VERIFIED

    def says_verified(self) -> bool:
        return self.label == LABEL_VERIFIED

    def spoken(self) -> str:
        """The accessible text. Unknown ids fall back to the most CONSERVATIVE label rather
        than to a blank: a row that announces nothing is worse than one that under-claims."""
        return LABEL_TEXT.get(self.label, LABEL_TEXT[LABEL_NONE])


class CertifiedSurface:
    """A loaded, verified render table. Construct via :func:`load`."""

    def __init__(self, doc: dict, *, source: Optional[Path] = None) -> None:
        self._doc = doc
        self._source = source
        self._index = {(r["in"]["trust"], r["in"]["name_len"]): r["out"] for r in doc["rows"]}

    # -- provenance a UI can show, and a reviewer can check ------------------------------------

    @property
    def digest(self) -> str:
        return str(self._doc["table_digest"])

    @property
    def laws(self) -> tuple:
        """((law_name, scope), ...) — every one proven, or the artifact would not exist."""
        return tuple((str(n), str(s)) for n, s in self._doc.get("laws", []))

    @property
    def member(self) -> str:
        return str(self._doc.get("member_mid", ""))

    def provenance(self) -> dict:
        """The shape the UI surfaces to a user who asks 'why should I believe this row?'"""
        return {
            "schema": self._doc.get("schema"),
            "digest": self.digest,
            "member": self.member,
            "laws": [{"name": n, "scope": s} for n, s in self.laws],
            "points": len(self._index),
            "source": str(self._source) if self._source else None,
        }

    # -- the read path ------------------------------------------------------------------------

    def row(self, trust: int, name_len: int) -> Optional[CertifiedRow]:
        """The proven layout for this peer, or None if outside the certified space.

        None is honest emptiness: the caller renders normally rather than being handed a guess.
        A table that extrapolated past its proven domain would be exactly the unproven code this
        replaces, wearing a digest.
        """
        out = self._index.get((int(trust), int(name_len)))
        if out is None:
            return None
        return CertifiedRow(glyph=int(out["glyph"]), name_w=int(out["name_w"]),
                            badge_x=int(out["badge_x"]), label=int(out.get("label", LABEL_NONE)))

    def covers(self, trust: int, name_len: int) -> bool:
        return (int(trust), int(name_len)) in self._index


def _signable(doc: dict) -> bytes:
    """The exact bytes the signature covers: everything EXCEPT the signature fields.

    Built by EXCLUSION, mirroring the producer, so a field added to the artifact tomorrow is covered
    by default. A signature whose scope is a hand-maintained list of keys is a signature that
    silently stops covering the newest thing anyone added.
    """
    body = {k: v for k, v in doc.items() if k not in ("signature", "signer")}
    return _SIG_DOMAIN + _canon(body)


def signature_ok(doc: dict, *, trusted: frozenset = TRUSTED_VIEW_SIGNERS) -> tuple:
    """(ok, reason) for the artifact's identity. Ed25519, stdlib + `cryptography` only."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    signer = str(doc.get("signer") or "")
    sig = str(doc.get("signature") or "")
    if not signer or not sig:
        return False, ("the artifact is UNSIGNED — its digest proves only that nobody EDITED it, "
                       "and a fabricated table with a freshly computed digest is self-consistent")
    if signer not in trusted:
        return False, (f"signed by {signer[:16]}, which is not a pinned signer — an artifact "
                       "verified against whatever key it names is verified against its author")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer)).verify(
            bytes.fromhex(sig), _signable(doc))
    except (InvalidSignature, ValueError):
        return False, "SIGNATURE INVALID: this is not the artifact that was signed"
    return True, f"signed by pinned {signer[:16]}"


def verify(doc: dict, *, trusted: frozenset = TRUSTED_VIEW_SIGNERS) -> tuple:
    """(ok, reason). Everything checkable without the producer.

    Deliberately dependency-free: this is what the product, a reviewer, or a stranger runs, and it
    must not need the machine that made the table.
    """
    if doc.get("schema") != SCHEMA:
        return False, f"unknown schema {doc.get('schema')!r}"

    rows = doc.get("rows")
    if not isinstance(rows, list) or not rows:
        return False, "the artifact carries no rows"

    recomputed = table_digest(rows)
    if recomputed != doc.get("table_digest"):
        return False, (f"DIGEST MISMATCH: rows hash to {recomputed[:16]}, artifact claims "
                       f"{str(doc.get('table_digest'))[:16]} — the answers were edited after they "
                       "were certified")

    axes = (doc.get("space") or {}).get("axes") or []
    if not axes:
        return False, "the artifact declares no state space, so 'exhaustive' means nothing"
    expected = 1
    for _name, values in axes:
        expected *= len(values)
    if len(rows) != expected:
        return False, (f"the space declares {expected} points, the table carries {len(rows)} — an "
                       "incomplete table is a broken surface, not a smaller one")

    if not doc.get("laws"):
        return False, ("no proven laws — this would be a lookup table with a hash, which is "
                       "precisely what the format exists not to be")

    # IDENTITY LAST, and it is not optional. Everything above is self-referential: it proves the
    # artifact is internally consistent, which a competent forger also achieves.
    signed, why_sig = signature_ok(doc, trusted=trusted)
    if not signed:
        return False, why_sig

    return True, (f"{len(rows)} points, exhaustive, {len(doc['laws'])} law(s) proven, "
                  f"digest {recomputed[:16]}, {why_sig}")


def load(path: Optional[Path] = None) -> Optional[CertifiedSurface]:
    """Load and VERIFY the certified surface. None on any failure — never a partial surface.

    Every failure is logged with its reason. A surface that vanished quietly would leave the UI
    rendering unproven rows while the code still claimed a proven one.
    """
    target = Path(path) if path is not None else DEFAULT_ARTIFACT
    try:
        doc = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError:
        log.info("certified surface absent at %s; rendering falls back to ordinary layout", target)
        return None
    except (OSError, ValueError) as exc:
        log.warning("certified surface unreadable (%s): %s", target, exc)
        return None

    ok, why = verify(doc)
    if not ok:
        log.warning("certified surface REFUSED (%s): %s", target, why)
        return None
    log.info("certified surface loaded: %s", why)
    return CertifiedSurface(doc, source=target)


_CACHE: dict = {}


def surface() -> Optional[CertifiedSurface]:
    """Process-wide loaded surface, or None. Cached — the artifact does not change under a run."""
    if "s" not in _CACHE:
        _CACHE["s"] = load()
    return _CACHE["s"]


def available() -> bool:
    return surface() is not None
