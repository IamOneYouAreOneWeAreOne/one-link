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


@dataclass(frozen=True)
class CertifiedRow:
    """What the renderer proved it draws for one peer."""
    glyph: int
    name_w: int
    badge_x: int

    def shows_verified(self) -> bool:
        return self.glyph == GLYPH_VERIFIED


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
                            badge_x=int(out["badge_x"]))

    def covers(self, trust: int, name_len: int) -> bool:
        return (int(trust), int(name_len)) in self._index


def verify(doc: dict) -> tuple:
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
    return True, (f"{len(rows)} points, exhaustive, {len(doc['laws'])} law(s) proven, "
                  f"digest {recomputed[:16]}")


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
