"""Replay-window protection for authenticated peer frames.

The window accepts new sequence numbers, accepts limited reordering, and
rejects duplicated or too-old frames. It is intentionally independent from
the wire/channel code so every future frame family can share the same
deterministic semantics.
"""

from __future__ import annotations

from dataclasses import dataclass


ACCEPT_NEW = "accept_new"
ACCEPT_REORDER = "accept_reorder"
REJECT_REPLAY = "reject_replay"
REJECT_TOO_OLD = "reject_too_old"
REJECT_BAD_SEQUENCE = "reject_bad_sequence"
REJECT_BAD_TIMESTAMP = "reject_bad_timestamp"


@dataclass(frozen=True)
class ReplayDecision:
    accepted: bool
    outcome: str
    high_water: int | None
    detail: str = ""


class ReplayWindow:
    """Sliding replay window with timestamp skew checks."""

    def __init__(
        self,
        *,
        window_size: int = 64,
        max_age_ms: int = 5 * 60 * 1000,
        max_future_skew_ms: int = 2 * 60 * 1000,
    ):
        if window_size <= 0:
            raise ValueError("window_size must be positive")
        if max_age_ms < 0:
            raise ValueError("max_age_ms must be non-negative")
        if max_future_skew_ms < 0:
            raise ValueError("max_future_skew_ms must be non-negative")
        self.window_size = window_size
        self.max_age_ms = max_age_ms
        self.max_future_skew_ms = max_future_skew_ms
        self.high_water: int | None = None
        self._bitmap = 0
        self._mask = (1 << window_size) - 1

    def check(self, *, seq: int, now_ms: int, ts_ms: int) -> ReplayDecision:
        """Validate and record a frame sequence number."""
        if not isinstance(seq, int) or seq < 0:
            return ReplayDecision(
                False,
                REJECT_BAD_SEQUENCE,
                self.high_water,
                "negative or non-integer sequence",
            )
        if not isinstance(now_ms, int) or not isinstance(ts_ms, int):
            return ReplayDecision(
                False,
                REJECT_BAD_TIMESTAMP,
                self.high_water,
                "timestamps must be integers",
            )
        if ts_ms < now_ms - self.max_age_ms:
            return ReplayDecision(
                False, REJECT_BAD_TIMESTAMP, self.high_water, "timestamp too old"
            )
        if ts_ms > now_ms + self.max_future_skew_ms:
            return ReplayDecision(
                False,
                REJECT_BAD_TIMESTAMP,
                self.high_water,
                "timestamp too far in future",
            )

        if self.high_water is None:
            self.high_water = seq
            self._bitmap = 1
            return ReplayDecision(True, ACCEPT_NEW, self.high_water)

        if seq > self.high_water:
            shift = seq - self.high_water
            if shift >= self.window_size:
                self._bitmap = 0
            else:
                self._bitmap = (self._bitmap << shift) & self._mask
            self.high_water = seq
            self._bitmap |= 1
            return ReplayDecision(True, ACCEPT_NEW, self.high_water)

        offset = self.high_water - seq
        if offset >= self.window_size:
            return ReplayDecision(
                False,
                REJECT_TOO_OLD,
                self.high_water,
                "sequence outside replay window",
            )

        bit = 1 << offset
        if self._bitmap & bit:
            return ReplayDecision(
                False, REJECT_REPLAY, self.high_water, "sequence already seen"
            )

        self._bitmap |= bit
        return ReplayDecision(True, ACCEPT_REORDER, self.high_water)

    def snapshot(self) -> dict:
        return {
            "window_size": self.window_size,
            "max_age_ms": self.max_age_ms,
            "max_future_skew_ms": self.max_future_skew_ms,
            "high_water": self.high_water,
            "bitmap": self._bitmap,
        }
