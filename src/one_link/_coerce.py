"""Typed coercion helpers for JSON-parsed (`object`-typed) values.

`json.loads` / `Mapping[str, object]` fields arrive as `object`, which the
`int()` / `float()` builtins reject under mypy (they want
`str | SupportsInt | ...`). These helpers do the same runtime coercion the
call sites already relied on, but with an honest signature so the checker
is satisfied without scattering `# type: ignore` or `cast(...)` around.

They raise `TypeError` (non-numeric type) or `ValueError` (bad numeric
string) — exactly what a bare `int(value)` would, so existing
`except (TypeError, ValueError)` handling keeps working.
"""

from __future__ import annotations


def to_int(value: object) -> int:
    """Coerce a JSON-parsed value to `int`, raising on a non-numeric value."""
    if isinstance(value, (int, float, str)):
        return int(value)
    raise TypeError(f"expected a number, got {type(value).__name__}")


def to_float(value: object) -> float:
    """Coerce a JSON-parsed value to `float`, raising on a non-numeric value."""
    if isinstance(value, (int, float, str)):
        return float(value)
    raise TypeError(f"expected a number, got {type(value).__name__}")
