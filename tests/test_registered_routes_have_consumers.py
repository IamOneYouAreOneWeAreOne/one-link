"""HTTP surface that nothing calls and nothing tests is surface nobody checks.

Audit finding (2026-08-05), from asking what the source REGISTERS that nothing
else can reach. Of 170 registered routes, 17 have no reference in any shipped
web asset. Most of those are legitimate machine APIs -- /api/metrics for a
monitor, /api/events for a stream -- and every one of them has tests.

Two had neither a consumer NOR a test:

    GET /api/capability-audit   the capability audit trail
    GET /api/update/plan        the standalone release contract

/api/update/plan is the sharper one. It calls
`_external_update_capability(fresh=True)`, which is the code path changed on
2026-08-04 to fix macOS self-install -- so that change could have broken this
endpoint and nothing would have reported it. An untested endpoint on the update
path is exactly where a silent break is most expensive.

These tests give both a consumer of last resort: the suite itself. They assert
the contract each endpoint promises, not merely that it returns 200.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from aiohttp import web

from one_link.server import UIServer


def _routes() -> dict[tuple[str, str], str]:
    """Every registered (method, path) -> handler name, without booting a UI."""
    server = UIServer.__new__(UIServer)
    server.app = web.Application()
    server._setup_routes()
    out: dict[tuple[str, str], str] = {}
    for resource in server.app.router.resources():
        for route in resource:
            info = route.get_info()
            path = info.get("path") or info.get("formatter") or ""
            out[(route.method, path)] = route.handler.__qualname__
    return out


def test_the_route_table_is_readable() -> None:
    """Control: an empty table would make every assertion below vacuous."""
    routes = _routes()
    assert len(routes) > 100, f"only {len(routes)} routes registered"


@pytest.mark.parametrize(
    "method,path",
    [("GET", "/api/capability-audit"), ("GET", "/api/update/plan")],
)
def test_the_previously_untested_endpoints_are_still_registered(
    method: str, path: str
) -> None:
    """If one is deleted, delete its tests here too -- deliberately.

    Both were reachable from nothing. That is a fine reason to REMOVE an
    endpoint, but removing it must be a decision someone makes, not something
    that drifts. Either way this test has to be edited.
    """
    assert (method, path) in _routes(), f"{method} {path} is no longer registered"


@pytest.mark.parametrize(
    "method,path",
    [("GET", "/api/capability-audit"), ("GET", "/api/update/plan")],
)
def test_both_endpoints_are_authenticated(method: str, path: str) -> None:
    """Neither may become public surface.

    /api/capability-audit returns a security audit trail; /api/update/plan
    describes the exact release artifacts this daemon would install. Both are
    behind `_guarded` today, and an audit of the whole table found 120 of 138
    registrations guarded with every exception explained -- so a NEW unguarded
    one would be an anomaly, not a pattern.
    """
    handler = _routes()[(method, path)]
    assert handler.startswith("UIServer._guarded."), (
        f"{method} {path} is registered unguarded (handler {handler})"
    )


@pytest.mark.asyncio
async def test_capability_audit_refuses_when_state_is_unavailable() -> None:
    """The documented failure mode, which nothing exercised."""
    server = UIServer.__new__(UIServer)
    server.daemon = SimpleNamespace(state=None)
    response = await server.api_capability_audit(
        SimpleNamespace(query={})  # type: ignore[arg-type]
    )
    assert response.status == 503


@pytest.mark.asyncio
async def test_capability_audit_clamps_a_hostile_limit() -> None:
    """`limit` is caller-controlled and reaches a database query.

    The handler clamps to [1, 1000] and falls back to 200 on garbage. Nothing
    tested that, so an unbounded or negative limit reaching the query would not
    have been noticed.
    """
    seen: list[int] = []

    class _State:
        def recent_capability_audit(self, *, fingerprint, limit):
            seen.append(limit)
            return []

    server = UIServer.__new__(UIServer)
    server.daemon = SimpleNamespace(state=_State())

    for supplied, expected in (
        ("999999", 1000),   # clamped down
        ("0", 1),           # clamped up
        ("-5", 1),          # negative clamped up
        ("banana", 200),    # unparseable falls back
        (None, 200),        # absent falls back
    ):
        query = {} if supplied is None else {"limit": supplied}
        await server.api_capability_audit(
            SimpleNamespace(query=query)  # type: ignore[arg-type]
        )
        assert seen[-1] == expected, (
            f"limit={supplied!r} reached the query as {seen[-1]}, expected {expected}"
        )
