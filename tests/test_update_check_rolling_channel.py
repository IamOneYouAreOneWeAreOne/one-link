"""An installed build must be able to discover that it is stale.

It could not. Two independent reasons, both verified against the live API:

  1. update_check polled ``/releases/latest``, which EXCLUDES prereleases. The
     only release this project publishes is the rolling prerelease every
     /download/* route serves, so GitHub answered:
         {"message": "Not Found", "status": "404"}
     fetch_latest turned that into status='unknown' and the UI stayed silent.

  2. Even reaching the rolling release would not have helped: its tag is
     ``auto-latest`` forever, and __version__ is ``0.21.0-alpha`` in every
     rolling build ever made. There was nothing to compare. Identity now comes
     from the build commit, stamped into the artifact at package time.

So a user who installed in May was still running May's bytes -- including a
startup crash behind antivirus -- and would never be told. These tests pin the
whole path, including that a source checkout is never nagged.
"""

from __future__ import annotations

import urllib.error

from one_link import build_info, update_check

_LOCAL = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
_REMOTE = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def _rolling_payload(commit: str, *, tag: str = "auto-latest") -> dict:
    return {
        "tag_name": tag,
        "name": f"Rolling build (master {commit})",
        "body": f"Rolling continuous build from master `{commit}`.",
        "published_at": "2026-07-27T02:00:00Z",
        "prerelease": True,
        "draft": False,
        "assets": [{"name": "one-link-setup-x86_64.exe"}],
    }


def _fetch_map(mapping: dict[str, object]):
    """A fetch hook that answers per-URL, raising 404 for absent entries."""

    def _fetch(url: str, timeout: float) -> dict:
        for fragment, value in mapping.items():
            if fragment in url:
                if isinstance(value, Exception):
                    raise value
                return value  # type: ignore[return-value]
        raise urllib.error.HTTPError(url, 404, "Not Found", None, None)

    return _fetch


def test_tagged_channel_404_falls_back_to_rolling_and_reports_stale() -> None:
    """The exact live situation: no tagged release, rolling is ahead."""

    result = update_check.check_for_update(
        "0.21.0-alpha",
        local_commit=_LOCAL,
        fetch=_fetch_map({"releases/tags/auto-latest": _rolling_payload(_REMOTE)}),
    )
    assert result.status == "newer", result
    assert result.channel == "rolling"
    assert result.latest_commit == _REMOTE
    assert result.local_commit == _LOCAL

    # The user must be told what to DO. A rolling build can never
    # self-install -- continuous builds hold no release authority -- so the
    # honest action is a download, and the note says why.
    payload = result.to_dict()
    assert payload["can_self_install"] is False
    assert payload["action"] == "download"
    assert "weareone-link.org/download" in payload["action_url"]
    assert "install authority" in payload["action_note"]


def test_matching_commit_is_reported_same_not_stale() -> None:
    result = update_check.check_for_update(
        "0.21.0-alpha",
        local_commit=_LOCAL,
        fetch=_fetch_map({"releases/tags/auto-latest": _rolling_payload(_LOCAL)}),
    )
    assert result.status == "same", result
    assert result.to_dict().get("action") is None, "no nag when already current"


def test_a_source_checkout_is_never_nagged() -> None:
    """An unknown local commit must not read as "different, therefore stale".

    Every developer running from source has no stamp. Comparing an unknown
    commit as though it were known would show a permanent update banner to the
    people least in need of one.
    """

    result = update_check.check_for_update(
        "0.21.0-alpha",
        local_commit="",
        fetch=_fetch_map({"releases/tags/auto-latest": _rolling_payload(_REMOTE)}),
    )
    assert result.status == "unknown", result
    assert result.to_dict().get("action") is None


def test_a_real_tagged_release_wins_over_rolling() -> None:
    """Fallback must not override an authoritative answer.

    On the day release.yml cuts a tag, that verdict is the truth and rolling
    must not be consulted -- including when the tagged answer is 'same'.
    """

    tagged = {
        "tag_name": "0.22.0",
        "name": "0.22.0",
        "published_at": "2026-08-01T00:00:00Z",
        "prerelease": False,
        "draft": False,
        "assets": [],
    }
    calls: list[str] = []

    def _fetch(url: str, timeout: float) -> dict:
        calls.append(url)
        if "releases/latest" in url:
            return tagged
        raise AssertionError("rolling must not be consulted when a tag exists")

    result = update_check.check_for_update(
        "0.21.0", local_commit=_LOCAL, fetch=_fetch
    )
    assert result.status == "newer"
    assert result.channel == "release"
    assert result.latest_version == "0.22.0"
    assert len(calls) == 1


def test_rolling_release_without_a_commit_is_unknown_not_stale() -> None:
    """A release whose title lost its commit must not imply staleness."""

    payload = _rolling_payload(_REMOTE)
    payload["name"] = "Rolling build"
    payload["body"] = "no commit recorded here"
    result = update_check.check_for_update(
        "0.21.0-alpha", local_commit=_LOCAL, fetch=_fetch_map({"tags/auto-latest": payload})
    )
    assert result.status == "unknown"
    assert "build commit" in (result.error or "")


def test_both_channels_unavailable_never_raises() -> None:
    """Offline must stay silent, not throw into the daemon's startup path."""

    def _fetch(url: str, timeout: float) -> dict:
        raise urllib.error.URLError("dns failure")

    result = update_check.check_for_update(
        "0.21.0-alpha", local_commit=_LOCAL, fetch=_fetch
    )
    assert result.status == "unknown"
    assert result.error and "network" in result.error


def test_commit_is_read_from_the_body_when_the_title_lacks_it() -> None:
    payload = _rolling_payload(_REMOTE)
    payload["name"] = "Rolling build"
    result = update_check.check_for_update(
        "0.21.0-alpha", local_commit=_LOCAL, fetch=_fetch_map({"tags/auto-latest": payload})
    )
    assert result.status == "newer"
    assert result.latest_commit == _REMOTE


def test_malformed_rolling_payloads_fail_closed() -> None:
    for bad in ([], "string", 42, {"assets": "nope", "name": f"x {_REMOTE}"}):
        result = update_check.check_for_update(
            "0.21.0-alpha",
            local_commit=_LOCAL,
            fetch=_fetch_map({"tags/auto-latest": bad}),
        )
        assert result.status == "unknown", bad


def test_build_stamp_round_trip_and_refusals(tmp_path) -> None:
    """The stamp is the new source of truth, so it must fail closed."""

    import json

    path = tmp_path / build_info.STAMP_FILENAME
    build_info.write_stamp(path, commit=_LOCAL, built_at="2026-07-27T02:00:00Z", channel="rolling")
    written = json.loads(path.read_text(encoding="utf-8"))
    assert written["commit"] == _LOCAL
    assert written["channel"] == "rolling"

    for bad_commit in ("", "abc", _LOCAL[:-1], "z" * 40, None):
        try:
            build_info.write_stamp(
                path, commit=bad_commit, built_at="x", channel="rolling"  # type: ignore[arg-type]
            )
        except ValueError:
            continue
        raise AssertionError(f"accepted an invalid commit: {bad_commit!r}")

    try:
        build_info.write_stamp(path, commit=_LOCAL, built_at="x", channel="nonsense")
    except ValueError:
        pass
    else:
        raise AssertionError("accepted an invalid channel")


def test_a_bundled_stamp_is_read_back_as_this_build_s_identity(tmp_path, monkeypatch) -> None:
    """End of the chain: what the packager writes is what the app reads.

    Without this the stamp could be written correctly and still never found,
    leaving every artifact permanently 'unknown' and silent.
    """

    stamp = tmp_path / build_info.STAMP_FILENAME
    build_info.write_stamp(
        stamp, commit=_REMOTE, built_at="2026-07-27T03:00:00Z", channel="rolling"
    )
    monkeypatch.setattr(build_info, "_candidate_paths", lambda: [stamp])

    assert build_info.build_commit() == _REMOTE
    assert build_info.build_channel() == "rolling"
    assert build_info.built_at() == "2026-07-27T03:00:00Z"

    # And an installed build carrying that stamp compares as current.
    result = update_check.check_for_update(
        "0.21.0-alpha",
        local_commit=build_info.build_commit(),
        fetch=_fetch_map({"tags/auto-latest": _rolling_payload(_REMOTE)}),
    )
    assert result.status == "same"


def test_a_corrupt_stamp_degrades_to_unknown_not_to_a_wrong_commit(
    tmp_path, monkeypatch
) -> None:
    stamp = tmp_path / build_info.STAMP_FILENAME
    for junk in ("", "{", '{"commit": "short"}', '{"commit": 42}', "[]"):
        stamp.write_text(junk, encoding="utf-8")
        monkeypatch.setattr(build_info, "_candidate_paths", lambda: [stamp])
        assert build_info.build_commit() == "", junk


def test_the_packager_stamps_the_real_commit(tmp_path) -> None:
    """scripts/build_binary.py must produce a stamp for the commit it packages."""

    import importlib.util
    import json
    import subprocess

    spec = importlib.util.spec_from_file_location(
        "_bb", "scripts/build_binary.py"
    )
    assert spec and spec.loader
    bb = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bb)

    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False
    ).stdout.strip().lower()
    if len(head) != 40:
        return  # no git available; the packager's own warning path covers this

    out = bb._write_build_stamp(tmp_path)
    assert out is not None and out.is_file()
    # PyInstaller keeps the source basename when bundling into a destination
    # directory, and build_info reads only STAMP_FILENAME — a stamp under any
    # other name ships but is invisible to the running app forever.
    from one_link.build_info import STAMP_FILENAME

    assert out.name == STAMP_FILENAME, (
        "stamp written under a name build_info can never read back"
    )
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["commit"] == head, "stamped a commit other than the one packaged"
    assert written["channel"] in {"rolling", "release"}


def test_unstamped_source_tree_reports_nothing_rather_than_guessing() -> None:
    """build_commit() must be empty in a checkout, not a fabricated value."""

    assert build_info.build_commit() == ""
    assert build_info.build_channel() == "source"
    assert build_info.describe()["commit"] == ""
