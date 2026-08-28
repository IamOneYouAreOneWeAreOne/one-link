"""Every "cannot reach the other device" cause must be named, not waited out.

`peers` printed "(no peers discovered yet - give it a few seconds)" for every
cause. A user whose firewall rule was orphaned, whose Wi-Fi was on a guest
network, or whose other machine was simply switched off all got the same
sentence, and only one of those three is fixed by waiting.

diagnose() is pure, so each branch below is reached with constructed facts --
no firewall, no network, no peer required. The point is that these tests CAN
fail: change a threshold and the matching case flips.
"""

from __future__ import annotations

from one_link import reachability_doctor as rd


def _healthy(**over) -> rd.ReachabilityFacts:
    """A device that is fully working; each test breaks exactly one thing."""

    base = dict(
        platform="win32",
        daemon_running=True,
        peer_port=55101,
        peer_port_listening=True,
        mdns_self_visible=True,
        mdns_peers_visible=1,
        mdns_other_hosts=4,
        network_profile="Private",
        firewall_enabled=True,
        executable_path=r"C:\python.exe",
        firewall_allow_matches_executable=True,
        firewall_block_matches_executable=False,
        lan_addresses=("192.168.1.142",),
    )
    base.update(over)
    return rd.ReachabilityFacts(**base)


def test_a_healthy_device_reports_ok() -> None:
    d = rd.diagnose(_healthy())
    assert d.cause == rd.CAUSE_OK
    assert d.ok and d.severity == rd.SEVERITY_OK
    assert not d.remedy, "a working device must not be handed chores"


def test_daemon_not_listening_beats_every_other_finding() -> None:
    """If we are not listening, nothing about the network matters yet."""

    d = rd.diagnose(_healthy(
        daemon_running=False, peer_port_listening=False,
        mdns_other_hosts=0, mdns_peers_visible=0, mdns_self_visible=False,
        firewall_block_matches_executable=True,
    ))
    assert d.cause == rd.CAUSE_DAEMON_DOWN
    assert d.severity == rd.SEVERITY_BLOCKED


def test_a_block_rule_is_reported_before_a_missing_allow_rule() -> None:
    """Order matters here more than anywhere: with a Block rule present, the
    obvious remedy (add an Allow rule) is the WRONG one, because Windows
    applies Block first."""

    d = rd.diagnose(_healthy(
        firewall_block_matches_executable=True,
        firewall_allow_matches_executable=False,
        network_profile="Public",
        mdns_peers_visible=0,
    ))
    assert d.cause == rd.CAUSE_INBOUND_BLOCKED
    assert any("Block before Allow" in s for s in (d.detail,)), d.detail
    assert any("delete" in step.lower() for step in d.remedy)


def test_hearing_nothing_at_all_is_a_local_problem_not_an_absent_peer() -> None:
    """No router, no printer, nothing -> our receive path, not their machine."""

    d = rd.diagnose(_healthy(mdns_other_hosts=0, mdns_peers_visible=0))
    assert d.cause == rd.CAUSE_MULTICAST_DEAF
    assert d.severity == rd.SEVERITY_BLOCKED
    assert any("VPN" in step for step in d.remedy)


def test_hearing_others_but_not_announcing_is_its_own_cause() -> None:
    d = rd.diagnose(_healthy(mdns_self_visible=False, mdns_peers_visible=0))
    assert d.cause == rd.CAUSE_NOT_ANNOUNCING
    assert d.severity == rd.SEVERITY_BLOCKED


def test_healthy_local_side_with_no_peer_blames_the_other_machine() -> None:
    """The exact case the old message hid, and the one seen in the field."""

    d = rd.diagnose(_healthy(mdns_peers_visible=0, mdns_other_hosts=4))
    assert d.cause == rd.CAUSE_PEER_ABSENT
    assert "not on this network" in d.headline
    assert any("SAME Wi-Fi" in step for step in d.remedy)
    assert any("192.168.1.142" in step for step in d.remedy), (
        "the remedy must show the subnet the other machine has to join"
    )


def test_a_missing_firewall_rule_does_not_masquerade_as_the_cause() -> None:
    """The discipline test.

    When no peer is advertising, the firewall CANNOT be why -- mDNS is
    multicast and independent of the TCP rule, so a present peer would still be
    visible. Reporting the firewall here would send the user to fix something
    real but unrelated and leave the actual problem untouched. It must appear
    as a secondary finding instead.
    """

    d = rd.diagnose(_healthy(
        mdns_peers_visible=0,
        network_profile="Public",
        firewall_allow_matches_executable=False,
    ))
    assert d.cause == rd.CAUSE_PEER_ABSENT, "firewall stole the diagnosis"
    assert any("firewall rule allows inbound" in item for item in d.also), (
        "the latent firewall problem must still be reported, just not as THE cause"
    )


def test_peers_visible_but_no_inbound_rule_is_warned_not_silenced() -> None:
    """Discovery works, transfers may not. Saying nothing until it bites is
    exactly how this class of bug stayed invisible."""

    d = rd.diagnose(_healthy(
        mdns_peers_visible=2,
        network_profile="Public",
        firewall_allow_matches_executable=False,
    ))
    assert d.cause == rd.CAUSE_FIREWALL_RULE_STALE
    assert d.severity == rd.SEVERITY_WARN, "traffic flows, so this is not 'blocked'"
    assert "connect TO this device" in d.headline
    assert any("New-NetFirewallRule" in step for step in d.remedy)
    assert r"C:\python.exe" in d.remedy[0], "the remedy must name the real path"


def test_an_unread_firewall_is_never_reported_as_a_problem() -> None:
    """None means 'we could not look', which is not the same as 'no rule'.

    Collapsing those two is how a diagnostic starts inventing faults on
    machines it cannot inspect -- a macOS box, or a locked-down Windows one.
    """

    d = rd.diagnose(_healthy(
        platform="darwin",
        network_profile=None,
        firewall_enabled=None,
        firewall_allow_matches_executable=None,
        firewall_block_matches_executable=None,
        mdns_peers_visible=0,
    ))
    assert d.cause == rd.CAUSE_PEER_ABSENT
    assert not any("firewall" in item.lower() for item in d.also), d.also


def test_a_private_network_without_a_rule_is_not_called_blocked() -> None:
    """The Public profile is what makes the missing rule bite. Firing on
    Private too would cry wolf on the machines that work."""

    d = rd.diagnose(_healthy(
        mdns_peers_visible=2,
        network_profile="Private",
        firewall_allow_matches_executable=False,
    ))
    assert d.cause == rd.CAUSE_OK
    assert any("firewall rule allows inbound" in item for item in d.also)


def test_stale_block_rules_are_reported_without_hijacking_the_verdict() -> None:
    d = rd.diagnose(_healthy(stale_block_rules=12))
    assert d.cause == rd.CAUSE_OK
    assert d.severity == rd.SEVERITY_OK
    assert any("no longer exist" in item for item in d.also)


def test_render_shows_verdict_remedy_and_secondary_findings() -> None:
    d = rd.diagnose(_healthy(
        mdns_peers_visible=0,
        network_profile="Public",
        firewall_allow_matches_executable=False,
        stale_block_rules=3,
    ))
    text = d.render()
    assert "[WARN]" in text
    assert "What to do:" in text
    assert "Also worth fixing" in text
    assert "1." in text and "- " in text


def test_summarize_marks_unknown_facts_distinctly_from_negative_ones() -> None:
    text = rd.summarize(_healthy(
        firewall_allow_matches_executable=None,
        firewall_block_matches_executable=False,
    ))
    rows = {line.strip().rsplit(" ", 1)[0].strip(): line.strip().rsplit(" ", 1)[1]
            for line in text.splitlines() if line.strip()}
    assert rows["firewall allows this program"] == "?", rows
    assert rows["firewall blocks this program"] == "NO", rows
    assert rows["firewall allows this program"] != rows["firewall blocks this program"], (
        "unknown and false must be visually distinct, or the reader cannot tell "
        "'we did not look' from 'we looked and it is missing'"
    )


def test_every_cause_constant_is_reachable_from_diagnose() -> None:
    """No dead vocabulary: a cause nothing can emit is a lie in the docs."""

    cases = [
        _healthy(),
        _healthy(daemon_running=False, peer_port_listening=False),
        _healthy(firewall_block_matches_executable=True),
        _healthy(mdns_other_hosts=0, mdns_peers_visible=0),
        _healthy(mdns_self_visible=False, mdns_peers_visible=0),
        _healthy(mdns_peers_visible=0),
        _healthy(mdns_peers_visible=2, network_profile="Public",
                 firewall_allow_matches_executable=False),
    ]
    seen = {rd.diagnose(f).cause for f in cases}
    expected = {
        rd.CAUSE_OK, rd.CAUSE_DAEMON_DOWN, rd.CAUSE_INBOUND_BLOCKED,
        rd.CAUSE_MULTICAST_DEAF, rd.CAUSE_NOT_ANNOUNCING, rd.CAUSE_PEER_ABSENT,
        rd.CAUSE_FIREWALL_RULE_STALE,
    }
    assert seen == expected, f"unreachable causes: {expected - seen}"


def test_program_path_is_resolved_before_it_is_compared(tmp_path) -> None:
    """The false alarm this exact helper exists to prevent.

    Windows matches a firewall rule against the RESOLVED image path. uv ships
    its interpreter behind a junction, so the path a process reports and the
    path a rule stores can differ by a whole directory name while pointing at
    one file. Comparing them unresolved finds no rule and invents a firewall
    fault on a machine whose firewall is correct -- which is precisely the
    wrong conclusion I reached by hand before this helper existed.
    """

    real_dir = tmp_path / "cpython-3.12.13-windows-x86_64-none"
    real_dir.mkdir()
    real = real_dir / "python.exe"
    real.write_text("binary", encoding="utf-8")

    link_dir = tmp_path / "cpython-3.12-windows-x86_64-none"
    try:
        link_dir.symlink_to(real_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        # Windows refuses symlinks without elevation or developer mode, but a
        # JUNCTION needs neither -- and a junction is what uv actually uses, so
        # falling back here makes the test exercise the real-world shape rather
        # than skipping on the very platform the bug lives on.
        import subprocess

        made = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link_dir), str(real_dir)],
            capture_output=True, text=True, check=False,
        )
        if made.returncode != 0 or not link_dir.exists():
            import pytest

            pytest.skip(f"cannot create a symlink or junction here: {made.stderr.strip()}")

    via_link = link_dir / "python.exe"
    assert rd.normalized_program_path(str(via_link)) == rd.normalized_program_path(str(real)), (
        "the linked and real interpreter paths must compare equal, or the "
        "firewall check reports a missing rule that is actually present"
    )
    assert "3.12.13" in rd.normalized_program_path(str(via_link))
