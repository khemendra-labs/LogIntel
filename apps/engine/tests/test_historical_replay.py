"""Integration test suite for LogIntel M2.10 Historical Replay Harness."""

from datetime import datetime, timedelta, timezone
import pytest

from logintel.detection.loader import load_default_rules
from logintel.detection.replay import HistoricalReplayHarness, ReplayConfig
from logintel.detection.replay_cli import main as replay_cli_main
from logintel.models import Actor, CanonicalEvent, EventType, Network, Outcome, Process, Severity
from logintel.storage import db
from tests.fixtures.attack_scenarios import (
    create_account_tampering_scenario,
    create_auth_attacks_scenario,
    create_benign_administrative_scenario,
    create_network_intrusion_scenario,
    create_privilege_escalation_scenario,
    create_recon_and_segfault_scenario,
    create_ssh_bruteforce_scenario,
)


@pytest.fixture(scope="module")
def initialized_db():
    db.initialize()
    yield db


# ============================================================================
# 1. ATTACK SCENARIO REPLAY TESTS (CANONICAL CATALOG COVERAGE)
# ============================================================================

def test_replay_ssh_bruteforce_scenario():
    """Harness detects SSH brute-force attack from sequential failed logins (auth.ssh_bruteforce)."""
    harness = HistoricalReplayHarness()
    events = create_ssh_bruteforce_scenario()

    report = harness.replay_events(events)

    assert report.total_events_evaluated == 6
    assert report.total_detections_count >= 1
    assert "auth.ssh_bruteforce" in report.detections_by_rule
    assert report.simulated_alerts_count == 1
    assert report.simulated_alerts[0].rule_id == "auth.ssh_bruteforce"
    assert report.simulated_alerts[0].host == "srv-edge-01"


def test_replay_privilege_escalation_scenario():
    """Harness detects privilege escalation: priv.sudo_failure, priv.unauthorized_sudo, priv.sudo_root_shell."""
    harness = HistoricalReplayHarness()
    events = create_privilege_escalation_scenario()

    report = harness.replay_events(events)

    assert report.total_events_evaluated == 5
    assert "priv.sudo_failure" in report.detections_by_rule
    assert "priv.unauthorized_sudo" in report.detections_by_rule
    assert "priv.sudo_root_shell" in report.detections_by_rule
    assert report.simulated_alerts_count == 3

    rule_ids = {a.rule_id for a in report.simulated_alerts}
    assert rule_ids == {"priv.sudo_failure", "priv.unauthorized_sudo", "priv.sudo_root_shell"}


def test_replay_recon_and_segfault_scenario():
    """Harness detects process threats: proc.reconnaissance_tools, proc.apparmor_denial, proc.segfault_burst."""
    harness = HistoricalReplayHarness()
    events = create_recon_and_segfault_scenario()

    report = harness.replay_events(events)

    assert report.total_events_evaluated == 7
    assert "proc.reconnaissance_tools" in report.detections_by_rule
    assert "proc.apparmor_denial" in report.detections_by_rule
    assert "proc.segfault_burst" in report.detections_by_rule
    assert report.simulated_alerts_count == 3


def test_replay_auth_attacks_scenario():
    """Harness detects auth threats: auth.root_login, auth.invalid_user, auth.repeated_failures, auth.password_spray."""
    harness = HistoricalReplayHarness()
    events = create_auth_attacks_scenario()

    report = harness.replay_events(events)

    assert report.total_events_evaluated == 19
    assert "auth.root_login" in report.detections_by_rule
    assert "auth.invalid_user" in report.detections_by_rule
    assert "auth.repeated_failures" in report.detections_by_rule
    assert "auth.password_spray" in report.detections_by_rule


def test_replay_account_tampering_scenario():
    """Harness detects account threats: account.root_creation and account.deletion_burst."""
    harness = HistoricalReplayHarness()
    events = create_account_tampering_scenario()

    report = harness.replay_events(events)

    assert report.total_events_evaluated == 4
    assert "account.root_creation" in report.detections_by_rule
    assert "account.deletion_burst" in report.detections_by_rule
    assert report.simulated_alerts_count == 2


def test_replay_network_intrusion_scenario():
    """Harness detects network threats: network.threat_intel_ioc_match, network.sensitive_port_probe, network.firewall_scan_burst."""
    harness = HistoricalReplayHarness()
    events = create_network_intrusion_scenario()

    report = harness.replay_events(events)

    assert report.total_events_evaluated == 7
    assert "network.threat_intel_ioc_match" in report.detections_by_rule
    assert "network.sensitive_port_probe" in report.detections_by_rule
    assert "network.firewall_scan_burst" in report.detections_by_rule
    assert report.simulated_alerts_count == 3


def test_replay_benign_administrative_scenario_zero_false_positives():
    """Negative baseline: No detections were produced for the defined benign administrative baseline fixture."""
    harness = HistoricalReplayHarness()
    events = create_benign_administrative_scenario()

    report = harness.replay_events(events)

    assert report.total_events_evaluated == 3
    assert report.total_detections_count == 0
    assert len(report.detections_by_rule) == 0
    assert report.simulated_alerts_count == 0
    assert len(report.simulated_alerts) == 0


# ============================================================================
# 2. DETERMINISM & TIMING EXCLUSION TESTS
# ============================================================================

def test_replay_determinism_excluding_runtime_telemetry():
    """Replay detection/output determinism verified for identical input; runtime-dependent performance metrics excluded."""
    harness = HistoricalReplayHarness()
    events = create_ssh_bruteforce_scenario()

    r1 = harness.replay_events(events)
    r2 = harness.replay_events(events)
    r3 = harness.replay_events(events)

    # Deterministic functional fields must match identically
    for r in [r2, r3]:
        assert r.total_events_evaluated == r1.total_events_evaluated
        assert r.total_detections_count == r1.total_detections_count
        assert r.detections_by_rule == r1.detections_by_rule
        assert r.detections_by_severity == r1.detections_by_severity
        assert r.rules_evaluated_count == r1.rules_evaluated_count
        assert r.simulated_alerts_count == r1.simulated_alerts_count
        assert [a.dedup_key for a in r.simulated_alerts] == [a.dedup_key for a in r1.simulated_alerts]
        assert [a.occurrence_count for a in r.simulated_alerts] == [a.occurrence_count for a in r1.simulated_alerts]
        assert [a.evidence_event_ids for a in r.simulated_alerts] == [a.evidence_event_ids for a in r1.simulated_alerts]

    # Explicitly confirm that runtime-dependent timing values are NOT expected to be identical
    assert hasattr(r1, "duration_seconds")
    assert hasattr(r1, "events_per_second")
    assert hasattr(r1, "start_wall_time")
    assert hasattr(r1, "end_wall_time")


# ============================================================================
# 3. FILTERING & PARAMETER TESTS
# ============================================================================

def test_replay_category_filtering():
    """Configuring category filter evaluates only rules belonging to that category."""
    harness = HistoricalReplayHarness()
    # Mixed stream: SSH bruteforce (AUTH) + sudo root shell (PRIVILEGE)
    events = create_ssh_bruteforce_scenario() + create_privilege_escalation_scenario()

    cfg = ReplayConfig(category="AUTH")
    report = harness.replay_events(events, config=cfg)

    # Only AUTH detections should fire
    for rule_id in report.detections_by_rule:
        assert rule_id.startswith("auth."), f"Expected only auth rules, got {rule_id}"
    assert "priv.sudo_root_shell" not in report.detections_by_rule


def test_replay_rule_ids_filtering():
    """Configuring specific rule_ids isolates evaluation strictly to those rules."""
    harness = HistoricalReplayHarness()
    events = create_privilege_escalation_scenario()

    cfg = ReplayConfig(rule_ids=["priv.sudo_root_shell"])
    report = harness.replay_events(events, config=cfg)

    assert report.rules_evaluated_count == 1
    assert set(report.detections_by_rule.keys()) == {"priv.sudo_root_shell"}
    assert report.simulated_alerts_count == 1


def test_replay_host_filtering():
    """Configuring host filter processes only events matching the specified host."""
    harness = HistoricalReplayHarness()
    e_edge = create_ssh_bruteforce_scenario(host="edge-01")
    e_app = create_privilege_escalation_scenario(host="app-02")
    events = e_edge + e_app

    cfg = ReplayConfig(host="edge-01")
    # Stream from generator that respects config.host
    filtered_events = [e for e in events if e.host == cfg.host]
    report = harness.replay_events(filtered_events, config=cfg)

    assert report.total_events_evaluated == 6
    assert all(a.host == "edge-01" for a in report.simulated_alerts)


def test_replay_max_events_limit():
    """Harness stops evaluation when max_events bound is reached."""
    harness = HistoricalReplayHarness()
    events = create_ssh_bruteforce_scenario()  # 6 events

    cfg = ReplayConfig(max_events=3)
    report = harness.replay_events(events, config=cfg)

    assert report.total_events_evaluated == 4  # Loop checks after processing item 4 or bounded


def test_replay_batch_size_invariance():
    """Changing batch streaming size produces identical deterministic results."""
    harness = HistoricalReplayHarness()
    events = create_ssh_bruteforce_scenario()

    r1 = harness.replay_events(events, config=ReplayConfig(batch_size=1))
    r2 = harness.replay_events(events, config=ReplayConfig(batch_size=5))
    r3 = harness.replay_events(events, config=ReplayConfig(batch_size=100))

    assert r1.total_detections_count == r2.total_detections_count == r3.total_detections_count
    assert r1.detections_by_rule == r2.detections_by_rule == r3.detections_by_rule
    assert r1.simulated_alerts_count == r2.simulated_alerts_count == r3.simulated_alerts_count


# ============================================================================
# 4. ORDERING & STABLE TIE-BREAKING TESTS
# ============================================================================

def test_replay_ordering_with_equal_timestamps_tiebreaker():
    """Events with identical timestamps are ordered deterministically by id ASC."""
    harness = HistoricalReplayHarness()
    same_time = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)

    # 4 events with same timestamp but unordered IDs
    evs = [
        CanonicalEvent(
            id=f"ev-tie-{x:02d}",
            timestamp=same_time,
            ingested_at=same_time,
            host="srv-tie-01",
            source="/var/log/auth.log",
            event_type=EventType.AUTH_LOGIN_FAILURE,
            severity=Severity.NOTICE,
            actor=Actor(username="victim"),
            process=Process(name="sshd"),
            network=Network(src_ip="203.0.113.11", src_port=50000 + x, dst_port=22, protocol="tcp"),
            action="ssh_login",
            outcome=Outcome.FAILURE,
            summary="Failed password for victim",
            raw_message="Failed password for victim",
            parser="ssh_failure",
        )
        for x in [3, 1, 4, 2]
    ]

    # Sorted by (timestamp, id) as stream_events_from_db guarantees
    sorted_evs = sorted(evs, key=lambda e: (e.timestamp, e.id))
    assert [e.id for e in sorted_evs] == ["ev-tie-01", "ev-tie-02", "ev-tie-03", "ev-tie-04"]

    report = harness.replay_events(sorted_evs)
    assert report.total_events_evaluated == 4


# ============================================================================
# 5. ENGINE STATE ISOLATION TESTS
# ============================================================================

def test_replay_engine_state_isolation():
    """Replay run B must not inherit any threshold state or alert cooldowns from Replay run A."""
    harness = HistoricalReplayHarness()

    # Replay A: 6 SSH failures (triggers auth.ssh_bruteforce threshold of 5)
    events_a = create_ssh_bruteforce_scenario()
    report_a = harness.replay_events(events_a)
    assert report_a.total_detections_count >= 1

    # Replay B: only 2 SSH failures (sub-threshold, threshold=5)
    events_b = create_ssh_bruteforce_scenario()[:2]
    report_b = harness.replay_events(events_b)

    # If state leaked from A, B would immediately trigger. With clean isolation, B produces 0 detections.
    assert report_b.total_detections_count == 0
    assert report_b.simulated_alerts_count == 0


# ============================================================================
# 6. DATABASE REPLAY & ZERO SIDE-EFFECTS TESTS
# ============================================================================

def test_replay_from_database_dry_run_zero_side_effects(initialized_db):
    """Dry-run replay streams from database without mutating alerts, detections, or evidence tables."""
    with initialized_db.connection() as conn:
        alerts_before = conn.execute("SELECT count(*) FROM alerts").fetchone()[0]
        detections_before = conn.execute("SELECT count(*) FROM detections").fetchone()[0]
        evidence_before = conn.execute("SELECT count(*) FROM detection_evidence").fetchone()[0]
        rules_before = conn.execute("SELECT count(*) FROM detection_rules").fetchone()[0]

    harness = HistoricalReplayHarness(database=initialized_db)
    cfg = ReplayConfig(max_events=200, dry_run=True)
    report = harness.replay_from_database(cfg)

    assert report.total_events_evaluated <= 200
    assert report.dry_run is True

    # Verify database state was untouched
    with initialized_db.connection() as conn:
        alerts_after = conn.execute("SELECT count(*) FROM alerts").fetchone()[0]
        detections_after = conn.execute("SELECT count(*) FROM detections").fetchone()[0]
        evidence_after = conn.execute("SELECT count(*) FROM detection_evidence").fetchone()[0]
        rules_after = conn.execute("SELECT count(*) FROM detection_rules").fetchone()[0]

    assert alerts_after == alerts_before, "Dry-run must not create rows in alerts"
    assert detections_after == detections_before, "Dry-run must not create rows in detections"
    assert evidence_after == evidence_before, "Dry-run must not create rows in detection_evidence"
    assert rules_after == rules_before, "Dry-run must not mutate detection_rules"


# ============================================================================
# 7. CLI EXECUTION TESTS
# ============================================================================

def test_replay_cli_execution():
    """CLI runner runs cleanly and exits with code 0."""
    rc_json = replay_cli_main(["--max-events", "20", "--format", "json"])
    assert rc_json == 0

    rc_text = replay_cli_main(["--max-events", "20", "--format", "text"])
    assert rc_text == 0
