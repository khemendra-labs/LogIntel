"""Comprehensive test suite for LogIntel M2.7 Alert Lifecycle, Deduplication, and Evidence."""

import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional
import pytest

from logintel.detection import EvidenceRole, load_default_rules
from logintel.detection.models import DetectionRule
from logintel.detection.results import DetectionResult
from logintel.models import (
    Actor,
    Alert,
    AlertStatus,
    CanonicalEvent,
    EventType,
    InvalidStatusTransitionError,
    Network,
    Outcome,
    Process,
    Severity,
)
from logintel.storage.alerts_repo import AlertsRepository
from logintel.storage.db import Database
from logintel.storage.events_repo import EventsRepository


@pytest.fixture
def temp_repo():
    """Provide an isolated, migrated AlertsRepository on a temporary SQLite database."""
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "alert_test.db"
        test_db = Database(db_path)
        test_db.initialize()

        ev_repo = EventsRepository(test_db)
        repo = AlertsRepository(test_db)
        # Sync canonical rules to satisfy foreign keys
        repo.sync_rules(load_default_rules())

        yield repo, ev_repo, test_db
        test_db.close()


def _insert_test_event(
    ev_repo: EventsRepository,
    event_id: str,
    ts: datetime,
    host: str = "srv-01",
    event_type: EventType = EventType.AUTH_LOGIN_FAILURE,
    username: str = "root",
) -> CanonicalEvent:
    """Helper to insert a valid canonical event to satisfy detection_evidence foreign keys."""
    event = CanonicalEvent(
        id=event_id,
        timestamp=ts,
        ingested_at=ts,
        host=host,
        source="/var/log/auth.log",
        event_type=event_type,
        severity=Severity.ALERT,
        actor=Actor(username=username, uid=0),
        process=Process(name="sshd", executable="/usr/sbin/sshd"),
        network=Network(src_ip="203.0.113.10"),
        action="LOGIN",
        outcome=Outcome.FAILURE,
        summary=f"Event {event_id} summary",
        raw_message=f"Raw log for {event_id}",
        parser="openssh_auth",
        metadata={},
    )
    ev_repo.insert_events([event])
    return event


# ============================================================================
# 1. RULE SYNC TESTS
# ============================================================================

def test_sync_rules_to_database(temp_repo):
    """Verify that canonical rules are properly synced into the detection_rules table."""
    repo, _, test_db = temp_repo
    rules = load_default_rules()
    assert len(rules) >= 16

    with test_db.connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM detection_rules")
        assert cur.fetchone()[0] >= 16

        # Check a specific rule row
        cur.execute("SELECT id, name, severity, category FROM detection_rules WHERE id = 'auth.ssh_bruteforce'")
        row = cur.fetchone()
        assert row is not None
        assert row[0] == "auth.ssh_bruteforce"
        assert row[2] == "ALERT"
        assert row[3] == "AUTH"


# ============================================================================
# 2. ALERT CREATION & DEDUPLICATION TESTS
# ============================================================================

def test_alert_creation_atomic(temp_repo):
    """Verify an atomic detection creates an OPEN alert with detection and evidence records."""
    repo, ev_repo, _ = temp_repo
    rules = {r.id: r for r in load_default_rules()}
    rule = rules["auth.root_login"]

    t0 = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)
    ev = _insert_test_event(ev_repo, "ev-root-1", t0, event_type=EventType.AUTH_LOGIN_SUCCESS)

    result = DetectionResult(
        rule_id="auth.root_login",
        timestamp=t0,
        host="srv-01",
        summary="SSH login successful for root",
        evidence_event_ids=["ev-root-1"],
        evidence_roles={"ev-root-1": EvidenceRole.TRIGGER},
        details={"matched_fields": {"username": "root"}},
    )

    alert = repo.record_detection(result, rule)
    assert alert.id is not None
    assert alert.rule_id == "auth.root_login"
    assert alert.status == AlertStatus.OPEN
    assert alert.occurrence_count == 1
    assert alert.first_seen == t0
    assert alert.last_seen == t0

    # Verify detection and evidence records
    details = repo.get_alert_details(alert.id)
    assert details is not None
    assert len(details["detections"]) == 1
    det = details["detections"][0]
    assert det["summary"] == "SSH login successful for root"
    assert len(det["evidence"]) == 1
    assert det["evidence"][0]["event_id"] == "ev-root-1"
    assert det["evidence"][0]["role"] == "TRIGGER"


def test_alert_deduplication_cooldown(temp_repo):
    """Verify that detections with the same dedup_key within cooldown aggregate into one alert."""
    repo, ev_repo, _ = temp_repo
    rules = {r.id: r for r in load_default_rules()}
    rule = rules["auth.ssh_bruteforce"]

    t0 = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(minutes=5)

    ev1 = _insert_test_event(ev_repo, "ev-bf-1", t0)
    ev2 = _insert_test_event(ev_repo, "ev-bf-2", t1)

    result1 = DetectionResult(
        rule_id="auth.ssh_bruteforce",
        timestamp=t0,
        host="srv-01",
        summary="SSH Brute Force burst 1",
        evidence_event_ids=["ev-bf-1"],
        evidence_roles={"ev-bf-1": EvidenceRole.TRIGGER},
        details={"group_key": "src_ip=203.0.113.10|host=srv-01"},
    )

    result2 = DetectionResult(
        rule_id="auth.ssh_bruteforce",
        timestamp=t1,
        host="srv-01",
        summary="SSH Brute Force burst 2",
        evidence_event_ids=["ev-bf-2"],
        evidence_roles={"ev-bf-2": EvidenceRole.TRIGGER},
        details={"group_key": "src_ip=203.0.113.10|host=srv-01"},
    )

    alert1 = repo.record_detection(result1, rule)
    alert2 = repo.record_detection(result2, rule)

    # Must be the exact same alert ID
    assert alert1.id == alert2.id
    assert alert2.occurrence_count == 2
    assert alert2.first_seen == t0
    assert alert2.last_seen == t1

    # Total alerts in database must be 1
    all_alerts = repo.list_alerts()
    assert len(all_alerts) == 1

    # Verify both detections are linked
    details = repo.get_alert_details(alert1.id)
    assert len(details["detections"]) == 2


def test_alert_distinct_group_keys_create_distinct_alerts(temp_repo):
    """Verify that detections with distinct group keys produce separate alerts."""
    repo, ev_repo, _ = temp_repo
    rules = {r.id: r for r in load_default_rules()}
    rule = rules["auth.ssh_bruteforce"]

    t0 = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)
    ev1 = _insert_test_event(ev_repo, "ev-ipA-1", t0)
    ev2 = _insert_test_event(ev_repo, "ev-ipB-1", t0)

    resA = DetectionResult(
        rule_id="auth.ssh_bruteforce",
        timestamp=t0,
        host="srv-01",
        summary="Brute Force from IP A",
        evidence_event_ids=["ev-ipA-1"],
        evidence_roles={"ev-ipA-1": EvidenceRole.TRIGGER},
        details={"group_key": "src_ip=10.0.0.1|host=srv-01"},
    )
    resB = DetectionResult(
        rule_id="auth.ssh_bruteforce",
        timestamp=t0,
        host="srv-01",
        summary="Brute Force from IP B",
        evidence_event_ids=["ev-ipB-1"],
        evidence_roles={"ev-ipB-1": EvidenceRole.TRIGGER},
        details={"group_key": "src_ip=10.0.0.2|host=srv-01"},
    )

    alertA = repo.record_detection(resA, rule)
    alertB = repo.record_detection(resB, rule)

    assert alertA.id != alertB.id
    assert repo.count_alerts() == 2


# ============================================================================
# 3. ALERT LIFECYCLE & STATE MACHINE TESTS
# ============================================================================

def test_alert_lifecycle_valid_transitions(temp_repo):
    """Verify the operational status transitions: OPEN -> ACKNOWLEDGED -> RESOLVED -> OPEN."""
    repo, ev_repo, _ = temp_repo
    rules = {r.id: r for r in load_default_rules()}
    rule = rules["priv.unauthorized_sudo"]

    t0 = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)
    _insert_test_event(ev_repo, "ev-sudo-unauth", t0)

    result = DetectionResult(
        rule_id="priv.unauthorized_sudo",
        timestamp=t0,
        host="srv-01",
        summary="Unauthorized sudo by guest",
        evidence_event_ids=["ev-sudo-unauth"],
        evidence_roles={"ev-sudo-unauth": EvidenceRole.TRIGGER},
        details={},
    )
    alert = repo.record_detection(result, rule)
    assert alert.status == AlertStatus.OPEN

    # 1. OPEN -> ACKNOWLEDGED (Analyst triage)
    ack_alert = repo.update_alert_status(alert.id, AlertStatus.ACKNOWLEDGED)
    assert ack_alert.status == AlertStatus.ACKNOWLEDGED
    assert ack_alert.acknowledged_at is not None

    # 2. ACKNOWLEDGED -> RESOLVED
    res_alert = repo.update_alert_status(alert.id, AlertStatus.RESOLVED, resolution_note="Investigated and benign script fixed")
    assert res_alert.status == AlertStatus.RESOLVED
    assert res_alert.resolved_at is not None
    assert res_alert.resolution_note == "Investigated and benign script fixed"

    # 3. RESOLVED -> OPEN (Reopen)
    reopen_alert = repo.update_alert_status(alert.id, AlertStatus.OPEN)
    assert reopen_alert.status == AlertStatus.OPEN
    assert reopen_alert.resolved_at is None
    assert reopen_alert.resolution_note is None

    # 4. OPEN -> FALSE_POSITIVE
    fp_alert = repo.update_alert_status(alert.id, AlertStatus.FALSE_POSITIVE, resolution_note="Legitimate automated task")
    assert fp_alert.status == AlertStatus.FALSE_POSITIVE
    assert fp_alert.resolved_at is not None


def test_alert_lifecycle_invalid_transitions_rejected(temp_repo):
    """Verify that invalid state transitions raise InvalidStatusTransitionError."""
    repo, ev_repo, _ = temp_repo
    rules = {r.id: r for r in load_default_rules()}
    rule = rules["priv.unauthorized_sudo"]

    t0 = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)
    _insert_test_event(ev_repo, "ev-sudo-err", t0)

    result = DetectionResult(
        rule_id="priv.unauthorized_sudo",
        timestamp=t0,
        host="srv-01",
        summary="Unauthorized sudo",
        evidence_event_ids=["ev-sudo-err"],
        evidence_roles={"ev-sudo-err": EvidenceRole.TRIGGER},
        details={},
    )
    alert = repo.record_detection(result, rule)

    # Resolve directly from OPEN
    repo.update_alert_status(alert.id, AlertStatus.RESOLVED)

    # Attempt direct transition from RESOLVED to ACKNOWLEDGED (forbidden)
    with pytest.raises(InvalidStatusTransitionError):
        repo.update_alert_status(alert.id, AlertStatus.ACKNOWLEDGED)

    # Attempt direct transition from RESOLVED to FALSE_POSITIVE (forbidden)
    with pytest.raises(InvalidStatusTransitionError):
        repo.update_alert_status(alert.id, AlertStatus.FALSE_POSITIVE)


def test_new_alert_after_resolution(temp_repo):
    """Verify that a new incident after resolution archives old alert and creates a fresh alert."""
    repo, ev_repo, _ = temp_repo
    rules = {r.id: r for r in load_default_rules()}
    rule = rules["account.root_creation"]

    t0 = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 9, 30, 14, 0, 0, tzinfo=timezone.utc)

    ev1 = _insert_test_event(ev_repo, "ev-acc-1", t0)
    ev2 = _insert_test_event(ev_repo, "ev-acc-2", t1)

    result1 = DetectionResult(
        rule_id="account.root_creation",
        timestamp=t0,
        host="srv-01",
        summary="Root creation incident 1",
        evidence_event_ids=["ev-acc-1"],
        evidence_roles={"ev-acc-1": EvidenceRole.TRIGGER},
        details={"matched_fields": {"username": "backdoor1"}},
    )

    alert1 = repo.record_detection(result1, rule)
    assert alert1.occurrence_count == 1

    # Resolve the first alert
    repo.update_alert_status(alert1.id, AlertStatus.RESOLVED, resolution_note="Account removed")

    # A new detection occurs hours later
    result2 = DetectionResult(
        rule_id="account.root_creation",
        timestamp=t1,
        host="srv-01",
        summary="Root creation incident 2",
        evidence_event_ids=["ev-acc-2"],
        evidence_roles={"ev-acc-2": EvidenceRole.TRIGGER},
        details={"matched_fields": {"username": "backdoor1"}},
    )

    alert2 = repo.record_detection(result2, rule)

    # A new alert must be created
    assert alert2.id != alert1.id
    assert alert2.status == AlertStatus.OPEN
    assert alert2.occurrence_count == 1

    # Both alerts exist in database
    assert repo.count_alerts() == 2

    # Old alert is still RESOLVED
    old = repo.get_alert(alert1.id)
    assert old.status == AlertStatus.RESOLVED


# ============================================================================
# 4. QUERY FILTERING & PAGINATION TESTS
# ============================================================================

def test_list_and_count_alerts_with_filtering(temp_repo):
    """Verify alert listing with status, severity, host, and pagination filters."""
    repo, ev_repo, _ = temp_repo
    rules = {r.id: r for r in load_default_rules()}

    base_time = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(5):
        ev = _insert_test_event(ev_repo, f"ev-filter-{i}", base_time + timedelta(minutes=i), host=f"host-{i % 2}")
        res = DetectionResult(
            rule_id="proc.apparmor_denial",
            timestamp=base_time + timedelta(minutes=i),
            host=f"host-{i % 2}",
            summary=f"Denial on host {i % 2}",
            evidence_event_ids=[f"ev-filter-{i}"],
            evidence_roles={f"ev-filter-{i}": EvidenceRole.TRIGGER},
            details={"group_key": f"host-{i % 2}"},
        )
        repo.record_detection(res, rules["proc.apparmor_denial"])

    # 2 hosts -> 2 distinct alerts
    assert repo.count_alerts() == 2
    assert repo.count_alerts(host="host-0") == 1
    assert repo.count_alerts(host="host-1") == 1
    assert repo.count_alerts(severity=Severity.ALERT) == 2
    assert repo.count_alerts(severity=Severity.CRITICAL) == 0

    alerts = repo.list_alerts(limit=1)
    assert len(alerts) == 1


# ============================================================================
# 5. MULTI-THREAD CONCURRENCY & TRANSACTION INTEGRITY
# ============================================================================

def test_concurrent_detection_recording(temp_repo):
    """Verify thread-safety and atomic deduplication under concurrent recording."""
    repo, ev_repo, _ = temp_repo
    rules = {r.id: r for r in load_default_rules()}
    rule = rules["network.firewall_scan_burst"]

    # Pre-insert events
    base_time = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)
    for i in range(20):
        _insert_test_event(ev_repo, f"ev-thread-{i}", base_time + timedelta(seconds=i))

    exceptions = []

    def record_worker(worker_id: int):
        try:
            ev_id = f"ev-thread-{worker_id}"
            res = DetectionResult(
                rule_id="network.firewall_scan_burst",
                timestamp=base_time + timedelta(seconds=worker_id),
                host="gateway-01",
                summary="Scan burst",
                evidence_event_ids=[ev_id],
                evidence_roles={ev_id: EvidenceRole.TRIGGER},
                details={"group_key": "src_ip=198.51.100.99|host=gateway-01"},
            )
            repo.record_detection(res, rule)
        except Exception as e:
            exceptions.append(e)

    threads = [threading.Thread(target=record_worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not exceptions, f"Exceptions during concurrent recording: {exceptions}"

    # Exactly 1 alert should exist with occurrence_count == 20
    all_alerts = repo.list_alerts()
    assert len(all_alerts) == 1
    alert = all_alerts[0]
    assert alert.occurrence_count == 20

    # Exactly 20 detections linked
    details = repo.get_alert_details(alert.id)
    assert len(details["detections"]) == 20


def test_get_alert_details_with_evidence_fields(temp_repo):
    """Verify get_alert_details retrieves joined event summaries and attributes."""
    repo, ev_repo, _ = temp_repo
    rules = {r.id: r for r in load_default_rules()}
    rule = rules["auth.root_login"]

    t0 = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)
    ev = _insert_test_event(ev_repo, "ev-det-root", t0, event_type=EventType.AUTH_LOGIN_SUCCESS)

    result = DetectionResult(
        rule_id="auth.root_login",
        timestamp=t0,
        host="srv-01",
        summary="SSH login successful for root",
        evidence_event_ids=["ev-det-root"],
        evidence_roles={"ev-det-root": EvidenceRole.TRIGGER},
        details={"matched_fields": {"username": "root"}},
    )

    alert = repo.record_detection(result, rule)
    details = repo.get_alert_details(alert.id)

    assert details is not None
    assert details["alert"]["id"] == alert.id
    assert len(details["detections"]) == 1
    det = details["detections"][0]
    assert len(det["evidence"]) == 1
    ev_item = det["evidence"][0]
    assert ev_item["event_id"] == "ev-det-root"
    assert ev_item["role"] == "TRIGGER"
    assert ev_item["event_summary"] == "Event ev-det-root summary"
    assert ev_item["event_type"] == "AUTH_LOGIN_SUCCESS"
    assert ev_item["source"] == "/var/log/auth.log"

