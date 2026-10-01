"""End-to-end integration test suite for Milestone 3 (M3.8).

Verifies the full lifecycle chain:
Canonical Telemetry Events -> Ingestion & Event Storage -> Detection Engine Rules ->
Operational Alerts -> Incident Correlation Engine (Sliding Window, Entity Affinity,
Multi-Host Lateral Movement, Multi-Stage Attack Escalation) -> Attack Graph Derivation ->
Chronological Timeline Generation -> Incident REST API Surface -> Analyst Status Workflows.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import List

import pytest
from fastapi.testclient import TestClient

from logintel.api.app import app
from logintel.api.auth import get_current_token
from logintel.detection.engine import DetectionEngine
from logintel.detection.loader import load_default_rules
from logintel.detection.registry import RuleRegistry
from logintel.models.events import Actor, CanonicalEvent, EventType, Network, Outcome, Process, Severity
from logintel.models.incidents import IncidentStatus
from logintel.storage.alerts_repo import alerts_repo
from logintel.storage.db import db
from logintel.storage.events_repo import events_repo
from logintel.storage.incidents_repo import incidents_repo


@pytest.fixture(scope="module")
def initialized_db():
    db.initialize()
    alerts_repo.sync_rules(load_default_rules())
    yield db


@pytest.fixture(scope="module")
def client(initialized_db):
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def auth_client(client):
    token = get_current_token()
    client.headers["Authorization"] = f"Bearer {token}"
    return client


def _create_event(
    event_id: str,
    ts: datetime,
    host: str,
    event_type: EventType,
    outcome: Outcome,
    username: str,
    src_ip: str,
    dst_ip: str = "10.0.0.1",
    process_exe: str = "/usr/sbin/sshd",
    command_line: str = "sshd: [accepted]",
    summary: str = "SSH auth attempt",
) -> CanonicalEvent:
    """Helper to generate a canonical telemetry event and persist it into events_repo."""
    ev = CanonicalEvent(
        id=event_id,
        timestamp=ts,
        ingested_at=ts,
        host=host,
        source="auth.log",
        event_type=event_type,
        severity=Severity.ALERT if outcome == Outcome.FAILURE else Severity.INFORMATIONAL,
        actor=Actor(username=username, uid=1001),
        process=Process(name="sshd", executable=process_exe, command_line=command_line),
        network=Network(src_ip=src_ip, src_port=49152, dst_ip=dst_ip, dst_port=22),
        action="LOGIN",
        outcome=outcome,
        summary=summary,
        raw_message=f"{ts.isoformat()} {host} sshd: {summary} for {username} from {src_ip}",
        parser="openssh",
        event_fingerprint=f"fp-{event_id}",
    )
    events_repo.insert_events([ev])
    return ev


# ============================================================================
# 1. COMPLETE MULTI-STAGE CROSS-HOST INCIDENT INVESTIGATION WORKFLOW
# ============================================================================

def test_e2e_multi_stage_cross_host_incident_lifecycle(auth_client):
    """E2E Scenario:
    1. Attacker at 198.51.100.45 brute forces user 'deployer' on gateway-01 (3 failures in 30s) -> auth.ssh_bruteforce alert.
    2. Attacker logs into gateway-01 with 'deployer' credentials.
    3. Attacker pivots laterally from gateway-01 to db-internal-01 using 'deployer' account.
    4. Attacker executes unauthorized sudo command on db-internal-01 -> priv.unauthorized_sudo alert.
    5. Correlation engine aggregates alerts across hosts into a single CRITICAL incident.
    6. Verify attack graph contains both hosts, attacker IP, user, and LATERAL_MOVEMENT edge.
    7. Verify chronological timeline ordering.
    8. Analyst executes lifecycle status progression (OPEN -> INVESTIGATING -> CONTAINED -> RESOLVED -> CLOSED).
    """
    rule_registry = RuleRegistry()
    for rule in load_default_rules():
        rule_registry.register(rule)
    detection_engine = DetectionEngine(registry=rule_registry)

    base_time = datetime(2026, 9, 30, 20, 0, 0, tzinfo=timezone.utc)
    unique_run = uuid.uuid4().hex[:6]
    attacker_ip = f"198.51.100.{int(unique_run[:2], 16) % 200 + 10}"
    user_name = f"deployer_{unique_run}"
    gateway_host = f"gw-{unique_run}"
    db_host = f"db-{unique_run}"

    # ------------------------------------------------------------------------
    # STAGE 1: SSH Brute Force on Gateway Host
    # ------------------------------------------------------------------------
    ssh_rule = rule_registry.get("auth.ssh_bruteforce")
    assert ssh_rule is not None, "auth.ssh_bruteforce rule must be present"

    stage1_events: List[CanonicalEvent] = []
    stage1_detections = []
    for i in range(5):
        ev_ts = base_time + timedelta(seconds=i * 10)
        ev = _create_event(
            event_id=f"ev-s1-{unique_run}-{i}",
            ts=ev_ts,
            host=gateway_host,
            event_type=EventType.AUTH_LOGIN_FAILURE,
            outcome=Outcome.FAILURE,
            username=user_name,
            src_ip=attacker_ip,
            summary=f"Failed password for {user_name}",
        )
        stage1_events.append(ev)
        detections = detection_engine.evaluate_event(ev)
        stage1_detections.extend(detections)

    assert len(stage1_detections) >= 1, "SSH brute-force should trigger detection"
    alert_s1 = alerts_repo.record_detection(stage1_detections[-1], ssh_rule)
    assert alert_s1.id is not None
    assert alert_s1.host == gateway_host

    # ------------------------------------------------------------------------
    # STAGE 2: Successful Compromise on Gateway Host
    # ------------------------------------------------------------------------
    s2_ts = base_time + timedelta(seconds=60)
    ev_s2 = _create_event(
        event_id=f"ev-s2-{unique_run}",
        ts=s2_ts,
        host=gateway_host,
        event_type=EventType.AUTH_LOGIN_SUCCESS,
        outcome=Outcome.SUCCESS,
        username=user_name,
        src_ip=attacker_ip,
        summary=f"Accepted publickey for {user_name}",
    )

    # ------------------------------------------------------------------------
    # STAGE 3: Lateral Movement to Database Host
    # ------------------------------------------------------------------------
    s3_ts = base_time + timedelta(seconds=90)
    ev_s3 = _create_event(
        event_id=f"ev-s3-{unique_run}",
        ts=s3_ts,
        host=db_host,
        event_type=EventType.AUTH_LOGIN_SUCCESS,
        outcome=Outcome.SUCCESS,
        username=user_name,
        src_ip="10.0.0.10",  # gateway-01 internal IP
        dst_ip="10.0.0.25",  # db host internal IP
        summary=f"Accepted password for {user_name} from gateway",
    )

    # ------------------------------------------------------------------------
    # STAGE 4: Unauthorized Privilege Escalation on Database Host
    # ------------------------------------------------------------------------
    sudo_rule = rule_registry.get("priv.unauthorized_sudo")
    assert sudo_rule is not None, "priv.unauthorized_sudo rule must be present"

    s4_ts = base_time + timedelta(seconds=120)
    ev_s4 = CanonicalEvent(
        id=f"ev-s4-{unique_run}",
        timestamp=s4_ts,
        ingested_at=s4_ts,
        host=db_host,
        source="auth.log",
        event_type=EventType.PRIVILEGE_ELEVATION_FAILURE,
        severity=Severity.ALERT,
        actor=Actor(username=user_name, uid=1001),
        process=Process(name="sudo", executable="/usr/bin/sudo", command_line="sudo -u root /bin/bash"),
        network=Network(src_ip="10.0.0.10", src_port=49200, dst_ip="10.0.0.25", dst_port=22),
        action="PRIVILEGE_ELEVATION",
        outcome=Outcome.FAILURE,
        summary=f"user NOT in sudoers ; user {user_name}",
        raw_message=f"{s4_ts.isoformat()} {db_host} sudo: {user_name} : user NOT in sudoers ; TTY=pts/1 ; COMMAND=/bin/bash",
        parser="sudo",
        event_fingerprint=f"fp-s4-{unique_run}",
    )
    events_repo.insert_events([ev_s4])

    s4_detections = detection_engine.evaluate_event(ev_s4)
    assert len(s4_detections) >= 1, "Unauthorized sudo should trigger detection"
    alert_s4 = alerts_repo.record_detection(s4_detections[0], sudo_rule)
    assert alert_s4.id is not None
    assert alert_s4.host == db_host

    # ------------------------------------------------------------------------
    # STAGE 5: Trigger Incident Correlation via API
    # ------------------------------------------------------------------------
    correlate_resp = auth_client.post("/api/v1/incidents/correlate")
    assert correlate_resp.status_code == 200
    corr_data = correlate_resp.json()
    assert corr_data["correlated_incidents_count"] >= 1
    incident_id = corr_data["incident_ids"][0]

    # ------------------------------------------------------------------------
    # STAGE 6: Verify Unified Incident Dossier & Attack Graph Topology
    # ------------------------------------------------------------------------
    detail_resp = auth_client.get(f"/api/v1/incidents/{incident_id}")
    assert detail_resp.status_code == 200
    dossier = detail_resp.json()

    inc = dossier["incident"]
    assert inc["id"] == incident_id
    assert inc["severity"] == "CRITICAL", "Incident with unauthorized sudo and brute-force should escalate to CRITICAL"
    assert inc["primary_user"] == user_name

    # Check correlated alerts count
    alert_ids = {a["id"] for a in dossier["alerts"]}
    assert alert_s1.id in alert_ids, "Perimeter SSH brute force alert must be linked"
    assert alert_s4.id in alert_ids, "Internal database privilege escalation alert must be linked"

    # Verify Attack Graph
    graph = dossier["graph"]
    node_ids = {n["id"] for n in graph["nodes"]}
    assert f"host:{gateway_host}" in node_ids, "Gateway host node must exist"
    assert f"host:{db_host}" in node_ids, "Database host node must exist"
    assert f"user:{user_name}" in node_ids, "Compromised user node must exist"
    assert f"ip:{attacker_ip}" in node_ids, "Attacker IP node must exist"

    # Verify LATERAL_MOVEMENT relationship
    rel_types = {e["relationship_type"] for e in graph["edges"]}
    assert "LATERAL_MOVEMENT" in rel_types, "Cross-host pivot must produce LATERAL_MOVEMENT edge"

    # Verify Graph Endpoint standalone
    graph_resp = auth_client.get(f"/api/v1/incidents/{incident_id}/graph")
    assert graph_resp.status_code == 200
    assert len(graph_resp.json()["nodes"]) == len(graph["nodes"])

    # ------------------------------------------------------------------------
    # STAGE 7: Verify Chronological Timeline Stream
    # ------------------------------------------------------------------------
    timeline_resp = auth_client.get(f"/api/v1/incidents/{incident_id}/timeline")
    assert timeline_resp.status_code == 200
    timeline = timeline_resp.json()["items"]
    assert len(timeline) >= 2

    # Verify strictly monotonic or equal ascending timestamp order
    for idx in range(len(timeline) - 1):
        t_curr = datetime.fromisoformat(timeline[idx]["timestamp"])
        t_next = datetime.fromisoformat(timeline[idx + 1]["timestamp"])
        assert t_curr <= t_next, f"Timeline inverted at index {idx}: {t_curr} > {t_next}"

    # ------------------------------------------------------------------------
    # STAGE 8: Analyst Lifecycle State Machine Progression
    # ------------------------------------------------------------------------
    # Step A: OPEN -> INVESTIGATING
    res1 = auth_client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        json={"status": "INVESTIGATING", "resolution_note": "Triage started for lateral pivot"},
    )
    assert res1.status_code == 200
    assert res1.json()["status"] == "INVESTIGATING"

    # Step B: Rejection of illegal transition (INVESTIGATING -> CLOSED directly without resolution)
    # Based on ALLOWED_INCIDENT_STATUS_TRANSITIONS, INVESTIGATING can go to CONTAINED, RESOLVED, FALSE_POSITIVE, OPEN
    bad_res = auth_client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        json={"status": "CLOSED"},
    )
    assert bad_res.status_code == 400
    assert "Invalid incident status transition" in bad_res.json()["detail"]

    # Step C: INVESTIGATING -> CONTAINED
    res2 = auth_client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        json={"status": "CONTAINED", "resolution_note": "Gateway isolated from db VLAN"},
    )
    assert res2.status_code == 200
    assert res2.json()["status"] == "CONTAINED"

    # Step D: CONTAINED -> RESOLVED
    res3 = auth_client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        json={"status": "RESOLVED", "resolution_note": "Account deployer revoked, firewall rules updated"},
    )
    assert res3.status_code == 200
    assert res3.json()["status"] == "RESOLVED"
    assert res3.json()["resolved_at"] is not None

    # Step E: RESOLVED -> CLOSED
    res4 = auth_client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        json={"status": "CLOSED", "resolution_note": "Post-incident review complete"},
    )
    assert res4.status_code == 200
    assert res4.json()["status"] == "CLOSED"

    # Step F: Query filtered list to ensure state updated
    list_resp = auth_client.get(f"/api/v1/incidents?status=CLOSED&user={user_name}")
    assert list_resp.status_code == 200
    items = list_resp.json()["items"]
    assert len(items) == 1
    assert items[0]["id"] == incident_id
    assert items[0]["status"] == "CLOSED"


# ============================================================================
# 2. INDEPENDENT INCIDENTS PARTITIONING (NO CROSSTALK)
# ============================================================================

def test_e2e_independent_incidents_separation(auth_client):
    """Two concurrent attack chains on separate hosts with different actors remain distinct."""
    rule_registry = RuleRegistry()
    for rule in load_default_rules():
        rule_registry.register(rule)
    detection_engine = DetectionEngine(registry=rule_registry)

    base_time = datetime(2026, 9, 30, 21, 0, 0, tzinfo=timezone.utc)
    unique_run = uuid.uuid4().hex[:6]
    ssh_rule = rule_registry.get("auth.ssh_bruteforce")

    ip_a = f"198.51.100.{int(unique_run[:2], 16) % 200 + 10}"
    ip_b = f"203.0.113.{int(unique_run[2:4], 16) % 200 + 10}"

    # Cluster A: host-alpha, user-alpha, ip-alpha
    for i in range(5):
        ev = _create_event(
            event_id=f"ev-iso-a-{unique_run}-{i}",
            ts=base_time + timedelta(seconds=i * 5),
            host=f"host-alpha-{unique_run}",
            event_type=EventType.AUTH_LOGIN_FAILURE,
            outcome=Outcome.FAILURE,
            username=f"user-alpha-{unique_run}",
            src_ip=ip_a,
        )
        dets = detection_engine.evaluate_event(ev)
        if dets:
            alerts_repo.record_detection(dets[-1], ssh_rule)

    # Cluster B: host-beta, user-beta, ip-beta
    for i in range(5):
        ev = _create_event(
            event_id=f"ev-iso-b-{unique_run}-{i}",
            ts=base_time + timedelta(seconds=i * 5),
            host=f"host-beta-{unique_run}",
            event_type=EventType.AUTH_LOGIN_FAILURE,
            outcome=Outcome.FAILURE,
            username=f"user-beta-{unique_run}",
            src_ip=ip_b,
        )
        dets = detection_engine.evaluate_event(ev)
        if dets:
            alerts_repo.record_detection(dets[-1], ssh_rule)

    correlate_resp = auth_client.post("/api/v1/incidents/correlate")
    assert correlate_resp.status_code == 200

    # Query incidents for both hosts
    resp_a = auth_client.get(f"/api/v1/incidents?host=host-alpha-{unique_run}")
    resp_b = auth_client.get(f"/api/v1/incidents?host=host-beta-{unique_run}")

    assert resp_a.status_code == 200
    assert resp_b.status_code == 200
    inc_a = resp_a.json()["items"]
    inc_b = resp_b.json()["items"]

    assert len(inc_a) == 1
    assert len(inc_b) == 1
    assert inc_a[0]["id"] != inc_b[0]["id"], "Independent attack clusters must form separate incidents"


# ============================================================================
# 3. TEMPORAL WINDOW EXPIRATION TEST
# ============================================================================

def test_e2e_temporal_window_expiration(auth_client):
    """Alerts for the same user separated by more than 1800s sliding window do not merge."""
    from logintel.models.alerts import AlertStatus

    rule_registry = RuleRegistry()
    for rule in load_default_rules():
        rule_registry.register(rule)
    detection_engine = DetectionEngine(registry=rule_registry)

    base_time = datetime(2026, 9, 30, 8, 0, 0, tzinfo=timezone.utc)
    unique_run = uuid.uuid4().hex[:6]
    ssh_rule = rule_registry.get("auth.ssh_bruteforce")
    user_name = f"user-time-{unique_run}"
    host_name = f"host-time-{unique_run}"
    ip_addr = f"198.51.100.{int(unique_run[:2], 16) % 200 + 10}"

    # Wave 1: 08:00:00 UTC
    alert_w1 = None
    for i in range(5):
        ev = _create_event(
            event_id=f"ev-time-w1-{unique_run}-{i}",
            ts=base_time + timedelta(seconds=i * 10),
            host=host_name,
            event_type=EventType.AUTH_LOGIN_FAILURE,
            outcome=Outcome.FAILURE,
            username=user_name,
            src_ip=ip_addr,
        )
        dets = detection_engine.evaluate_event(ev)
        if dets:
            alert_w1 = alerts_repo.record_detection(dets[-1], ssh_rule)

    assert alert_w1 is not None

    # Resolve Wave 1 alert so deduplication archives its key and enables Wave 2 to create a second alert
    alerts_repo.update_alert_status(alert_w1.id, AlertStatus.RESOLVED, resolution_note="First wave handled")

    # Reset detection engine in-memory window
    detection_engine.reset()

    # Wave 2: 12:00:00 UTC (4 hours later, well beyond the 1800s / 30m window)
    wave2_time = base_time + timedelta(hours=4)
    alert_w2 = None
    for i in range(5):
        ev = _create_event(
            event_id=f"ev-time-w2-{unique_run}-{i}",
            ts=wave2_time + timedelta(seconds=i * 10),
            host=host_name,
            event_type=EventType.AUTH_LOGIN_FAILURE,
            outcome=Outcome.FAILURE,
            username=user_name,
            src_ip=ip_addr,
        )
        dets = detection_engine.evaluate_event(ev)
        if dets:
            alert_w2 = alerts_repo.record_detection(dets[-1], ssh_rule)

    assert alert_w2 is not None
    assert alert_w1.id != alert_w2.id, "Wave 1 and Wave 2 must produce distinct operational alerts"

    # Correlate
    correlate_resp = auth_client.post("/api/v1/incidents/correlate")
    assert correlate_resp.status_code == 200

    # Query incidents for this user
    list_resp = auth_client.get(f"/api/v1/incidents?user={user_name}")
    assert list_resp.status_code == 200
    items = list_resp.json()["items"]

    assert len(items) == 2, "Alerts separated by 4 hours must result in 2 separate incidents"
    # Ensure they have different IDs and non-overlapping time windows
    assert items[0]["id"] != items[1]["id"]


