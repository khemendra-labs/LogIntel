"""Tests for M3.4 Incident Correlation Engine (Alert Aggregation, Graph Synthesis & Multi-Stage Escalation)."""

from __future__ import annotations

import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from logintel.correlation.config import CorrelationConfig
from logintel.correlation.engine import IncidentCorrelationEngine
from logintel.correlation.scenarios import AttackStage, classify_stages, evaluate_escalation
from logintel.detection import EvidenceRole, load_default_rules
from logintel.detection.results import DetectionResult
from logintel.models.events import (
    Actor,
    CanonicalEvent,
    EventType,
    Network,
    Outcome,
    Process,
    Severity,
)
from logintel.models.incidents import (
    ConfidenceLevel,
    EntityType,
    Incident,
    IncidentRelationship,
    IncidentStatus,
    RelationshipType,
)
from logintel.storage.alerts_repo import AlertsRepository
from logintel.storage.db import Database
from logintel.storage.events_repo import EventsRepository
from logintel.storage.incidents_repo import IncidentsRepository


@pytest.fixture
def correlation_env():
    """Create isolated test database, repositories, and IncidentCorrelationEngine."""
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "test_correlation.db"
        test_db = Database(db_path)
        test_db.initialize()

        alerts_repo = AlertsRepository(test_db)
        events_repo = EventsRepository(test_db)
        incidents_repo = IncidentsRepository(test_db, alerts_repo)

        # Sync canonical rule catalog
        rules = load_default_rules()
        alerts_repo.sync_rules(rules)

        config = CorrelationConfig(
            window_seconds=1800,  # 30 minutes
            cross_host_correlation=True,
            multi_stage_escalation=True,
        )
        engine = IncidentCorrelationEngine(
            database=test_db,
            incidents_repository=incidents_repo,
            alerts_repository=alerts_repo,
            config=config,
        )

        yield {
            "db": test_db,
            "alerts_repo": alerts_repo,
            "events_repo": events_repo,
            "incidents_repo": incidents_repo,
            "engine": engine,
            "rules": {r.id: r for r in rules},
        }
        test_db.close()


def _seed_alert(
    env,
    rule_id: str,
    host: str,
    user: str,
    src_ip: str,
    ts: datetime,
    event_type: str = "AUTH_LOGIN_FAILURE",
    process_name: str = "sshd",
    outcome: str = "FAILURE",
):
    """Helper to seed an underlying event, a detection, and an operational alert."""
    ev_id = f"ev-{int(ts.timestamp())}-{host}-{user}-{rule_id}"
    event = CanonicalEvent(
        id=ev_id,
        event_fingerprint=f"fp-{ev_id}",
        timestamp=ts,
        ingested_at=ts,
        host=host,
        source="auth",
        event_type=EventType(event_type) if event_type in EventType._value2member_map_ else EventType.AUTH_LOGIN_FAILURE,
        severity=Severity.WARNING,
        outcome=Outcome(outcome) if outcome in Outcome._value2member_map_ else Outcome.FAILURE,
        actor=Actor(username=user),
        network=Network(src_ip=src_ip),
        process=Process(name=process_name),
        summary=f"Event for {user} on {host}",
        raw_message=f"Raw log line for {user} from {src_ip} at {ts.isoformat()}",
        parser="ssh",
    )
    env["events_repo"].insert_events([event])

    rule = env["rules"][rule_id]
    det_result = DetectionResult(
        rule_id=rule.id,
        timestamp=ts,
        host=host,
        summary=f"Detection for {rule.name} on {host}",
        evidence_event_ids=[ev_id],
        evidence_roles={ev_id: EvidenceRole.TRIGGER},
        details={"group_key": f"{host}:{user}:{int(ts.timestamp())}"},
    )
    alert = env["alerts_repo"].record_detection(det_result, rule)
    return event, alert



def test_correlate_single_alert_creates_incident(correlation_env):
    """Verify that correlating a single alert creates a new incident with entities and relationships."""
    env = correlation_env
    engine = env["engine"]
    now = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)

    _, alert = _seed_alert(
        env,
        rule_id="auth.ssh_bruteforce",
        host="srv-alpha",
        user="root",
        src_ip="192.168.1.100",
        ts=now,
    )

    incident = engine.correlate_alert(alert.id)
    assert incident is not None
    assert incident.id is not None
    assert incident.primary_host == "srv-alpha"
    assert incident.primary_user == "root"
    assert incident.status == IncidentStatus.OPEN
    assert incident.alert_count == 1
    assert incident.severity == Severity.ALERT

    # Verify graph entities extracted
    entities = env["incidents_repo"].get_incident_entities(incident.id)
    entity_keys = {e.entity_key for e in entities}
    assert "host:srv-alpha" in entity_keys
    assert "user:root" in entity_keys
    assert "ip:192.168.1.100" in entity_keys

    # Verify relationships created
    rels = env["incidents_repo"].get_incident_relationships(incident.id)
    assert len(rels) >= 2
    rel_targets = {(r.source_entity_key, r.target_entity_key) for r in rels}
    assert ("ip:192.168.1.100", "host:srv-alpha") in rel_targets
    assert ("user:root", "host:srv-alpha") in rel_targets


def test_correlate_subsequent_alert_same_host_within_window(correlation_env):
    """Verify subsequent alert on the same host within 30 min merges into the active incident."""
    env = correlation_env
    engine = env["engine"]
    t0 = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(minutes=10)

    _, alert1 = _seed_alert(
        env,
        rule_id="auth.ssh_bruteforce",
        host="srv-alpha",
        user="root",
        src_ip="192.168.1.100",
        ts=t0,
    )
    inc1 = engine.correlate_alert(alert1.id)

    _, alert2 = _seed_alert(
        env,
        rule_id="auth.repeated_failures",
        host="srv-alpha",
        user="root",
        src_ip="192.168.1.100",
        ts=t1,
    )
    inc2 = engine.correlate_alert(alert2.id)

    # Should be the same incident merged
    assert inc1.id == inc2.id
    assert inc2.alert_count == 2
    assert inc2.first_seen == alert1.first_seen
    assert inc2.last_seen == alert2.last_seen

    # Verify total incidents in repo remains 1
    assert env["incidents_repo"].count_incidents() == 1


def test_correlate_alert_outside_window_creates_new_incident(correlation_env):
    """Verify alert arriving after the correlation window expires starts a separate incident."""
    env = correlation_env
    engine = env["engine"]
    t0 = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(minutes=45)  # Outside 30-min window

    _, alert1 = _seed_alert(
        env,
        rule_id="auth.ssh_bruteforce",
        host="srv-alpha",
        user="root",
        src_ip="192.168.1.100",
        ts=t0,
    )
    inc1 = engine.correlate_alert(alert1.id)

    _, alert2 = _seed_alert(
        env,
        rule_id="auth.repeated_failures",
        host="srv-alpha",
        user="root",
        src_ip="192.168.1.100",
        ts=t1,
    )
    inc2 = engine.correlate_alert(alert2.id)

    # Must be separate incidents
    assert inc1.id != inc2.id
    assert env["incidents_repo"].count_incidents() == 2


def test_multi_stage_attack_escalation(correlation_env):
    """Verify alerts across AUTH and PRIVILEGE stages trigger multi-stage CRITICAL escalation."""
    env = correlation_env
    engine = env["engine"]
    t0 = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(minutes=5)

    # Stage 1: Initial Access / Brute Force (AUTH category)
    _, alert_auth = _seed_alert(
        env,
        rule_id="auth.ssh_bruteforce",
        host="srv-finance",
        user="admin",
        src_ip="10.200.5.15",
        ts=t0,
    )
    inc = engine.correlate_alert(alert_auth.id)
    assert inc.severity == Severity.ALERT

    # Stage 2: Privilege Escalation (PRIVILEGE category)
    _, alert_priv = _seed_alert(
        env,
        rule_id="priv.sudo_root_shell",
        host="srv-finance",
        user="admin",
        src_ip="10.200.5.15",
        ts=t1,
        event_type="SUDO_COMMAND",
        process_name="sudo",
        outcome="SUCCESS",
    )
    inc_updated = engine.correlate_alert(alert_priv.id)

    # Escalated to CRITICAL
    assert inc_updated.id == inc.id
    assert inc_updated.severity == Severity.CRITICAL
    assert "Initial Access Followed by Privilege Escalation" in inc_updated.title


def test_cross_host_correlation_via_attacker_ip(correlation_env):
    """Verify attacker IP probing multiple hosts is correlated into a multi-host campaign."""
    env = correlation_env
    engine = env["engine"]
    t0 = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(minutes=8)
    attacker_ip = "198.51.100.77"

    # Alert on Host A
    _, alert_host_a = _seed_alert(
        env,
        rule_id="auth.ssh_bruteforce",
        host="srv-web-01",
        user="ubuntu",
        src_ip=attacker_ip,
        ts=t0,
    )
    inc_a = engine.correlate_alert(alert_host_a.id)

    # Alert on Host B from same IP
    _, alert_host_b = _seed_alert(
        env,
        rule_id="auth.ssh_bruteforce",
        host="srv-db-01",
        user="ubuntu",
        src_ip=attacker_ip,
        ts=t1,
    )
    inc_b = engine.correlate_alert(alert_host_b.id)

    # Correlated together across hosts
    assert inc_a.id == inc_b.id
    assert inc_b.alert_count == 2

    # Verify lateral movement relationship is present
    rels = env["incidents_repo"].get_incident_relationships(
        inc_b.id, relationship_type=RelationshipType.LATERAL_MOVEMENT.value
    )
    assert len(rels) >= 1
    lateral_rel = rels[0]
    assert lateral_rel.relationship_type == RelationshipType.LATERAL_MOVEMENT.value
    assert lateral_rel.confidence == ConfidenceLevel.STRONG


def test_correlate_unassigned_alerts_batch(correlation_env):
    """Verify batch processing of unassigned alerts across multiple hosts."""
    env = correlation_env
    engine = env["engine"]
    t0 = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)

    # Seed 3 alerts across 2 hosts
    _seed_alert(
        env,
        rule_id="auth.ssh_bruteforce",
        host="host-one",
        user="user1",
        src_ip="10.0.0.1",
        ts=t0,
    )
    _seed_alert(
        env,
        rule_id="auth.repeated_failures",
        host="host-one",
        user="user1",
        src_ip="10.0.0.1",
        ts=t0 + timedelta(minutes=5),
    )
    _seed_alert(
        env,
        rule_id="auth.ssh_bruteforce",
        host="host-two",
        user="user2",
        src_ip="10.0.0.2",
        ts=t0 + timedelta(minutes=2),
    )

    incidents = engine.correlate_unassigned_alerts()
    assert len(incidents) == 2  # 1 for host-one (merged), 1 for host-two

    # Second pass has zero unassigned alerts
    recheck = engine.correlate_unassigned_alerts()
    assert len(recheck) == 0


def test_already_correlated_alert_idempotency(correlation_env):
    """Verify calling correlate_alert on an already-correlated alert is idempotent."""
    env = correlation_env
    engine = env["engine"]
    now = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)

    _, alert = _seed_alert(
        env,
        rule_id="auth.ssh_bruteforce",
        host="srv-alpha",
        user="root",
        src_ip="10.0.0.5",
        ts=now,
    )

    inc1 = engine.correlate_alert(alert.id)
    inc2 = engine.correlate_alert(alert.id)

    assert inc1.id == inc2.id
    assert env["incidents_repo"].count_incidents() == 1


def test_closed_incident_does_not_absorb_new_alert(correlation_env):
    """Verify that resolved or closed incidents do not absorb newly arrived alerts."""
    env = correlation_env
    engine = env["engine"]
    t0 = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(minutes=5)

    _, alert1 = _seed_alert(
        env,
        rule_id="auth.ssh_bruteforce",
        host="srv-alpha",
        user="root",
        src_ip="10.0.0.5",
        ts=t0,
    )
    inc1 = engine.correlate_alert(alert1.id)

    # Resolve incident
    env["incidents_repo"].update_incident_status(
        inc1.id, IncidentStatus.RESOLVED, resolution_note="Mitigated"
    )

    # Second alert arrives shortly after
    _, alert2 = _seed_alert(
        env,
        rule_id="auth.ssh_bruteforce",
        host="srv-alpha",
        user="root",
        src_ip="10.0.0.5",
        ts=t1,
    )
    inc2 = engine.correlate_alert(alert2.id)

    # New alert must start a fresh incident, not reopen the resolved one
    assert inc1.id != inc2.id
    assert env["incidents_repo"].count_incidents() == 2


def test_attack_graph_nodes_and_edges_synthesis(correlation_env):
    """Verify complete attack graph synthesis with node types and directed edge types."""
    env = correlation_env
    engine = env["engine"]
    t0 = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)

    _, alert = _seed_alert(
        env,
        rule_id="auth.ssh_bruteforce",
        host="srv-dc-01",
        user="svc-backup",
        src_ip="192.168.10.55",
        ts=t0,
        process_name="sshd",
        outcome="FAILURE",
    )
    inc = engine.correlate_alert(alert.id)

    graph = env["incidents_repo"].get_attack_graph(inc.id)
    assert graph["incident_id"] == inc.id

    node_types = {n["entity_type"] for n in graph["nodes"]}
    assert "HOST" in node_types
    assert "USER" in node_types
    assert "IP" in node_types

    edge_types = {e["relationship_type"] for e in graph["edges"]}
    assert "CONNECTED_TO" in edge_types
    assert "AUTHENTICATED_TO" in edge_types


def test_relationship_deduplication_and_idempotency(correlation_env):
    """Verify that adding duplicate relationships does not produce duplicate rows and consolidates evidence."""
    env = correlation_env
    repo = env["incidents_repo"]
    t0 = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)

    inc = repo.create_incident(
        Incident(
            incident_key="test-dedup-inc-1",
            title="Dedup Test",
            summary="Testing deduplication",
            severity=Severity.ALERT,
            primary_host="host-1",
            first_seen=t0,
            last_seen=t0,
        )
    )

    # Insert initial relationship
    rel1 = IncidentRelationship(
        incident_id=inc.id,
        source_entity_key="user:alice",
        target_entity_key="host:host-1",
        relationship_type=RelationshipType.AUTHENTICATED_TO.value,
        confidence=ConfidenceLevel.STRONG,
        evidence_event_ids=["ev-1"],
    )
    repo.add_relationships(inc.id, [rel1])

    # Insert duplicate relationship with additional evidence
    rel2 = IncidentRelationship(
        incident_id=inc.id,
        source_entity_key="user:alice",
        target_entity_key="host:host-1",
        relationship_type=RelationshipType.AUTHENTICATED_TO.value,
        confidence=ConfidenceLevel.DIRECT,
        evidence_event_ids=["ev-2"],
    )
    repo.add_relationships(inc.id, [rel2])

    rels = repo.get_incident_relationships(inc.id)
    assert len(rels) == 1
    assert rels[0].confidence == ConfidenceLevel.DIRECT
    assert sorted(rels[0].evidence_event_ids) == ["ev-1", "ev-2"]


def test_dangling_entity_prevention(correlation_env):
    """Verify that relationships automatically ensure endpoints exist in incident_entities."""
    env = correlation_env
    repo = env["incidents_repo"]
    t0 = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)

    inc = repo.create_incident(
        Incident(
            incident_key="test-dangling-inc-1",
            title="Dangling Prevention Test",
            summary="Testing auto-creation of endpoints",
            severity=Severity.WARNING,
            primary_host="host-auto",
            first_seen=t0,
            last_seen=t0,
        ),
        relationships=[
            IncidentRelationship(
                incident_id=0,
                source_entity_key="user:bob",
                target_entity_key="host:host-auto",
                relationship_type=RelationshipType.AUTHENTICATED_TO.value,
                confidence=ConfidenceLevel.DIRECT,
            )
        ],
    )

    entities = {e.entity_key for e in repo.get_incident_entities(inc.id)}
    assert "user:bob" in entities
    assert "host:host-auto" in entities


def test_incident_merge_atomic_and_idempotent(correlation_env):
    """Verify that merge_incidents is atomic, idempotent, and preserves all alerts, entities, and evidence."""
    env = correlation_env
    repo = env["incidents_repo"]
    t1 = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 3, 30, 10, 15, 0, tzinfo=timezone.utc)

    _, a1 = _seed_alert(env, rule_id="auth.ssh_bruteforce", host="host-a", user="root", src_ip="192.168.1.10", ts=t1)
    _, a2 = _seed_alert(env, rule_id="priv.unauthorized_sudo", host="host-b", user="charlie", src_ip="192.168.1.20", ts=t2)

    inc_a = repo.create_incident(
        Incident(
            incident_key="inc-merge-src",
            title="Source Inc",
            summary="Source",
            severity=Severity.ALERT,
            primary_host="host-a",
            first_seen=t1,
            last_seen=t1,
        ),
        alert_ids=[a1.id],
    )
    inc_b = repo.create_incident(
        Incident(
            incident_key="inc-merge-tgt",
            title="Target Inc",
            summary="Target",
            severity=Severity.WARNING,
            primary_host="host-b",
            first_seen=t2,
            last_seen=t2,
        ),
        alert_ids=[a2.id],
    )

    # Idempotent: merging into self is a no-op
    self_merge = repo.merge_incidents(inc_b.id, inc_b.id)
    assert self_merge.id == inc_b.id

    # Merge A into B
    merged = repo.merge_incidents(inc_a.id, inc_b.id)
    assert merged.id == inc_b.id
    assert merged.first_seen == t1
    assert merged.last_seen == t2
    assert merged.severity == Severity.ALERT
    assert merged.alert_count == 2

    # Verify source incident A no longer exists
    assert repo.get_incident(inc_a.id) is None

    # Verify all alerts belong to B
    alerts = repo.get_incident_alerts(inc_b.id)
    assert {a.id for a in alerts} == {a1.id, a2.id}


def test_correlation_arrival_order_invariance(correlation_env):
    """Verify that different alert arrival permutations converge to the same single incident."""
    import itertools

    permutations = list(itertools.permutations([0, 1, 2]))
    # Test at least 6 permutations
    for perm in permutations:
        # Re-initialize clean test database
        with tempfile.TemporaryDirectory() as td:
            db_p = Path(td) / "test_perm.db"
            db = Database(db_p)
            db.initialize()
            alerts_r = AlertsRepository(db)
            events_r = EventsRepository(db)
            incidents_r = IncidentsRepository(db, alerts_r)
            default_rules = load_default_rules()
            alerts_r.sync_rules(default_rules)

            eng = IncidentCorrelationEngine(
                database=db,
                incidents_repository=incidents_r,
                alerts_repository=alerts_r,
                config=CorrelationConfig(window_seconds=1800, cross_host_correlation=True),
            )

            # Alert 1: Host A with attacker IP 198.51.100.55
            # Alert 2: Host B with same attacker IP 198.51.100.55 (cross-host pivot)
            # Alert 3: Host B with lateral movement / internal IP 10.0.0.99
            t0 = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)
            env_local = {
                "events_repo": events_r,
                "alerts_repo": alerts_r,
                "rules": {r.id: r for r in default_rules},
            }
            _, al0 = _seed_alert(env_local, rule_id="auth.ssh_bruteforce", host="host-a", user="root", src_ip="198.51.100.55", ts=t0)
            _, al1 = _seed_alert(env_local, rule_id="auth.ssh_bruteforce", host="host-b", user="root", src_ip="198.51.100.55", ts=t0 + timedelta(minutes=5))
            _, al2 = _seed_alert(env_local, rule_id="priv.unauthorized_sudo", host="host-b", user="admin", src_ip="10.0.0.99", ts=t0 + timedelta(minutes=10))

            alerts_pool = [al0, al1, al2]

            # Ingest in permutation order
            for idx in perm:
                eng.correlate_alert(alerts_pool[idx].id)

            active_incidents = incidents_r.list_incidents(status=IncidentStatus.OPEN)
            assert len(active_incidents) == 1, f"Failed for permutation {perm}: expected 1 incident, got {len(active_incidents)}"
            assert active_incidents[0].alert_count == 3


def test_entity_canonicalization(correlation_env):
    """Verify that entity canonicalization handles IPv4, IPv6, port stripping, and host case normalization."""
    env = correlation_env
    engine = env["engine"]
    t0 = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)

    # 1. Test host case normalization: "SRV-TEST-01" -> "host:srv-test-01"
    _, al1 = _seed_alert(
        env,
        rule_id="auth.ssh_bruteforce",
        host="SRV-TEST-01",
        user="Deployer",
        src_ip="192.0.2.1:54321",
        ts=t0,
    )
    inc = engine.correlate_alert(al1.id)

    entities = {e.entity_key: e for e in env["incidents_repo"].get_incident_entities(inc.id)}
    assert "host:srv-test-01" in entities
    assert entities["host:srv-test-01"].display_name == "srv-test-01"

    # 2. Test IP normalization and port stripping: "192.0.2.1:54321" -> "ip:192.0.2.1"
    assert "ip:192.0.2.1" in entities
    assert entities["ip:192.0.2.1"].display_name == "192.0.2.1"

    # 3. Test IPv6 normalization
    _, al2 = _seed_alert(
        env,
        rule_id="auth.ssh_bruteforce",
        host="srv-test-01",
        user="Deployer",
        src_ip="2001:0db8:0000:0000:0000:0000:0000:0001",
        ts=t0 + timedelta(minutes=1),
    )
    engine.correlate_alert(al2.id)
    entities2 = {e.entity_key: e for e in env["incidents_repo"].get_incident_entities(inc.id)}
    assert "ip:2001:db8::1" in entities2



