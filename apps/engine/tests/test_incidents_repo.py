"""Tests for M3.3 IncidentsRepository (Incident Lifecycle, Alert Aggregation & Attack Graph)."""

from __future__ import annotations

import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from logintel.detection import EvidenceRole, load_default_rules
from logintel.detection.results import DetectionResult
from logintel.models.events import CanonicalEvent, Severity
from logintel.models.incidents import (
    ConfidenceLevel,
    EntityType,
    Incident,
    IncidentEntity,
    IncidentRelationship,
    IncidentStatus,
    InvalidIncidentStatusTransitionError,
    RelationshipType,
    TimelineItemType,
)
from logintel.storage.alerts_repo import AlertsRepository
from logintel.storage.db import Database
from logintel.storage.events_repo import EventsRepository
from logintel.storage.incidents_repo import IncidentsRepository


@pytest.fixture
def repo_env():
    """Create an isolated database and repository instances for testing."""
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "test_incidents.db"
        test_db = Database(db_path)
        test_db.initialize()

        alerts_repo = AlertsRepository(test_db)
        events_repo = EventsRepository(test_db)
        incidents_repo = IncidentsRepository(test_db, alerts_repo)

        # Seed detection rules
        rules = load_default_rules()
        alerts_repo.sync_rules(rules)
        rule = next(r for r in rules if r.id == "auth.ssh_bruteforce")

        yield {
            "db": test_db,
            "alerts_repo": alerts_repo,
            "events_repo": events_repo,
            "incidents_repo": incidents_repo,
            "rule": rule,
        }
        test_db.close()


def _seed_event_and_alert(env, host="srv-01", user="root", ts_offset_min=0):
    """Helper to seed a canonical event, a detection, and an operational alert."""
    base_time = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc) + timedelta(minutes=ts_offset_min)
    ev_id = f"ev-{ts_offset_min}-{host}"
    event = CanonicalEvent(
        id=ev_id,
        timestamp=base_time,
        ingested_at=base_time,
        host=host,
        source="sshd",
        event_type="AUTH_LOGIN_FAILURE",
        severity=Severity.WARNING,
        outcome="FAILURE",
        summary=f"Failed SSH login for {user}",
        raw_message=f"Failed password for {user} from 10.0.0.{ts_offset_min} port 22 ssh2",
        username=user,
        src_ip=f"10.0.0.{ts_offset_min}",
        parser="ssh",
    )
    env["events_repo"].insert_events([event])

    det_result = DetectionResult(
        rule_id=env["rule"].id,
        timestamp=base_time,
        host=host,
        summary=f"Brute force detection on {host}",
        evidence_event_ids=[ev_id],
        evidence_roles={ev_id: EvidenceRole.TRIGGER},
        details={"group_key": f"{host}:{user}:{ts_offset_min}"},
    )
    alert = env["alerts_repo"].record_detection(det_result, env["rule"])
    return event, alert


def test_create_and_get_incident(repo_env):
    """Verify basic incident creation and retrieval by ID and by key."""
    repo = repo_env["incidents_repo"]
    now = datetime(2026, 3, 30, 12, 0, 0, tzinfo=timezone.utc)

    incident = Incident(
        incident_key="inc-auth-001",
        title="Unauthorized Root Access Campaign",
        summary="Multiple brute force attempts followed by suspicious escalation",
        severity=Severity.CRITICAL,
        status=IncidentStatus.OPEN,
        primary_host="srv-alpha",
        primary_user="root",
        first_seen=now,
        last_seen=now,
    )

    created = repo.create_incident(incident)
    assert created.id is not None
    assert created.incident_key == "inc-auth-001"
    assert created.status == IncidentStatus.OPEN
    assert created.severity == Severity.CRITICAL
    assert created.alert_count == 0

    # Retrieve by ID
    fetched_by_id = repo.get_incident(created.id)
    assert fetched_by_id is not None
    assert fetched_by_id.id == created.id
    assert fetched_by_id.title == incident.title

    # Retrieve by Key
    fetched_by_key = repo.get_incident_by_key("inc-auth-001")
    assert fetched_by_key is not None
    assert fetched_by_key.id == created.id


def test_create_incident_with_alerts_entities_and_relationships(repo_env):
    """Verify atomic incident creation with linked alerts, graph entities, and relationships."""
    repo = repo_env["incidents_repo"]
    now = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)
    ev1, alert1 = _seed_event_and_alert(repo_env, host="srv-01", ts_offset_min=0)
    ev2, alert2 = _seed_event_and_alert(repo_env, host="srv-01", ts_offset_min=5)

    entities = [
        IncidentEntity(
            incident_id=0,  # Will be assigned
            entity_key="host:srv-01",
            entity_type=EntityType.HOST,
            display_name="srv-01",
            metadata={"os": "Ubuntu 24.04"},
        ),
        IncidentEntity(
            incident_id=0,
            entity_key="ip:10.0.0.0",
            entity_type=EntityType.IP,
            display_name="10.0.0.0",
        ),
    ]

    relationships = [
        IncidentRelationship(
            incident_id=0,
            source_entity_key="ip:10.0.0.0",
            target_entity_key="host:srv-01",
            relationship_type=RelationshipType.CONNECTED_TO.value,
            confidence=ConfidenceLevel.DIRECT,
            evidence_event_ids=[ev1.id, ev2.id],
        )
    ]

    incident = Incident(
        incident_key="inc-full-001",
        title="Coordinated Attack on srv-01",
        summary="Attacker IP probed and executed brute force",
        severity=Severity.ALERT,
        primary_host="srv-01",
        first_seen=now,
        last_seen=now,
    )

    created = repo.create_incident(
        incident,
        alert_ids=[alert1.id, alert2.id],
        entities=entities,
        relationships=relationships,
    )

    assert created.alert_count == 2
    assert created.event_count == 2
    assert created.first_seen == alert1.first_seen
    assert created.last_seen == alert2.last_seen

    # Verify entities retrieved
    stored_entities = repo.get_incident_entities(created.id)
    assert len(stored_entities) == 2
    assert {e.entity_key for e in stored_entities} == {"host:srv-01", "ip:10.0.0.0"}

    # Verify relationships retrieved
    stored_rels = repo.get_incident_relationships(created.id)
    assert len(stored_rels) == 1
    assert stored_rels[0].source_entity_key == "ip:10.0.0.0"
    assert stored_rels[0].target_entity_key == "host:srv-01"
    assert stored_rels[0].relationship_type == RelationshipType.CONNECTED_TO.value


def test_list_and_count_incidents(repo_env):
    """Verify listing and counting incidents with various filter combinations."""
    repo = repo_env["incidents_repo"]
    now = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)

    for i in range(5):
        repo.create_incident(
            Incident(
                incident_key=f"inc-list-{i}",
                title=f"Incident {i}",
                summary="Summary",
                severity=Severity.CRITICAL if i % 2 == 0 else Severity.WARNING,
                status=IncidentStatus.OPEN if i < 3 else IncidentStatus.RESOLVED,
                primary_host="host-A" if i < 2 else "host-B",
                primary_user="user-1" if i == 0 else None,
                first_seen=now,
                last_seen=now,
            )
        )

    # Total count
    assert repo.count_incidents() == 5

    # Filter by status
    open_incidents = repo.list_incidents(status=IncidentStatus.OPEN)
    assert len(open_incidents) == 3
    assert repo.count_incidents(status=IncidentStatus.OPEN) == 3

    # Filter by severity
    crit_incidents = repo.list_incidents(severity=Severity.CRITICAL)
    assert len(crit_incidents) == 3

    # Filter by host
    host_a = repo.list_incidents(host="host-A")
    assert len(host_a) == 2

    # Filter by user
    user_1 = repo.list_incidents(user="user-1")
    assert len(user_1) == 1

    # Pagination
    paged = repo.list_incidents(limit=2, offset=0)
    assert len(paged) == 2
    paged_2 = repo.list_incidents(limit=2, offset=2)
    assert len(paged_2) == 2
    assert paged[0].id != paged_2[0].id


def test_incident_status_transitions_valid(repo_env):
    """Verify authorized incident status transitions and resolution timestamps."""
    repo = repo_env["incidents_repo"]
    now = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)
    inc = repo.create_incident(
        Incident(
            incident_key="inc-trans-01",
            title="Lifecycle Incident",
            summary="Lifecycle test",
            severity=Severity.ALERT,
            primary_host="srv-01",
            first_seen=now,
            last_seen=now,
        )
    )
    assert inc.status == IncidentStatus.OPEN
    assert inc.resolved_at is None

    # OPEN -> INVESTIGATING
    inc = repo.update_incident_status(inc.id, IncidentStatus.INVESTIGATING)
    assert inc.status == IncidentStatus.INVESTIGATING

    # INVESTIGATING -> CONTAINED
    inc = repo.update_incident_status(inc.id, IncidentStatus.CONTAINED)
    assert inc.status == IncidentStatus.CONTAINED

    # CONTAINED -> RESOLVED (with note)
    inc = repo.update_incident_status(
        inc.id, IncidentStatus.RESOLVED, resolution_note="Firewall rule deployed"
    )
    assert inc.status == IncidentStatus.RESOLVED
    assert inc.resolved_at is not None
    assert inc.resolution_note == "Firewall rule deployed"

    # RESOLVED -> CLOSED
    inc = repo.update_incident_status(inc.id, IncidentStatus.CLOSED)
    assert inc.status == IncidentStatus.CLOSED

    # Reopening: CLOSED -> OPEN
    inc = repo.update_incident_status(inc.id, IncidentStatus.OPEN)
    assert inc.status == IncidentStatus.OPEN
    assert inc.resolved_at is None
    assert inc.resolution_note is None


def test_incident_status_transitions_invalid(repo_env):
    """Verify that unauthorized status transitions raise InvalidIncidentStatusTransitionError."""
    repo = repo_env["incidents_repo"]
    now = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)
    inc = repo.create_incident(
        Incident(
            incident_key="inc-bad-trans",
            title="Illegal Transition",
            summary="Test",
            severity=Severity.ALERT,
            primary_host="srv-01",
            first_seen=now,
            last_seen=now,
        )
    )

    # OPEN -> CLOSED directly is illegal (must go through RESOLVED or FALSE_POSITIVE)
    with pytest.raises(InvalidIncidentStatusTransitionError):
        repo.update_incident_status(inc.id, IncidentStatus.CLOSED)


def test_add_and_remove_alerts(repo_env):
    """Verify adding and removing alerts dynamically updates aggregated metrics."""
    repo = repo_env["incidents_repo"]
    now = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)
    _, alert1 = _seed_event_and_alert(repo_env, host="srv-01", ts_offset_min=0)
    _, alert2 = _seed_event_and_alert(repo_env, host="srv-01", ts_offset_min=10)

    inc = repo.create_incident(
        Incident(
            incident_key="inc-dyn-alerts",
            title="Dynamic Alerts Incident",
            summary="Test",
            severity=Severity.ALERT,
            primary_host="srv-01",
            first_seen=now,
            last_seen=now,
        )
    )
    assert inc.alert_count == 0

    # Add first alert
    inc = repo.add_alerts_to_incident(inc.id, [alert1.id])
    assert inc.alert_count == 1
    assert inc.first_seen == alert1.first_seen
    assert inc.last_seen == alert1.last_seen

    # Add second alert
    inc = repo.add_alerts_to_incident(inc.id, [alert2.id])
    assert inc.alert_count == 2
    assert inc.first_seen == alert1.first_seen
    assert inc.last_seen == alert2.last_seen

    # Verify alert IDs and alerts list
    alert_ids = repo.get_incident_alert_ids(inc.id)
    assert set(alert_ids) == {alert1.id, alert2.id}

    alerts = repo.get_incident_alerts(inc.id)
    assert len(alerts) == 2

    # Remove alert1
    inc = repo.remove_alert_from_incident(inc.id, alert1.id)
    assert inc.alert_count == 1
    assert inc.first_seen == alert2.first_seen
    assert inc.last_seen == alert2.last_seen


def test_entities_upsert_and_filtering(repo_env):
    """Verify entity upsert on conflict and filtering by type."""
    repo = repo_env["incidents_repo"]
    now = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)
    inc = repo.create_incident(
        Incident(
            incident_key="inc-ent-test",
            title="Entity Incident",
            summary="Test",
            severity=Severity.ALERT,
            primary_host="srv-01",
            first_seen=now,
            last_seen=now,
        )
    )

    entities = [
        IncidentEntity(
            incident_id=inc.id,
            entity_key="host:srv-01",
            entity_type=EntityType.HOST,
            display_name="srv-01 (v1)",
        ),
        IncidentEntity(
            incident_id=inc.id,
            entity_key="user:alice",
            entity_type=EntityType.USER,
            display_name="alice",
        ),
    ]
    repo.add_entities(inc.id, entities)

    # Upsert existing entity with new display_name
    repo.add_entities(
        inc.id,
        [
            IncidentEntity(
                incident_id=inc.id,
                entity_key="host:srv-01",
                entity_type=EntityType.HOST,
                display_name="srv-01 (updated)",
                metadata={"rack": "R12"},
            )
        ],
    )

    stored = repo.get_incident_entities(inc.id)
    assert len(stored) == 2
    host_ent = next(e for e in stored if e.entity_key == "host:srv-01")
    assert host_ent.display_name == "srv-01 (updated)"
    assert host_ent.metadata == {"rack": "R12"}

    # Filter by type
    users = repo.get_incident_entities(inc.id, entity_type=EntityType.USER)
    assert len(users) == 1
    assert users[0].entity_key == "user:alice"


def test_relationships_and_attack_graph_format(repo_env):
    """Verify relationship insertion and graph payload formation."""
    repo = repo_env["incidents_repo"]
    now = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)
    inc = repo.create_incident(
        Incident(
            incident_key="inc-graph-test",
            title="Graph Incident",
            summary="Test",
            severity=Severity.ALERT,
            primary_host="srv-01",
            first_seen=now,
            last_seen=now,
        )
    )

    repo.add_entities(
        inc.id,
        [
            IncidentEntity(
                incident_id=inc.id,
                entity_key="host:srv-01",
                entity_type=EntityType.HOST,
                display_name="srv-01",
            ),
            IncidentEntity(
                incident_id=inc.id,
                entity_key="ip:1.2.3.4",
                entity_type=EntityType.IP,
                display_name="1.2.3.4",
            ),
        ],
    )

    repo.add_relationships(
        inc.id,
        [
            IncidentRelationship(
                incident_id=inc.id,
                source_entity_key="ip:1.2.3.4",
                target_entity_key="host:srv-01",
                relationship_type=RelationshipType.CONNECTED_TO.value,
                confidence=ConfidenceLevel.STRONG,
            )
        ],
    )

    graph = repo.get_attack_graph(inc.id)
    assert graph["incident_id"] == inc.id
    assert len(graph["nodes"]) == 2
    assert len(graph["edges"]) == 1
    assert graph["edges"][0]["source"] == "ip:1.2.3.4"
    assert graph["edges"][0]["target"] == "host:srv-01"
    assert graph["edges"][0]["relationship_type"] == "CONNECTED_TO"
    assert graph["edges"][0]["confidence"] == "STRONG"


def test_incident_timeline_chronological_ordering(repo_env):
    """Verify that investigation timeline items are sorted chronologically with tie-breakers."""
    repo = repo_env["incidents_repo"]
    now = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)
    ev1, alert1 = _seed_event_and_alert(repo_env, host="srv-01", ts_offset_min=0)
    ev2, alert2 = _seed_event_and_alert(repo_env, host="srv-01", ts_offset_min=5)

    inc = repo.create_incident(
        Incident(
            incident_key="inc-time-01",
            title="Timeline Incident",
            summary="Test",
            severity=Severity.CRITICAL,
            primary_host="srv-01",
            first_seen=now,
            last_seen=now,
        ),
        alert_ids=[alert1.id, alert2.id],
    )

    # Add relationship matched at minute 10
    rel_time = datetime(2026, 3, 30, 10, 10, 0, tzinfo=timezone.utc)
    repo.add_relationships(
        inc.id,
        [
            IncidentRelationship(
                incident_id=inc.id,
                source_entity_key="ip:10.0.0.0",
                target_entity_key="host:srv-01",
                relationship_type=RelationshipType.CONNECTED_TO.value,
                confidence=ConfidenceLevel.DIRECT,
                matched_at=rel_time,
            )
        ],
    )

    timeline = repo.get_incident_timeline(inc.id)
    assert len(timeline) >= 4  # 2 alerts + 2 events + 1 relationship

    # Verify timestamps are strictly monotonically non-decreasing
    for i in range(len(timeline) - 1):
        assert timeline[i].timestamp <= timeline[i + 1].timestamp


def test_get_incident_details_workspace_payload(repo_env):
    """Verify aggregated workspace payload for incident triage and investigation."""
    repo = repo_env["incidents_repo"]
    now = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)
    _, alert1 = _seed_event_and_alert(repo_env, host="srv-01", ts_offset_min=0)

    inc = repo.create_incident(
        Incident(
            incident_key="inc-details-01",
            title="Details Test",
            summary="Full details payload",
            severity=Severity.ALERT,
            primary_host="srv-01",
            first_seen=now,
            last_seen=now,
        ),
        alert_ids=[alert1.id],
    )

    details = repo.get_incident_details(inc.id)
    assert details is not None
    assert "incident" in details
    assert "alerts" in details
    assert "graph" in details
    assert "timeline" in details
    assert len(details["alerts"]) == 1
    assert details["incident"]["id"] == inc.id


def test_delete_incident_cascade(repo_env):
    """Verify that deleting an incident cleanly cascades to links and graph data without removing alerts."""
    repo = repo_env["incidents_repo"]
    now = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)
    _, alert1 = _seed_event_and_alert(repo_env, host="srv-01", ts_offset_min=0)

    inc = repo.create_incident(
        Incident(
            incident_key="inc-delete-test",
            title="Delete Test",
            summary="Test deletion cascade",
            severity=Severity.ALERT,
            primary_host="srv-01",
            first_seen=now,
            last_seen=now,
        ),
        alert_ids=[alert1.id],
        entities=[
            IncidentEntity(
                incident_id=0,
                entity_key="host:srv-01",
                entity_type=EntityType.HOST,
                display_name="srv-01",
            )
        ],
    )

    assert repo.get_incident(inc.id) is not None
    assert len(repo.get_incident_entities(inc.id)) == 1
    assert len(repo.get_incident_alert_ids(inc.id)) == 1

    # Delete
    deleted = repo.delete_incident(inc.id)
    assert deleted is True

    # Incident and associations gone
    assert repo.get_incident(inc.id) is None
    assert len(repo.get_incident_entities(inc.id)) == 0
    assert len(repo.get_incident_alert_ids(inc.id)) == 0

    # Underlying alert remains intact
    remaining_alert = repo_env["alerts_repo"].get_alert(alert1.id)
    assert remaining_alert is not None
