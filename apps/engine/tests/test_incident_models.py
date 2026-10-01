"""Unit tests for Milestone 3 Incident, Entity, Relationship, and Timeline Domain Models."""

from datetime import datetime, timedelta, timezone
import pytest
from pydantic import ValidationError

from logintel.models.events import Severity
from logintel.models.incidents import (
    ALLOWED_INCIDENT_STATUS_TRANSITIONS,
    ConfidenceLevel,
    EntityType,
    Incident,
    IncidentAlertLink,
    IncidentEntity,
    IncidentRelationship,
    IncidentStatus,
    InvalidIncidentStatusTransitionError,
    RelationshipType,
    TimelineItem,
    TimelineItemType,
)


# ============================================================================
# 1. INCIDENT DOMAIN MODEL & VALIDATION TESTS
# ============================================================================

def test_incident_instantiation_defaults():
    now = datetime.now(timezone.utc)
    inc = Incident(
        incident_key="INC-20260930-001",
        title="SSH Brute Force followed by Root Shell",
        summary="Repeated failed logins followed by root elevation on srv-api-01",
        primary_host="srv-api-01",
        primary_user="root",
        first_seen=now - timedelta(minutes=5),
        last_seen=now,
        alert_count=2,
        event_count=8,
    )

    assert inc.id is None
    assert inc.incident_key == "INC-20260930-001"
    assert inc.status == IncidentStatus.OPEN
    assert inc.severity == Severity.WARNING  # Default
    assert inc.primary_host == "srv-api-01"
    assert inc.primary_user == "root"
    assert inc.alert_count == 2
    assert inc.event_count == 8
    assert inc.resolved_at is None
    assert inc.resolution_note is None
    assert inc.created_at <= datetime.now(timezone.utc)
    assert inc.updated_at <= datetime.now(timezone.utc)


def test_incident_custom_severity_and_status():
    now = datetime.now(timezone.utc)
    inc = Incident(
        incident_key="INC-20260930-002",
        title="Unauthorized Sudo Abuse",
        summary="User attacker executed unauthorized sudo commands",
        severity=Severity.CRITICAL,
        status=IncidentStatus.INVESTIGATING,
        primary_host="srv-db-01",
        first_seen=now,
        last_seen=now,
    )

    assert inc.severity == Severity.CRITICAL
    assert inc.status == IncidentStatus.INVESTIGATING


def test_incident_missing_required_fields():
    with pytest.raises(ValidationError):
        # Missing required primary_host, title, summary, first_seen, last_seen
        Incident(incident_key="INC-MISSING")


# ============================================================================
# 2. INCIDENT LIFECYCLE STATE MACHINE TESTS
# ============================================================================

def test_valid_incident_status_transitions():
    """Verify that all authorized status transitions exist in the state machine."""
    # From OPEN
    assert IncidentStatus.INVESTIGATING in ALLOWED_INCIDENT_STATUS_TRANSITIONS[IncidentStatus.OPEN]
    assert IncidentStatus.CONTAINED in ALLOWED_INCIDENT_STATUS_TRANSITIONS[IncidentStatus.OPEN]
    assert IncidentStatus.RESOLVED in ALLOWED_INCIDENT_STATUS_TRANSITIONS[IncidentStatus.OPEN]
    assert IncidentStatus.FALSE_POSITIVE in ALLOWED_INCIDENT_STATUS_TRANSITIONS[IncidentStatus.OPEN]

    # From INVESTIGATING
    assert IncidentStatus.CONTAINED in ALLOWED_INCIDENT_STATUS_TRANSITIONS[IncidentStatus.INVESTIGATING]
    assert IncidentStatus.RESOLVED in ALLOWED_INCIDENT_STATUS_TRANSITIONS[IncidentStatus.INVESTIGATING]
    assert IncidentStatus.FALSE_POSITIVE in ALLOWED_INCIDENT_STATUS_TRANSITIONS[IncidentStatus.INVESTIGATING]
    assert IncidentStatus.OPEN in ALLOWED_INCIDENT_STATUS_TRANSITIONS[IncidentStatus.INVESTIGATING]

    # From CONTAINED
    assert IncidentStatus.RESOLVED in ALLOWED_INCIDENT_STATUS_TRANSITIONS[IncidentStatus.CONTAINED]
    assert IncidentStatus.FALSE_POSITIVE in ALLOWED_INCIDENT_STATUS_TRANSITIONS[IncidentStatus.CONTAINED]
    assert IncidentStatus.INVESTIGATING in ALLOWED_INCIDENT_STATUS_TRANSITIONS[IncidentStatus.CONTAINED]

    # Reopening from terminal states
    assert IncidentStatus.OPEN in ALLOWED_INCIDENT_STATUS_TRANSITIONS[IncidentStatus.RESOLVED]
    assert IncidentStatus.OPEN in ALLOWED_INCIDENT_STATUS_TRANSITIONS[IncidentStatus.FALSE_POSITIVE]
    assert IncidentStatus.OPEN in ALLOWED_INCIDENT_STATUS_TRANSITIONS[IncidentStatus.CLOSED]

    # Closing
    assert IncidentStatus.CLOSED in ALLOWED_INCIDENT_STATUS_TRANSITIONS[IncidentStatus.RESOLVED]
    assert IncidentStatus.CLOSED in ALLOWED_INCIDENT_STATUS_TRANSITIONS[IncidentStatus.FALSE_POSITIVE]


def test_invalid_incident_status_transitions():
    """Verify invalid transition prevention and custom error creation."""
    # CLOSED cannot jump directly to INVESTIGATING without reopening to OPEN first
    assert IncidentStatus.INVESTIGATING not in ALLOWED_INCIDENT_STATUS_TRANSITIONS[IncidentStatus.CLOSED]

    # RESOLVED cannot jump directly to FALSE_POSITIVE without reopening to OPEN first
    assert IncidentStatus.FALSE_POSITIVE not in ALLOWED_INCIDENT_STATUS_TRANSITIONS[IncidentStatus.RESOLVED]

    # OPEN cannot jump directly to CLOSED without being RESOLVED or FALSE_POSITIVE first
    assert IncidentStatus.CLOSED not in ALLOWED_INCIDENT_STATUS_TRANSITIONS[IncidentStatus.OPEN]

    err = InvalidIncidentStatusTransitionError(IncidentStatus.OPEN, IncidentStatus.CLOSED)
    assert "Invalid incident status transition from 'OPEN' to 'CLOSED'" in str(err)
    assert err.from_status == IncidentStatus.OPEN
    assert err.to_status == IncidentStatus.CLOSED


# ============================================================================
# 3. ENTITY & RELATIONSHIP DOMAIN MODEL TESTS
# ============================================================================

def test_entity_types_and_instantiation():
    entity_types = {e.value for e in EntityType}
    assert "HOST" in entity_types
    assert "USER" in entity_types
    assert "IP" in entity_types
    assert "PROCESS" in entity_types
    assert "COMMAND" in entity_types
    assert "FILE" in entity_types
    assert "SESSION" in entity_types

    ent = IncidentEntity(
        incident_id=1,
        entity_key="user:attacker",
        entity_type=EntityType.USER,
        display_name="attacker",
        metadata={"uid": 1001, "primary_group": "users"},
    )
    assert ent.entity_key == "user:attacker"
    assert ent.entity_type == EntityType.USER
    assert ent.metadata["uid"] == 1001


def test_confidence_level_ordering_and_categories():
    assert ConfidenceLevel.DIRECT.value == "DIRECT"
    assert ConfidenceLevel.STRONG.value == "STRONG"
    assert ConfidenceLevel.CORRELATED.value == "CORRELATED"
    assert ConfidenceLevel.INFERRED.value == "INFERRED"
    assert ConfidenceLevel.WEAK.value == "WEAK"


def test_incident_relationship_instantiation():
    rel = IncidentRelationship(
        incident_id=1,
        source_entity_key="ip:198.51.100.66",
        target_entity_key="host:srv-api-01",
        relationship_type=RelationshipType.AUTHENTICATED_TO.value,
        confidence=ConfidenceLevel.DIRECT,
        evidence_event_ids=["ev-ssh-login-01"],
    )

    assert rel.incident_id == 1
    assert rel.source_entity_key == "ip:198.51.100.66"
    assert rel.target_entity_key == "host:srv-api-01"
    assert rel.relationship_type == "AUTHENTICATED_TO"
    assert rel.confidence == ConfidenceLevel.DIRECT
    assert rel.evidence_event_ids == ["ev-ssh-login-01"]


def test_incident_alert_link():
    now = datetime.now(timezone.utc)
    link = IncidentAlertLink(
        incident_id=42,
        alert_id=10,
        added_at=now,
    )
    assert link.incident_id == 42
    assert link.alert_id == 10
    assert link.added_at == now


# ============================================================================
# 4. INVESTIGATION TIMELINE MODEL & DETERMINISTIC SORTING TESTS
# ============================================================================

def test_timeline_item_instantiation_and_sorting():
    t1 = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 9, 30, 10, 5, 0, tzinfo=timezone.utc)

    item1 = TimelineItem(
        id="item-02",
        timestamp=t1,
        item_type=TimelineItemType.EVENT,
        title="Failed SSH Authentication",
        summary="Failed password for invalid user admin",
        severity=Severity.ALERT,
        entity_keys=["ip:198.51.100.66", "host:srv-api-01"],
        ref_id="ev-101",
    )

    item2 = TimelineItem(
        id="item-01",
        timestamp=t1,  # Same timestamp as item1
        item_type=TimelineItemType.EVENT,
        title="Failed SSH Authentication",
        summary="Failed password for invalid user test",
        severity=Severity.ALERT,
        entity_keys=["ip:198.51.100.66", "host:srv-api-01"],
        ref_id="ev-100",
    )

    item3 = TimelineItem(
        id="item-03",
        timestamp=t2,
        item_type=TimelineItemType.ALERT,
        title="SSH Brute Force Triggered",
        summary="auth.ssh_bruteforce matched 5 events in 300s",
        severity=Severity.ALERT,
        entity_keys=["ip:198.51.100.66", "host:srv-api-01"],
        ref_id="alt-1",
    )

    # Sort items using deterministic key: timestamp ASC, id ASC
    sorted_items = sorted([item3, item1, item2], key=lambda x: x.sort_key())

    # item2 (t1, item-01) comes before item1 (t1, item-02), followed by item3 (t2, item-03)
    assert sorted_items[0].id == "item-01"
    assert sorted_items[1].id == "item-02"
    assert sorted_items[2].id == "item-03"
