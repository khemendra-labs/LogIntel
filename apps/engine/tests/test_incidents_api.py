"""Integration test suite for LogIntel M3.5 Incident & Attack Graph REST API endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from logintel.api.app import app
from logintel.api.auth import get_current_token
from logintel.detection import load_default_rules
from logintel.models.events import Severity
from logintel.models.incidents import (
    ConfidenceLevel,
    EntityType,
    Incident,
    IncidentEntity,
    IncidentRelationship,
    IncidentStatus,
    RelationshipType,
)
from logintel.storage import db
from logintel.storage.alerts_repo import alerts_repo
from logintel.storage.incidents_repo import incidents_repo


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    """Test client with isolated temporary database and canonical rules initialized."""
    temp_dir = tmp_path_factory.mktemp("incidents_api_db")
    temp_db_path = temp_dir / "incidents_api_test.db"
    orig_db_path = db.db_path
    db.close()
    db.db_path = temp_db_path
    db._initialized = False
    db.initialize()
    alerts_repo.sync_rules(load_default_rules())

    from logintel.ingestion import ingestion_engine
    orig_start = ingestion_engine.start
    orig_stop = ingestion_engine.stop
    ingestion_engine.start = lambda: None
    ingestion_engine.stop = lambda: None

    with TestClient(app) as test_client:
        yield test_client

    db.close()
    db.db_path = orig_db_path
    db._initialized = False
    ingestion_engine.start = orig_start
    ingestion_engine.stop = orig_stop


@pytest.fixture(scope="module")
def auth_client(client):
    """Test client with valid Bearer token attached."""
    token = get_current_token()
    client.headers["Authorization"] = f"Bearer {token}"
    return client


# ============================================================================
# 1. AUTHENTICATION ENFORCEMENT
# ============================================================================

def test_incident_endpoints_require_auth(client):
    """All incident and graph endpoints must reject unauthenticated requests with 401."""
    endpoints = [
        ("GET", "/api/v1/incidents"),
        ("GET", "/api/v1/incidents/1"),
        ("GET", "/api/v1/incidents/1/alerts"),
        ("PATCH", "/api/v1/incidents/1/status"),
        ("GET", "/api/v1/incidents/1/graph"),
        ("GET", "/api/v1/incidents/1/timeline"),
        ("POST", "/api/v1/incidents/correlate"),
    ]
    for method, path in endpoints:
        res = client.request(method, path, headers={"Authorization": ""})
        assert res.status_code == 401, f"{method} {path} should be 401 without auth, got {res.status_code}"


def test_incident_endpoints_reject_invalid_token(client):
    """Incident endpoints must reject invalid or forged tokens."""
    bad_headers = {"Authorization": "Bearer fraudulent_token_12345"}
    res = client.get("/api/v1/incidents", headers=bad_headers)
    assert res.status_code == 401


# ============================================================================
# 2. INCIDENT LISTING & QUERY FILTERS
# ============================================================================

def test_list_incidents_success_and_filtering(auth_client):
    """Verify listing incidents with status, severity, host, user filters and pagination."""
    now = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)
    key1 = f"api-inc-01-{uuid.uuid4().hex[:8]}"
    key2 = f"api-inc-02-{uuid.uuid4().hex[:8]}"
    inc1 = incidents_repo.create_incident(
        Incident(
            incident_key=key1,
            title="Finance Server SSH Breach",
            summary="Multiple brute force attempts",
            severity=Severity.CRITICAL,
            status=IncidentStatus.OPEN,
            primary_host="srv-finance-01",
            primary_user="root",
            first_seen=now,
            last_seen=now,
        )
    )
    inc2 = incidents_repo.create_incident(
        Incident(
            incident_key=key2,
            title="Web Server Reconnaissance",
            summary="Port scan detected",
            severity=Severity.WARNING,
            status=IncidentStatus.INVESTIGATING,
            primary_host="srv-web-01",
            primary_user="ubuntu",
            first_seen=now,
            last_seen=now,
        )
    )

    # 1. Basic list
    res = auth_client.get("/api/v1/incidents?limit=10&offset=0")
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert "total" in data
    assert data["total"] >= 2
    assert data["limit"] == 10
    assert data["offset"] == 0

    # 2. Filter by status
    res_status = auth_client.get("/api/v1/incidents?status=OPEN")
    assert res_status.status_code == 200
    items = res_status.json()["items"]
    assert all(i["status"] == "OPEN" for i in items)

    # 3. Filter by severity
    res_sev = auth_client.get("/api/v1/incidents?severity=CRITICAL")
    assert res_sev.status_code == 200
    crit_items = res_sev.json()["items"]
    assert any(i["incident_key"] == key1 for i in crit_items)

    # 4. Filter by host
    res_host = auth_client.get("/api/v1/incidents?host=srv-finance-01")
    assert res_host.status_code == 200
    host_items = res_host.json()["items"]
    assert all(i["primary_host"] == "srv-finance-01" for i in host_items)


def test_list_incidents_invalid_parameters(auth_client):
    """Verify validation errors on invalid status or severity filter parameters."""
    res_bad_status = auth_client.get("/api/v1/incidents?status=INVALID_STATUS")
    assert res_bad_status.status_code == 400
    assert "Invalid incident status" in res_bad_status.json()["detail"]

    res_bad_sev = auth_client.get("/api/v1/incidents?severity=BOGUS_SEVERITY")
    assert res_bad_sev.status_code == 400
    assert "Invalid severity" in res_bad_sev.json()["detail"]


# ============================================================================
# 3. INCIDENT DETAIL & ALERTS ENDPOINTS
# ============================================================================

def test_get_incident_detail_found_and_not_found(auth_client):
    """Verify fetching full incident detail payload and 404 behavior."""
    now = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)
    key = f"api-inc-detail-{uuid.uuid4().hex[:8]}"
    inc = incidents_repo.create_incident(
        Incident(
            incident_key=key,
            title="Database Elevation",
            summary="Unauthorized sudo su command",
            severity=Severity.ALERT,
            primary_host="srv-db-01",
            first_seen=now,
            last_seen=now,
        )
    )

    # Existing incident
    res = auth_client.get(f"/api/v1/incidents/{inc.id}")
    assert res.status_code == 200
    data = res.json()
    assert "incident" in data
    assert "alerts" in data
    assert "graph" in data
    assert "timeline" in data
    assert data["incident"]["id"] == inc.id

    # Non-existent incident
    res_404 = auth_client.get("/api/v1/incidents/999999")
    assert res_404.status_code == 404


def test_get_incident_alerts_endpoint(auth_client):
    """Verify fetching operational alerts linked to an incident."""
    now = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)
    key = f"api-inc-alerts-{uuid.uuid4().hex[:8]}"
    inc = incidents_repo.create_incident(
        Incident(
            incident_key=key,
            title="Alerts Link Test",
            summary="Testing alerts sub-resource",
            severity=Severity.NOTICE,
            primary_host="srv-api-01",
            first_seen=now,
            last_seen=now,
        )
    )

    res = auth_client.get(f"/api/v1/incidents/{inc.id}/alerts")
    assert res.status_code == 200
    data = res.json()
    assert data["incident_id"] == inc.id
    assert "items" in data
    assert "total" in data

    # 404 for non-existent incident
    res_404 = auth_client.get("/api/v1/incidents/999999/alerts")
    assert res_404.status_code == 404


# ============================================================================
# 4. INCIDENT STATUS MUTATION ENDPOINT
# ============================================================================

def test_update_incident_status_lifecycle(auth_client):
    """Verify incident status transitions via PATCH endpoint."""
    now = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)
    key = f"api-inc-patch-{uuid.uuid4().hex[:8]}"
    inc = incidents_repo.create_incident(
        Incident(
            incident_key=key,
            title="Status Lifecycle Test",
            summary="Transitioning through lifecycle",
            severity=Severity.ALERT,
            status=IncidentStatus.OPEN,
            primary_host="srv-app-01",
            first_seen=now,
            last_seen=now,
        )
    )

    # 1. OPEN -> INVESTIGATING
    res1 = auth_client.patch(
        f"/api/v1/incidents/{inc.id}/status",
        json={"status": "INVESTIGATING"},
    )
    assert res1.status_code == 200
    assert res1.json()["status"] == "INVESTIGATING"

    # 2. INVESTIGATING -> RESOLVED with resolution_note
    res2 = auth_client.patch(
        f"/api/v1/incidents/{inc.id}/status",
        json={
            "status": "RESOLVED",
            "resolution_note": "Host isolated and credentials rotated.",
        },
    )
    assert res2.status_code == 200
    assert res2.json()["status"] == "RESOLVED"
    assert res2.json()["resolution_note"] == "Host isolated and credentials rotated."
    assert res2.json()["resolved_at"] is not None

    # 3. Invalid status string -> 400
    res_invalid = auth_client.patch(
        f"/api/v1/incidents/{inc.id}/status",
        json={"status": "UNKNOWN_BOGUS_STATUS"},
    )
    assert res_invalid.status_code == 400

    # 4. Illegal state transition -> 400 (e.g. RESOLVED directly to CONTAINED)
    res_illegal = auth_client.patch(
        f"/api/v1/incidents/{inc.id}/status",
        json={"status": "CONTAINED"},
    )
    assert res_illegal.status_code == 400

    # 5. Non-existent incident -> 404
    res_404 = auth_client.patch(
        "/api/v1/incidents/999999/status",
        json={"status": "OPEN"},
    )
    assert res_404.status_code == 404


# ============================================================================
# 5. ATTACK GRAPH & TIMELINE ENDPOINTS
# ============================================================================

def test_get_incident_attack_graph_endpoint(auth_client):
    """Verify graph nodes and edges payload via REST API."""
    now = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)
    key = f"api-inc-graph-{uuid.uuid4().hex[:8]}"
    inc = incidents_repo.create_incident(
        Incident(
            incident_key=key,
            title="Graph API Test",
            summary="Graph payload verification",
            severity=Severity.ALERT,
            primary_host="srv-graph-01",
            first_seen=now,
            last_seen=now,
        ),
        entities=[
            IncidentEntity(
                incident_id=0,
                entity_key="host:srv-graph-01",
                entity_type=EntityType.HOST,
                display_name="srv-graph-01",
            ),
            IncidentEntity(
                incident_id=0,
                entity_key="user:developer",
                entity_type=EntityType.USER,
                display_name="developer",
            ),
        ],
        relationships=[
            IncidentRelationship(
                incident_id=0,
                source_entity_key="user:developer",
                target_entity_key="host:srv-graph-01",
                relationship_type=RelationshipType.AUTHENTICATED_TO.value,
                confidence=ConfidenceLevel.DIRECT,
            )
        ],
    )

    res = auth_client.get(f"/api/v1/incidents/{inc.id}/graph")
    assert res.status_code == 200
    data = res.json()
    assert data["incident_id"] == inc.id
    assert len(data["nodes"]) == 2
    assert len(data["edges"]) == 1
    assert data["edges"][0]["source"] == "user:developer"
    assert data["edges"][0]["target"] == "host:srv-graph-01"

    # 404 on non-existent incident
    assert auth_client.get("/api/v1/incidents/999999/graph").status_code == 404


def test_get_incident_timeline_endpoint(auth_client):
    """Verify investigation timeline streaming via REST API."""
    now = datetime(2026, 3, 30, 10, 0, 0, tzinfo=timezone.utc)
    key = f"api-inc-timeline-{uuid.uuid4().hex[:8]}"
    inc = incidents_repo.create_incident(
        Incident(
            incident_key=key,
            title="Timeline API Test",
            summary="Timeline stream verification",
            severity=Severity.ALERT,
            primary_host="srv-time-01",
            first_seen=now,
            last_seen=now,
        ),
        relationships=[
            IncidentRelationship(
                incident_id=0,
                source_entity_key="user:alice",
                target_entity_key="host:srv-time-01",
                relationship_type=RelationshipType.AUTHENTICATED_TO.value,
                confidence=ConfidenceLevel.DIRECT,
                matched_at=now,
            )
        ],
    )

    res = auth_client.get(f"/api/v1/incidents/{inc.id}/timeline")
    assert res.status_code == 200
    data = res.json()
    assert data["incident_id"] == inc.id
    assert "items" in data
    assert "total" in data
    assert data["total"] >= 1

    # 404 on non-existent incident
    assert auth_client.get("/api/v1/incidents/999999/timeline").status_code == 404


# ============================================================================
# 6. TRIGGER CORRELATION ENDPOINT
# ============================================================================

def test_trigger_correlation_endpoint(auth_client):
    """Verify on-demand execution of unassigned alert correlation via REST endpoint."""
    res = auth_client.post("/api/v1/incidents/correlate")
    assert res.status_code == 200
    data = res.json()
    assert "correlated_incidents_count" in data
    assert "incident_ids" in data
    assert isinstance(data["incident_ids"], list)
