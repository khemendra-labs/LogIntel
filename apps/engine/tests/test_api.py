"""Integration tests for the REST API contract and local IPC authentication boundary."""

import pytest
from fastapi.testclient import TestClient
from logintel.api.app import app
from logintel.api.auth import get_current_token
from logintel.models import Actor, CanonicalEvent, EventType, Outcome, Severity
from logintel.storage import db, events_repo


@pytest.fixture(scope="module")
def client():
    db.initialize()
    # Insert test events
    event = CanonicalEvent(
        host="test-node",
        source="auth.log",
        event_type=EventType.AUTH_LOGIN_FAILURE,
        severity=Severity.ALERT,
        actor=Actor(username="baduser"),
        outcome=Outcome.FAILURE,
        summary="Failed login for baduser",
        raw_message="Failed password for baduser from 10.0.0.5",
        parser="openssh_auth",
    )
    events_repo.insert_events([event])
    
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def auth_client(client):
    token = get_current_token()
    client.headers["Authorization"] = f"Bearer {token}"
    return client


def test_handshake_unauthenticated(client):
    """Handshake endpoint must be reachable without auth and verify engine identity."""
    res = client.get("/api/v1/handshake", headers={"Authorization": ""})
    assert res.status_code == 200
    data = res.json()
    assert data["service"] == "logintel-engine"
    assert data["api_version"] == "v1"
    assert data["status"] == "ready"
    assert "version" in data


def test_authentication_enforcement(client):
    """All sensitive endpoints must reject unauthenticated or fraudulent requests."""
    # 1. No Authorization header
    res_no_auth = client.get("/api/v1/system/status", headers={"Authorization": ""})
    assert res_no_auth.status_code == 401

    # 2. Invalid / wrong token
    res_wrong_token = client.get(
        "/api/v1/system/status",
        headers={"Authorization": "Bearer 0123456789abcdef0123456789abcdef"},
    )
    assert res_wrong_token.status_code == 401

    # 3. Malformed Authorization header
    res_malformed = client.get(
        "/api/v1/system/status",
        headers={"Authorization": "Basic somebase64credentials"},
    )
    assert res_malformed.status_code == 401


def test_system_status(auth_client):
    res = auth_client.get("/api/v1/system/status")
    assert res.status_code == 200
    data = res.json()
    assert data["app_name"] == "LogIntel"
    assert "version" in data
    assert data["total_events"] >= 1


def test_telemetry_health(auth_client):
    res = auth_client.get("/api/v1/telemetry/health")
    assert res.status_code == 200
    data = res.json()
    assert "overall_status" in data
    assert "sources" in data
    assert len(data["sources"]) >= 4


def test_events_query_and_pagination(auth_client):
    res = auth_client.get("/api/v1/events?limit=10&offset=0")
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert "total" in data
    assert data["limit"] == 10
    assert data["offset"] == 0
    assert len(data["items"]) >= 1


def test_events_filtering(auth_client):
    res = auth_client.get("/api/v1/events?username=baduser")
    assert res.status_code == 200
    data = res.json()
    assert len(data["items"]) >= 1
    assert data["items"][0]["actor"]["username"] == "baduser"


def test_event_stats_summary(auth_client):
    res = auth_client.get("/api/v1/events/stats/summary?hours=24")
    assert res.status_code == 200
    data = res.json()
    assert "total_events" in data
    assert "by_severity" in data
    assert "by_type" in data
    assert "by_source" in data
