"""Integration tests for the REST API contract."""

import pytest
from fastapi.testclient import TestClient
from logintel.api.app import app
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


def test_system_status(client):
    res = client.get("/api/v1/system/status")
    assert res.status_code == 200
    data = res.json()
    assert data["app_name"] == "LogIntel"
    assert "version" in data
    assert data["total_events"] >= 1


def test_telemetry_health(client):
    res = client.get("/api/v1/telemetry/health")
    assert res.status_code == 200
    data = res.json()
    assert "overall_status" in data
    assert "sources" in data
    assert len(data["sources"]) >= 4


def test_events_query_and_pagination(client):
    res = client.get("/api/v1/events?limit=10&offset=0")
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert "total" in data
    assert data["limit"] == 10
    assert data["offset"] == 0
    assert len(data["items"]) >= 1


def test_events_filtering(client):
    res = client.get("/api/v1/events?username=baduser")
    assert res.status_code == 200
    data = res.json()
    assert len(data["items"]) >= 1
    assert data["items"][0]["actor"]["username"] == "baduser"


def test_event_stats_summary(client):
    res = client.get("/api/v1/events/stats/summary?hours=24")
    assert res.status_code == 200
    data = res.json()
    assert "total_events" in data
    assert "by_severity" in data
    assert "by_type" in data
    assert "by_source" in data
