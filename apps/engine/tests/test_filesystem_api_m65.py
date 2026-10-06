"""API tests for Filesystem & Persistence Telemetry (Milestone M6.5)."""

import pytest
from fastapi.testclient import TestClient

from logintel.api.app import app
from logintel.api.auth import get_current_token


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth_headers():
    token = get_current_token()
    return {"Authorization": f"Bearer {token}"}


def test_get_filesystem_targets_api(client, auth_headers):
    """Verify GET /api/v1/investigations/filesystem/targets returns monitored targets."""
    response = client.get("/api/v1/investigations/filesystem/targets", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "items" in data
    assert isinstance(data["items"], list)
    if data["items"]:
        first = data["items"][0]
        assert "path" in first
        assert "category" in first
        assert "exists" in first
        assert "epistemic_status" in first


def test_get_filesystem_targets_with_category_filter(client, auth_headers):
    """Verify filtering filesystem targets by category."""
    response = client.get(
        "/api/v1/investigations/filesystem/targets?category=PERSISTENCE_CRON",
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    for item in data["items"]:
        assert item["category"] == "PERSISTENCE_CRON"


def test_get_filesystem_transitions_api(client, auth_headers):
    """Verify GET /api/v1/investigations/filesystem/transitions returns list."""
    response = client.get("/api/v1/investigations/filesystem/transitions", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "items" in data
    assert isinstance(data["items"], list)


def test_filesystem_endpoints_require_authentication(client):
    """Verify unauthenticated requests to filesystem endpoints are rejected."""
    r1 = client.get("/api/v1/investigations/filesystem/targets")
    assert r1.status_code in (401, 403)

    r2 = client.get("/api/v1/investigations/filesystem/transitions")
    assert r2.status_code in (401, 403)
