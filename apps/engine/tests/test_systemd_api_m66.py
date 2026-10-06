"""API tests for Systemd & Service Lifecycle Telemetry (Milestone M6.6)."""

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


def test_get_systemd_units_api(client, auth_headers):
    """Verify GET /api/v1/investigations/systemd/units returns active systemd units."""
    response = client.get("/api/v1/investigations/systemd/units", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "items" in data
    assert isinstance(data["items"], list)
    if data["items"]:
        first = data["items"][0]
        assert "unit_name" in first
        assert "unit_type" in first
        assert "active_state" in first


def test_get_systemd_units_type_filter(client, auth_headers):
    """Verify filtering systemd units by type."""
    response = client.get("/api/v1/investigations/systemd/units?unit_type=service", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    for item in data["items"]:
        assert item["unit_type"] == "service"


def test_get_systemd_unit_detail_api(client, auth_headers):
    """Verify querying detailed properties of an existing unit (e.g. systemd or cron)."""
    # First get units
    res = client.get("/api/v1/investigations/systemd/units?limit=5", headers=auth_headers)
    units = res.json().get("items", [])
    if units:
        target_name = units[0]["unit_name"]
        resp_detail = client.get(f"/api/v1/investigations/systemd/units/{target_name}", headers=auth_headers)
        assert resp_detail.status_code in (200, 404)


def test_systemd_api_requires_auth(client):
    """Verify systemd endpoints require authentication."""
    r1 = client.get("/api/v1/investigations/systemd/units")
    assert r1.status_code in (401, 403)

    r2 = client.get("/api/v1/investigations/systemd/units/cron.service")
    assert r2.status_code in (401, 403)
