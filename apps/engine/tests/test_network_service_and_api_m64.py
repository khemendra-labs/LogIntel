"""API and Service tests for Network & Socket Telemetry (Milestone M6.4)."""

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


def test_get_network_sockets_api(client, auth_headers):
    """Verify GET /api/v1/investigations/network/sockets returns socket records."""
    response = client.get("/api/v1/investigations/network/sockets", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "host" in data
    assert "timestamp" in data
    assert "total" in data
    assert "items" in data
    assert isinstance(data["items"], list)
    if data["items"]:
        first = data["items"][0]
        assert "protocol" in first
        assert "local_address" in first
        assert "local_port" in first
        assert "state" in first
        assert "inode" in first


def test_get_network_sockets_with_state_filter(client, auth_headers):
    """Verify querying listening sockets only."""
    response = client.get(
        "/api/v1/investigations/network/sockets?state=LISTEN", headers=auth_headers
    )
    assert response.status_code == 200
    data = response.json()
    for item in data["items"]:
        assert item["state"] == "LISTEN"


def test_get_network_connections_api(client, auth_headers):
    """Verify GET /api/v1/investigations/network/connections returns established sockets."""
    response = client.get("/api/v1/investigations/network/connections", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    for item in data["items"]:
        assert item["state"] == "ESTABLISHED"


def test_network_endpoints_require_authentication(client):
    """Verify that network telemetry endpoints reject unauthenticated requests."""
    r1 = client.get("/api/v1/investigations/network/sockets")
    assert r1.status_code in (401, 403)

    r2 = client.get("/api/v1/investigations/network/connections")
    assert r2.status_code in (401, 403)
