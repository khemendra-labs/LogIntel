"""Integration tests for Host Graph API endpoints (Milestone M6.8)."""

from fastapi.testclient import TestClient
from logintel.api.app import app
from logintel.api.auth import get_current_token

client = TestClient(app)


def test_get_host_telemetry_graph_endpoint():
    """Verify GET /api/v1/investigations/hosts/{host}/graph returns valid graph structure."""
    token = get_current_token()
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.get("/api/v1/investigations/hosts/localhost/graph", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "host" in data
    assert data["host"] == "localhost"
    assert "nodes" in data
    assert "edges" in data
    assert "summary" in data


def test_get_host_graph_requires_auth():
    """Verify endpoint rejects unauthenticated requests with 401."""
    resp = client.get("/api/v1/investigations/hosts/localhost/graph")
    assert resp.status_code == 401


def test_get_incident_host_graph_nonexistent_returns_404():
    """Verify nonexistent incident ID returns 404 cleanly without 500 error."""
    token = get_current_token()
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.get("/api/v1/investigations/999999/host-graph", headers=headers)
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()
