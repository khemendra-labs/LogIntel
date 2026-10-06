"""API tests for Container and Namespace Telemetry (Milestone M6.7)."""

import os
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


def test_get_containers_api(client, auth_headers):
    """Verify GET /api/v1/investigations/containers returns list structure."""
    res = client.get("/api/v1/investigations/containers", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert "total" in data
    assert "items" in data
    assert isinstance(data["items"], list)


def test_get_process_namespace_api(client, auth_headers):
    """Verify GET /api/v1/investigations/processes/{pid}/namespace inspects active process."""
    my_pid = os.getpid()
    res = client.get(f"/api/v1/investigations/processes/{my_pid}/namespace", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["pid"] == my_pid
    assert "is_isolated" in data
    assert "container_runtime" in data
    assert "epistemic_status" in data


def test_get_process_namespace_nonexistent_pid(client, auth_headers):
    """Verify non-existent PID returns 404 cleanly."""
    res = client.get("/api/v1/investigations/processes/999999999/namespace", headers=auth_headers)
    assert res.status_code == 404


def test_get_container_detail_nonexistent(client, auth_headers):
    """Verify non-existent container ID returns 404 cleanly."""
    res = client.get("/api/v1/investigations/containers/nonexistent_container_xyz", headers=auth_headers)
    assert res.status_code == 404


def test_container_endpoints_require_auth(client):
    """Verify container endpoints enforce authentication."""
    r1 = client.get("/api/v1/investigations/containers")
    assert r1.status_code in (401, 403)

    r2 = client.get("/api/v1/investigations/processes/1/namespace")
    assert r2.status_code in (401, 403)
