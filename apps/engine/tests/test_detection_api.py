"""Integration test suite for LogIntel M2.8 Detection REST API endpoints."""

from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from logintel.api.app import app
from logintel.api.auth import get_current_token
from logintel.detection import EvidenceRole, load_default_rules
from logintel.detection.results import DetectionResult
from logintel.models import Actor, CanonicalEvent, EventType, Outcome, Process, Severity
from logintel.storage import db, events_repo
from logintel.storage.alerts_repo import alerts_repo


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    """Test client with isolated temporary database and rules initialized."""
    temp_dir = tmp_path_factory.mktemp("detection_api_db")
    temp_db_path = temp_dir / "detection_api_test.db"
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
# 1. AUTHENTICATION ENFORCEMENT ON DETECTION ENDPOINTS
# ============================================================================

def test_detection_endpoints_require_auth(client):
    """Detection and alert endpoints must reject unauthenticated requests with 401."""
    endpoints = [
        ("GET", "/api/v1/detection/rules"),
        ("GET", "/api/v1/detection/rules/auth.ssh_bruteforce"),
        ("GET", "/api/v1/alerts"),
        ("GET", "/api/v1/alerts/1"),
        ("PATCH", "/api/v1/alerts/1/status"),
    ]
    for method, path in endpoints:
        res = client.request(method, path, headers={"Authorization": ""})
        assert res.status_code == 401, f"{method} {path} should be 401 without auth, got {res.status_code}"


def test_detection_endpoints_reject_invalid_token(client):
    """Detection endpoints must reject invalid or fraudulent tokens."""
    bad_headers = {"Authorization": "Bearer deadbeef00112233445566778899aabb"}
    res = client.get("/api/v1/detection/rules", headers=bad_headers)
    assert res.status_code == 401


# ============================================================================
# 2. DETECTION RULES ENDPOINTS
# ============================================================================

def test_list_detection_rules_all(auth_client):
    """GET /api/v1/detection/rules returns full catalog of 16 canonical rules."""
    res = auth_client.get("/api/v1/detection/rules")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 16
    assert len(data["items"]) >= 16

    rule_ids = {r["id"] for r in data["items"]}
    assert "auth.ssh_bruteforce" in rule_ids
    assert "priv.sudo_root_shell" in rule_ids
    assert "proc.apparmor_denial" in rule_ids
    assert "account.root_creation" in rule_ids
    assert "network.firewall_scan_burst" in rule_ids


def test_list_detection_rules_filter_category(auth_client):
    """GET /api/v1/detection/rules?category=... properly filters rules by category."""
    categories = {
        "AUTH": 5,
        "PRIVILEGE": 3,
        "PROCESS": 3,
        "ACCOUNT": 2,
        "NETWORK": 3,
    }
    for cat, expected_count in categories.items():
        res = auth_client.get(f"/api/v1/detection/rules?category={cat}")
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == expected_count, f"Category {cat} expected {expected_count}, got {data['total']}"
        for item in data["items"]:
            assert item["category"] == cat


def test_get_detection_rule_detail_success(auth_client):
    """GET /api/v1/detection/rules/{rule_id} returns rule details and raw YAML definition."""
    res = auth_client.get("/api/v1/detection/rules/auth.ssh_bruteforce")
    assert res.status_code == 200
    data = res.json()
    assert data["rule"]["id"] == "auth.ssh_bruteforce"
    assert data["rule"]["category"] == "AUTH"
    assert data["rule"]["rule_type"] == "THRESHOLD"
    assert "yaml_definition" in data
    assert "auth.ssh_bruteforce" in data["yaml_definition"]


def test_get_detection_rule_detail_not_found(auth_client):
    """GET /api/v1/detection/rules/{rule_id} returns 404 for unknown rule ID."""
    res = auth_client.get("/api/v1/detection/rules/nonexistent.rule.id")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


# ============================================================================
# 3. ALERTS QUERY & DETAIL ENDPOINTS
# ============================================================================

def test_list_alerts_empty_or_populated(auth_client):
    """GET /api/v1/alerts returns paginated structure."""
    res = auth_client.get("/api/v1/alerts")
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert "total" in data
    assert "limit" in data
    assert "offset" in data


def test_alert_lifecycle_via_api(auth_client):
    """End-to-end integration: Record detection -> Query alert -> Patch status -> Verify transitions."""
    rules = {r.id: r for r in load_default_rules()}
    rule = rules["priv.unauthorized_sudo"]

    # 1. Insert backing canonical event
    t0 = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)
    ev = CanonicalEvent(
        id="ev-api-unauth",
        timestamp=t0,
        ingested_at=t0,
        host="srv-api-01",
        source="/var/log/auth.log",
        event_type=EventType.PRIVILEGE_ELEVATION_FAILURE,
        severity=Severity.ALERT,
        actor=Actor(username="attacker"),
        process=Process(name="sudo"),
        action="sudo_command",
        outcome=Outcome.FAILURE,
        summary="Sudo privilege elevation failure for user 'attacker': user NOT in sudoers",
        raw_message="user NOT in sudoers",
        parser="sudo_privilege",
    )
    events_repo.insert_events([ev])

    # 2. Record detection via AlertsRepository
    res_det = DetectionResult(
        rule_id="priv.unauthorized_sudo",
        timestamp=t0,
        host="srv-api-01",
        summary="Unauthorized sudo by attacker",
        evidence_event_ids=["ev-api-unauth"],
        evidence_roles={"ev-api-unauth": EvidenceRole.TRIGGER},
        details={"matched_fields": {"username": "attacker"}},
    )
    alert = alerts_repo.record_detection(res_det, rule)
    alert_id = alert.id

    # 3. Query alert via GET /api/v1/alerts/{alert_id}
    res_get = auth_client.get(f"/api/v1/alerts/{alert_id}")
    assert res_get.status_code == 200
    detail = res_get.json()
    assert detail["alert"]["id"] == alert_id
    assert detail["alert"]["status"] == "OPEN"
    assert len(detail["detections"]) >= 1
    assert detail["detections"][0]["evidence"][0]["event_id"] == "ev-api-unauth"

    # 4. Filter alerts via GET /api/v1/alerts?status=OPEN&host=srv-api-01
    res_filtered = auth_client.get(f"/api/v1/alerts?status=OPEN&host=srv-api-01")
    assert res_filtered.status_code == 200
    filter_data = res_filtered.json()
    assert filter_data["total"] >= 1
    matched_ids = [a["id"] for a in filter_data["items"]]
    assert alert_id in matched_ids

    # 5. Transition to ACKNOWLEDGED via PATCH /api/v1/alerts/{alert_id}/status
    res_patch_ack = auth_client.patch(
        f"/api/v1/alerts/{alert_id}/status",
        json={"status": "ACKNOWLEDGED"},
    )
    assert res_patch_ack.status_code == 200
    assert res_patch_ack.json()["status"] == "ACKNOWLEDGED"
    assert res_patch_ack.json()["acknowledged_at"] is not None

    # 6. Transition to RESOLVED with note
    res_patch_res = auth_client.patch(
        f"/api/v1/alerts/{alert_id}/status",
        json={"status": "RESOLVED", "resolution_note": "Attacker account locked"},
    )
    assert res_patch_res.status_code == 200
    assert res_patch_res.json()["status"] == "RESOLVED"
    assert res_patch_res.json()["resolved_at"] is not None
    assert res_patch_res.json()["resolution_note"] == "Attacker account locked"

    # 7. Invalid transition: RESOLVED -> ACKNOWLEDGED directly must return 400
    res_patch_inv = auth_client.patch(
        f"/api/v1/alerts/{alert_id}/status",
        json={"status": "ACKNOWLEDGED"},
    )
    assert res_patch_inv.status_code == 400
    assert "invalid" in res_patch_inv.json()["detail"].lower()

    # 8. Reopen: RESOLVED -> OPEN
    res_reopen = auth_client.patch(
        f"/api/v1/alerts/{alert_id}/status",
        json={"status": "OPEN"},
    )
    assert res_reopen.status_code == 200
    assert res_reopen.json()["status"] == "OPEN"
    assert res_reopen.json()["resolved_at"] is None


def test_patch_alert_status_invalid_inputs(auth_client):
    """PATCH /api/v1/alerts/{alert_id}/status handles unknown alerts and invalid statuses."""
    # Unknown alert ID -> 404
    res_404 = auth_client.patch(
        "/api/v1/alerts/999999/status",
        json={"status": "ACKNOWLEDGED"},
    )
    assert res_404.status_code == 404

    # Invalid status enum string -> 400
    res_bad_status = auth_client.patch(
        "/api/v1/alerts/1/status",
        json={"status": "BOGUS_STATUS"},
    )
    assert res_bad_status.status_code == 400
    assert "invalid alert status" in res_bad_status.json()["detail"].lower()


def test_list_alerts_invalid_query_params(auth_client):
    """GET /api/v1/alerts rejects invalid status or severity with 400."""
    res_bad_status = auth_client.get("/api/v1/alerts?status=NOT_A_STATUS")
    assert res_bad_status.status_code == 400

    res_bad_sev = auth_client.get("/api/v1/alerts?severity=SUPER_HIGH")
    assert res_bad_sev.status_code == 400
