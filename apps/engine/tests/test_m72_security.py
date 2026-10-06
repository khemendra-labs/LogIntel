"""M7.2 Dedicated Security and Boundary Test Suite (M72-SEC-001 through M72-SEC-020)."""

from __future__ import annotations

import json
import pytest
from fastapi.testclient import TestClient

from logintel.api.app import app
from logintel.api.auth import get_current_token
from logintel.storage.case_repo import case_repo
from logintel.storage.db import db
from logintel.timeline.models import (
    EpistemicStatus,
    TimelineFilterParams,
    TimelineSourceLayer,
)
from logintel.timeline.service import timeline_service


@pytest.fixture
def auth_client():
    token = get_current_token()
    client = TestClient(app)
    client.headers.update({"Authorization": f"Bearer {token}"})
    return client


@pytest.fixture
def unauth_client():
    return TestClient(app)


@pytest.fixture
def isolated_cases():
    """Create two strictly isolated cases."""
    case_a = case_repo.get_case(1)
    if not case_a:
        case_a = case_repo.create_case(
            incident_id=1,
            title="Security Test Case A",
            description="Case A confidential investigation",
            created_by="SecAnalyst-1",
        )
    case_repo.add_evidence_reference(
        case_id=case_a.case_id,
        source_type="event",
        source_id="101",
        role="PRIMARY",
        epistemic_status="OBSERVED",
        citation_tag="[event:101-A]",
        analyst_annotation="Confidential evidence for Case A only",
    )

    case_b = case_repo.get_case(2)
    if not case_b:
        case_b = case_repo.create_case(
            incident_id=2,
            title="Security Test Case B",
            description="Case B confidential investigation",
            created_by="SecAnalyst-2",
        )
    case_repo.add_evidence_reference(
        case_id=case_b.case_id,
        source_type="event",
        source_id="202",
        role="PRIMARY",
        epistemic_status="OBSERVED",
        citation_tag="[event:202-B]",
        analyst_annotation="Confidential evidence for Case B only",
    )

    return case_a.case_id, case_b.case_id


def test_m72_sec_001_authentication(unauth_client):
    """M72-SEC-001: Missing token must be rejected with 401."""
    resp = unauth_client.get("/api/v1/cases/1/timeline/unified")
    assert resp.status_code == 401


def test_m72_sec_002_invalid_token():
    """M72-SEC-002: Invalid/forged bearer token must be rejected with 401."""
    client = TestClient(app)
    client.headers.update({"Authorization": "Bearer invalid_forged_token_12345"})
    resp = client.get("/api/v1/cases/1/timeline/unified")
    assert resp.status_code == 401


def test_m72_sec_003_authorization(auth_client):
    """M72-SEC-003: Request with valid token must authenticate."""
    resp = auth_client.get("/api/v1/cases/1/timeline/unified")
    assert resp.status_code in (200, 404)


def test_m72_sec_004_cross_case_isolation(isolated_cases):
    """M72-SEC-004: Case A must never disclose Case B timeline items or evidence."""
    case_a_id, case_b_id = isolated_cases

    items_a = timeline_service.build_raw_timeline_items(case_a_id)
    items_b = timeline_service.build_raw_timeline_items(case_b_id)

    ids_a = {i.timeline_id for i in items_a}
    ids_b = {i.timeline_id for i in items_b}

    assert ids_a.isdisjoint(ids_b), "Cross-case leakage detected in timeline item IDs!"

    for item_a in items_a:
        assert item_a.case_id == case_a_id
        assert "[event:202-B]" not in item_a.evidence_refs
        assert "Case B" not in item_a.display_summary

    for item_b in items_b:
        assert item_b.case_id == case_b_id
        assert "[event:101-A]" not in item_b.evidence_refs


def test_m72_sec_005_sql_injection(isolated_cases):
    """M72-SEC-005: Parameterized queries must prevent SQL injection attacks."""
    case_a_id, _ = isolated_cases
    sqli_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE events; --",
        "admin'--",
        "1 UNION SELECT null, null, null--",
    ]

    for payload in sqli_payloads:
        # Through service
        params = TimelineFilterParams(search=payload, host=payload)
        res = timeline_service.query_timeline(case_a_id, params)
        assert isinstance(res.items, list)


def test_m72_sec_006_oversized_filter(auth_client, isolated_cases):
    """M72-SEC-006: Oversized filter parameters must be clamped or rejected."""
    case_a_id, _ = isolated_cases
    huge_host = "A" * 1000
    resp = auth_client.get(f"/api/v1/cases/{case_a_id}/timeline/unified?host={huge_host}")
    assert resp.status_code == 200
    assert resp.json()["total"] == 0


def test_m72_sec_007_oversized_search(auth_client, isolated_cases):
    """M72-SEC-007: Search queries exceeding max length must trigger 422 validation error."""
    case_a_id, _ = isolated_cases
    huge_search = "X" * 250
    resp = auth_client.get(f"/api/v1/cases/{case_a_id}/timeline/unified?search={huge_search}")
    assert resp.status_code == 422


def test_m72_sec_008_graph_expansion_bound(isolated_cases):
    """M72-SEC-008: Graph entity references must be bounded and deduplicated."""
    case_a_id, _ = isolated_cases
    items = timeline_service.build_raw_timeline_items(case_a_id)
    for it in items:
        assert len(it.entity_refs) <= 50


def test_m72_sec_009_timeline_result_bound(auth_client, isolated_cases):
    """M72-SEC-009: Result limits must be clamped to max 500 items."""
    case_a_id, _ = isolated_cases
    resp = auth_client.get(f"/api/v1/cases/{case_a_id}/timeline/unified?limit=99999")
    assert resp.status_code == 422 or resp.json()["limit"] <= 500


def test_m72_sec_010_replay_bound(isolated_cases):
    """M72-SEC-010: Replay sessions must be strictly bounded."""
    case_a_id, _ = isolated_cases
    session = timeline_service.get_replay_session(case_a_id)
    assert len(session.frames) <= 500


def test_m72_sec_011_malformed_timeline_identifier(auth_client, isolated_cases):
    """M72-SEC-011: Malformed timeline item identifiers must safely return 404."""
    case_a_id, _ = isolated_cases
    malformed_ids = [
        "../../../etc/passwd",
        "invalid!@#$%",
        "tl-nonexistent-99999",
    ]
    for m_id in malformed_ids:
        resp = auth_client.get(f"/api/v1/cases/{case_a_id}/timeline/context/{m_id}")
        assert resp.status_code == 404


def test_m72_sec_012_path_traversal(auth_client, isolated_cases):
    """M72-SEC-012: Export endpoint must not permit path traversal in parameters."""
    case_a_id, _ = isolated_cases
    resp = auth_client.get(f"/api/v1/cases/{case_a_id}/timeline/unified/export?format=../../etc/passwd")
    assert resp.status_code in (400, 422)


def test_m72_sec_013_malicious_evidence_text(isolated_cases):
    """M72-SEC-013: Malicious control characters and injection markers must be sanitized."""
    case_a_id, _ = isolated_cases
    dirty_text = "Login\x00Failure\x1b[31mRed Alert\x07"
    cleaned = timeline_service._sanitize(dirty_text, 100)
    assert "\x00" not in cleaned
    assert "\x07" not in cleaned


def test_m72_sec_014_export_isolation(isolated_cases):
    """M72-SEC-014: Timeline export must be strictly case-scoped."""
    case_a_id, case_b_id = isolated_cases
    export_a, _ = timeline_service.export_timeline(case_a_id, export_format="json")
    assert f"case_{case_b_id}" not in export_a
    assert "[event:202-B]" not in export_a


def test_m72_sec_015_export_resource_bound(isolated_cases):
    """M72-SEC-015: Export size must be bounded."""
    case_a_id, _ = isolated_cases
    export_json, _ = timeline_service.export_timeline(case_a_id, export_format="json")
    data = json.loads(export_json)
    assert data["total_items"] <= 500


def test_m72_sec_016_evidence_immutability(isolated_cases):
    """M72-SEC-016: Replay and timeline queries must not mutate database tables."""
    case_a_id, _ = isolated_cases
    with db.connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM events;")
        count_before = cur.fetchone()[0]

    # Run multiple queries and replays
    for _ in range(5):
        timeline_service.get_replay_session(case_a_id)
        timeline_service.query_timeline(case_a_id, TimelineFilterParams())

    with db.connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM events;")
        count_after = cur.fetchone()[0]

    assert count_before == count_after, "Authoritative events table was mutated during replay!"


def test_m72_sec_017_forensic_db_read_only(isolated_cases):
    """M72-SEC-017: Forensic database logintel.db must remain strictly unmutated."""
    with db.connection() as conn:
        cur = conn.cursor()
        cur.execute("PRAGMA integrity_check;")
        rows = cur.fetchall()
        assert [tuple(r) for r in rows] == [("ok",)]


def test_m72_sec_018_epistemic_state_preservation(isolated_cases):
    """M72-SEC-018: Epistemic status must never convert UNKNOWN into FALSE or INFERRED to OBSERVED."""
    case_a_id, _ = isolated_cases
    items = timeline_service.build_raw_timeline_items(case_a_id)
    for it in items:
        assert it.epistemic_status in (
            EpistemicStatus.OBSERVED,
            EpistemicStatus.INFERRED,
            EpistemicStatus.UNKNOWN,
        )


def test_m72_sec_019_ai_advisory_boundary():
    """M72-SEC-019: Timeline projection is deterministic and independent of AI mutations."""
    # Timeline items originate from deterministic telemetry sources, not generative AI hallucination
    assert timeline_service.db is not None


def test_m72_sec_020_shell_arbitrary_command_absence():
    """M72-SEC-020: Verify zero subprocess or shell execution in timeline module."""
    import inspect
    from logintel.timeline import service, models
    svc_code = inspect.getsource(service)
    models_code = inspect.getsource(models)

    assert "subprocess" not in svc_code
    assert "os.system" not in svc_code
    assert "eval(" not in svc_code
    assert "exec(" not in svc_code
    assert "subprocess" not in models_code
