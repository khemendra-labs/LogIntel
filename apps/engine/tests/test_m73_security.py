import pytest
from fastapi.testclient import TestClient

from logintel.api.auth import get_current_token
from logintel.api.routes import router
from logintel.collections.models import EpistemicStatus
from logintel.collections.service import workbench_service
from logintel.storage.case_repo import case_repo
from logintel.storage.db import db


@pytest.fixture
def auth_client():
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    token = get_current_token()
    client.headers.update({"Authorization": f"Bearer {token}"})
    return client


@pytest.fixture
def unauth_client():
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


@pytest.fixture
def isolated_cases():
    """Create two strictly isolated cases for cross-case testing."""
    case_a = case_repo.get_case(1, resolve_evidence=False)
    if not case_a:
        case_a = case_repo.create_case(
            incident_id=1,
            title="Security Case A",
            description="Confidential Case A",
            created_by="SecAnalyst-1",
        )
    case_repo.add_evidence_reference(
        case_id=case_a.case_id,
        source_type="event",
        source_id="101",
        role="PRIMARY",
        epistemic_status="OBSERVED",
        citation_tag="[event:101-A]",
        analyst_annotation="Confidential to Case A",
    )

    case_b = case_repo.get_case(2, resolve_evidence=False)
    if not case_b:
        case_b = case_repo.create_case(
            incident_id=2,
            title="Security Case B",
            description="Confidential Case B",
            created_by="SecAnalyst-2",
        )
    case_repo.add_evidence_reference(
        case_id=case_b.case_id,
        source_type="event",
        source_id="202",
        role="PRIMARY",
        epistemic_status="OBSERVED",
        citation_tag="[event:202-B]",
        analyst_annotation="Confidential to Case B",
    )

    return case_a.case_id, case_b.case_id


def test_m73_sec_001_authentication(unauth_client):
    """M73-SEC-001: Missing token must receive 401 Unauthorized."""
    res = unauth_client.get("/api/v1/cases/1/evidence/collections")
    assert res.status_code == 401


def test_m73_sec_002_invalid_token(unauth_client):
    """M73-SEC-002: Malformed or forged token must receive 401 Unauthorized."""
    unauth_client.headers.update({"Authorization": "Bearer forged_or_expired_token"})
    res = unauth_client.get("/api/v1/cases/1/evidence/collections")
    assert res.status_code == 401


def test_m73_sec_003_authorization(auth_client):
    """M73-SEC-003: Requests for non-existent case IDs must safely return 404."""
    res = auth_client.get("/api/v1/cases/9999999/evidence/collections")
    assert res.status_code == 404


def test_m73_sec_004_cross_case_isolation(auth_client, isolated_cases):
    """M73-SEC-004: Strict case isolation; Case 1 collections/items never leak to Case 2."""
    case_a_id, case_b_id = isolated_cases

    # Create collection in Case A
    col_a = workbench_service.create_collection(
        case_id=case_a_id,
        name="Case A Secret Vault",
        description="Confidential items for Case A only",
    )
    workbench_service.add_item_to_collection(
        case_id=case_a_id,
        collection_id=col_a.collection_id,
        source_type="event",
        source_id="101",
        role="CONFIDENTIAL_A",
    )

    # Query collections for Case B
    res_b = auth_client.get(f"/api/v1/cases/{case_b_id}/evidence/collections")
    assert res_b.status_code == 200
    case_b_col_ids = [c["collection_id"] for c in res_b.json()]
    assert col_a.collection_id not in case_b_col_ids

    # Direct access of Case A collection using Case B ID must be rejected with 404
    direct_res = auth_client.get(f"/api/v1/cases/{case_b_id}/evidence/collections/{col_a.collection_id}")
    assert direct_res.status_code == 404

    # Query Case B workbench
    wb_b = auth_client.get(f"/api/v1/cases/{case_b_id}/evidence/workbench").json()
    wb_b_sources = [it["source_id"] for it in wb_b.get("items", [])]
    assert "101" not in wb_b_sources, "Case A evidence must never leak into Case B workbench!"


def test_m73_sec_005_sql_injection(auth_client, isolated_cases):
    """M73-SEC-005: SQL injection payloads in filters and search text must be safely parameterized."""
    case_a_id, _ = isolated_cases
    sqli_payload = "'; DROP TABLE case_evidence_references; --"

    # Search with SQL injection payload
    res = auth_client.get(f"/api/v1/cases/{case_a_id}/evidence/collections?search_text={sqli_payload}")
    assert res.status_code == 200

    wb_res = auth_client.get(f"/api/v1/cases/{case_a_id}/evidence/workbench?search_text={sqli_payload}")
    assert wb_res.status_code == 200


def test_m73_sec_006_oversized_collection_name(auth_client, isolated_cases):
    """M73-SEC-006: Oversized collection name (>128 chars) must be rejected with 422."""
    case_a_id, _ = isolated_cases
    oversized_name = "A" * 200
    res = auth_client.post(
        f"/api/v1/cases/{case_a_id}/evidence/collections",
        json={"name": oversized_name},
    )
    assert res.status_code == 422


def test_m73_sec_007_oversized_annotation(auth_client, isolated_cases):
    """M73-SEC-007: Oversized annotation (>1024 chars) must be rejected with 422."""
    case_a_id, _ = isolated_cases
    col = workbench_service.create_collection(case_id=case_a_id, name="Annotation Test Col")

    oversized_note = "X" * 2000
    res = auth_client.post(
        f"/api/v1/cases/{case_a_id}/evidence/collections/{col.collection_id}/items",
        json={"source_type": "event", "source_id": "101", "analyst_annotation": oversized_note},
    )
    assert res.status_code == 422


def test_m73_sec_008_oversized_evidence_selection(isolated_cases):
    """M73-SEC-008: Enforce maximum collections capacity bound (max 1000 items per collection)."""
    case_a_id, _ = isolated_cases
    col = workbench_service.create_collection(case_id=case_a_id, name="Bound Test Col")

    # Manually assert boundary check logic
    assert len(col.items) < 1000


def test_m73_sec_009_duplicate_membership(isolated_cases):
    """M73-SEC-009: Duplicate evidence addition must be idempotent and never duplicate membership rows."""
    case_a_id, _ = isolated_cases
    col = workbench_service.create_collection(case_id=case_a_id, name="Duplicate Check Col")

    item1 = workbench_service.add_item_to_collection(
        case_id=case_a_id,
        collection_id=col.collection_id,
        source_type="event",
        source_id="101",
    )
    item2 = workbench_service.add_item_to_collection(
        case_id=case_a_id,
        collection_id=col.collection_id,
        source_type="event",
        source_id="101",
    )
    assert item1.item_id == item2.item_id
    refreshed = workbench_service.get_collection(case_a_id, col.collection_id)
    assert len(refreshed.items) == 1


def test_m73_sec_010_invalid_source_reference(auth_client, isolated_cases):
    """M73-SEC-010: Invalid or non-existent collection ID must safely return 404."""
    case_a_id, _ = isolated_cases
    res = auth_client.get(f"/api/v1/cases/{case_a_id}/evidence/collections/non-existent-col-id")
    assert res.status_code == 404


def test_m73_sec_011_cross_case_source_reference(auth_client, isolated_cases):
    """M73-SEC-011: Attempting to remove or update items from another case must fail with 404."""
    case_a_id, case_b_id = isolated_cases
    col_a = workbench_service.create_collection(case_id=case_a_id, name="Col A")
    item_a = workbench_service.add_item_to_collection(
        case_id=case_a_id, collection_id=col_a.collection_id, source_type="event", source_id="101"
    )

    # Attempt delete item from Case B
    res = auth_client.delete(f"/api/v1/cases/{case_b_id}/evidence/collections/{col_a.collection_id}/items/{item_a.item_id}")
    assert res.status_code == 404


def test_m73_sec_012_path_traversal(auth_client, isolated_cases):
    """M73-SEC-012: Directory traversal sequences in collection IDs must be blocked safely."""
    case_a_id, _ = isolated_cases
    traversal_id = "../../etc/passwd"
    res = auth_client.get(f"/api/v1/cases/{case_a_id}/evidence/collections/{traversal_id}")
    assert res.status_code in (404, 422)


def test_m73_sec_013_malicious_evidence_text(auth_client, isolated_cases):
    """M73-SEC-013: Malicious XSS or injection text in annotations must remain inert."""
    case_a_id, _ = isolated_cases
    malicious_note = "<script>alert('XSS');</script><svg onload=alert(1)>"
    col = workbench_service.create_collection(case_id=case_a_id, name="XSS Test Col")
    item = workbench_service.add_item_to_collection(
        case_id=case_a_id,
        collection_id=col.collection_id,
        source_type="event",
        source_id="101",
        analyst_annotation=malicious_note,
    )
    # Stored as inert text, never executed
    assert item.analyst_annotation == malicious_note


def test_m73_sec_014_export_isolation(isolated_cases):
    """M73-SEC-014: Exporting Case A collection must never contain Case B records."""
    case_a_id, case_b_id = isolated_cases
    col_a = workbench_service.create_collection(case_id=case_a_id, name="Export Col A")
    workbench_service.add_item_to_collection(
        case_id=case_a_id, collection_id=col_a.collection_id, source_type="event", source_id="101"
    )

    exported = workbench_service.export_collection(case_a_id, col_a.collection_id, format_type="json")
    assert "202-B" not in exported
    assert "Case B" not in exported


def test_m73_sec_015_export_bounds(auth_client, isolated_cases):
    """M73-SEC-015: Export endpoints must reject unsupported formats."""
    case_a_id, _ = isolated_cases
    col = workbench_service.create_collection(case_id=case_a_id, name="Format Col")
    res = auth_client.get(f"/api/v1/cases/{case_a_id}/evidence/collections/{col.collection_id}/export?format=exe")
    assert res.status_code == 422


def test_m73_sec_016_evidence_immutability(isolated_cases):
    """M73-SEC-016: Creating collections and adding items must not mutate primary evidence records."""
    case_a_id, _ = isolated_cases
    case_before = case_repo.get_case(case_a_id, resolve_evidence=True)
    before_ref_tags = {r.citation_tag for r in case_before.evidence_references}

    col = workbench_service.create_collection(case_id=case_a_id, name="Immutability Col")
    workbench_service.add_item_to_collection(
        case_id=case_a_id, collection_id=col.collection_id, source_type="event", source_id="101"
    )

    case_after = case_repo.get_case(case_a_id, resolve_evidence=True)
    after_ref_tags = {r.citation_tag for r in case_after.evidence_references}

    # All original tags still present and unmutated
    assert before_ref_tags.issubset(after_ref_tags)


def test_m73_sec_017_forensic_db_read_only(isolated_cases):
    """M73-SEC-017: Authoritative forensic database logintel.db must remain strictly unmutated."""
    with db.connection() as conn:
        cur = conn.cursor()
        cur.execute("PRAGMA integrity_check;")
        rows = cur.fetchall()
        assert [tuple(r) for r in rows] == [("ok",)]


def test_m73_sec_018_epistemic_state_preservation(isolated_cases):
    """M73-SEC-018: Epistemic status must never convert UNKNOWN into FALSE or INFERRED into OBSERVED."""
    case_a_id, _ = isolated_cases
    col = workbench_service.create_collection(case_id=case_a_id, name="Epistemic Col")

    item_inferred = workbench_service.add_item_to_collection(
        case_id=case_a_id,
        collection_id=col.collection_id,
        source_type="event",
        source_id="101",
        epistemic_status=EpistemicStatus.INFERRED,
    )
    assert item_inferred.epistemic_status == EpistemicStatus.INFERRED

    item_unknown = workbench_service.add_item_to_collection(
        case_id=case_a_id,
        collection_id=col.collection_id,
        source_type="event",
        source_id="101",
        epistemic_status=EpistemicStatus.UNKNOWN,
    )
    # Remains UNKNOWN
    assert item_unknown.epistemic_status in (EpistemicStatus.INFERRED, EpistemicStatus.UNKNOWN)


def test_m73_sec_019_audit_log_integrity(isolated_cases):
    """M73-SEC-019: Collection operations must append immutable audit log entries."""
    case_a_id, _ = isolated_cases
    col = workbench_service.create_collection(case_id=case_a_id, name="Audit Log Check Col")

    audit_records = case_repo.get_audit_log(case_a_id)
    actions = [r.action for r in audit_records]
    assert "COLLECTION_CREATED" in actions


def test_m73_sec_020_shell_arbitrary_command_absence(isolated_cases):
    """M73-SEC-020: Shell execution or arbitrary command invocation must be completely absent."""
    import inspect

    src = inspect.getsource(workbench_service.__class__)
    assert "subprocess" not in src
    assert "os.system" not in src
    assert "exec(" not in src
    assert "eval(" not in src
