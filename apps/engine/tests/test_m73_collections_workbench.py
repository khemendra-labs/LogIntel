import pytest
from fastapi.testclient import TestClient

from logintel.api.auth import get_current_token
from logintel.api.routes import router
from logintel.collections.models import EpistemicStatus, EvidenceCollectionStatus
from logintel.collections.service import workbench_service
from logintel.storage.case_repo import case_repo


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
def test_case():
    case = case_repo.get_case(1, resolve_evidence=False)
    if not case:
        case = case_repo.create_case(
            incident_id=1,
            title="M7.3 Test Investigation Case",
            description="Case for validating Evidence Collections & Workbench",
            created_by="SecAnalyst-1",
        )
    # Ensure some underlying evidence exists in the case
    case_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="event",
        source_id="101",
        role="PRIMARY",
        epistemic_status="OBSERVED",
        citation_tag="[event:101]",
        analyst_annotation="Initial suspicious process execution",
    )
    case_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="alert",
        source_id="5",
        role="SUPPORTING",
        epistemic_status="OBSERVED",
        citation_tag="[alert:5]",
        analyst_annotation="Privilege escalation detection alert",
    )
    return case.case_id


def test_collection_lifecycle(test_case):
    """Verify collection creation, retrieval, updating, and deletion."""
    col = workbench_service.create_collection(
        case_id=test_case,
        name="Persistence Mechanisms",
        description="Collection of cron and systemd persistence evidence",
        tags=["persistence", "cron"],
        actor="SecAnalyst-1",
    )
    assert col.name == "Persistence Mechanisms"
    assert col.case_id == test_case
    assert col.status == EvidenceCollectionStatus.ACTIVE
    assert "cron" in col.tags

    # Retrieve
    fetched = workbench_service.get_collection(test_case, col.collection_id)
    assert fetched.collection_id == col.collection_id
    assert fetched.items_count == 0

    # Update
    updated = workbench_service.update_collection(
        case_id=test_case,
        collection_id=col.collection_id,
        name="Persistence & Scheduled Tasks",
        status=EvidenceCollectionStatus.ACTIVE,
        tags=["persistence", "cron", "systemd"],
        actor="SecAnalyst-1",
    )
    assert updated.name == "Persistence & Scheduled Tasks"
    assert "systemd" in updated.tags

    # Delete
    del_ok = workbench_service.delete_collection(test_case, col.collection_id, actor="SecAnalyst-1")
    assert del_ok is True
    with pytest.raises(ValueError):
        workbench_service.get_collection(test_case, col.collection_id)


def test_collection_membership_and_duplicate_handling(test_case):
    """Verify adding items, duplicate idempotency, and removal."""
    col = workbench_service.create_collection(
        case_id=test_case,
        name="Initial Access Evidence",
        description="SSH and auth anomalies",
        tags=["initial-access"],
    )

    # Add item
    item1 = workbench_service.add_item_to_collection(
        case_id=test_case,
        collection_id=col.collection_id,
        source_type="event",
        source_id="101",
        role="INITIAL_ACCESS",
        epistemic_status=EpistemicStatus.OBSERVED,
        analyst_annotation="SSH session leading to shell invocation",
    )
    assert item1.source_type == "event"
    assert item1.source_id == "101"
    assert item1.role == "INITIAL_ACCESS"
    assert item1.epistemic_status == EpistemicStatus.OBSERVED

    # Duplicate addition must be idempotent (no duplicate rows, returns existing)
    item_dup = workbench_service.add_item_to_collection(
        case_id=test_case,
        collection_id=col.collection_id,
        source_type="event",
        source_id="101",
        role="INITIAL_ACCESS",
    )
    assert item_dup.item_id == item1.item_id

    # Verify collection items length is exactly 1
    fetched = workbench_service.get_collection(test_case, col.collection_id)
    assert len(fetched.items) == 1
    assert fetched.items[0].item_id == item1.item_id

    # Update item annotation
    updated_item = workbench_service.update_collection_item(
        case_id=test_case,
        collection_id=col.collection_id,
        item_id=item1.item_id,
        role="INITIAL_ACCESS_CONFIRMED",
        analyst_annotation="Updated note after review",
    )
    assert updated_item.role == "INITIAL_ACCESS_CONFIRMED"
    assert updated_item.analyst_annotation == "Updated note after review"

    # Remove item from collection
    removed = workbench_service.remove_item_from_collection(test_case, col.collection_id, item1.item_id)
    assert removed is True

    # Crucial forensic invariant: Removing item from collection does NOT delete underlying evidence!
    case = case_repo.get_case(test_case, resolve_evidence=True)
    evidence_tags = [ref.citation_tag for ref in case.evidence_references]
    assert "[event:101]" in evidence_tags, "Underlying authoritative evidence reference must remain intact!"

    workbench_service.delete_collection(test_case, col.collection_id)


def test_workbench_filtering_and_export(test_case):
    """Verify Evidence Workbench multi-parameter filtering and deterministic export."""
    col = workbench_service.create_collection(
        case_id=test_case,
        name="Exfiltration Candidates",
        tags=["exfiltration"],
    )
    workbench_service.add_item_to_collection(
        case_id=test_case,
        collection_id=col.collection_id,
        source_type="event",
        source_id="101",
        role="SUPPORTING",
        epistemic_status=EpistemicStatus.OBSERVED,
    )
    workbench_service.add_item_to_collection(
        case_id=test_case,
        collection_id=col.collection_id,
        source_type="alert",
        source_id="5",
        role="SUPPORTING",
        epistemic_status=EpistemicStatus.OBSERVED,
    )

    wb_data = workbench_service.get_workbench_data(test_case)
    assert wb_data.case_id == test_case
    assert len(wb_data.collections) >= 1
    assert wb_data.total_evidence_count >= 2
    assert len(wb_data.deterministic_hash) == 32

    # Export JSON
    json_export = workbench_service.export_collection(test_case, col.collection_id, format_type="json")
    assert '"collection_id":' in json_export
    assert '"items":' in json_export
    assert "101" in json_export

    # Export CSV
    csv_export = workbench_service.export_collection(test_case, col.collection_id, format_type="csv")
    assert "item_id,source_type,source_id,role" in csv_export
    assert "101" in csv_export

    workbench_service.delete_collection(test_case, col.collection_id)


def test_api_endpoints_collections_and_workbench(auth_client, test_case):
    """Verify REST API routes for collections, items, and workbench."""
    # 1. Create collection
    res = auth_client.post(
        f"/api/v1/cases/{test_case}/evidence/collections",
        json={"name": "API Test Collection", "description": "Created via REST", "tags": ["api", "test"]},
    )
    assert res.status_code == 200, res.text
    data = res.json()
    col_id = data["collection_id"]
    assert data["name"] == "API Test Collection"

    # 2. List collections
    res = auth_client.get(f"/api/v1/cases/{test_case}/evidence/collections")
    assert res.status_code == 200
    cols = res.json()
    assert any(c["collection_id"] == col_id for c in cols)

    # 3. Add item
    res = auth_client.post(
        f"/api/v1/cases/{test_case}/evidence/collections/{col_id}/items",
        json={
            "source_type": "event",
            "source_id": "101",
            "role": "SUPPORTING",
            "analyst_annotation": "Added via REST test",
        },
    )
    assert res.status_code == 200
    item = res.json()
    item_id = item["item_id"]
    assert item["source_id"] == "101"

    # 4. Get collection details
    res = auth_client.get(f"/api/v1/cases/{test_case}/evidence/collections/{col_id}")
    assert res.status_code == 200
    col_detail = res.json()
    assert col_detail["items_count"] == 1
    assert col_detail["items"][0]["item_id"] == item_id

    # 5. Get workbench
    res = auth_client.get(f"/api/v1/cases/{test_case}/evidence/workbench")
    assert res.status_code == 200
    wb = res.json()
    assert wb["case_id"] == test_case
    assert "items" in wb
    assert "collections" in wb

    # 6. Export collection
    res = auth_client.get(f"/api/v1/cases/{test_case}/evidence/collections/{col_id}/export?format=json")
    assert res.status_code == 200
    assert "application/json" in res.headers["content-type"]
    assert col_id in res.text

    # 7. Remove item
    res = auth_client.delete(f"/api/v1/cases/{test_case}/evidence/collections/{col_id}/items/{item_id}")
    assert res.status_code == 200
    assert res.json()["success"] is True

    # 8. Delete collection
    res = auth_client.delete(f"/api/v1/cases/{test_case}/evidence/collections/{col_id}")
    assert res.status_code == 200
    assert res.json()["success"] is True
