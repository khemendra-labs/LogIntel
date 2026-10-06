import pytest
from fastapi.testclient import TestClient

from logintel.api.auth import get_current_token
from logintel.api.routes import router
from logintel.findings.models import EpistemicStatus, FindingReviewStatus, HypothesisLifecycleStatus
from logintel.findings.service import findings_workbench_service
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
def sample_case():
    case = case_repo.get_case(1, resolve_evidence=False)
    if not case:
        case = case_repo.create_case(
            incident_id=1,
            title="M7.4 Functional Test Case",
            description="Case for findings and hypotheses tests",
            created_by="SecAnalyst-1",
        )
    return case.case_id


def test_finding_crud_and_versioning(auth_client, sample_case):
    """Test finding creation, versioned update, retrieval, and deletion."""
    # 1. Create finding
    create_payload = {
        "title": "Privilege Escalation Detected via Sudo",
        "statement": "The actor executed sudo -u root /bin/bash after initial SSH access.",
        "epistemic_status": "INFERRED",
        "severity": "HIGH",
        "supporting_evidence": [
            {"source_type": "event", "source_id": "evt-sudo-101", "citation_tag": "EVT-101", "epistemic_status": "OBSERVED"}
        ],
        "contradicting_evidence": [],
        "supporting_collections": ["COLL-1"],
        "related_hypotheses": ["HYP-1"],
        "analyst_notes": "Initial draft of finding",
    }
    res = auth_client.post(f"/api/v1/cases/{sample_case}/findings", json=create_payload)
    assert res.status_code == 200, res.text
    created = res.json()
    finding_id = created["finding_id"]
    assert created["title"] == create_payload["title"]
    assert created["version"] == 1
    assert len(created["supporting_evidence"]) == 1
    assert created["review_status"] == "UNREVIEWED"
    assert created["epistemic_status"] == "INFERRED"

    # 2. Update finding -> version 2
    update_payload = {
        "title": "Confirmed Privilege Escalation via Sudo",
        "statement": "The actor confirmed sudo escalation following compromised SSH key use.",
        "severity": "CRITICAL",
        "change_summary": "Elevated severity after corrobating auth logs",
    }
    res_up = auth_client.patch(f"/api/v1/cases/{sample_case}/findings/{finding_id}", json=update_payload)
    assert res_up.status_code == 200, res_up.text
    updated = res_up.json()
    assert updated["version"] == 2
    assert updated["title"] == "Confirmed Privilege Escalation via Sudo"
    assert len(updated["version_history"]) == 1
    assert updated["version_history"][0]["version"] == 1

    # 3. Get single finding
    res_get = auth_client.get(f"/api/v1/cases/{sample_case}/findings/{finding_id}")
    assert res_get.status_code == 200
    assert res_get.json()["finding_id"] == finding_id

    # 4. Delete finding -> evidence preserved
    res_del = auth_client.delete(f"/api/v1/cases/{sample_case}/findings/{finding_id}")
    assert res_del.status_code == 200
    assert res_del.json()["evidence_preserved"] is True


def test_finding_review_workflow_epistemic_separation(auth_client, sample_case):
    """Test analyst review preserves epistemic status strictly."""
    # Create finding with INFERRED status
    res = auth_client.post(
        f"/api/v1/cases/{sample_case}/findings",
        json={
            "title": "Lateral Movement to Database Server",
            "statement": "Anomalous SMB sessions suggest lateral movement.",
            "epistemic_status": "INFERRED",
        },
    )
    assert res.status_code == 200
    f_data = res.json()
    finding_id = f_data["finding_id"]
    assert f_data["epistemic_status"] == "INFERRED"
    assert f_data["review_status"] == "UNREVIEWED"

    # Review finding -> ACCEPTED
    res_rev = auth_client.post(
        f"/api/v1/cases/{sample_case}/findings/{finding_id}/review",
        json={
            "review_status": "ACCEPTED",
            "analyst_notes": "Corroborated by network flow records.",
            "reviewed_by": "SeniorAnalyst-42",
        },
    )
    assert res_rev.status_code == 200
    rev_data = res_rev.json()
    assert rev_data["review_status"] == "ACCEPTED"
    # Epistemic status MUST NOT change to OBSERVED merely because accepted!
    assert rev_data["epistemic_status"] == "INFERRED"
    assert rev_data["reviewed_by"] == "SeniorAnalyst-42"


def test_hypothesis_evidence_assessment_and_comparison(auth_client, sample_case):
    """Test hypothesis creation, evidence attachment, gaps, and categorical comparison."""
    # 1. Create H1: Malicious Compromise
    res_h1 = auth_client.post(
        f"/api/v1/cases/{sample_case}/hypotheses/m74",
        json={
            "title": "H1: Malicious Compromise",
            "statement": "External threat actor gained unauthorized root access.",
            "status": "OPEN",
            "supporting_evidence": ["EVT-101", "ALRT-202"],
            "contradicting_evidence": [],
            "evidence_gaps": [],
        },
    )
    assert res_h1.status_code == 200
    h1_id = res_h1.json()["hypothesis_id"]

    # 2. Create H2: Authorized Admin Activity
    res_h2 = auth_client.post(
        f"/api/v1/cases/{sample_case}/hypotheses/m74",
        json={
            "title": "H2: Authorized Admin Activity",
            "statement": "System administrator conducted scheduled maintenance.",
            "status": "OPEN",
            "supporting_evidence": ["EVT-303"],
            "contradicting_evidence": ["ALRT-202"],
            "evidence_gaps": [],
        },
    )
    assert res_h2.status_code == 200
    h2_id = res_h2.json()["hypothesis_id"]

    # 3. Add explicit evidence gap to H1
    res_gap = auth_client.post(
        f"/api/v1/cases/{sample_case}/hypotheses/{h1_id}/gaps",
        json={
            "gap_type": "NO_EVENT_OBSERVED",
            "description": "Missing sudo execution log in auth.log during key interval",
            "expected_source": "auth.log",
        },
    )
    assert res_gap.status_code == 200
    assert len(res_gap.json()["evidence_gaps"]) == 1

    # 4. Compare competing hypotheses
    res_comp = auth_client.get(f"/api/v1/cases/{sample_case}/hypotheses/compare")
    assert res_comp.status_code == 200
    comp_data = res_comp.json()
    assert comp_data["total_hypotheses"] >= 2
    # Verify categorical metrics (supporting_count, contradicting_count, gaps_count)
    comp_items = {h["hypothesis_id"]: h for h in comp_data["hypotheses"]}
    assert comp_items[h1_id]["supporting_count"] == 2
    assert comp_items[h1_id]["gaps_count"] == 1
    assert comp_items[h2_id]["contradicting_count"] == 1


def test_findings_workbench_state_and_export(auth_client, sample_case):
    """Test full workbench state query and deterministic JSON/CSV export."""
    # 1. Query full workbench state
    res_wb = auth_client.get(f"/api/v1/cases/{sample_case}/findings/workbench")
    assert res_wb.status_code == 200
    wb_data = res_wb.json()
    assert "findings" in wb_data
    assert "hypotheses" in wb_data
    assert "evidence_gaps" in wb_data

    # 2. Export JSON
    res_json = auth_client.get(f"/api/v1/cases/{sample_case}/findings/export?format=json")
    assert res_json.status_code == 200
    assert "application/json" in res_json.headers["content-type"]
    assert "findings" in res_json.text

    # 3. Export CSV
    res_csv = auth_client.get(f"/api/v1/cases/{sample_case}/findings/export?format=csv")
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.headers["content-type"]
    assert "FINDING" in res_csv.text or "HYPOTHESIS" in res_csv.text
