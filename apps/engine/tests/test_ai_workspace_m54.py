"""Milestone 5.4 Functional Test Suite — Analyst Investigation Workspace & Explainability.

Validates investigation lifecycle, reproducible scope, analyst-owned hypotheses,
approved query execution into evidence candidates, structured summaries, explainable report drafts,
and interactive claim-to-source provenance tracing.
"""

from __future__ import annotations

from pathlib import Path
import tempfile
import pytest
from fastapi.testclient import TestClient

from logintel.ai.domain.intelligence import QueryProposal
from logintel.ai.domain.workspace import (
    HypothesisStatus,
    InvestigationScope,
    InvestigationState,
)
from logintel.ai.workspace_service import WorkspaceService
from logintel.api.routes import router
from logintel.config import settings
from logintel.storage.db import Database
from logintel.storage.incidents_repo import IncidentsRepository
from logintel.storage.investigation_repo import InvestigationRepository


@pytest.fixture
def test_db():
    """Create a temporary isolated SQLite database seeded with representative telemetry."""
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "workspace_test.db"
        database = Database(db_path)
        database.initialize()
        with database.connection() as conn:
            cur = conn.cursor()
            cur.execute("INSERT INTO hosts (id, hostname, first_seen, last_seen) VALUES ('h1', 'srv-alpha', '2026-09-30T00:00:00Z', '2026-09-30T23:59:59Z')")
            cur.execute("INSERT INTO detection_rules (id, name, description, severity, category, rule_type, definition_yaml) VALUES ('rule.ssh', 'SSH Failure', 'SSH brute force', 'WARNING', 'Auth', 'pattern', 'yaml')")

            cur.execute(
                """
                INSERT INTO events (id, timestamp, ingested_at, host, username, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint)
                VALUES ('ev-fail', '2026-09-30T10:00:00Z', '2026-09-30T10:00:01Z', 'srv-alpha', 'admin', 'auth.log', 'syslog', 'NOTICE', 'login', 'failure', 'Failed login for user', 'Failed password for admin', 'openssh', 'fp-f')
                """
            )
            cur.execute(
                """
                INSERT INTO events (id, timestamp, ingested_at, host, username, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint)
                VALUES ('ev-succ', '2026-09-30T09:50:00Z', '2026-09-30T09:50:01Z', 'srv-alpha', 'admin', 'auth.log', 'syslog', 'WARNING', 'login', 'success', 'Accepted login for user', 'Accepted password for admin', 'openssh', 'fp-s')
                """
            )
            cur.execute(
                """
                INSERT INTO alerts (id, rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count)
                VALUES (1, 'rule.ssh', 'dedup-1', 'SSH Alert', 'Desc', 'WARNING', 'OPEN', 'srv-alpha', '2026-09-30T10:00:00Z', '2026-09-30T10:00:00Z', 1)
                """
            )
            cur.execute(
                """
                INSERT INTO detections (id, alert_id, rule_id, timestamp, host, summary, evidence_count)
                VALUES (1, 1, 'rule.ssh', '2026-09-30T10:00:00Z', 'srv-alpha', 'SSH Failure', 1)
                """
            )
            cur.execute("INSERT INTO detection_evidence (detection_id, event_id, role) VALUES (1, 'ev-fail', 'primary')")
            cur.execute("INSERT INTO detection_evidence (detection_id, event_id, role) VALUES (1, 'ev-succ', 'supporting')")
            cur.execute(
                """
                INSERT INTO incidents (id, incident_key, title, summary, severity, status, primary_host, primary_user, first_seen, last_seen, alert_count, event_count)
                VALUES (1, 'INC-001', 'Test Incident', 'Summary', 'CRITICAL', 'OPEN', 'srv-alpha', 'admin', '2026-09-30T09:50:00Z', '2026-09-30T10:00:00Z', 1, 2)
                """
            )
            cur.execute("INSERT INTO incident_alerts (incident_id, alert_id) VALUES (1, 1)")
            cur.execute("INSERT INTO incident_entities (incident_id, entity_type, entity_key, display_name) VALUES (1, 'HOST', 'host:srv-alpha', 'srv-alpha')")
            conn.commit()

        yield database


@pytest.fixture
def ws_service(test_db):
    inc_repo = IncidentsRepository(test_db)
    inv_repo = InvestigationRepository(test_db, inc_repo)
    return WorkspaceService(database=test_db, incidents_repository=inc_repo, investigation_repository=inv_repo)


# =========================================================================
# 1. Investigation Workspace Lifecycle & Validated State Transitions
# =========================================================================

def test_workspace_creation_and_default_scope(ws_service):
    """Verify workspace initialization creates reproducible default scope and initial audit."""
    ws = ws_service.get_or_create_workspace(incident_id=1, user_id="SecAnalyst-1")
    assert ws.investigation_id == 1
    assert ws.state == InvestigationState.OPEN
    assert ws.scope.subject_type == "incident"
    assert ws.scope.subject_id == "1"
    assert "host:srv-alpha" in ws.scope.selected_entity_ids
    assert 1 in ws.scope.selected_alert_ids
    assert len(ws.state_history) == 1
    assert ws.state_history[0].new_state == InvestigationState.OPEN.value


def test_valid_state_transitions(ws_service):
    """Verify valid transitions: OPEN -> ACTIVE -> PAUSED -> ACTIVE -> READY_FOR_REVIEW -> CLOSED -> ACTIVE."""
    ws = ws_service.update_state(1, InvestigationState.ACTIVE, actor="analyst_1", reason="Commenced triage")
    assert ws.state == InvestigationState.ACTIVE
    assert len(ws.state_history) == 2

    ws = ws_service.update_state(1, InvestigationState.PAUSED, actor="analyst_1", reason="Waiting on forensic image")
    assert ws.state == InvestigationState.PAUSED

    ws = ws_service.update_state(1, InvestigationState.ACTIVE, actor="analyst_1", reason="Forensic image received")
    assert ws.state == InvestigationState.ACTIVE

    ws = ws_service.update_state(1, InvestigationState.READY_FOR_REVIEW, actor="analyst_1", reason="Analysis complete")
    assert ws.state == InvestigationState.READY_FOR_REVIEW

    ws = ws_service.update_state(1, InvestigationState.CLOSED, actor="lead_analyst", reason="Approved and closed")
    assert ws.state == InvestigationState.CLOSED

    # Test reopening
    ws = ws_service.update_state(1, InvestigationState.ACTIVE, actor="lead_analyst", reason="Reopened due to new IOCs")
    assert ws.state == InvestigationState.ACTIVE


def test_invalid_state_transition_rejection(ws_service):
    """Verify invalid state transitions are rejected with descriptive error."""
    ws_service.get_or_create_workspace(1)
    # OPEN cannot transition directly to PAUSED
    with pytest.raises(ValueError) as exc:
        ws_service.update_state(1, InvestigationState.PAUSED)
    assert "Invalid investigation state transition" in str(exc.value)


# =========================================================================
# 2. Scope Management
# =========================================================================

def test_scope_customization(ws_service):
    """Verify analyst can customize and reproduce investigation scope."""
    custom_scope = InvestigationScope(
        investigation_id=1,
        time_start="2026-09-30T09:00:00Z",
        time_end="2026-09-30T11:00:00Z",
        subject_type="host",
        subject_id="srv-alpha",
        selected_entity_ids=["host:srv-alpha", "user:admin"],
        selected_alert_ids=[1],
        selected_detection_ids=[1],
        selected_event_ids=["ev-fail"],
    )
    ws = ws_service.set_scope(1, custom_scope)
    assert ws.scope.subject_type == "host"
    assert ws.scope.subject_id == "srv-alpha"
    assert len(ws.scope.selected_entity_ids) == 2


# =========================================================================
# 3. Analyst Hypotheses Lifecycle
# =========================================================================

def test_hypothesis_lifecycle(ws_service):
    """Verify analyst hypothesis creation, evidence association, and status updates."""
    hyp = ws_service.create_hypothesis(
        incident_id=1,
        statement="Initial access accomplished via SSH brute force password guessing",
        status=HypothesisStatus.OPEN,
        supporting_tags=["[event:ev-fail]", "[alert:1]"],
        contradicting_tags=[],
        gaps=["auditd process telemetry"],
        assessment="Probable based on repeated authentication failures",
        created_by="SecAnalyst-1",
    )
    assert hyp.hypothesis_id == "hyp-1-1"
    assert hyp.status == HypothesisStatus.OPEN
    assert len(hyp.supporting_evidence_tags) == 2

    # Update status to SUPPORTED
    updated = ws_service.update_hypothesis(
        incident_id=1,
        hypothesis_id="hyp-1-1",
        status=HypothesisStatus.SUPPORTED,
        assessment="Confirmed by correlation with alert ALT-01",
    )
    assert updated.status == HypothesisStatus.SUPPORTED
    assert "Confirmed" in (updated.analyst_assessment or "")

    hyps = ws_service.list_hypotheses(1)
    assert len(hyps) == 1
    assert hyps[0].status == HypothesisStatus.SUPPORTED


# =========================================================================
# 4. Approved Query Execution into Evidence Candidates
# =========================================================================

def test_approved_query_execution(ws_service):
    """Verify executing an analyst-approved threat hunting query deterministically collects evidence candidates."""
    proposal = QueryProposal(
        proposal_id="prop-001",
        intent="NEXT_QUERY",
        title="Hunt for admin login failures",
        host="srv-alpha",
        username="admin",
        search_text="Failed",
    )

    result = ws_service.execute_approved_query(incident_id=1, proposal=proposal, actor="SecAnalyst-1")
    assert result["matched_events_count"] == 1
    assert result["matched_events"][0]["id"] == "ev-fail"

    ws = ws_service.get_or_create_workspace(1)
    assert len(ws.evidence_candidates) == 1
    assert ws.evidence_candidates[0].evidence_id == "ev-fail"
    assert ws.evidence_candidates[0].citation_tag == "[event:ev-fail]"


# =========================================================================
# 5. Structured Summary & Explainable Report Drafting
# =========================================================================

def test_investigation_summary_generation(ws_service):
    """Verify deterministic investigation summary covers all required analysis sections."""
    ws_service.create_hypothesis(1, "Testing hypothesis")
    summary = ws_service.generate_investigation_summary(incident_id=1)

    assert summary.investigation_id == 1
    assert len(summary.key_observations) >= 2
    assert len(summary.hypotheses) == 1
    assert len(summary.open_questions) >= 3
    assert "coverage_ratio" in summary.ai_assisted_analysis


def test_explainable_report_drafting(ws_service):
    """Verify report draft separates facts, inferences, hypotheses, and unknowns with citation grounding."""
    draft = ws_service.generate_report_draft(incident_id=1)

    assert draft.investigation_id == 1
    assert draft.is_draft is True
    assert len(draft.facts) > 0
    assert all("evidence_tag" in f for f in draft.facts)
    assert len(draft.inferences) > 0
    assert len(draft.recommendations) >= 2


# =========================================================================
# 6. Interactive Claim Explainability Tracing
# =========================================================================

def test_claim_explainability_tracing(ws_service):
    """Verify tracing a cited tag resolves to its authoritative database table and record."""
    traces = ws_service.trace_claim_explainability(
        incident_id=1,
        claim_text="Admin authentication failed on srv-alpha",
        citation_tags=["[event:ev-fail]", "[alert:1]", "[event:ev-nonexistent]"],
    )

    assert len(traces) == 3

    # Event trace
    ev_trace = next(t for t in traces if t.citation_tag == "[event:ev-fail]")
    assert ev_trace.source_table == "events"
    assert ev_trace.source_id == "ev-fail"
    assert ev_trace.raw_evidence is not None
    assert ev_trace.raw_evidence["host"] == "srv-alpha"

    # Non-existent trace
    non_trace = next(t for t in traces if t.citation_tag == "[event:ev-nonexistent]")
    assert non_trace.epistemic_status == "UNKNOWN"
    assert non_trace.source_table == "UNKNOWN"


# =========================================================================
# 7. FastAPI REST API Endpoint Verification
# =========================================================================

def test_api_workspace_endpoints(test_db, monkeypatch):
    """Verify all M5.4 endpoints respond correctly via TestClient."""
    from fastapi import FastAPI
    import logintel.ai.workspace_service as ws_mod
    from logintel.storage.incidents_repo import IncidentsRepository
    from logintel.storage.investigation_repo import InvestigationRepository

    inc_repo = IncidentsRepository(test_db)
    inv_repo = InvestigationRepository(test_db, inc_repo)
    test_ws = WorkspaceService(database=test_db, incidents_repository=inc_repo, investigation_repository=inv_repo)
    monkeypatch.setattr(ws_mod, "workspace_service", test_ws)

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    from logintel.api.auth import get_current_token
    token = get_current_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. GET workspace
    res = client.get("/api/v1/ai/investigations/1/workspace", headers=headers)
    assert res.status_code == 200
    assert res.json()["state"] == "OPEN"

    # 2. PATCH state
    res = client.patch(
        "/api/v1/ai/investigations/1/state",
        headers=headers,
        json={"state": "ACTIVE", "reason": "Triage started"},
    )
    assert res.status_code == 200
    assert res.json()["state"] == "ACTIVE"

    # 3. POST hypothesis
    res = client.post(
        "/api/v1/ai/investigations/1/hypotheses",
        headers=headers,
        json={"statement": "Credential stuffing via SSH", "status": "OPEN"},
    )
    assert res.status_code == 200
    hyp_id = res.json()["hypothesis_id"]

    # 4. PATCH hypothesis
    res = client.patch(
        "/api/v1/ai/investigations/1/hypotheses/" + hyp_id,
        headers=headers,
        json={"status": "SUPPORTED", "assessment": "Corroborated by telemetry"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "SUPPORTED"

    # 5. GET hypotheses
    res = client.get("/api/v1/ai/investigations/1/hypotheses", headers=headers)
    assert res.status_code == 200
    assert res.json()["total"] == 1

    # 6. POST query execute
    res = client.post(
        "/api/v1/ai/investigations/1/query/execute",
        headers=headers,
        json={"proposal_id": "p1", "intent": "NEXT_QUERY", "host": "srv-alpha"},
    )
    assert res.status_code == 200
    assert res.json()["matched_events_count"] >= 1

    # 7. GET summary
    res = client.get("/api/v1/ai/investigations/1/summary", headers=headers)
    assert res.status_code == 200
    assert "key_observations" in res.json()

    # 8. POST report draft
    res = client.post("/api/v1/ai/investigations/1/report/draft", headers=headers)
    assert res.status_code == 200
    assert "facts" in res.json()

    # 9. POST explainability
    res = client.post(
        "/api/v1/ai/investigations/1/explainability",
        headers=headers,
        json={"claim_text": "Failed login", "citation_tags": ["[event:ev-fail]"]},
    )
    assert res.status_code == 200
    assert len(res.json()["traces"]) == 1
