"""Functional verification tests for M5.5 Persistent Investigation Cases and Case Continuity.

Tests:
1. Case creation, retrieval, and filtered listing.
2. Lifecycle state transitions and invalid transition rejection.
3. Case handoff and ownership transfer with audit trail.
4. Hypothesis persistence, status transitions, and version tracking.
5. Evidence reference association, disassociation, and stale evidence detection.
6. Governed threat hunting query execution and query history recording.
7. Report draft versioning, analyst notes preservation, and version diff comparison.
8. Deterministic AI context reconstruction.
9. Chronological case audit ledger.
10. REST API endpoint contract verification.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
from typing import Generator
from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from logintel.ai.case_service import CaseService
from logintel.ai.domain.case import (
    CaseReportVersion,
    CaseStatus,
    ContentOrigin,
    ResolutionStatus,
)
from logintel.ai.domain.intelligence import QueryProposal
from logintel.ai.domain.workspace import HypothesisStatus, InvestigationScope
from logintel.api.auth import get_current_token
from logintel.api.routes import router
from logintel.storage.case_repo import CaseRepository
from logintel.storage.db import Database


@pytest.fixture
def case_env() -> Generator[tuple[Database, CaseRepository, CaseService], None, None]:
    """Provide isolated SQLite databases for forensic records and persistent cases."""
    with tempfile.TemporaryDirectory() as td:
        forensic_path = Path(td) / "forensic.db"
        case_path = Path(td) / "cases.db"

        forensic_db = Database(forensic_path)
        forensic_db.initialize()

        with forensic_db.connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO detection_rules (id, name, description, severity, category, rule_type, definition_yaml)
                VALUES ('rule.ssh', 'SSH Attack', 'SSH Rule', 'CRITICAL', 'Auth', 'threshold', 'yaml')
                """
            )
            cur.execute(
                """
                INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint, username)
                VALUES ('ev-55-1', '2026-09-30T10:00:00Z', '2026-09-30T10:00:01Z', 'srv-alpha', 'auth.log', 'auth', 'ALERT', 'login', 'failure', 'Failed login deployer', 'Failed password for deployer from 10.0.0.1', 'openssh', 'fp-55-1', 'deployer')
                """
            )
            cur.execute(
                """
                INSERT INTO alerts (id, rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count)
                VALUES (301, 'rule.ssh', 'dedup-301', 'SSH Alert Alpha', 'Desc', 'ALERT', 'OPEN', 'srv-alpha', '2026-09-30T10:00:00Z', '2026-09-30T10:00:00Z', 1)
                """
            )
            cur.execute("INSERT INTO detections (id, alert_id, rule_id, timestamp, host, summary, evidence_count) VALUES (301, 301, 'rule.ssh', '2026-09-30T10:00:00Z', 'srv-alpha', 'SSH Failure Alpha', 1)")
            cur.execute("INSERT INTO detection_evidence (detection_id, event_id, role) VALUES (301, 'ev-55-1', 'primary')")
            cur.execute(
                """
                INSERT INTO incidents (id, incident_key, title, summary, severity, status, primary_host, primary_user, first_seen, last_seen, alert_count, event_count)
                VALUES (301, 'INC-55-301', 'Persistent Compromise', 'Summary 301', 'CRITICAL', 'OPEN', 'srv-alpha', 'deployer', '2026-09-30T10:00:00Z', '2026-09-30T10:00:00Z', 1, 1)
                """
            )
            cur.execute("INSERT INTO incident_alerts (incident_id, alert_id) VALUES (301, 301)")
            cur.execute("INSERT INTO incident_entities (incident_id, entity_type, entity_key, display_name) VALUES (301, 'HOST', 'host:srv-alpha', 'srv-alpha')")
            conn.commit()

        case_repo = CaseRepository(db_path=case_path, forensic_db=forensic_db)
        case_svc = CaseService(case_repository=case_repo, forensic_database=forensic_db)

        yield forensic_db, case_repo, case_svc
        forensic_db.close()


def test_case_creation_and_listing(case_env):
    """Verify creating and listing persistent cases."""
    _, _, svc = case_env
    case = svc.create_or_open_case(301, title="Test Investigation", description="Testing case lifecycle")

    assert case.case_id == 301
    assert case.status == CaseStatus.OPEN
    assert case.version == 1
    assert case.title == "Test Investigation"

    cases = svc.list_cases()
    assert len(cases) == 1
    assert cases[0].case_id == 301


def test_case_lifecycle_state_machine(case_env):
    """Verify state machine transitions and invalid transition rejection."""
    _, _, svc = case_env
    case = svc.create_or_open_case(301)

    # Valid transitions
    svc.transition_case_state(301, CaseStatus.ACTIVE, actor="analyst_1", reason="Starting analysis")
    assert svc.get_case(301).status == CaseStatus.ACTIVE

    svc.transition_case_state(301, CaseStatus.PAUSED, actor="analyst_1", reason="Waiting for logs")
    assert svc.get_case(301).status == CaseStatus.PAUSED

    svc.transition_case_state(301, CaseStatus.ACTIVE, actor="analyst_1", reason="Resuming")
    svc.transition_case_state(301, CaseStatus.READY_FOR_REVIEW, actor="analyst_1", reason="Peer review")
    svc.transition_case_state(301, CaseStatus.CLOSED, actor="analyst_1", reason="Resolved")
    assert svc.get_case(301).status == CaseStatus.CLOSED

    # Closed can be explicitly reopened to ACTIVE or ARCHIVED
    svc.transition_case_state(301, CaseStatus.ARCHIVED, actor="analyst_1", reason="Cold storage")
    assert svc.get_case(301).status == CaseStatus.ARCHIVED

    # Invalid transitions must raise ValueError
    with pytest.raises(ValueError):
        svc.transition_case_state(301, CaseStatus.PAUSED, actor="analyst_1", reason="Invalid jump")


def test_case_handoff(case_env):
    """Verify analyst handoff updates owner and creates audit trail."""
    _, _, svc = case_env
    case = svc.create_or_open_case(301, actor="analyst_alice")
    assert case.owner == "analyst_alice"

    updated = svc.transfer_case(
        case_id=301,
        new_owner="analyst_bob",
        actor="analyst_alice",
        handoff_notes="Shift change. Please review SSH failures.",
    )
    assert updated.owner == "analyst_bob"
    assert updated.version > case.version

    # Verify audit entry
    audits = svc.get_audit_history(301)
    handoff_audit = next(a for a in audits if a.action == "CASE_HANDOFF")
    assert handoff_audit.previous_value == "analyst_alice"
    assert handoff_audit.new_value == "analyst_bob"


def test_case_hypotheses_persistence(case_env):
    """Verify hypothesis creation, status change, and versioning survive reload."""
    _, _, svc = case_env
    case = svc.create_or_open_case(301)

    hyp = svc.create_hypothesis(
        case_id=301,
        statement="Compromise initiated via SSH brute force",
        status=HypothesisStatus.OPEN,
        actor="analyst_1",
    )
    assert hyp.version == 1

    updated_hyp = svc.update_hypothesis(
        case_id=301,
        hypothesis_id=hyp.hypothesis_id,
        status=HypothesisStatus.SUPPORTED,
        supporting_tags=["[event:ev-55-1]"],
        assessment="Corroborated by failed auth events",
        actor="analyst_1",
    )
    assert updated_hyp.status == HypothesisStatus.SUPPORTED
    assert updated_hyp.version == 2

    # Reload from SQLite database
    reloaded = svc.get_case(301)
    target = next(h for h in reloaded.hypotheses if h.hypothesis_id == hyp.hypothesis_id)
    assert target.status == HypothesisStatus.SUPPORTED
    assert "[event:ev-55-1]" in target.supporting_evidence_tags


def test_case_evidence_resolution_and_stale_detection(case_env):
    """Verify available records resolve correctly and missing records are marked MISSING."""
    forensic_db, _, svc = case_env
    case = svc.create_or_open_case(301)

    # 1. Existing event reference resolves as AVAILABLE
    ref_ok = svc.associate_evidence(301, "event", "ev-55-1", citation_tag="[event:ev-55-1]")
    assert ref_ok.resolution_status == ResolutionStatus.AVAILABLE
    assert ref_ok.resolved_record is not None
    assert ref_ok.resolved_record["host"] == "srv-alpha"

    # 2. Reference to deleted or missing record resolves as MISSING
    ref_missing = svc.associate_evidence(301, "event", "ev-deleted-999", citation_tag="[event:ev-deleted-999]")
    assert ref_missing.resolution_status == ResolutionStatus.MISSING
    assert ref_missing.resolved_record is None


def test_case_approved_query_execution_and_history(case_env):
    """Verify approved query execution records in query history and stages candidates."""
    _, _, svc = case_env
    case = svc.create_or_open_case(301)

    prop = QueryProposal(
        proposal_id="qp-hunt-55",
        query_template_id="query_failed_logins_by_user",
        username="deployer",
        rationale="Hunting deployer login attempts",
    )
    res = svc.execute_approved_query(301, prop, actor="analyst_1")

    assert res["result_count"] == 1
    assert res["matched_events"][0]["id"] == "ev-55-1"

    # Verify query history in case
    case_reloaded = svc.get_case(301)
    assert len(case_reloaded.query_history) == 1
    q = case_reloaded.query_history[0]
    assert q.proposal_id == "qp-hunt-55"
    assert q.result_count == 1


def test_case_report_versioning_and_comparison(case_env):
    """Verify report draft versioning, analyst notes preservation, and version comparison."""
    _, _, svc = case_env
    case = svc.create_or_open_case(301)

    # Draft version 1
    v1 = svc.draft_or_revise_report(301, title="Initial Draft v1", analyst_notes="Notes v1")
    assert v1.version == 1
    assert v1.generated_by == ContentOrigin.AI_GENERATED

    # Draft version 2 (with additional notes)
    v2 = svc.draft_or_revise_report(301, title="Revised Draft v2", analyst_notes="Notes v2 updated", is_final=True)
    assert v2.version == 2
    assert v2.is_final is True
    assert v2.generated_by == ContentOrigin.ANALYST_AUTHORED

    # Compare versions v1 and v2
    diff = svc.compare_report_versions(301, v1.report_id, 1, 2)
    assert diff["version_older"] == 1
    assert diff["version_newer"] == 2
    assert diff["title_changed"] is True
    assert diff["analyst_notes_v1"] == "Notes v1"
    assert diff["analyst_notes_v2"] == "Notes v2 updated"


def test_case_ai_context_reconstruction(case_env):
    """Verify deterministic AI context reconstruction without persistent chat memory."""
    _, _, svc = case_env
    case = svc.create_or_open_case(301)
    svc.create_hypothesis(301, "Test hypothesis for AI context")

    ctx = svc.reconstruct_ai_context(301)
    assert ctx.case_id == 301
    assert ctx.status == CaseStatus.OPEN.value
    assert len(ctx.hypotheses) == 1
    assert ctx.reconstructed_at is not None


def test_case_api_endpoints(case_env, monkeypatch):
    """Verify REST API routes for case management."""
    import logintel.ai.case_service as cs_mod

    _, _, svc = case_env
    monkeypatch.setattr(cs_mod, "case_service", svc)

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    token = get_current_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Create/open case
    res_create = client.post("/api/v1/cases", json={"incident_id": 301, "title": "API Case"}, headers=headers)
    assert res_create.status_code == 200
    data = res_create.json()
    assert data["case_id"] == 301

    # 2. Get case
    res_get = client.get("/api/v1/cases/301", headers=headers)
    assert res_get.status_code == 200
    assert res_get.json()["title"] == "API Case"

    # 3. State transition
    res_state = client.post("/api/v1/cases/301/state", json={"target_status": "ACTIVE"}, headers=headers)
    assert res_state.status_code == 200
    assert res_state.json()["status"] == "ACTIVE"

    # 4. Handoff
    res_handoff = client.post(
        "/api/v1/cases/301/handoff",
        json={"new_owner": "analyst_carol", "handoff_notes": "Takeover for investigation"},
        headers=headers,
    )
    assert res_handoff.status_code == 200
    assert res_handoff.json()["owner"] == "analyst_carol"

    # 5. List cases
    res_list = client.get("/api/v1/cases", headers=headers)
    assert res_list.status_code == 200
    assert len(res_list.json()) >= 1


def test_case_audit_trail_and_version_increments(case_env):
    """Verify that case mutations record audit log entries and increment case version."""
    _, repo, svc = case_env
    case = svc.create_or_open_case(301, actor="lead_analyst")
    v1 = case.version

    # Scope update bumps version
    scope2 = case.scope.model_copy(update={"hypotheses_count": 2})
    c2 = repo.update_case_scope(301, scope2, actor="lead_analyst")
    assert c2.version == v1 + 1

    # Adding evidence reference bumps version
    repo.add_evidence_reference(
        case_id=301,
        source_type="alert",
        source_id="alt-999",
        role="CORROBORATING",
        epistemic_status="OBSERVED",
        citation_tag="[alert:alt-999]",
        actor="lead_analyst",
        bump_version=True,
    )
    c3 = repo.get_case(301)
    assert c3.version == v1 + 2

    # Verify audit trail contains all recorded operations
    audit_entries = repo.get_audit_log(301)
    actions = [e.action for e in audit_entries]
    assert "CASE_CREATED" in actions
    assert "SCOPE_UPDATED" in actions
    assert "EVIDENCE_ASSOCIATED" in actions
    for entry in audit_entries:
        assert entry.case_id == 301
        assert entry.actor is not None
        assert entry.timestamp is not None

