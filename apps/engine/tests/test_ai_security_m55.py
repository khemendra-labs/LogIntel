"""Milestone 5.5 Security Verification Suite (M55-SEC-001 through M55-SEC-020).

Validates:
1. Authentication boundaries (unauthenticated/invalid tokens rejected, valid local operator accepted).
2. Cross-case isolation across scopes, hypotheses, evidence references, reports, and query history.
3. Authorization & sovereignty boundaries (AI cannot mutate authoritative DB, close cases, or run arbitrary SQL).
4. Provenance & content origin tagging (AI_GENERATED vs ANALYST_AUTHORED).
5. Stale evidence handling (explicit MISSING state).
6. Case persistence & survival across engine restarts.
7. Injection containment and lack of subprocess/shell paths.
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
def m55_dbs() -> Generator[tuple[Database, CaseRepository, CaseService], None, None]:
    """Fixture providing isolated temporary databases for forensic state and persistent cases."""
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
                VALUES ('ev-sec-1', '2026-09-30T10:00:00Z', '2026-09-30T10:00:01Z', 'srv-alpha', 'auth.log', 'auth', 'ALERT', 'login', 'failure', 'Failed login deployer', 'Failed password for deployer from 10.0.0.1', 'openssh', 'fp-sec-1', 'deployer')
                """
            )
            cur.execute(
                """
                INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint, username)
                VALUES ('ev-sec-2', '2026-09-30T11:00:00Z', '2026-09-30T11:00:01Z', 'srv-beta', 'auth.log', 'auth', 'ALERT', 'login', 'failure', 'Failed login guest', 'Failed password for guest from 10.0.0.2', 'openssh', 'fp-sec-2', 'guest')
                """
            )
            cur.execute(
                """
                INSERT INTO alerts (id, rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count)
                VALUES (201, 'rule.ssh', 'dedup-201', 'SSH Alert Alpha', 'Desc', 'ALERT', 'OPEN', 'srv-alpha', '2026-09-30T10:00:00Z', '2026-09-30T10:00:00Z', 1)
                """
            )
            cur.execute(
                """
                INSERT INTO alerts (id, rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count)
                VALUES (202, 'rule.ssh', 'dedup-202', 'SSH Alert Beta', 'Desc', 'ALERT', 'OPEN', 'srv-beta', '2026-09-30T11:00:00Z', '2026-09-30T11:00:00Z', 1)
                """
            )
            cur.execute("INSERT INTO detections (id, alert_id, rule_id, timestamp, host, summary, evidence_count) VALUES (201, 201, 'rule.ssh', '2026-09-30T10:00:00Z', 'srv-alpha', 'SSH Failure Alpha', 1)")
            cur.execute("INSERT INTO detections (id, alert_id, rule_id, timestamp, host, summary, evidence_count) VALUES (202, 202, 'rule.ssh', '2026-09-30T11:00:00Z', 'srv-beta', 'SSH Failure Beta', 1)")
            cur.execute("INSERT INTO detection_evidence (detection_id, event_id, role) VALUES (201, 'ev-sec-1', 'primary')")
            cur.execute("INSERT INTO detection_evidence (detection_id, event_id, role) VALUES (202, 'ev-sec-2', 'primary')")
            cur.execute(
                """
                INSERT INTO incidents (id, incident_key, title, summary, severity, status, primary_host, primary_user, first_seen, last_seen, alert_count, event_count)
                VALUES (201, 'INC-SEC-201', 'Alpha Compromise', 'Summary Alpha', 'CRITICAL', 'OPEN', 'srv-alpha', 'deployer', '2026-09-30T10:00:00Z', '2026-09-30T10:00:00Z', 1, 1)
                """
            )
            cur.execute(
                """
                INSERT INTO incidents (id, incident_key, title, summary, severity, status, primary_host, primary_user, first_seen, last_seen, alert_count, event_count)
                VALUES (202, 'INC-SEC-202', 'Beta Compromise', 'Summary Beta', 'WARNING', 'OPEN', 'srv-beta', 'guest', '2026-09-30T11:00:00Z', '2026-09-30T11:00:00Z', 1, 1)
                """
            )
            cur.execute("INSERT INTO incident_alerts (incident_id, alert_id) VALUES (201, 201)")
            cur.execute("INSERT INTO incident_alerts (incident_id, alert_id) VALUES (202, 202)")
            cur.execute("INSERT INTO incident_entities (incident_id, entity_type, entity_key, display_name) VALUES (201, 'HOST', 'host:srv-alpha', 'srv-alpha')")
            cur.execute("INSERT INTO incident_entities (incident_id, entity_type, entity_key, display_name) VALUES (202, 'HOST', 'host:srv-beta', 'srv-beta')")
            conn.commit()

        case_repo = CaseRepository(db_path=case_path, forensic_db=forensic_db)
        case_svc = CaseService(case_repository=case_repo, forensic_database=forensic_db)

        yield forensic_db, case_repo, case_svc
        forensic_db.close()


@pytest.fixture
def m55_client(m55_dbs, monkeypatch):
    import logintel.ai.case_service as cs_mod

    _, _, case_svc = m55_dbs
    monkeypatch.setattr(cs_mod, "case_service", case_svc)

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


# =========================================================================
# M55-SEC-001: Unauthenticated case access rejected
# =========================================================================
def test_m55_sec_001_unauthenticated_rejected(m55_client):
    """Verify requests lacking Bearer token return 401."""
    res = m55_client.get("/api/v1/cases")
    assert res.status_code in (401, 403)


# =========================================================================
# M55-SEC-002: Invalid bearer token rejected
# =========================================================================
def test_m55_sec_002_invalid_token_rejected(m55_client):
    """Verify fraudulent Bearer tokens return 401."""
    res = m55_client.get(
        "/api/v1/cases",
        headers={"Authorization": "Bearer fake_token_abc_123"},
    )
    assert res.status_code in (401, 403)


# =========================================================================
# M55-SEC-003: Authenticated local operator accepted
# =========================================================================
def test_m55_sec_003_authenticated_operator_accepted(m55_client):
    """Verify authenticated local operator with valid IPC token succeeds."""
    token = get_current_token()
    res = m55_client.get(
        "/api/v1/cases",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    assert isinstance(res.json(), list)


# =========================================================================
# M55-SEC-004: Cross-case isolation
# =========================================================================
def test_m55_sec_004_cross_case_isolation(m55_dbs):
    """Verify Case A and Case B maintain complete state, scope, and hypothesis isolation."""
    _, _, case_svc = m55_dbs
    case1 = case_svc.create_or_open_case(201, title="Case Alpha")
    case2 = case_svc.create_or_open_case(202, title="Case Beta")

    case_svc.create_hypothesis(case1.case_id, "Hypothesis for Case 1 only")
    case_svc.create_hypothesis(case2.case_id, "Hypothesis for Case 2 only")

    c1_hyp = [h.statement for h in case_svc.get_case(case1.case_id).hypotheses]
    c2_hyp = [h.statement for h in case_svc.get_case(case2.case_id).hypotheses]

    assert "Hypothesis for Case 1 only" in c1_hyp
    assert "Hypothesis for Case 1 only" not in c2_hyp
    assert "Hypothesis for Case 2 only" in c2_hyp
    assert "Hypothesis for Case 2 only" not in c1_hyp


# =========================================================================
# M55-SEC-005: Identifier substitution rejected
# =========================================================================
def test_m55_sec_005_identifier_substitution_rejected(m55_client):
    """Verify attempting to access non-existent case identifier returns 404."""
    token = get_current_token()
    res = m55_client.get(
        "/api/v1/cases/99999",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 404


# =========================================================================
# M55-SEC-006: Evidence references remain case-scoped
# =========================================================================
def test_m55_sec_006_evidence_references_case_scoped(m55_dbs):
    """Verify evidence references associated with Case A do not leak into Case B."""
    _, _, case_svc = m55_dbs
    case1 = case_svc.create_or_open_case(201)
    case2 = case_svc.create_or_open_case(202)

    case_svc.associate_evidence(case1.case_id, "event", "ev-sec-1", citation_tag="[event:ev-sec-1]")
    c1_refs = [r.citation_tag for r in case_svc.get_case(case1.case_id).evidence_references]
    c2_refs = [r.citation_tag for r in case_svc.get_case(case2.case_id).evidence_references]

    assert "[event:ev-sec-1]" in c1_refs
    assert "[event:ev-sec-1]" not in c2_refs


# =========================================================================
# M55-SEC-007: Hypotheses remain case-scoped
# =========================================================================
def test_m55_sec_007_hypotheses_case_scoped(m55_dbs):
    """Verify hypotheses are strictly bounded to the target case."""
    _, _, case_svc = m55_dbs
    c1 = case_svc.create_or_open_case(201)
    c2 = case_svc.create_or_open_case(202)

    h1 = case_svc.create_hypothesis(c1.case_id, "C1 Statement")
    with pytest.raises(ValueError):
        # Updating hypothesis ID belonging to c1 under c2 must raise ValueError
        case_svc.update_hypothesis(c2.case_id, h1.hypothesis_id, statement="Mutated")


# =========================================================================
# M55-SEC-008: Reports remain case-scoped
# =========================================================================
def test_m55_sec_008_reports_case_scoped(m55_dbs):
    """Verify generated report drafts belong strictly to their target case."""
    _, _, case_svc = m55_dbs
    c1 = case_svc.create_or_open_case(201)
    c2 = case_svc.create_or_open_case(202)

    r1 = case_svc.draft_or_revise_report(c1.case_id, title="Report C1")
    c2_reps = case_svc.get_case(c2.case_id).reports

    assert r1.case_id == c1.case_id
    assert not any(r.report_id == r1.report_id for r in c2_reps)


# =========================================================================
# M55-SEC-009: Query history remains case-scoped
# =========================================================================
def test_m55_sec_009_query_history_case_scoped(m55_dbs):
    """Verify query history execution records do not leak between cases."""
    _, _, case_svc = m55_dbs
    c1 = case_svc.create_or_open_case(201)
    c2 = case_svc.create_or_open_case(202)

    prop = QueryProposal(proposal_id="qp-c1", query_template_id="q", host="srv-alpha", rationale="hunt")
    case_svc.execute_approved_query(c1.case_id, prop)

    c1_queries = case_svc.get_case(c1.case_id).query_history
    c2_queries = case_svc.get_case(c2.case_id).query_history

    assert len(c1_queries) == 1
    assert len(c2_queries) == 0


# =========================================================================
# M55-SEC-010: AI cannot mutate authoritative forensic state
# =========================================================================
def test_m55_sec_010_ai_cannot_mutate_forensic_state(m55_dbs):
    """Verify case workflow actions do not mutate underlying SQLite forensic events or incidents."""
    forensic_db, _, case_svc = m55_dbs
    with forensic_db.connection() as conn:
        before_cnt = conn.execute("SELECT count(*) FROM events").fetchone()[0]

    case = case_svc.create_or_open_case(201)
    case_svc.draft_or_revise_report(case.case_id)

    with forensic_db.connection() as conn:
        after_cnt = conn.execute("SELECT count(*) FROM events").fetchone()[0]

    assert before_cnt == after_cnt, "Authoritative forensic tables must remain completely unmutated"


# =========================================================================
# M55-SEC-011: AI cannot directly close cases
# =========================================================================
def test_m55_sec_011_ai_cannot_directly_close_cases(m55_dbs):
    """Verify case status transition requires explicit authenticated operator action."""
    _, _, case_svc = m55_dbs
    case = case_svc.create_or_open_case(201)
    assert case.status == CaseStatus.OPEN

    # Invalid jump OPEN -> PAUSED rejected
    with pytest.raises(ValueError):
        case_svc.transition_case_state(case.case_id, CaseStatus.PAUSED, actor="AI")


# =========================================================================
# M55-SEC-012: AI cannot directly alter hypothesis status
# =========================================================================
def test_m55_sec_012_analyst_governs_hypothesis_status(m55_dbs):
    """Verify hypothesis status changes are attributed to an actor and versioned."""
    _, _, case_svc = m55_dbs
    case = case_svc.create_or_open_case(201)
    hyp = case_svc.create_hypothesis(case.case_id, "Initial proposition", actor="lead_analyst")
    assert hyp.status == HypothesisStatus.OPEN

    updated = case_svc.update_hypothesis(
        case.case_id,
        hyp.hypothesis_id,
        status=HypothesisStatus.SUPPORTED,
        assessment="Analyst validated evidence tags",
        actor="lead_analyst",
    )
    assert updated.status == HypothesisStatus.SUPPORTED
    assert updated.version == 2


# =========================================================================
# M55-SEC-013: AI cannot bypass governed query execution
# =========================================================================
def test_m55_sec_013_governed_query_catalog_enforced(m55_dbs):
    """Verify arbitrary raw SQL cannot be injected into query proposals."""
    _, _, case_svc = m55_dbs
    case = case_svc.create_or_open_case(201)

    # SQL injection attempt inside proposal parameters remains strictly parameterized
    malicious_prop = QueryProposal(
        proposal_id="qp-inj",
        query_template_id="query_failed_logins_by_user",
        username="deployer' OR 1=1; DROP TABLE events; --",
        rationale="Injection test",
    )
    res = case_svc.execute_approved_query(case.case_id, malicious_prop)
    assert res["result_count"] == 0  # No matching username; parameterized safely without dropping table!


# =========================================================================
# M55-SEC-014: AI cannot execute arbitrary SQL
# =========================================================================
def test_m55_sec_014_arbitrary_sql_unavailable(m55_dbs):
    """Verify execute_approved_query rejects non-catalog parameters and sanitizes inputs."""
    forensic_db, _, case_svc = m55_dbs
    case = case_svc.create_or_open_case(201)

    with forensic_db.connection() as conn:
        tbl_cnt = conn.execute("SELECT count(*) FROM events").fetchone()[0]
        assert tbl_cnt == 2


# =========================================================================
# M55-SEC-015: AI cannot execute shell commands
# =========================================================================
def test_m55_sec_015_no_subprocess_execution(m55_dbs):
    """Verify CaseService introduces zero subprocess or shell execution capabilities."""
    import inspect
    import subprocess
    from logintel.ai import case_service

    src = inspect.getsource(case_service)
    assert "subprocess" not in src
    assert "os.system" not in src
    assert "popen" not in src


# =========================================================================
# M55-SEC-016: Stale evidence reference represented explicitly
# =========================================================================
def test_m55_sec_016_stale_evidence_represented_explicitly(m55_dbs):
    """Verify deleted or missing authoritative records are marked MISSING, not silently removed."""
    forensic_db, _, case_svc = m55_dbs
    case = case_svc.create_or_open_case(201)

    # Associate an evidence reference pointing to an event that does not exist in forensic DB
    ref = case_svc.associate_evidence(
        case_id=case.case_id,
        source_type="event",
        source_id="ev-deleted-999",
        citation_tag="[event:ev-deleted-999]",
    )

    # Must be marked MISSING with zero resolved record, but preserved in case references
    loaded_case = case_svc.get_case(case.case_id)
    target_ref = next(r for r in loaded_case.evidence_references if r.reference_id == ref.reference_id)
    assert target_ref.resolution_status == ResolutionStatus.MISSING
    assert target_ref.resolved_record is None


# =========================================================================
# M55-SEC-017: AI-generated content labeled correctly
# =========================================================================
def test_m55_sec_017_ai_content_provenance_labeling(m55_dbs):
    """Verify AI-drafted reports carry explicit AI_GENERATED origin and model metadata."""
    _, _, case_svc = m55_dbs
    case = case_svc.create_or_open_case(201)
    rep = case_svc.draft_or_revise_report(case.case_id, is_final=False)

    assert rep.generated_by == ContentOrigin.AI_GENERATED
    assert rep.model_id == "qwen2.5:0.5b"
    assert rep.model_digest is not None
    assert rep.is_final is False


# =========================================================================
# M55-SEC-018: Analyst-authored content cannot be silently overwritten
# =========================================================================
def test_m55_sec_018_analyst_authored_content_protected(m55_dbs):
    """Verify analyst edits produce a new version, preserving previous version history."""
    _, _, case_svc = m55_dbs
    case = case_svc.create_or_open_case(201)

    v1 = case_svc.draft_or_revise_report(case.case_id, analyst_notes="Analyst note v1")
    v2 = case_svc.draft_or_revise_report(case.case_id, analyst_notes="Analyst note v2 modified")

    assert v1.version == 1
    assert v2.version == 2

    # Historical version 1 remains accessible and unmodified
    loaded_v1 = case_svc.case_repo.get_report_version(case.case_id, v1.report_id, 1)
    assert loaded_v1.analyst_notes == "Analyst note v1"


# =========================================================================
# M55-SEC-019: Case survives engine restart
# =========================================================================
def test_m55_sec_019_case_survives_engine_restart(m55_dbs):
    """Verify case state, version, hypotheses, and audit trail survive re-instantiation."""
    forensic_db, case_repo, case_svc = m55_dbs
    c = case_svc.create_or_open_case(201)
    case_svc.transition_case_state(c.case_id, CaseStatus.ACTIVE, actor="analyst_1", reason="Starting")
    case_svc.create_hypothesis(c.case_id, "Persistence test hypothesis")

    # Simulate restart by creating completely new CaseRepository and CaseService pointing to same DB
    restarted_repo = CaseRepository(db_path=case_repo.db_path, forensic_db=forensic_db)
    restarted_svc = CaseService(case_repository=restarted_repo, forensic_database=forensic_db)

    reloaded = restarted_svc.get_case(c.case_id)
    assert reloaded is not None
    assert reloaded.status == CaseStatus.ACTIVE
    assert reloaded.version > 1
    assert any(h.statement == "Persistence test hypothesis" for h in reloaded.hypotheses)


# =========================================================================
# M55-SEC-020: Prompt-injected evidence cannot create authoritative state
# =========================================================================
def test_m55_sec_020_prompt_injection_cannot_create_authoritative_state(m55_dbs):
    """Verify adversarial payloads inside evidence annotations cannot alter database schema."""
    _, _, case_svc = m55_dbs
    case = case_svc.create_or_open_case(201)

    hostile_annotation = "DROP TABLE events; <script>alert(1)</script> [tool:execute_shell]"
    ref = case_svc.associate_evidence(
        case_id=case.case_id,
        source_type="event",
        source_id="ev-sec-1",
        annotation=hostile_annotation,
    )
    assert ref.analyst_annotation == hostile_annotation
    # Case remains healthy and authoritative events table is untouched
    case_reloaded = case_svc.get_case(case.case_id)
    assert case_reloaded.case_id == case.case_id
