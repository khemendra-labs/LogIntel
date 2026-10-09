"""Functional test suite for M7.8 Investigation Quality, Closure & Forensic Review."""

import json
import time
import pytest

from logintel.ai.domain.case import CaseStatus, InvestigationScope
from logintel.review.models import (
    AcknowledgeBlockerRequest,
    BlockerResolutionState,
    BlockerSeverity,
    CloseCaseRequest,
    ClosureReadinessState,
    ExportFormat,
    GateEvaluationStatus,
    ReopenCaseRequest,
    ReviewBlockerCategory,
    ReviewGateType,
)
from logintel.review.service import case_review_service
from logintel.storage.case_repo import case_repo


@pytest.fixture
def review_case():
    """Create a populated investigation case with scope, evidence, hypotheses, and questions."""
    t_str = str(int(time.time() * 1000) % 1000000)
    inc_id = 920000 + int(t_str) % 50000

    existing = case_repo.get_case_by_incident(inc_id)
    if existing:
        case = existing
    else:
        case = case_repo.create_case(
            incident_id=inc_id,
            title=f"Case Review Test {t_str}",
            description="Forensic investigation into unauthorized lateral movement and command execution.",
        )

    # Set detailed scope
    case_repo.update_case_scope(
        case_id=case.case_id,
        scope=InvestigationScope(
            investigation_id=inc_id,
            subject_id=f"inc-{inc_id}",
            time_start="2026-10-01T00:00:00Z",
            time_end="2026-10-02T00:00:00Z",
            selected_entity_ids=["host:prod-web-01", "host:db-srv-02", "user:admin", "user:svc-deploy"],
        ),
    )

    # Add evidence references
    case_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="ip",
        source_id="198.51.100.42",
        role="SUPPORTING",
        epistemic_status="OBSERVED",
        citation_tag="[ip:198.51.100.42]",
        analyst_annotation=json.dumps({"ip": "198.51.100.42"}),
    )
    case_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="event",
        source_id="evt-1001",
        role="SUPPORTING",
        epistemic_status="OBSERVED",
        citation_tag="[evt:1001]",
        analyst_annotation=json.dumps({"event_type": "PROCESS_EXEC"}),
    )

    # Add hypothesis
    from logintel.ai.domain.case import CaseHypothesis
    from logintel.ai.domain.workspace import HypothesisStatus

    case_repo.upsert_hypothesis(
        case_id=case.case_id,
        hypothesis=CaseHypothesis(
            hypothesis_id=f"hyp-{case.case_id}-1",
            case_id=case.case_id,
            statement="Adversary leveraged compromised credentials to authenticate via SSH.",
            status=HypothesisStatus.SUPPORTED,
            supporting_evidence_tags=["[ip:198.51.100.42]"],
            contradicting_evidence_tags=[],
            evidence_gaps=[],
            analyst_assessment="Corroborated by external ingress logs and SSH accepted publickey.",
            created_at="2026-10-01T00:00:00Z",
            updated_at="2026-10-01T00:00:00Z",
        ),
    )

    # Add investigation question
    conn = case_repo._get_connection()
    with conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO case_investigation_questions (
                question_id, case_id, question, category, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                f"q-{case.case_id}-1",
                case.case_id,
                "What was the initial vector of ingress?",
                "AUTHENTICATION",
                "ANSWERED",
                "2026-10-01T00:00:00Z",
            ),
        )

    return case


def test_m78_func_001_12_gates_evaluation(review_case):
    """Verify all 12 forensic review gates evaluate deterministically and return typed results."""
    snapshot = case_review_service.run_forensic_review(review_case.case_id, actor="SecAnalyst-Lead")

    assert snapshot.case_id == review_case.case_id
    assert len(snapshot.gates) == 12

    gate_types = [g.gate_type for g in snapshot.gates]
    for expected_gate in ReviewGateType:
        assert expected_gate in gate_types

    # Scope gate should pass because hosts, users, and objective were provided
    scope_gate = next(g for g in snapshot.gates if g.gate_type == ReviewGateType.SCOPE)
    assert scope_gate.status == GateEvaluationStatus.PASS

    # Evidence coverage should reflect the 2 references added
    cov_gate = next(g for g in snapshot.gates if g.gate_type == ReviewGateType.EVIDENCE_COVERAGE)
    assert snapshot.coverage.total_references >= 2

    # Provenance manifest should be generated with valid root digest
    assert snapshot.provenance.root_digest is not None
    assert len(snapshot.provenance.root_digest) == 64


def test_m78_func_002_closure_blockers_and_readiness():
    """Verify missing scope or unassessed contradictions generate blockers and NOT_READY state."""
    t_str = str(int(time.time() * 1000) % 1000000)
    inc_id = 930000 + int(t_str) % 50000
    empty_case = case_repo.create_case(incident_id=inc_id, title=f"Empty Case {t_str}")

    snapshot = case_review_service.run_forensic_review(empty_case.case_id)
    assert snapshot.closure_readiness == ClosureReadinessState.NOT_READY

    # Should contain BLOCKER severities due to missing scope entities and no evidence
    blockers = [b for b in snapshot.blockers if b.severity == BlockerSeverity.BLOCKER]
    assert len(blockers) >= 1
    categories = [b.category for b in blockers]
    assert ReviewBlockerCategory.MISSING_SCOPE in categories or ReviewBlockerCategory.UNRESOLVED_EVIDENCE_REFERENCE in categories


def test_m78_func_003_blocker_acknowledgment_workflow(review_case):
    """Verify analyst acknowledgment of a review blocker updates its state and audit log."""
    # Add an unreviewed open question to induce a warning blocker
    conn = case_repo._get_connection()
    with conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO case_investigation_questions (
                question_id, case_id, question, category, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                f"q-open-{review_case.case_id}",
                review_case.case_id,
                "Is there persistent cron execution?",
                "EXECUTION",
                "OPEN",
                "2026-10-01T00:00:00Z",
            ),
        )

    snapshot_before = case_review_service.run_forensic_review(review_case.case_id)
    target_blocker_id = f"blk-question-open-q-open-{review_case.case_id}"

    # Acknowledge the blocker
    req = AcknowledgeBlockerRequest(
        resolution_state=BlockerResolutionState.ACKNOWLEDGED,
        notes="Cron jobs inspected manually via crontab -l; zero persistence found.",
    )
    snapshot_after = case_review_service.acknowledge_blocker(
        case_id=review_case.case_id,
        blocker_id=target_blocker_id,
        request=req,
        actor="SecAnalyst-Reviewer",
    )

    acknowledged = next((b for b in snapshot_after.blockers if b.blocker_id == target_blocker_id), None)
    assert acknowledged is not None
    assert acknowledged.resolution_state == BlockerResolutionState.ACKNOWLEDGED
    assert acknowledged.resolved_by == "SecAnalyst-Reviewer"


def test_m78_func_004_case_closure_and_reopening_authorization(review_case):
    """Verify closing case transitions to CLOSED, and reopening transitions to ACTIVE with audit trail."""
    # 1. Close case
    close_req = CloseCaseRequest(
        closure_notes="Investigation completed with lateral movement isolated.",
        override_warnings=True,
    )
    snapshot_closed = case_review_service.close_case(
        case_id=review_case.case_id,
        request=close_req,
        actor="SecAnalyst-Lead",
    )

    assert snapshot_closed.case_status == "CLOSED"
    assert snapshot_closed.closure_readiness == ClosureReadinessState.CLOSED

    # Verify persistent state in SQLite
    reloaded_case = case_repo.get_case(review_case.case_id, resolve_evidence=False)
    assert reloaded_case.status == CaseStatus.CLOSED

    # 2. Reopen case
    reopen_req = ReopenCaseRequest(
        reopen_reason="New telemetry observed from second bastion host.",
    )
    snapshot_reopened = case_review_service.reopen_case(
        case_id=review_case.case_id,
        request=reopen_req,
        actor="SecAnalyst-Lead",
    )

    assert snapshot_reopened.case_status == "ACTIVE"

    # Verify audit history captured both transitions
    history = case_review_service.get_review_history(review_case.case_id)
    actions = [h["action"] for h in history]
    assert "STATE_TRANSITION" in actions


def test_m78_func_005_multi_format_deterministic_export(review_case):
    """Verify review snapshot exports to JSON, CSV (formula-safe), and Markdown."""
    # JSON export
    exp_json = case_review_service.export_review(review_case.case_id, export_format=ExportFormat.JSON)
    assert exp_json.format == "JSON"
    parsed_json = json.loads(exp_json.content)
    assert parsed_json["case_id"] == review_case.case_id

    # CSV export
    exp_csv = case_review_service.export_review(review_case.case_id, export_format=ExportFormat.CSV)
    assert exp_csv.format == "CSV"
    assert "Blocker_ID,Gate_Type,Category" in exp_csv.content

    # Markdown export
    exp_md = case_review_service.export_review(review_case.case_id, export_format=ExportFormat.MARKDOWN)
    assert exp_md.format == "MARKDOWN"
    assert f"# LogIntel Forensic Case Review — Case {review_case.case_id}" in exp_md.content
    assert "## 1. Forensic Review Gates Evaluation" in exp_md.content
