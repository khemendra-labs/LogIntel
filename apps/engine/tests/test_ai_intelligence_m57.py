"""Milestone 5.7 Intelligence Engine Test Suite.

Validates:
1. M57-INTEL-001: Investigation Dossier generation with structured sections and review summaries.
2. M57-INTEL-002: Key Findings review workflow (UNREVIEWED, UNDER_REVIEW, ACCEPTED, REJECTED, NEEDS_MORE_EVIDENCE).
3. M57-INTEL-003: Deterministic Hypothesis Evidence Matrix resolution.
4. M57-INTEL-004: Evidence-Gap-driven next-action generation (analyst-controlled).
5. M57-INTEL-005: Refined multi-source Timeline Intelligence with authoritative provenance demarcation.
6. M57-INTEL-006: Governed Threat-Hunting result incorporation as evidence references.
7. M57-INTEL-007: Structured Case Briefing generation distinguishing evidence from interpretation.
8. M57-INTEL-008: Immutable report version generation derived deterministically from dossier.
9. M57-INTEL-009: Provenance manifest verification linking statements to forensic sources.
10. M57-INTEL-010: Advisory AI investigation synthesis grounding without authoritative state mutation.
"""

from __future__ import annotations

from pathlib import Path
import tempfile
from typing import Generator
import pytest

from logintel.ai.case_service import CaseService
from logintel.ai.domain.investigation_dossier import (
    EvidenceItemResolution,
    EvidenceMatrixStatus,
    FindingReviewState,
    RefinedTimelineSourceType,
)
from logintel.ai.domain.investigation_intel import EpistemicStatus, QueryResultStatus
from logintel.storage.case_repo import CaseRepository
from logintel.storage.db import Database


@pytest.fixture
def m57_setup() -> Generator[tuple[CaseService, int, Database], None, None]:
    """Isolated test environment with test case and authoritative forensic database."""
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
                ('rule.ssh', 'SSH Attack', 'SSH Rule', 'CRITICAL', 'Auth', 'threshold', 'yaml')
                """
            )
            cur.execute(
                """
                INSERT INTO incidents (id, incident_key, title, summary, severity, status, primary_host, primary_user, first_seen, last_seen, alert_count, event_count)
                VALUES
                (500, 'INC-500', 'SSH Intrusion Burst', 'SSH brute force', 'CRITICAL', 'OPEN', 'srv-app-01', 'deployer', '2026-10-02T12:00:00Z', '2026-10-02T12:00:35Z', 1, 3)
                """
            )
            cur.execute(
                """
                INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint, username, src_ip)
                VALUES
                ('101', '2026-10-02T12:00:00Z', '2026-10-02T12:00:01Z', 'srv-app-01', 'auth.log', 'authentication_failure', 'ALERT', 'login', 'failure', 'Failed login deployer', 'Failed password for deployer from 192.168.1.50', 'openssh', 'fp-101', 'deployer', '192.168.1.50'),
                ('102', '2026-10-02T12:00:15Z', '2026-10-02T12:00:16Z', 'srv-app-01', 'auth.log', 'authentication_failure', 'ALERT', 'login', 'failure', 'Failed login deployer', 'Failed password for deployer from 192.168.1.50', 'openssh', 'fp-102', 'deployer', '192.168.1.50'),
                ('103', '2026-10-02T12:00:30Z', '2026-10-02T12:00:31Z', 'srv-app-01', 'auth.log', 'authentication_failure', 'ALERT', 'login', 'failure', 'Failed login deployer', 'Failed password for deployer from 192.168.1.50', 'openssh', 'fp-103', 'deployer', '192.168.1.50')
                """
            )
            cur.execute(
                """
                INSERT INTO alerts (id, rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count)
                VALUES (11, 'rule.ssh', 'dedup-11', 'Brute Force Burst Detected', 'Brute force alert', 'ALERT', 'OPEN', 'srv-app-01', '2026-10-02T12:00:35Z', '2026-10-02T12:00:35Z', 3)
                """
            )
            cur.execute("INSERT INTO incident_alerts (incident_id, alert_id) VALUES (500, 11)")
            cur.execute(
                """
                INSERT INTO incident_entities (incident_id, entity_type, entity_key, display_name)
                VALUES
                (500, 'HOST', 'host:srv-app-01', 'srv-app-01'),
                (500, 'USER', 'user:deployer', 'deployer')
                """
            )
            conn.commit()

        case_repo = CaseRepository(db_path=cases_path, forensic_db=forensic_db)
        case_svc = CaseService(case_repository=case_repo, forensic_database=forensic_db)

        # Create persistent case
        case = case_svc.create_or_open_case(incident_id=500, title="Investigation: SSH Intrusion Burst")
        case_id = case.case_id

        # Associate forensic evidence references
        case_svc.associate_evidence(case_id, "event", "101", citation_tag="[event:101]")
        case_svc.associate_evidence(case_id, "event", "102", citation_tag="[event:102]")
        case_svc.associate_evidence(case_id, "alert", "11", citation_tag="[alert:11]")

        # Create analyst hypothesis
        case_svc.create_hypothesis(
            case_id=case_id,
            statement="Attacker attempted SSH credential brute force against deployer account",
            supporting_tags=["[event:101]", "[event:102]", "[alert:11]"],
            contradicting_tags=[],
            gaps=["Missing process attribution for deployer"],
        )

        yield case_svc, case_id, forensic_db


def test_m57_intel_001_dossier_generation(m57_setup):
    """M57-INTEL-001: Investigation Dossier generation with structured sections and review summaries."""
    case_svc, case_id, _ = m57_setup
    dossier = case_svc.get_investigation_dossier(case_id)

    assert dossier.case_id == case_id
    assert dossier.incident_id == 500
    assert "SSH Intrusion" in dossier.case_title
    assert len(dossier.findings) >= 1
    assert len(dossier.timeline) >= 3
    assert len(dossier.evidence_matrix) >= 1
    assert len(dossier.evidence_gaps) >= 1
    assert "UNREVIEWED" in dossier.review_state_summary
    assert len(dossier.provenance_manifest) >= 5


def test_m57_intel_002_finding_review_lifecycle(m57_setup):
    """M57-INTEL-002: Key Findings review workflow (UNREVIEWED, UNDER_REVIEW, ACCEPTED, REJECTED, NEEDS_MORE_EVIDENCE)."""
    case_svc, case_id, _ = m57_setup
    dossier = case_svc.get_investigation_dossier(case_id)
    finding_id = dossier.findings[0]["finding_id"]

    # 1. Initially UNREVIEWED
    assert dossier.findings[0]["review_state"] == FindingReviewState.UNREVIEWED.value

    # 2. Transition to UNDER_REVIEW
    rev1 = case_svc.update_finding_review(
        case_id=case_id,
        finding_id=finding_id,
        review_state=FindingReviewState.UNDER_REVIEW.value,
        analyst_notes="Reviewing authentication burst pattern",
        reviewer="lead-analyst",
    )
    assert rev1["review_state"] == "UNDER_REVIEW"

    # 3. Transition to ACCEPTED
    rev2 = case_svc.update_finding_review(
        case_id=case_id,
        finding_id=finding_id,
        review_state=FindingReviewState.ACCEPTED.value,
        analyst_notes="Confirmed brute force pattern across 3 failed events",
        reviewer="lead-analyst",
    )
    assert rev2["review_state"] == "ACCEPTED"

    # Verify reflected in dossier
    reloaded_dossier = case_svc.get_investigation_dossier(case_id)
    target_f = next(f for f in reloaded_dossier.findings if f["finding_id"] == finding_id)
    assert target_f["review_state"] == "ACCEPTED"
    assert target_f["analyst_review_notes"] == "Confirmed brute force pattern across 3 failed events"
    assert reloaded_dossier.review_state_summary["ACCEPTED"] >= 1

    # Verify audit log records review action
    audit = case_svc.case_repo.get_audit_log(case_id)
    review_audits = [a for a in audit if a.action == "REVIEW_FINDING"]
    assert len(review_audits) == 2
    assert review_audits[-1].new_value == "ACCEPTED"


def test_m57_intel_003_evidence_matrix_evaluation(m57_setup):
    """M57-INTEL-003: Deterministic Hypothesis Evidence Matrix resolution."""
    case_svc, case_id, _ = m57_setup
    matrix = case_svc.get_evidence_matrix(case_id)

    assert len(matrix) >= 1
    entry = matrix[0]
    assert entry.case_id == case_id
    assert "credential brute force" in entry.statement
    # Has resolved support but has evidence gaps -> WEAKLY_SUPPORTED
    assert entry.status == EvidenceMatrixStatus.WEAKLY_SUPPORTED

    for ev in entry.supporting_evidence:
        assert ev["resolution"] in (EvidenceItemResolution.RESOLVED.value, EvidenceItemResolution.MISSING.value)
        assert ev["citation_tag"].startswith("[")


def test_m57_intel_004_evidence_gap_actions(m57_setup):
    """M57-INTEL-004: Evidence-Gap-driven next-action generation (analyst-controlled)."""
    case_svc, case_id, _ = m57_setup
    actions = case_svc.get_evidence_gap_actions(case_id)

    assert len(actions) >= 1
    for a in actions:
        assert a.case_id == case_id
        assert a.execution_control == "ANALYST_CONTROLLED"
        assert len(a.suggested_action) > 10
        assert len(a.reason) > 5
        assert len(a.evidence_requirement) > 5


def test_m57_intel_005_refined_timeline_intelligence(m57_setup):
    """M57-INTEL-005: Refined multi-source Timeline Intelligence with authoritative provenance demarcation."""
    case_svc, case_id, _ = m57_setup
    timeline = case_svc.get_refined_timeline(case_id)

    assert len(timeline) >= 4
    # Check strict provenance and authority
    source_types = {item.source_type for item in timeline}
    assert RefinedTimelineSourceType.OBSERVED_EVENT in source_types
    assert RefinedTimelineSourceType.ALERT in source_types
    assert RefinedTimelineSourceType.HYPOTHESIS in source_types

    for item in timeline:
        if item.source_type in (RefinedTimelineSourceType.OBSERVED_EVENT, RefinedTimelineSourceType.ALERT):
            assert item.is_authoritative
        elif item.source_type in (RefinedTimelineSourceType.HYPOTHESIS, RefinedTimelineSourceType.CORRELATION, RefinedTimelineSourceType.FINDING):
            assert not item.is_authoritative


def test_m57_intel_006_threat_hunt_result_integration(m57_setup):
    """M57-INTEL-006: Governed Threat-Hunting result incorporation as evidence references."""
    case_svc, case_id, _ = m57_setup

    proposal = case_svc.create_hunt_proposal(
        case_id=case_id,
        template_id="search_auth_failures",
        parameters={"username": "deployer", "limit": 10},
        rationale="Hunt deployer auth logs",
    )
    exec_res = case_svc.execute_hunt_query(proposal, approved_by="lead-analyst")
    assert exec_res.result_status == QueryResultStatus.MATCHED

    # Verify query history and results retrieval
    hunt_results = case_svc.get_threat_hunt_results(case_id)
    assert len(hunt_results) >= 1
    assert hunt_results[-1]["executed_by"] == "lead-analyst"

    # Verify timeline incorporates threat hunt result
    timeline = case_svc.get_refined_timeline(case_id)
    hunt_items = [t for t in timeline if t.source_type == RefinedTimelineSourceType.THREAT_HUNT_RESULT]
    assert len(hunt_items) >= 1
    assert hunt_items[0].is_authoritative


def test_m57_intel_007_case_briefing(m57_setup):
    """M57-INTEL-007: Structured Case Briefing generation distinguishing evidence from interpretation."""
    case_svc, case_id, _ = m57_setup
    briefing = case_svc.get_case_briefing(case_id)

    assert briefing.case_id == case_id
    assert briefing.incident_id == 500
    assert briefing.observed_metrics["observed_events"] >= 2
    assert briefing.observed_metrics["associated_alerts"] >= 1
    assert len(briefing.key_findings_summary) >= 1
    assert len(briefing.recommended_next_actions) >= 1
    assert briefing.generated_by == "DETERMINISTIC_BRIEFING_ENGINE"


def test_m57_intel_008_report_draft_from_dossier(m57_setup):
    """M57-INTEL-008: Immutable report version generation derived deterministically from dossier."""
    case_svc, case_id, _ = m57_setup
    report = case_svc.draft_report_from_dossier(
        case_id=case_id,
        title="Official Intrusion Report",
        analyst_notes="Validated brute force incident",
        is_final=False,
        actor="lead-analyst",
    )

    assert report.case_id == case_id
    assert report.version == 1
    assert "Official Intrusion Report" in report.title
    assert len(report.facts) >= 2

    # Verify second draft creates version 2 without overwriting v1
    report_v2 = case_svc.draft_report_from_dossier(
        case_id=case_id,
        title="Official Intrusion Report v2",
        analyst_notes="Updated report notes",
        is_final=True,
        actor="lead-analyst",
    )
    assert report_v2.version == 2
    assert report_v2.is_final == 1


def test_m57_intel_009_provenance_manifest(m57_setup):
    """M57-INTEL-009: Provenance manifest verification linking statements to forensic sources."""
    case_svc, case_id, _ = m57_setup
    manifest = case_svc.get_provenance_manifest(case_id)

    assert len(manifest) >= 5
    item_types = {m.item_type for m in manifest}
    assert "evidence_reference" in item_types
    assert "finding" in item_types
    assert "timeline_item" in item_types

    for entry in manifest:
        assert entry.case_id == case_id
        assert entry.source_hash_or_ref is not None
        assert entry.epistemic_status in (EpistemicStatus.OBSERVED, EpistemicStatus.INFERRED, EpistemicStatus.UNKNOWN)


def test_m57_intel_010_ai_advisory_synthesis_grounding(m57_setup):
    """M57-INTEL-010: Advisory AI investigation synthesis grounding without authoritative state mutation."""
    case_svc, case_id, _ = m57_setup
    synth = case_svc.generate_ai_investigation_intelligence(case_id)

    assert synth.case_id == case_id
    assert len(synth.summary) > 20
    assert len(synth.citations) >= 1
    assert synth.provenance["containment_mode"] == "APPLICATION_LEVEL_AI_CONTAINMENT"
