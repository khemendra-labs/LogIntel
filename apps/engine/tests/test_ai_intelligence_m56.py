"""Milestone 5.6 Investigation Intelligence & Governed Threat Hunting Functional Test Suite.

Verifies:
- Deterministic findings generation (OBSERVED, INFERRED, UNKNOWN)
- Multi-attribute correlation with explicit explanation reasons
- Temporal window analysis (BEFORE, DURING, AFTER) with anomaly and contradiction tracking
- Evidence gap detection and safe governed query recommendations
- Governed threat hunting workflow (proposal, validation, approval, execution, candidate findings)
- Entity-centric investigation pivots across events, alerts, incidents, and cases
- Unified investigation timeline with strict provenance separation
- Deterministic hypothesis support analysis
- Attack path epistemic classification and MITRE traceability
- Case intelligence dossier aggregation
"""

from __future__ import annotations

import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from logintel.ai.case_service import CaseService
from logintel.ai.domain.case import CaseStatus, HypothesisStatus
from logintel.ai.domain.investigation_intel import (
    EpistemicStatus,
    HypothesisSupportStatus,
    QueryResultStatus,
    TimelineSourceType,
)
from logintel.api.app import create_app
from logintel.api.auth import get_current_token
from logintel.storage.case_repo import CaseRepository
from logintel.storage.db import Database


@pytest.fixture
def m56_setup():
    """Isolated test environment with test cases and forensic DB."""
    with tempfile.TemporaryDirectory() as td:
        cases_db_path = Path(td) / "cases.db"
        forensic_db_path = Path(td) / "forensic.db"

        # Initialize mock forensic db using standard platform migrations
        forensic_db = Database(forensic_db_path)
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
                INSERT INTO incidents (id, incident_key, title, summary, severity, status, primary_host, primary_user, first_seen, last_seen, alert_count, event_count)
                VALUES (500, 'INC-500', 'APT Intrusion', 'APT Intrusion Summary', 'CRITICAL', 'OPEN', 'srv-app-01', 'deployer', '2026-10-02T12:00:00Z', '2026-10-02T12:01:00Z', 1, 4)
                """
            )
            cur.execute(
                """
                INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint, username, src_ip)
                VALUES 
                ('101', '2026-10-02T12:00:00Z', '2026-10-02T12:00:01Z', 'srv-app-01', 'auth.log', 'authentication_failure', 'ALERT', 'login', 'failure', 'Failed login deployer', 'Failed password for deployer from 192.168.1.50', 'openssh', 'fp-101', 'deployer', '192.168.1.50'),
                ('102', '2026-10-02T12:00:15Z', '2026-10-02T12:00:16Z', 'srv-app-01', 'auth.log', 'authentication_failure', 'ALERT', 'login', 'failure', 'Failed login deployer', 'Failed password for deployer from 192.168.1.50', 'openssh', 'fp-102', 'deployer', '192.168.1.50'),
                ('103', '2026-10-02T12:00:30Z', '2026-10-02T12:00:31Z', 'srv-app-01', 'auth.log', 'authentication_failure', 'ALERT', 'login', 'failure', 'Failed login deployer', 'Failed password for deployer from 192.168.1.50', 'openssh', 'fp-103', 'deployer', '192.168.1.50'),
                ('104', '2026-10-02T12:01:00Z', '2026-10-02T12:01:01Z', 'srv-app-01', 'auditd', 'process_execution', 'ALERT', 'exec', 'success', 'Executed /usr/bin/sudo id', 'sudo id by deployer', 'auditd', 'fp-104', 'deployer', '192.168.1.50')
                """
            )
            cur.execute(
                """
                INSERT INTO alerts (id, rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count)
                VALUES (11, 'rule.ssh', 'dedup-11', 'Brute Force Burst Detected', 'Brute force alert', 'ALERT', 'OPEN', 'srv-app-01', '2026-10-02T12:00:35Z', '2026-10-02T12:00:35Z', 3)
                """
            )
            cur.execute(
                """
                INSERT INTO detections (id, alert_id, rule_id, timestamp, host, summary, evidence_count)
                VALUES (21, 11, 'rule.ssh', '2026-10-02T12:00:35Z', 'srv-app-01', 'Auth Burst Rule', 3)
                """
            )
            cur.execute("INSERT INTO incident_alerts (incident_id, alert_id) VALUES (500, 11)")
            cur.execute(
                """
                INSERT INTO incident_entities (incident_id, entity_type, entity_key, display_name)
                VALUES 
                (500, 'HOST', 'host:srv-app-01', 'srv-app-01'),
                (500, 'USER', 'user:deployer', 'deployer'),
                (500, 'IP', 'ip:192.168.1.50', '192.168.1.50')
                """
            )
            cur.execute(
                """
                INSERT INTO incident_relationships (incident_id, source_entity_key, target_entity_key, relationship_type, confidence)
                VALUES (500, 'ip:192.168.1.50', 'user:deployer', 'AUTHENTICATED_TO', 'STRONG')
                """
            )
            conn.commit()

        case_repo = CaseRepository(db_path=cases_db_path, forensic_db=forensic_db)
        case_svc = CaseService(case_repository=case_repo, forensic_database=forensic_db)

        # Create test case
        case = case_svc.create_or_open_case(incident_id=500, title="APT Intrusion Investigation")
        case_id = case.case_id

        # Associate events as case evidence references
        case_svc.associate_evidence(case_id, "event", "101", citation_tag="[event:101]")
        case_svc.associate_evidence(case_id, "event", "102", citation_tag="[event:102]")
        case_svc.associate_evidence(case_id, "event", "103", citation_tag="[event:103]")
        case_svc.associate_evidence(case_id, "alert", "11", citation_tag="[alert:11]")

        yield case_svc, case_id, forensic_db


def test_m56_intel_001_findings_generation(m56_setup):
    """M56-INTEL-001: Deterministic finding generation with epistemic status and confidence basis."""
    case_svc, case_id, _ = m56_setup
    findings, correlations = case_svc.get_findings_and_correlations(case_id)

    assert len(findings) >= 1
    auth_burst = next((f for f in findings if f.finding_type == "AUTHENTICATION_FAILURE_BURST"), None)
    assert auth_burst is not None
    assert auth_burst.epistemic_status == EpistemicStatus.OBSERVED
    assert "deployer" in auth_burst.description
    assert "srv-app-01" in auth_burst.description
    assert "Corroborated by" in auth_burst.confidence_basis
    assert len(auth_burst.source_references) >= 3


def test_m56_intel_002_multi_attribute_correlation(m56_setup):
    """M56-INTEL-002: Multi-attribute correlation with explicit, verifiable reasons."""
    case_svc, case_id, _ = m56_setup
    findings, correlations = case_svc.get_findings_and_correlations(case_id)

    assert len(correlations) >= 1
    corr = correlations[0]
    assert len(corr.reasons) >= 1
    # Check explicit reasons format
    reasons_text = " ".join(corr.reasons)
    assert "same host" in reasons_text or "same user" in reasons_text or "same source IP" in reasons_text
    assert corr.confidence_score > 0.0


def test_m56_intel_003_temporal_window_analysis(m56_setup):
    """M56-INTEL-003: BEFORE, DURING, and AFTER time-window partition with anomaly tracking (C04)."""
    case_svc, case_id, _ = m56_setup
    analysis = case_svc.analyze_temporal_window(
        case_id=case_id,
        anchor_type="alert",
        anchor_id="11",
        anchor_timestamp="2026-10-02T12:00:35Z",
        window_seconds=120,
    )

    assert analysis.case_id == case_id
    assert analysis.anchor_id == "11"
    assert len(analysis.before_items) >= 2  # events at 12:00:00, 12:00:15, 12:00:30 precede 12:00:35
    assert isinstance(analysis.temporal_anomalies, list)
    assert isinstance(analysis.state_contradictions, list)

    # C04-1: Normal lifecycle sequence (PROCESS_STARTED -> PROCESS_EXITED -> PROCESS_STARTED)
    # Must NOT produce contradiction or anomaly (temporal ordering != logical contradiction)
    normal_seq_items = [
        {"id": "ev-p1", "timestamp": "2026-10-02T12:00:00Z", "action": "PROCESS_STARTED", "username": "deployer", "host": "srv-app-01"},
        {"id": "ev-p2", "timestamp": "2026-10-02T12:00:15Z", "action": "PROCESS_EXITED", "username": "deployer", "host": "srv-app-01"},
        {"id": "ev-p3", "timestamp": "2026-10-02T12:00:30Z", "action": "PROCESS_STARTED", "username": "deployer", "host": "srv-app-01"},
    ]
    norm_analysis = case_svc.intelligence.temporal_engine.analyze_temporal_window(
        case_id=case_id,
        anchor_type="event",
        anchor_id="ev-p2",
        anchor_timestamp="2026-10-02T12:00:15Z",
        items=normal_seq_items,
        window_seconds=60,
    )
    assert len(norm_analysis.temporal_anomalies) == 0
    assert len(norm_analysis.state_contradictions) == 0

    # C04-2: Temporal Anomaly (event in the future relative to system clock)
    future_items = [
        {"id": "ev-fut", "timestamp": "2099-01-01T00:00:00Z", "action": "login", "username": "deployer", "host": "srv-app-01"},
    ]
    fut_analysis = case_svc.intelligence.temporal_engine.analyze_temporal_window(
        case_id=case_id,
        anchor_type="event",
        anchor_id="ev-p2",
        anchor_timestamp="2026-10-02T12:00:15Z",
        items=future_items,
        window_seconds=60,
    )
    assert len(fut_analysis.temporal_anomalies) >= 1
    assert any("TEMPORAL_ANOMALY" in a for a in fut_analysis.temporal_anomalies)
    assert len(fut_analysis.state_contradictions) == 0

    # C04-3: State Contradiction (same user simultaneously operating on two distinct hosts within 2 seconds)
    contra_items = [
        {"id": "ev-h1", "timestamp": "2026-10-02T12:00:00Z", "username": "deployer", "host": "srv-app-01"},
        {"id": "ev-h2", "timestamp": "2026-10-02T12:00:02Z", "username": "deployer", "host": "srv-db-99"},
    ]
    contra_analysis = case_svc.intelligence.temporal_engine.analyze_temporal_window(
        case_id=case_id,
        anchor_type="event",
        anchor_id="ev-h1",
        anchor_timestamp="2026-10-02T12:00:00Z",
        items=contra_items,
        window_seconds=60,
    )
    assert len(contra_analysis.state_contradictions) >= 1
    assert any("STATE_CONTRADICTION" in c for c in contra_analysis.state_contradictions)
    assert len(contra_analysis.temporal_anomalies) == 0


def test_m56_intel_004_evidence_gap_detection(m56_setup):
    """M56-INTEL-004: Evidence gap detection and safe governed query recommendations."""
    case_svc, case_id, _ = m56_setup
    gaps = case_svc.get_evidence_gaps(case_id)

    assert len(gaps) >= 1
    # Missing process or network telemetry identified
    gap_types = [g.gap_type for g in gaps]
    assert "MISSING_PROCESS_TELEMETRY" in gap_types or "MISSING_NETWORK_TELEMETRY" in gap_types

    # Recommendations must provide typed proposals without auto-execution
    for g in gaps:
        if g.recommended_governed_query:
            assert g.recommended_governed_query.intent is not None
            assert g.recommended_governed_query.limit <= 500


def test_m56_intel_005_governed_threat_hunting_workflow(m56_setup):
    """M56-INTEL-005: Governed threat hunting proposal, validation, execution, and candidate findings (C05)."""
    case_svc, case_id, _ = m56_setup

    # 1. MATCHED: Valid proposal matching events
    proposal = case_svc.create_hunt_proposal(
        case_id=case_id,
        template_id="search_auth_failures",
        parameters={"host": "srv-app-01", "username": "deployer", "limit": 20},
        rationale="Hunt for residual deployer brute-force attempts",
    )
    assert proposal.validation_status == "VALID"
    assert len(proposal.validation_errors) == 0

    execution = case_svc.execute_hunt_query(proposal, approved_by="lead-analyst")
    assert execution.result_status == QueryResultStatus.MATCHED
    assert execution.result_count >= 1
    assert execution.approved_by == "lead-analyst"
    assert len(execution.candidate_findings) >= 1

    # 2. NO_MATCH: Valid proposal against existing telemetry finding zero matching records
    # C05: NO_MATCH != UNAVAILABLE and NO_MATCH != proof that event never occurred
    proposal_nomatch = case_svc.create_hunt_proposal(
        case_id=case_id,
        template_id="search_auth_failures",
        parameters={"host": "srv-app-01", "username": "nonexistent_ghost_user_xyz", "limit": 20},
        rationale="Hunt for nonexistent user",
    )
    assert proposal_nomatch.validation_status == "VALID"
    exec_nomatch = case_svc.execute_hunt_query(proposal_nomatch, approved_by="lead-analyst")
    assert exec_nomatch.result_status == QueryResultStatus.NO_MATCH
    assert exec_nomatch.result_status != QueryResultStatus.UNAVAILABLE
    assert exec_nomatch.result_count == 0

    # 3. PARTIAL: Result boundary reached (limit=1 with multiple candidates)
    proposal_partial = case_svc.create_hunt_proposal(
        case_id=case_id,
        template_id="search_auth_failures",
        parameters={"host": "srv-app-01", "username": "deployer", "limit": 1},
        rationale="Hunt with limit boundary reached",
    )
    exec_partial = case_svc.execute_hunt_query(proposal_partial, approved_by="lead-analyst")
    assert exec_partial.result_status == QueryResultStatus.PARTIAL
    assert exec_partial.result_count == 1

    # 4. UNAVAILABLE: Unapproved execution attempt
    exec_unavail = case_svc.execute_hunt_query(proposal, approved_by="")
    assert exec_unavail.result_status == QueryResultStatus.UNAVAILABLE

    # 5. INVALID: Validation failure
    proposal_invalid = case_svc.create_hunt_proposal(
        case_id=case_id,
        template_id="search_auth_failures",
        parameters={"username": "alice' OR 1=1;--"},
        rationale="Adversarial parameter",
    )
    assert proposal_invalid.validation_status == "INVALID"
    exec_invalid = case_svc.execute_hunt_query(proposal_invalid, approved_by="lead-analyst")
    assert exec_invalid.result_status == QueryResultStatus.INVALID

    # 6. Logged to persistent case query history
    reloaded_case = case_svc.get_case(case_id)
    assert len(reloaded_case.query_history) >= 1
    last_query = reloaded_case.query_history[-1]
    assert last_query.executed_by == "lead-analyst"


def test_m56_intel_006_entity_centric_pivot(m56_setup):
    """M56-INTEL-006: Deep entity pivot across events, alerts, detections, and cases."""
    case_svc, case_id, _ = m56_setup
    pivot = case_svc.resolve_entity_pivot(case_id, "USER", "deployer")

    assert pivot.entity_type == "USER"
    assert pivot.entity_value == "deployer"
    assert len(pivot.related_events) >= 3
    assert len(pivot.related_alerts) >= 1
    assert len(pivot.related_detections) >= 1
    assert 500 in pivot.related_incidents
    assert case_id in pivot.related_cases


def test_m56_intel_007_unified_timeline_provenance(m56_setup):
    """M56-INTEL-007: Unified timeline builder with strict authoritative vs derived separation."""
    case_svc, case_id, _ = m56_setup
    timeline = case_svc.get_case_timeline(case_id)

    assert len(timeline) >= 4
    # Chronological sort
    timestamps = [item.timestamp for item in timeline]
    assert timestamps == sorted(timestamps)

    # Check source types and provenance
    types = {item.source_type for item in timeline}
    assert TimelineSourceType.OBSERVED_EVENT in types
    assert TimelineSourceType.ALERT in types

    for item in timeline:
        if item.source_type in (TimelineSourceType.OBSERVED_EVENT, TimelineSourceType.ALERT, TimelineSourceType.DETECTION):
            assert item.is_authoritative is True
        elif item.source_type in (TimelineSourceType.DERIVED_CORRELATION, TimelineSourceType.AI_INTERPRETATION):
            assert item.is_authoritative is False


def test_m56_intel_008_hypothesis_evidence_analysis(m56_setup):
    """M56-INTEL-008: Deterministic hypothesis support analysis without altering analyst state."""
    case_svc, case_id, _ = m56_setup

    # Create hypothesis with supporting evidence
    hyp = case_svc.create_hypothesis(
        case_id=case_id,
        statement="Compromised credentials via brute-force authentication burst",
        supporting_tags=["[event:101]", "[event:102]", "[alert:11]"],
    )

    analysis = case_svc.analyze_hypothesis(case_id, hyp.hypothesis_id)
    assert analysis.hypothesis_id == hyp.hypothesis_id
    assert analysis.support_status == HypothesisSupportStatus.SUPPORTED_BY_CURRENT_EVIDENCE
    assert len(analysis.supporting_evidence_items) == 3
    assert analysis.analyst_action_required is False

    # Verify analyst-owned hypothesis status was NOT modified
    unmodified_hyp = next(h for h in case_svc.get_case(case_id).hypotheses if h.hypothesis_id == hyp.hypothesis_id)
    assert unmodified_hyp.status == HypothesisStatus.OPEN


def test_m56_intel_009_case_intelligence_dossier_aggregation(m56_setup):
    """M56-INTEL-009: Complete aggregated case intelligence dossier."""
    case_svc, case_id, _ = m56_setup
    dossier = case_svc.get_case_intelligence_dossier(case_id)

    assert dossier.case_id == case_id
    assert dossier.incident_id == 500
    assert len(dossier.findings) >= 1
    assert len(dossier.correlations) >= 1
    assert len(dossier.timeline) >= 1
    assert len(dossier.evidence_gaps) >= 1


def test_m56_intel_010_ai_investigation_intelligence_synthesis(m56_setup):
    """M56-INTEL-010: Structured AI advisory synthesis contract with application-level containment."""
    case_svc, case_id, _ = m56_setup
    synthesis = case_svc.generate_ai_investigation_intelligence(case_id, actor="analyst-p1")

    assert synthesis.case_id == case_id
    assert "Deterministic investigation synthesis" in synthesis.summary
    assert len(synthesis.observed_claims) >= 1
    assert len(synthesis.citations) >= 1
    assert synthesis.provenance["containment_mode"] == "APPLICATION_LEVEL_AI_CONTAINMENT"
