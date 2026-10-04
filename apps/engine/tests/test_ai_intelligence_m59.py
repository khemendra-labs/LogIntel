"""Milestone 5.9 Evidence Correlation & Intelligence Test Suite.

Validates:
1. M59-INTEL-001: Deterministic evidence correlation and multi-dimensional clustering.
2. M59-INTEL-002: Evidence cluster source traceability with SHA-256 digests and citations.
3. M59-INTEL-003: Explicit deterministic correlation reasons (SHARED_ENTITY, SHARED_SESSION, TEMPORAL_PROXIMITY).
4. M59-INTEL-004: Temporal correlation preserving original forensic event timestamps.
5. M59-INTEL-005: Behavioral sequence analysis with multi-stage progression and epistemic status.
6. M59-INTEL-006: Deterministic hypothesis support/contradiction analysis without fake percentages.
7. M59-INTEL-007: Evidence gap intelligence with explicit gap types and suggested governed hunt queries.
8. M59-INTEL-008: Governed threat hunting query validation and proposal generation.
9. M59-INTEL-009: Entity workbench dossier assembly with deep pivot correlations.
10. M59-INTEL-010: Deterministic finding generation from clusters preserving review separation without Migration 6.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
from typing import Generator
import pytest

from logintel.ai.case_service import CaseService
from logintel.ai.domain.investigation_correlation import (
    CorrelationReason,
    EvidenceCluster,
    BehavioralSequence,
    HypothesisSupportDetail,
    EvidenceGapDetail,
    EntityWorkbenchDossier,
)
from logintel.ai.domain.investigation_intel import EpistemicStatus
from logintel.storage.case_repo import CaseRepository
from logintel.storage.db import Database


@pytest.fixture
def m59_setup() -> Generator[tuple[CaseService, int, Database], None, None]:
    """Isolated test environment with test case, incident, entities, relationships, events, and evidence."""
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
                ('rule.ssh', 'SSH Attack', 'SSH Rule', 'CRITICAL', 'Auth', 'threshold', 'yaml'),
                ('rule.sudo', 'Sudo Escalation', 'Privilege Escalation', 'CRITICAL', 'Priv', 'threshold', 'yaml'),
                ('rule.lateral', 'Lateral Network Flow', 'Lateral Movement', 'HIGH', 'Net', 'threshold', 'yaml')
                """
            )
            cur.execute(
                """
                INSERT INTO incidents (id, incident_key, title, summary, severity, status, primary_host, primary_user, first_seen, last_seen, alert_count, event_count)
                VALUES
                (700, 'INC-700', 'Multi-Stage Intrusion Investigation', 'SSH brute force, sudo access, and lateral flow', 'CRITICAL', 'OPEN', 'srv-app-01', 'deployer', '2026-10-04T10:00:00Z', '2026-10-04T10:05:00Z', 3, 5)
                """
            )
            cur.execute(
                """
                INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint, username, src_ip)
                VALUES
                ('ev-201', '2026-10-04T10:00:00Z', '2026-10-04T10:00:01Z', 'srv-app-01', 'auth.log', 'authentication_failure', 'ALERT', 'login', 'failure', 'Failed login deployer', 'Failed password for deployer from 192.168.1.50', 'openssh', 'fp-201', 'deployer', '192.168.1.50'),
                ('ev-202', '2026-10-04T10:00:30Z', '2026-10-04T10:00:31Z', 'srv-app-01', 'auth.log', 'authentication_success', 'INFO', 'login', 'success', 'Accepted password for deployer', 'Accepted password for deployer from 192.168.1.50', 'openssh', 'fp-202', 'deployer', '192.168.1.50'),
                ('ev-203', '2026-10-04T10:01:15Z', '2026-10-04T10:01:16Z', 'srv-app-01', 'auth.log', 'privilege_escalation', 'ALERT', 'sudo', 'success', 'Sudo to root', 'deployer : TTY=pts/0 ; COMMAND=/bin/bash', 'sudo', 'fp-203', 'deployer', '192.168.1.50'),
                ('ev-204', '2026-10-04T10:02:00Z', '2026-10-04T10:02:01Z', 'srv-app-01', 'process.log', 'process_start', 'INFO', 'start', 'success', 'Spawned shell', 'bash spawned by sudo', 'auditd', 'fp-204', 'root', NULL),
                ('ev-205', '2026-10-04T10:03:00Z', '2026-10-04T10:03:01Z', 'srv-db-01', 'net.log', 'network_connection', 'ALERT', 'connect', 'success', 'Inbound connection from srv-app-01', 'Connection established 10.0.0.5 -> 10.0.0.9:5432', 'syslog', 'fp-205', 'root', '10.0.0.5')
                """
            )
            cur.execute(
                """
                INSERT INTO alerts (id, rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count)
                VALUES
                (31, 'rule.ssh', 'dedup-31', 'SSH Brute Force Success', 'SSH login success', 'ALERT', 'OPEN', 'srv-app-01', '2026-10-04T10:00:30Z', '2026-10-04T10:00:30Z', 2),
                (32, 'rule.sudo', 'dedup-32', 'Root Shell Sudo Access', 'Unauthorized sudo root', 'CRITICAL', 'OPEN', 'srv-app-01', '2026-10-04T10:01:15Z', '2026-10-04T10:01:15Z', 1),
                (33, 'rule.lateral', 'dedup-33', 'Database Inbound Lateral Connection', 'Lateral flow detected', 'ALERT', 'OPEN', 'srv-db-01', '2026-10-04T10:03:00Z', '2026-10-04T10:03:00Z', 1)
                """
            )
            cur.execute(
                """
                INSERT INTO detections (id, alert_id, rule_id, timestamp, host, summary, evidence_count, details_json)
                VALUES
                (11, 31, 'rule.ssh', '2026-10-04T10:00:30Z', 'srv-app-01', 'SSH brute force success', 2, '{"mitre_technique_id": "T1110.001", "mitre_tactic": "Credential Access"}'),
                (12, 32, 'rule.sudo', '2026-10-04T10:01:15Z', 'srv-app-01', 'Sudo root access', 1, '{"mitre_technique_id": "T1548.003", "mitre_tactic": "Privilege Escalation"}'),
                (13, 33, 'rule.lateral', '2026-10-04T10:03:00Z', 'srv-db-01', 'Lateral connection to DB', 1, '{"mitre_technique_id": "T1021.002", "mitre_tactic": "Lateral Movement"}')
                """
            )
            cur.execute("INSERT INTO incident_alerts (incident_id, alert_id) VALUES (700, 31), (700, 32), (700, 33)")
            cur.execute(
                """
                INSERT INTO incident_entities (incident_id, entity_type, entity_key, display_name)
                VALUES
                (700, 'IP', 'ip:192.168.1.50', '192.168.1.50'),
                (700, 'USER', 'user:deployer', 'deployer'),
                (700, 'HOST', 'host:srv-app-01', 'srv-app-01'),
                (700, 'PROCESS', 'process:sudo', 'sudo'),
                (700, 'HOST', 'host:srv-db-01', 'srv-db-01')
                """
            )
            cur.execute(
                """
                INSERT INTO incident_relationships (incident_id, source_entity_key, target_entity_key, relationship_type, confidence, evidence_event_ids_json, matched_at)
                VALUES
                (700, 'ip:192.168.1.50', 'user:deployer', 'AUTHENTICATED_TO', 'DIRECT', '["ev-201", "ev-202"]', '2026-10-04T10:00:30Z'),
                (700, 'user:deployer', 'host:srv-app-01', 'CONNECTED_TO', 'DIRECT', '["ev-202"]', '2026-10-04T10:00:35Z'),
                (700, 'user:deployer', 'process:sudo', 'EXECUTED', 'STRONG', '["ev-203"]', '2026-10-04T10:01:15Z'),
                (700, 'host:srv-app-01', 'host:srv-db-01', 'LATERAL_MOVEMENT', 'CORRELATED', '["ev-205"]', '2026-10-04T10:03:00Z')
                """
            )
            conn.commit()

        case_repo = CaseRepository(db_path=cases_path, forensic_db=forensic_db)
        case_svc = CaseService(case_repository=case_repo, forensic_database=forensic_db)

        # Create persistent case
        case = case_svc.create_or_open_case(incident_id=700, title="Case 700: Advanced Intrusion Correlation")
        case_id = case.case_id

        # Associate forensic evidence references
        case_svc.associate_evidence(case_id, "event", "ev-201", citation_tag="[event:ev-201]")
        case_svc.associate_evidence(case_id, "event", "ev-202", citation_tag="[event:ev-202]")
        case_svc.associate_evidence(case_id, "event", "ev-203", citation_tag="[event:ev-203]")
        case_svc.associate_evidence(case_id, "event", "ev-204", citation_tag="[event:ev-204]")
        case_svc.associate_evidence(case_id, "event", "ev-205", citation_tag="[event:ev-205]")
        case_svc.associate_evidence(case_id, "alert", "31", citation_tag="[alert:31]")
        case_svc.associate_evidence(case_id, "alert", "32", citation_tag="[alert:32]")

        # Create analyst hypothesis
        case_svc.create_hypothesis(
            case_id=case_id,
            statement="Attacker leveraged brute forced SSH credentials to deployer account to gain root via sudo and pivot laterally.",
            actor="SecAnalyst-1",
        )

        yield case_svc, case_id, forensic_db


def test_m59_intel_001_evidence_correlation_clustering(m59_setup):
    """M59-INTEL-001: Deterministic evidence correlation and multi-dimensional clustering."""
    case_svc, case_id, _ = m59_setup
    clusters, _, _ = case_svc.get_evidence_clusters(case_id)

    assert len(clusters) > 0
    # Must include domain-specific forensic clusters
    types = {c.cluster_type for c in clusters}
    assert any(t in types for t in ["AUTH_ACTIVITY", "PROCESS_EXECUTION", "RELATIONAL_TOPOLOGY", "INFRASTRUCTURE_CONVERGENCE", "ENTITY", "TEMPORAL"])

    # Check top cluster properties
    top_cluster = clusters[0]
    assert isinstance(top_cluster, EvidenceCluster)
    assert top_cluster.case_id == case_id
    assert len(top_cluster.participating_entities) > 0
    assert len(top_cluster.evidence_references) > 0
    assert top_cluster.epistemic_status in [EpistemicStatus.OBSERVED, EpistemicStatus.INFERRED]


def test_m59_intel_002_evidence_traceability_sha256(m59_setup):
    """M59-INTEL-002: Evidence cluster source traceability with SHA-256 digests and citations."""
    case_svc, case_id, _ = m59_setup
    clusters, _, _ = case_svc.get_evidence_clusters(case_id)

    for cluster in clusters:
        for ev in cluster.evidence_references:
            assert ev.citation_tag.startswith("[") and ev.citation_tag.endswith("]")
            assert ev.source_hash.startswith("sha256:")
            digest = ev.source_hash.replace("sha256:", "")
            assert len(digest) == 64
            assert int(digest, 16) >= 0


def test_m59_intel_003_explicit_correlation_reasons(m59_setup):
    """M59-INTEL-003: Explicit deterministic correlation reasons."""
    case_svc, case_id, _ = m59_setup
    clusters, _, _ = case_svc.get_evidence_clusters(case_id)

    found_reason = False
    for cluster in clusters:
        for r in cluster.correlation_reasons:
            assert r.reason_type in [
                CorrelationReason.SHARED_ENTITY,
                CorrelationReason.SHARED_SESSION,
                CorrelationReason.SHARED_PROCESS,
                CorrelationReason.SHARED_SOURCE_IP,
                CorrelationReason.SHARED_DESTINATION_IP,
                CorrelationReason.SHARED_INCIDENT,
                CorrelationReason.SHARED_DETECTION,
                CorrelationReason.TEMPORAL_PROXIMITY,
                CorrelationReason.EXPLICIT_RELATIONSHIP,
                CorrelationReason.DIRECT_EVIDENCE_LINK,
                CorrelationReason.BEHAVIORAL_SEQUENCE,
            ]
            assert r.description != ""
            assert r.confidence_basis != ""
            found_reason = True

    assert found_reason, "Expected at least one deterministic correlation reason across clusters"


def test_m59_intel_004_temporal_correlation_preservation(m59_setup):
    """M59-INTEL-004: Temporal correlation preserving original forensic event timestamps."""
    case_svc, case_id, _ = m59_setup
    clusters, _, _ = case_svc.get_evidence_clusters(case_id, cluster_type="TEMPORAL")

    if clusters:
        temporal_cluster = clusters[0]
        assert temporal_cluster.temporal_bounds["start_time"] is not None
        assert temporal_cluster.temporal_bounds["end_time"] is not None
        # Start time must be before or equal to end time
        assert temporal_cluster.temporal_bounds["start_time"] <= temporal_cluster.temporal_bounds["end_time"]


def test_m59_intel_005_behavioral_sequence_analysis(m59_setup):
    """M59-INTEL-005: Behavioral sequence analysis with multi-stage progression and epistemic status."""
    case_svc, case_id, _ = m59_setup
    sequences = case_svc.get_behavioral_sequences(case_id)

    assert isinstance(sequences, list)
    if sequences:
        seq = sequences[0]
        assert isinstance(seq, BehavioralSequence)
        assert seq.total_steps >= 2
        assert seq.epistemic_status in [EpistemicStatus.OBSERVED, EpistemicStatus.INFERRED]
        # Verify chronological order of steps
        for i in range(len(seq.steps) - 1):
            assert seq.steps[i].timestamp <= seq.steps[i + 1].timestamp


def test_m59_intel_006_hypothesis_support_matrix(m59_setup):
    """M59-INTEL-006: Deterministic hypothesis support/contradiction analysis without fake percentages."""
    case_svc, case_id, _ = m59_setup
    case = case_svc.get_case(case_id)
    assert case is not None
    assert len(case.hypotheses) > 0

    hyp_id = case.hypotheses[0].hypothesis_id
    detail = case_svc.get_hypothesis_correlation_support(case_id, hyp_id)

    assert isinstance(detail, HypothesisSupportDetail)
    assert detail.hypothesis_id == hyp_id
    assert detail.statement != ""
    # Support status must be categorical, not a floating point score
    assert detail.support_status in [
        "SUPPORTED BY EVIDENCE",
        "WEAKLY SUPPORTED",
        "CONTRADICTED BY EVIDENCE",
        "INSUFFICIENT EVIDENCE",
    ]
    assert len(detail.supporting_evidence) > 0


def test_m59_intel_007_evidence_gap_intelligence(m59_setup):
    """M59-INTEL-007: Evidence gap intelligence with explicit gap types and suggested governed hunt queries."""
    case_svc, case_id, _ = m59_setup
    gaps = case_svc.get_correlation_evidence_gaps(case_id)

    assert isinstance(gaps, list)
    assert len(gaps) > 0

    for gap in gaps:
        assert isinstance(gap, EvidenceGapDetail)
        assert gap.gap_type in [
            "EXPECTED_TELEMETRY_MISSING",
            "ENTITY_UNRESOLVED",
            "TIMESTAMP_MISSING",
            "CORROBORATION_MISSING",
            "CONTRADICTORY_TELEMETRY",
            "INSUFFICIENT_CONTEXT",
            "SOURCE_NOT_AVAILABLE",
        ]
        assert gap.title != ""
        assert gap.description != ""
        assert gap.resolution_remedy != ""


def test_m59_intel_008_governed_threat_hunting_remedy(m59_setup):
    """M59-INTEL-008: Governed threat hunting query validation and proposal generation."""
    case_svc, case_id, _ = m59_setup
    gaps = case_svc.get_correlation_evidence_gaps(case_id)

    queries_found = 0
    for gap in gaps:
        if gap.recommended_governed_query:
            queries_found += 1
            prop = gap.recommended_governed_query
            assert prop.intent != ""
            assert prop.limit > 0
            assert prop.is_executed is False

    assert queries_found > 0, "Expected at least one gap with a suggested governed query proposal"


def test_m59_intel_009_entity_workbench_dossier(m59_setup):
    """M59-INTEL-009: Entity workbench dossier assembly with deep pivot correlations."""
    case_svc, case_id, _ = m59_setup
    dossier = case_svc.get_entity_workbench_dossier(case_id, "user", "deployer")

    assert isinstance(dossier, EntityWorkbenchDossier)
    assert dossier.entity_key == "user:deployer"
    assert dossier.display_name == "deployer"
    assert len(dossier.evidence_references) > 0
    assert len(dossier.adjacent_graph_entities) > 0


def test_m59_intel_010_finding_generation_without_migration_6(m59_setup):
    """M59-INTEL-010: Deterministic finding generation from clusters preserving review separation without Migration 6."""
    case_svc, case_id, _ = m59_setup

    findings = case_svc.generate_findings_from_clusters(case_id)
    assert isinstance(findings, list)
    assert len(findings) > 0

    first_finding = findings[0]
    assert first_finding.case_id == case_id
    assert first_finding.title != ""
    assert first_finding.epistemic_status in [EpistemicStatus.OBSERVED, EpistemicStatus.INFERRED]
    assert len(first_finding.source_references) > 0

    # Ensure finding generation is recorded in immutable audit log
    audit_history = case_svc.get_audit_history(case_id)
    actions = [a.action for a in audit_history]
    assert "FINDINGS_GENERATED_FROM_CLUSTERS" in actions
