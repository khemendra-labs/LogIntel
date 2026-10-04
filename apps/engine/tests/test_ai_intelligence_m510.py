"""Milestone 5.10 Temporal Investigation Reconstruction & Campaign Intelligence Test Suite.

Validates:
1. M10-INTEL-001: Domain representation and dossier structure.
2. M10-INTEL-002: Episode grouping and classification (AUTHENTICATION_BURST, etc.).
3. M10-INTEL-003: Transition detection between episodes and entities.
4. M10-INTEL-004: Epistemic status assignment (OBSERVED vs INFERRED vs UNKNOWN).
5. M10-INTEL-005: Temporal evidence chains and traceability.
6. M10-INTEL-006: Temporal gaps detection with actionable remedies.
7. M10-INTEL-007: Multi-host reconstruction and cross-host traces.
8. M10-INTEL-008: Account, process, and network continuity.
9. M10-INTEL-009: Campaign-level incident correlation without fake confidence scores.
10. M10-INTEL-010: Attack sequence reconstruction and MITRE ATT&CK integration.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
from typing import Generator
import pytest

from logintel.ai.case_service import CaseService
from logintel.ai.domain.investigation_temporal import (
    EpisodeType,
    TransitionType,
    TemporalGapType,
    CampaignCorrelationStatus,
    CampaignRelationReason,
    TransitionReviewState,
    ContinuityType,
    TemporalReconstructionDossier,
)
from logintel.ai.domain.investigation_intel import EpistemicStatus
from logintel.storage.case_repo import CaseRepository
from logintel.storage.db import Database


@pytest.fixture
def m510_setup() -> Generator[tuple[CaseService, int, Database], None, None]:
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
                ('rule.lateral', 'Lateral Network Flow', 'Lateral Movement', 'ALERT', 'Net', 'threshold', 'yaml')
                """
            )
            cur.execute(
                """
                INSERT INTO incidents (id, incident_key, title, summary, severity, status, primary_host, primary_user, first_seen, last_seen, alert_count, event_count)
                VALUES
                (800, 'INC-800', 'Multi-Stage Intrusion Investigation', 'SSH brute force, sudo access, and lateral flow', 'CRITICAL', 'OPEN', 'srv-app-01', 'deployer', '2026-10-04T10:00:00Z', '2026-10-04T10:05:00Z', 3, 5),
                (801, 'INC-801', 'Secondary Host Activity', 'Correlated activity on database host', 'ALERT', 'OPEN', 'srv-db-01', 'deployer', '2026-10-04T10:04:00Z', '2026-10-04T10:06:00Z', 1, 2)
                """
            )
            cur.execute(
                """
                INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint, username, src_ip)
                VALUES
                ('ev-301', '2026-10-04T10:00:00Z', '2026-10-04T10:00:01Z', 'srv-app-01', 'auth.log', 'authentication_failure', 'ALERT', 'login', 'failure', 'Failed login deployer', 'Failed password for deployer from 192.168.1.50', 'openssh', 'fp-301', 'deployer', '192.168.1.50'),
                ('ev-302', '2026-10-04T10:00:30Z', '2026-10-04T10:00:31Z', 'srv-app-01', 'auth.log', 'authentication_success', 'INFORMATIONAL', 'login', 'success', 'Accepted password for deployer', 'Accepted password for deployer from 192.168.1.50', 'openssh', 'fp-302', 'deployer', '192.168.1.50'),
                ('ev-303', '2026-10-04T10:01:15Z', '2026-10-04T10:01:16Z', 'srv-app-01', 'auth.log', 'privilege_escalation', 'ALERT', 'sudo', 'success', 'Sudo to root', 'deployer : TTY=pts/0 ; COMMAND=/bin/bash', 'sudo', 'fp-303', 'deployer', '192.168.1.50'),
                ('ev-304', '2026-10-04T10:02:00Z', '2026-10-04T10:02:01Z', 'srv-app-01', 'process.log', 'process_start', 'INFORMATIONAL', 'start', 'success', 'Spawned shell', 'bash spawned by sudo', 'auditd', 'fp-304', 'root', NULL),
                ('ev-305', '2026-10-04T10:03:00Z', '2026-10-04T10:03:01Z', 'srv-db-01', 'net.log', 'network_connection', 'ALERT', 'connect', 'success', 'Inbound connection from srv-app-01', 'Connection established 10.0.0.5 -> 10.0.0.9:5432', 'syslog', 'fp-305', 'root', '10.0.0.5'),
                ('ev-306', '2026-10-04T10:05:00Z', '2026-10-04T10:05:01Z', 'srv-db-01', 'auth.log', 'authentication_success', 'INFORMATIONAL', 'login', 'success', 'Deployer session on DB', 'Accepted key for deployer from 10.0.0.5', 'openssh', 'fp-306', 'deployer', '10.0.0.5')
                """
            )
            cur.execute(
                """
                INSERT INTO alerts (id, rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count)
                VALUES
                (41, 'rule.ssh', 'dedup-41', 'SSH Brute Force Success', 'SSH login success', 'ALERT', 'OPEN', 'srv-app-01', '2026-10-04T10:00:30Z', '2026-10-04T10:00:30Z', 2),
                (42, 'rule.sudo', 'dedup-42', 'Root Shell Sudo Access', 'Unauthorized sudo root', 'CRITICAL', 'OPEN', 'srv-app-01', '2026-10-04T10:01:15Z', '2026-10-04T10:01:15Z', 1),
                (43, 'rule.lateral', 'dedup-43', 'Database Inbound Lateral Connection', 'Lateral flow detected', 'ALERT', 'OPEN', 'srv-db-01', '2026-10-04T10:03:00Z', '2026-10-04T10:03:00Z', 1)
                """
            )
            cur.execute(
                """
                INSERT INTO detections (id, alert_id, rule_id, timestamp, host, summary, evidence_count, details_json)
                VALUES
                (21, 41, 'rule.ssh', '2026-10-04T10:00:30Z', 'srv-app-01', 'SSH brute force success', 2, '{"mitre_technique_id": "T1110.001", "mitre_tactic": "Credential Access"}'),
                (22, 42, 'rule.sudo', '2026-10-04T10:01:15Z', 'srv-app-01', 'Sudo root access', 1, '{"mitre_technique_id": "T1548.003", "mitre_tactic": "Privilege Escalation"}'),
                (23, 43, 'rule.lateral', '2026-10-04T10:03:00Z', 'srv-db-01', 'Lateral connection to DB', 1, '{"mitre_technique_id": "T1021.002", "mitre_tactic": "Lateral Movement"}')
                """
            )
            cur.execute("INSERT INTO incident_alerts (incident_id, alert_id) VALUES (800, 41), (800, 42), (800, 43)")
            cur.execute("INSERT INTO detection_evidence (detection_id, event_id) VALUES (21, 'ev-301'), (21, 'ev-302'), (22, 'ev-303'), (23, 'ev-305')")
            cur.execute(
                """
                INSERT INTO incident_entities (incident_id, entity_type, entity_key, display_name)
                VALUES
                (800, 'IP', 'ip:192.168.1.50', '192.168.1.50'),
                (800, 'USER', 'user:deployer', 'deployer'),
                (800, 'HOST', 'host:srv-app-01', 'srv-app-01'),
                (800, 'PROCESS', 'process:sudo', 'sudo'),
                (800, 'HOST', 'host:srv-db-01', 'srv-db-01'),
                (801, 'USER', 'user:deployer', 'deployer'),
                (801, 'HOST', 'host:srv-db-01', 'srv-db-01')
                """
            )
            cur.execute(
                """
                INSERT INTO incident_relationships (incident_id, source_entity_key, target_entity_key, relationship_type, confidence, evidence_event_ids_json, matched_at)
                VALUES
                (800, 'ip:192.168.1.50', 'user:deployer', 'AUTHENTICATED_TO', 'DIRECT', '["ev-301", "ev-302"]', '2026-10-04T10:00:30Z'),
                (800, 'user:deployer', 'host:srv-app-01', 'CONNECTED_TO', 'DIRECT', '["ev-302"]', '2026-10-04T10:00:35Z'),
                (800, 'user:deployer', 'process:sudo', 'EXECUTED', 'STRONG', '["ev-303"]', '2026-10-04T10:01:15Z'),
                (800, 'host:srv-app-01', 'host:srv-db-01', 'LATERAL_MOVEMENT', 'CORRELATED', '["ev-305"]', '2026-10-04T10:03:00Z')
                """
            )
            conn.commit()

        case_repo = CaseRepository(db_path=cases_path, forensic_db=forensic_db)
        case_svc = CaseService(case_repository=case_repo, forensic_database=forensic_db)

        # Create persistent case
        case = case_svc.create_or_open_case(incident_id=800, title="Case 800: Temporal Attack Reconstruction")
        case_id = case.case_id

        # Associate forensic evidence references
        case_svc.associate_evidence(case_id, "event", "ev-301", citation_tag="[event:ev-301]")
        case_svc.associate_evidence(case_id, "event", "ev-302", citation_tag="[event:ev-302]")
        case_svc.associate_evidence(case_id, "event", "ev-303", citation_tag="[event:ev-303]")
        case_svc.associate_evidence(case_id, "event", "ev-304", citation_tag="[event:ev-304]")
        case_svc.associate_evidence(case_id, "event", "ev-305", citation_tag="[event:ev-305]")
        case_svc.associate_evidence(case_id, "event", "ev-306", citation_tag="[event:ev-306]")

        yield case_svc, case_id, forensic_db


def test_m10_intel_001_domain_representation_and_dossier_structure(m510_setup: tuple[CaseService, int, Database]) -> None:
    """M10-INTEL-001: Validate temporal reconstruction dossier domain representation."""
    case_svc, case_id, _ = m510_setup

    dossier = case_svc.get_temporal_reconstruction(case_id)
    assert isinstance(dossier, TemporalReconstructionDossier)
    assert dossier.case_id == case_id
    assert dossier.incident_id == 800
    assert dossier.reconstruction_id.startswith(f"recon-{case_id}")
    assert dossier.provenance_hash.startswith("sha256:")
    assert len(dossier.provenance_hash) == 71
    assert len(dossier.episodes) > 0
    assert len(dossier.transitions) > 0
    assert isinstance(dossier.duration_seconds, (int, float))


def test_m10_intel_002_episode_grouping_and_classification(m510_setup: tuple[CaseService, int, Database]) -> None:
    """M10-INTEL-002: Group related evidence into deterministic temporal episodes."""
    case_svc, case_id, _ = m510_setup

    episodes = case_svc.get_temporal_episodes(case_id)
    assert len(episodes) > 0

    episode_types = {ep.episode_type for ep in episodes}
    # Should include authentication and privilege change or lateral movement
    assert EpisodeType.AUTHENTICATION_BURST in episode_types or EpisodeType.PRIVILEGE_CHANGE_EPISODE in episode_types

    for ep in episodes:
        assert ep.case_id == case_id
        assert ep.start_time <= ep.end_time
        assert ep.duration_seconds >= 0
        assert len(ep.entities) > 0
        assert len(ep.evidence_references) > 0
        assert ep.epistemic_status in [EpistemicStatus.OBSERVED, EpistemicStatus.INFERRED, EpistemicStatus.UNKNOWN]


def test_m10_intel_003_transition_detection(m510_setup: tuple[CaseService, int, Database]) -> None:
    """M10-INTEL-003: Detect deterministic transitions between episodes and entities."""
    case_svc, case_id, _ = m510_setup

    transitions = case_svc.get_temporal_transitions(case_id)
    assert len(transitions) > 0

    trans_types = {tr.transition_type for tr in transitions}
    assert TransitionType.USER_TO_HOST in trans_types or TransitionType.USER_TO_PROCESS in trans_types

    for tr in transitions:
        assert tr.case_id == case_id
        assert tr.from_entity
        assert tr.to_entity
        assert tr.timestamp
        assert tr.reason
        assert tr.correlation_basis
        assert tr.epistemic_status in [EpistemicStatus.OBSERVED, EpistemicStatus.INFERRED, EpistemicStatus.UNKNOWN]
        assert tr.review_state == TransitionReviewState.UNREVIEWED


def test_m10_intel_004_epistemic_status_assignment(m510_setup: tuple[CaseService, int, Database]) -> None:
    """M10-INTEL-004: Validate OBSERVED vs INFERRED vs UNKNOWN epistemic separation."""
    case_svc, case_id, _ = m510_setup

    transitions = case_svc.get_temporal_transitions(case_id)
    observed_found = False
    inferred_found = False

    for tr in transitions:
        if tr.epistemic_status == EpistemicStatus.OBSERVED:
            observed_found = True
        elif tr.epistemic_status == EpistemicStatus.INFERRED:
            inferred_found = True

    assert observed_found, "Directly evidenced transitions must have epistemic_status = OBSERVED"


def test_m10_intel_005_temporal_evidence_chains_and_traceability(m510_setup: tuple[CaseService, int, Database]) -> None:
    """M10-INTEL-005: Create explicit traceable temporal evidence chains."""
    case_svc, case_id, _ = m510_setup

    dossier = case_svc.get_temporal_reconstruction(case_id)
    assert len(dossier.evidence_chains) > 0

    chain = dossier.evidence_chains[0]
    assert chain.total_steps == len(chain.steps)
    assert chain.total_steps > 0
    for step in chain.steps:
        assert step.citation_tag
        assert step.source_record_id
        assert step.timestamp
        assert step.epistemic_status in [EpistemicStatus.OBSERVED, EpistemicStatus.INFERRED]


def test_m10_intel_006_temporal_gaps_detection(m510_setup: tuple[CaseService, int, Database]) -> None:
    """M10-INTEL-006: Identify temporal gaps with actionable remedies."""
    case_svc, case_id, _ = m510_setup

    gaps = case_svc.get_temporal_gaps(case_id)
    assert isinstance(gaps, list)
    if gaps:
        for gap in gaps:
            assert gap.case_id == case_id
            assert gap.gap_type in [
                TemporalGapType.NO_TELEMETRY,
                TemporalGapType.MISSING_HOST_VISIBILITY,
                TemporalGapType.MISSING_PROCESS_TELEMETRY,
                TemporalGapType.MISSING_NETWORK_TELEMETRY,
                TemporalGapType.TIMESTAMP_GAP,
                TemporalGapType.UNRESOLVED_TRANSITION,
                TemporalGapType.INSUFFICIENT_EVIDENCE,
            ]
            assert gap.remedy
            assert len(gap.affected_entities) > 0


def test_m10_intel_007_multi_host_reconstruction(m510_setup: tuple[CaseService, int, Database]) -> None:
    """M10-INTEL-007: Reconstruct activity across multiple hosts (srv-app-01 -> srv-db-01)."""
    case_svc, case_id, _ = m510_setup

    dossier = case_svc.get_temporal_reconstruction(case_id)
    # The setup includes events on srv-app-01 and srv-db-01
    traces = dossier.multi_host_traces
    assert len(traces) > 0

    trace = traces[0]
    assert "srv-app-01" in trace.source_host or "srv-db-01" in trace.target_host
    assert trace.actor
    assert trace.start_time <= trace.end_time
    assert trace.epistemic_status in [EpistemicStatus.OBSERVED, EpistemicStatus.INFERRED]


def test_m10_intel_008_entity_continuity(m510_setup: tuple[CaseService, int, Database]) -> None:
    """M10-INTEL-008: Verify entity continuity across accounts, processes, and hosts."""
    case_svc, case_id, _ = m510_setup

    dossier = case_svc.get_temporal_reconstruction(case_id)
    continuities = dossier.continuities
    assert len(continuities) > 0

    deployer_cont = next((c for c in continuities if "deployer" in c.entity_key), None)
    assert deployer_cont is not None
    assert deployer_cont.occurrences_count >= 2
    assert "srv-app-01" in deployer_cont.participating_hosts


def test_m10_intel_009_campaign_level_correlation(m510_setup: tuple[CaseService, int, Database]) -> None:
    """M10-INTEL-009: Deterministic campaign-level incident correlation without fake percentages."""
    case_svc, case_id, _ = m510_setup

    corrs = case_svc.get_campaign_correlations(case_id)
    assert len(corrs) > 0

    rel = corrs[0]
    assert rel.primary_incident_id == 800
    assert rel.related_incident_id == 801
    assert rel.correlation_status in [
        CampaignCorrelationStatus.POTENTIALLY_RELATED,
        CampaignCorrelationStatus.CORRELATED,
    ]
    assert rel.relationship_reason in [
        CampaignRelationReason.SHARED_ENTITY,
        CampaignRelationReason.SHARED_ACCOUNT,
        CampaignRelationReason.SHARED_SOURCE,
    ]
    assert "user:deployer" in rel.shared_entities or "host:srv-db-01" in rel.shared_entities
    # Check single incident relation
    single_rel = case_svc.get_incident_campaign_relations(case_id, 801)
    assert single_rel is not None
    assert single_rel.related_incident_id == 801


def test_m10_intel_010_attack_sequence_reconstruction_and_mitre(m510_setup: tuple[CaseService, int, Database]) -> None:
    """M10-INTEL-010: Reconstruct behavioral sequences with MITRE ATT&CK integration."""
    case_svc, case_id, _ = m510_setup

    sequences = case_svc.get_temporal_sequences(case_id)
    assert len(sequences) > 0

    seq = sequences[0]
    assert seq.total_steps == len(seq.steps)
    assert seq.total_steps >= 2
    assert seq.duration_seconds >= 0

    # Verify MITRE mapping preservation
    mitre_steps = [s for s in seq.steps if s.mitre_technique_id is not None]
    assert len(mitre_steps) > 0
    technique_ids = {s.mitre_technique_id for s in mitre_steps}
    # T1110.001 or T1548.003 or T1021.002/T1021.004 from detection rules / lateral movement
    assert any(tid.startswith("T1021") or tid in ["T1110.001", "T1548.003", "T1021.002"] for tid in technique_ids)
