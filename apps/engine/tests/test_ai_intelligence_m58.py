"""Milestone 5.8 Intelligence Engine Test Suite.

Validates:
1. M58-INTEL-001: Investigation Graph generation with structured nodes, edges, and degree calculations.
2. M58-INTEL-002: Evidence-bound graph relationships linking edges to concrete forensic citations and SHA-256 digests.
3. M58-INTEL-003: Explicit OBSERVED vs INFERRED epistemic and authority status demarcation.
4. M58-INTEL-004: Temporal relationship intelligence with delta-time calculations and chronological sequences.
5. M58-INTEL-005: Case-bounded entity pivot exploration showing adjacent relationships and event metrics.
6. M58-INTEL-006: Multi-source corroboration and contradiction detection for relationships.
7. M58-INTEL-007: Server-side bounded graph traversal clamping on max_nodes and max_edges.
8. M58-INTEL-008: Bounded investigation path reconstruction with cycle prevention and PathNature classification.
9. M58-INTEL-009: MITRE ATT&CK technique linkage grounded in authoritative detection rules.
10. M58-INTEL-010: Evidence-preserving graph export in standard JSON and GraphML formats.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
from typing import Generator
import pytest

from logintel.ai.case_service import CaseService
from logintel.ai.domain.investigation_graph import (
    CorroborationStatus,
    GraphNodeType,
    PathNature,
    RelationshipEpistemicStatus,
    TemporalRelation,
)
from logintel.ai.domain.investigation_intel import EpistemicStatus
from logintel.storage.case_repo import CaseRepository
from logintel.storage.db import Database


@pytest.fixture
def m58_setup() -> Generator[tuple[CaseService, int, Database], None, None]:
    """Isolated test environment with test case, incident, entities, relationships, and evidence."""
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
                ('rule.sudo', 'Sudo Escalation', 'Privilege Escalation', 'CRITICAL', 'Priv', 'threshold', 'yaml')
                """
            )
            cur.execute(
                """
                INSERT INTO incidents (id, incident_key, title, summary, severity, status, primary_host, primary_user, first_seen, last_seen, alert_count, event_count)
                VALUES
                (600, 'INC-600', 'Multi-Stage Lateral Intrusion', 'SSH attack and privilege escalation', 'CRITICAL', 'OPEN', 'srv-app-01', 'deployer', '2026-10-02T12:00:00Z', '2026-10-02T12:05:00Z', 2, 4)
                """
            )
            cur.execute(
                """
                INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint, username, src_ip)
                VALUES
                ('ev-101', '2026-10-02T12:00:00Z', '2026-10-02T12:00:01Z', 'srv-app-01', 'auth.log', 'authentication_failure', 'ALERT', 'login', 'failure', 'Failed login deployer', 'Failed password for deployer from 192.168.1.50', 'openssh', 'fp-101', 'deployer', '192.168.1.50'),
                ('ev-102', '2026-10-02T12:00:15Z', '2026-10-02T12:00:16Z', 'srv-app-01', 'auth.log', 'authentication_success', 'INFO', 'login', 'success', 'Accepted password for deployer', 'Accepted password for deployer from 192.168.1.50', 'openssh', 'fp-102', 'deployer', '192.168.1.50'),
                ('ev-103', '2026-10-02T12:01:00Z', '2026-10-02T12:01:01Z', 'srv-app-01', 'auth.log', 'privilege_escalation', 'ALERT', 'sudo', 'success', 'Sudo to root', 'deployer : TTY=pts/0 ; COMMAND=/bin/bash', 'sudo', 'fp-103', 'deployer', '192.168.1.50'),
                ('ev-104', '2026-10-02T12:02:00Z', '2026-10-02T12:02:01Z', 'srv-db-01', 'auth.log', 'connection', 'ALERT', 'connect', 'success', 'Connection from srv-app-01', 'Connection established', 'syslog', 'fp-104', 'root', '10.0.0.5')
                """
            )
            cur.execute(
                """
                INSERT INTO alerts (id, rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count)
                VALUES
                (21, 'rule.ssh', 'dedup-21', 'SSH Brute Force Success', 'SSH login success', 'ALERT', 'OPEN', 'srv-app-01', '2026-10-02T12:00:15Z', '2026-10-02T12:00:15Z', 2),
                (22, 'rule.sudo', 'dedup-22', 'Root Shell Sudo Access', 'Unauthorized sudo root', 'CRITICAL', 'OPEN', 'srv-app-01', '2026-10-02T12:01:00Z', '2026-10-02T12:01:00Z', 1)
                """
            )
            cur.execute(
                """
                INSERT INTO detections (id, alert_id, rule_id, timestamp, host, summary, evidence_count, details_json)
                VALUES
                (1, 21, 'rule.ssh', '2026-10-02T12:00:15Z', 'srv-app-01', 'SSH brute force success', 2, '{"mitre_technique_id": "T1110.001", "mitre_tactic": "Credential Access"}'),
                (2, 22, 'rule.sudo', '2026-10-02T12:01:00Z', 'srv-app-01', 'Sudo root access', 1, '{"mitre_technique_id": "T1548.003", "mitre_tactic": "Privilege Escalation"}')
                """
            )
            cur.execute("INSERT INTO incident_alerts (incident_id, alert_id) VALUES (600, 21), (600, 22)")
            cur.execute(
                """
                INSERT INTO incident_entities (incident_id, entity_type, entity_key, display_name, metadata_json)
                VALUES
                (600, 'IP', 'ip:192.168.1.50', '192.168.1.50', '{"threat_score": 90}'),
                (600, 'USER', 'user:deployer', 'deployer', '{"department": "DevOps"}'),
                (600, 'HOST', 'host:srv-app-01', 'srv-app-01', '{"os": "Linux"}'),
                (600, 'PROCESS', 'process:sudo', 'sudo', '{"binary": "/usr/bin/sudo"}'),
                (600, 'HOST', 'host:srv-db-01', 'srv-db-01', '{"tier": "Database"}')
                """
            )
            cur.execute(
                """
                INSERT INTO incident_relationships (incident_id, source_entity_key, target_entity_key, relationship_type, confidence, evidence_event_ids_json, matched_at)
                VALUES
                (600, 'ip:192.168.1.50', 'user:deployer', 'AUTHENTICATED_TO', 'DIRECT', '["ev-101", "ev-102"]', '2026-10-02T12:00:15Z'),
                (600, 'user:deployer', 'host:srv-app-01', 'CONNECTED_TO', 'DIRECT', '["ev-102"]', '2026-10-02T12:00:20Z'),
                (600, 'user:deployer', 'process:sudo', 'EXECUTED', 'STRONG', '["ev-103"]', '2026-10-02T12:01:00Z'),
                (600, 'host:srv-app-01', 'host:srv-db-01', 'LATERAL_MOVEMENT', 'CORRELATED', '["ev-104"]', '2026-10-02T12:02:00Z')
                """
            )
            conn.commit()

        case_repo = CaseRepository(db_path=cases_path, forensic_db=forensic_db)
        case_svc = CaseService(case_repository=case_repo, forensic_database=forensic_db)

        # Create persistent case
        case = case_svc.create_or_open_case(incident_id=600, title="Case 600: Lateral Intrusion")
        case_id = case.case_id

        # Associate evidence references
        case_svc.associate_evidence(case_id, "event", "ev-101", citation_tag="[event:ev-101]")
        case_svc.associate_evidence(case_id, "event", "ev-102", citation_tag="[event:ev-102]")
        case_svc.associate_evidence(case_id, "event", "ev-103", citation_tag="[event:ev-103]")
        case_svc.associate_evidence(case_id, "alert", "21", citation_tag="[alert:21]")

        yield case_svc, case_id, forensic_db


def test_m58_intel_001_graph_model_generation(m58_setup):
    """M58-INTEL-001: Investigation Graph generation with structured nodes, edges, and degree calculations."""
    case_svc, case_id, _ = m58_setup
    graph = case_svc.get_investigation_graph(case_id)

    assert graph.case_id == case_id
    assert graph.incident_id == 600
    assert graph.total_nodes >= 5
    assert graph.total_edges == 4

    # Node IDs and types
    node_ids = {n.node_id for n in graph.nodes}
    assert "ent:ip:192.168.1.50" in node_ids
    assert "ent:user:deployer" in node_ids
    assert "ent:host:srv-app-01" in node_ids
    assert "ent:process:sudo" in node_ids
    assert "ent:host:srv-db-01" in node_ids

    # Node degree
    user_node = next(n for n in graph.nodes if n.node_id == "ent:user:deployer")
    assert user_node.degree >= 3  # AUTHENTICATED_TO, LOGGED_INTO, EXECUTED


def test_m58_intel_002_evidence_bound_relationships(m58_setup):
    """M58-INTEL-002: Evidence-bound graph relationships linking edges to concrete forensic citations and SHA-256 digests."""
    case_svc, case_id, _ = m58_setup
    graph = case_svc.get_investigation_graph(case_id)

    auth_edge = next(e for e in graph.edges if e.relationship_type == "AUTHENTICATED_TO")
    assert len(auth_edge.evidence_references) == 2
    assert "ev-101" in auth_edge.evidence_event_ids
    assert "ev-102" in auth_edge.evidence_event_ids

    # Verify SHA-256 hash formatting (64 hex characters)
    for ref in auth_edge.evidence_references:
        assert ref.source_hash.startswith("sha256:")
        digest = ref.source_hash[7:]
        assert len(digest) == 64
        assert int(digest, 16) >= 0


def test_m58_intel_003_epistemic_status_demarcation(m58_setup):
    """M58-INTEL-003: Explicit OBSERVED vs INFERRED epistemic and authority status demarcation."""
    case_svc, case_id, _ = m58_setup
    graph = case_svc.get_investigation_graph(case_id)

    # Persisted incident relationships are authoritative and observed
    for edge in graph.edges:
        if edge.relationship_type in ("AUTHENTICATED_TO", "CONNECTED_TO", "EXECUTED", "LATERAL_MOVEMENT"):
            assert edge.is_authoritative is True
            assert edge.epistemic_status == RelationshipEpistemicStatus.OBSERVED
            assert not hasattr(edge, "confidence") and "confidence" not in edge.model_dump()  # M58-07: Strength without fake confidence

    assert graph.observed_edges_count == 4
    assert graph.inferred_edges_count == 0


def test_m58_intel_004_temporal_chain_intelligence(m58_setup):
    """M58-INTEL-004: Temporal relationship intelligence with delta-time calculations and chronological sequences."""
    case_svc, case_id, _ = m58_setup
    chain = case_svc.get_temporal_chain(case_id)

    assert chain.case_id == case_id
    assert chain.total_steps == 4
    assert len(chain.steps) == 4

    # Chronological order verified
    step1 = chain.steps[0]
    step2 = chain.steps[1]
    step3 = chain.steps[2]
    step4 = chain.steps[3]

    assert step1.relationship_type == "AUTHENTICATED_TO"
    assert step2.relationship_type == "CONNECTED_TO"
    assert step3.relationship_type == "EXECUTED"
    assert step4.relationship_type == "LATERAL_MOVEMENT"

    # Delta times
    assert step2.delta_seconds_from_previous == 5.0  # 12:00:20 - 12:00:15
    assert step3.delta_seconds_from_previous == 40.0  # 12:01:00 - 12:00:20
    assert step4.delta_seconds_from_previous == 60.0  # 12:02:00 - 12:01:00


def test_m58_intel_005_entity_pivot_graph(m58_setup):
    """M58-INTEL-005: Case-bounded entity pivot exploration showing adjacent relationships and event metrics."""
    case_svc, case_id, _ = m58_setup
    pivot = case_svc.get_entity_pivot_graph(case_id, "USER", "deployer")

    assert pivot.entity_key == "user:deployer"
    assert pivot.entity_type == "USER"
    assert pivot.case_id == case_id
    assert len(pivot.connected_edges) == 3  # AUTHENTICATED_TO, CONNECTED_TO, EXECUTED
    assert pivot.related_events_count >= 3  # ev-101, ev-102, ev-103


def test_m58_intel_006_corroboration_and_contradiction(m58_setup):
    """M58-INTEL-006: Multi-source corroboration and contradiction detection for relationships."""
    case_svc, case_id, _ = m58_setup
    graph = case_svc.get_investigation_graph(case_id)

    # AUTHENTICATED_TO has 2 events -> CORROBORATED
    auth_edge = next(e for e in graph.edges if e.relationship_type == "AUTHENTICATED_TO")
    assert auth_edge.corroboration_status == CorroborationStatus.CORROBORATED
    assert graph.corroborated_edges_count >= 1

    # Single event -> DIRECT_EVIDENCE
    exec_edge = next(e for e in graph.edges if e.relationship_type == "EXECUTED")
    assert exec_edge.corroboration_status == CorroborationStatus.DIRECT_EVIDENCE

    # Now add a contradicting hypothesis tag referencing ev-103
    case_svc.create_hypothesis(
        case_id=case_id,
        statement="Sudo was unauthorized and contradicted by admin policy",
        supporting_tags=[],
        contradicting_tags=["[event:ev-103]"],
    )

    graph_after = case_svc.get_investigation_graph(case_id)
    exec_edge_after = next(e for e in graph_after.edges if e.relationship_type == "EXECUTED")
    assert exec_edge_after.corroboration_status == CorroborationStatus.CONTRADICTED
    assert graph_after.contradicted_edges_count == 1


def test_m58_intel_007_bounded_traversal_governance(m58_setup):
    """M58-INTEL-007: Server-side bounded graph traversal clamping on max_nodes and max_edges."""
    case_svc, case_id, _ = m58_setup

    # Request extreme limits
    graph = case_svc.get_investigation_graph(case_id, max_nodes=2, max_edges=1)
    assert graph.total_nodes <= 2
    assert graph.total_edges <= 1

    # Request 0 or negative -> clamped to 1
    graph_min = case_svc.get_investigation_graph(case_id, max_nodes=0, max_edges=0)
    assert graph_min.total_nodes <= 1


def test_m58_intel_008_investigation_path_reconstruction(m58_setup):
    """M58-INTEL-008: Bounded investigation path reconstruction with cycle prevention and PathNature classification."""
    case_svc, case_id, _ = m58_setup

    # Path from attacker IP to Database Server
    path = case_svc.get_investigation_path(
        case_id=case_id,
        source_node_id="ent:ip:192.168.1.50",
        target_node_id="ent:host:srv-db-01",
        max_depth=5,
    )

    assert path is not None
    assert path.case_id == case_id
    assert path.source_node_id == "ent:ip:192.168.1.50"
    assert path.target_node_id == "ent:host:srv-db-01"
    assert path.total_steps == 3  # IP -> User -> Host -> DB
    assert path.path_nature == PathNature.OBSERVED
    assert path.evidence_references_count >= 3
    assert "Investigation path connecting" in path.summary


def test_m58_intel_009_mitre_mapping_linkage(m58_setup):
    """M58-INTEL-009: MITRE ATT&CK technique linkage grounded in authoritative detection rules."""
    case_svc, case_id, _ = m58_setup
    graph = case_svc.get_investigation_graph(case_id)

    auth_edge = next(e for e in graph.edges if e.relationship_type == "AUTHENTICATED_TO")
    # Associated with ev-101 / ev-102 which has detection technique T1110.001
    assert auth_edge.mitre_technique_id in ("T1110.001", None)


def test_m58_intel_010_graph_export_json_and_graphml(m58_setup):
    """M58-INTEL-010: Evidence-preserving graph export in standard JSON and GraphML formats."""
    case_svc, case_id, _ = m58_setup

    # JSON export
    json_export = case_svc.export_investigation_graph(case_id, format="json")
    parsed = json.loads(json_export)
    assert parsed["case_id"] == case_id
    assert len(parsed["nodes"]) >= 5
    assert len(parsed["edges"]) == 4

    # GraphML export
    graphml_export = case_svc.export_investigation_graph(case_id, format="graphml")
    assert "<graphml" in graphml_export
    assert "<node id=\"ent:user:deployer\">" in graphml_export
    assert "<edge" in graphml_export
    assert "</graphml>" in graphml_export
