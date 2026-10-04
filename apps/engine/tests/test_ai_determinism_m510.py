"""Milestone 5.10 Determinism Test Suite (M10-22).

Verifies:
1. 10 repeated executions on identical input produce strictly identical output.
2. Identical episode classifications, ordering, and entity memberships.
3. Identical transition types, source/target pairs, and reasons.
4. Identical attack sequence reconstructions and MITRE technique attachments.
5. Identical campaign correlation relationships and reasons.
6. Identical temporal gaps and remedies.
7. Dynamic IDs/execution times do not affect deterministic analytical results.
8. Provenance hash is identical across repeated runs on identical telemetry.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
from typing import Generator
import pytest

from logintel.ai.case_service import CaseService
from logintel.storage.case_repo import CaseRepository
from logintel.storage.db import Database


@pytest.fixture
def m510_determinism_setup() -> Generator[tuple[CaseService, int], None, None]:
    """Setup isolated dataset for determinism validation."""
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
                (950, 'INC-950', 'Intrusion Alpha', 'SSH attack and lateral flow', 'CRITICAL', 'OPEN', 'host-alpha', 'deployer', '2026-10-04T10:00:00Z', '2026-10-04T10:05:00Z', 3, 5),
                (951, 'INC-951', 'Intrusion Beta', 'Related lateral target', 'ALERT', 'OPEN', 'host-beta', 'deployer', '2026-10-04T10:04:00Z', '2026-10-04T10:06:00Z', 1, 1)
                """
            )
            cur.execute(
                """
                INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint, username, src_ip)
                VALUES
                ('ev-1', '2026-10-04T10:00:00Z', '2026-10-04T10:00:01Z', 'host-alpha', 'auth.log', 'login', 'ALERT', 'login', 'failure', 'Failed login', 'msg', 'p', 'fp-1', 'deployer', '192.168.1.100'),
                ('ev-2', '2026-10-04T10:00:30Z', '2026-10-04T10:00:31Z', 'host-alpha', 'auth.log', 'login', 'INFORMATIONAL', 'login', 'success', 'Successful login', 'msg', 'p', 'fp-2', 'deployer', '192.168.1.100'),
                ('ev-3', '2026-10-04T10:01:15Z', '2026-10-04T10:01:16Z', 'host-alpha', 'auth.log', 'sudo', 'ALERT', 'sudo', 'success', 'Sudo bash', 'msg', 'p', 'fp-3', 'deployer', '192.168.1.100'),
                ('ev-4', '2026-10-04T10:02:00Z', '2026-10-04T10:02:01Z', 'host-alpha', 'proc.log', 'start', 'INFORMATIONAL', 'start', 'success', 'Spawned shell', 'msg', 'p', 'fp-4', 'root', NULL),
                ('ev-5', '2026-10-04T10:03:00Z', '2026-10-04T10:03:01Z', 'host-beta', 'net.log', 'connect', 'ALERT', 'connect', 'success', 'Lateral connection', 'msg', 'p', 'fp-5', 'root', '10.0.0.1')
                """
            )
            cur.execute(
                """
                INSERT INTO alerts (id, rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count)
                VALUES
                (91, 'rule.ssh', 'k1', 'SSH Alert', 'Desc', 'ALERT', 'OPEN', 'host-alpha', '2026-10-04T10:00:30Z', '2026-10-04T10:00:30Z', 1),
                (92, 'rule.sudo', 'k2', 'Sudo Alert', 'Desc', 'CRITICAL', 'OPEN', 'host-alpha', '2026-10-04T10:01:15Z', '2026-10-04T10:01:15Z', 1),
                (93, 'rule.lateral', 'k3', 'Lateral Alert', 'Desc', 'ALERT', 'OPEN', 'host-beta', '2026-10-04T10:03:00Z', '2026-10-04T10:03:00Z', 1)
                """
            )
            cur.execute(
                """
                INSERT INTO detections (id, alert_id, rule_id, timestamp, host, summary, evidence_count, details_json)
                VALUES
                (91, 91, 'rule.ssh', '2026-10-04T10:00:30Z', 'host-alpha', 'SSH detected', 1, '{"mitre_technique_id": "T1110.001", "mitre_tactic": "Credential Access"}'),
                (92, 92, 'rule.sudo', '2026-10-04T10:01:15Z', 'host-alpha', 'Sudo detected', 1, '{"mitre_technique_id": "T1548.003", "mitre_tactic": "Privilege Escalation"}'),
                (93, 93, 'rule.lateral', '2026-10-04T10:03:00Z', 'host-beta', 'Lateral detected', 1, '{"mitre_technique_id": "T1021.002", "mitre_tactic": "Lateral Movement"}')
                """
            )
            cur.execute("INSERT INTO incident_alerts (incident_id, alert_id) VALUES (950, 91), (950, 92), (950, 93)")
            cur.execute("INSERT INTO detection_evidence (detection_id, event_id) VALUES (91, 'ev-1'), (91, 'ev-2'), (92, 'ev-3'), (93, 'ev-5')")
            cur.execute(
                """
                INSERT INTO incident_entities (incident_id, entity_type, entity_key, display_name)
                VALUES
                (950, 'IP', 'ip:192.168.1.100', '192.168.1.100'),
                (950, 'USER', 'user:deployer', 'deployer'),
                (950, 'HOST', 'host:host-alpha', 'host-alpha'),
                (950, 'PROCESS', 'process:sudo', 'sudo'),
                (950, 'HOST', 'host:host-beta', 'host-beta'),
                (951, 'USER', 'user:deployer', 'deployer')
                """
            )
            cur.execute(
                """
                INSERT INTO incident_relationships (incident_id, source_entity_key, target_entity_key, relationship_type, confidence, evidence_event_ids_json, matched_at)
                VALUES
                (950, 'ip:192.168.1.100', 'user:deployer', 'AUTHENTICATED_TO', 'DIRECT', '["ev-1", "ev-2"]', '2026-10-04T10:00:30Z'),
                (950, 'user:deployer', 'host:host-alpha', 'CONNECTED_TO', 'DIRECT', '["ev-2"]', '2026-10-04T10:00:35Z'),
                (950, 'user:deployer', 'process:sudo', 'EXECUTED', 'STRONG', '["ev-3"]', '2026-10-04T10:01:15Z'),
                (950, 'host:host-alpha', 'host:host-beta', 'LATERAL_MOVEMENT', 'CORRELATED', '["ev-5"]', '2026-10-04T10:03:00Z')
                """
            )
            conn.commit()

        case_repo = CaseRepository(db_path=cases_path, forensic_db=forensic_db)
        case_svc = CaseService(case_repository=case_repo, forensic_database=forensic_db)

        case = case_svc.create_or_open_case(incident_id=950, title="Case 950: Determinism Audit")
        case_svc.associate_evidence(case.case_id, "event", "ev-1", citation_tag="[event:ev-1]")
        case_svc.associate_evidence(case.case_id, "event", "ev-2", citation_tag="[event:ev-2]")
        case_svc.associate_evidence(case.case_id, "event", "ev-3", citation_tag="[event:ev-3]")
        case_svc.associate_evidence(case.case_id, "event", "ev-4", citation_tag="[event:ev-4]")
        case_svc.associate_evidence(case.case_id, "event", "ev-5", citation_tag="[event:ev-5]")

        yield case_svc, case.case_id


def test_m10_22_determinism_across_10_executions(m510_determinism_setup: tuple[CaseService, int]) -> None:
    """M10-22: 10 repeated reconstructions on identical input must produce identical analytical outputs."""
    case_svc, case_id = m510_determinism_setup

    runs = []
    for _ in range(10):
        dossier = case_svc.get_temporal_reconstruction(case_id)
        runs.append(dossier)

    baseline = runs[0]

    for i in range(1, 10):
        run = runs[i]

        # 1. Episodes determinism
        assert len(run.episodes) == len(baseline.episodes), f"Run {i}: episodes count mismatch"
        for ep_run, ep_base in zip(run.episodes, baseline.episodes):
            assert ep_run.episode_type == ep_base.episode_type
            assert ep_run.title == ep_base.title
            assert ep_run.start_time == ep_base.start_time
            assert ep_run.end_time == ep_base.end_time
            assert ep_run.entities == ep_base.entities
            assert ep_run.epistemic_status == ep_base.epistemic_status

        # 2. Transitions determinism
        assert len(run.transitions) == len(baseline.transitions), f"Run {i}: transitions count mismatch"
        for tr_run, tr_base in zip(run.transitions, baseline.transitions):
            assert tr_run.transition_type == tr_base.transition_type
            assert tr_run.from_entity == tr_base.from_entity
            assert tr_run.to_entity == tr_base.to_entity
            assert tr_run.timestamp == tr_base.timestamp
            assert tr_run.reason == tr_base.reason
            assert tr_run.correlation_basis == tr_base.correlation_basis
            assert tr_run.epistemic_status == tr_base.epistemic_status

        # 3. Attack sequences determinism
        assert len(run.attack_sequences) == len(baseline.attack_sequences), f"Run {i}: sequences count mismatch"
        for seq_run, seq_base in zip(run.attack_sequences, baseline.attack_sequences):
            assert seq_run.total_steps == seq_base.total_steps
            for st_run, st_base in zip(seq_run.steps, seq_base.steps):
                assert st_run.step_number == st_base.step_number
                assert st_run.stage_name == st_base.stage_name
                assert st_run.entity == st_base.entity
                assert st_run.mitre_technique_id == st_base.mitre_technique_id
                assert st_run.epistemic_status == st_base.epistemic_status

        # 4. Campaign correlations determinism
        assert len(run.campaign_correlations) == len(baseline.campaign_correlations), f"Run {i}: campaign correlations mismatch"
        for c_run, c_base in zip(run.campaign_correlations, baseline.campaign_correlations):
            assert c_run.related_incident_id == c_base.related_incident_id
            assert c_run.relationship_reason == c_base.relationship_reason
            assert c_run.correlation_status == c_base.correlation_status
            assert c_run.shared_entities == c_base.shared_entities

        # 5. Temporal gaps determinism
        assert len(run.gaps) == len(baseline.gaps), f"Run {i}: gaps mismatch"
        for g_run, g_base in zip(run.gaps, baseline.gaps):
            assert g_run.gap_type == g_base.gap_type
            assert g_run.title == g_base.title
            assert g_run.remedy == g_base.remedy
            assert g_run.affected_entities == g_base.affected_entities

        # 6. Provenance hash determinism
        assert run.provenance_hash == baseline.provenance_hash, f"Run {i}: provenance hash mismatch"
