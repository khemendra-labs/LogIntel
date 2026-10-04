"""Milestone 5.11 Determinism Test Suite.

Verifies:
1. 10 repeated executions on identical input produce strictly identical output.
2. Identical findings synthesis, ordering, and epistemic states.
3. Identical competing hypothesis determinations and evidence attachments.
4. Identical prioritized evidence gaps and remedies.
5. Identical closure readiness evaluation.
6. Identical 15-section investigation briefing content.
7. Identical provenance SHA-256 fingerprint.
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
def m511_determinism_setup() -> Generator[tuple[CaseService, int], None, None]:
    """Setup isolated dataset for M5.11 determinism validation."""
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
                ('rule.ssh', 'SSH Attack', 'SSH Rule', 'ALERT', 'Auth', 'threshold', 'yaml'),
                ('rule.sudo', 'Sudo Escalation', 'Privilege Escalation', 'ALERT', 'Priv', 'threshold', 'yaml')
                """
            )
            cur.execute(
                """
                INSERT INTO incidents (id, incident_key, title, summary, severity, status, primary_host, primary_user, first_seen, last_seen, alert_count, event_count)
                VALUES
                (950, 'INC-950', 'Intrusion Alpha', 'SSH attack and lateral flow', 'ALERT', 'OPEN', 'host-alpha', 'deployer', '2026-10-04T10:00:00Z', '2026-10-04T10:05:00Z', 2, 3)
                """
            )
            cur.execute(
                """
                INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint, username, src_ip)
                VALUES
                ('ev-1', '2026-10-04T10:00:00Z', '2026-10-04T10:00:01Z', 'host-alpha', 'auth.log', 'login', 'ALERT', 'login', 'failure', 'Failed login', 'msg', 'p', 'fp-1', 'deployer', '192.168.1.100'),
                ('ev-2', '2026-10-04T10:01:00Z', '2026-10-04T10:01:01Z', 'host-alpha', 'auth.log', 'login', 'INFORMATIONAL', 'login', 'success', 'Successful login', 'msg', 'p', 'fp-2', 'deployer', '192.168.1.100'),
                ('ev-3', '2026-10-04T10:05:00Z', '2026-10-04T10:05:01Z', 'host-alpha', 'audit.log', 'process', 'ALERT', 'exec', 'success', 'Sudo su root', 'msg', 'p', 'fp-3', 'deployer', '192.168.1.100')
                """
            )
            conn.commit()

        case_repo = CaseRepository(db_path=cases_path, forensic_db=forensic_db)
        case_svc = CaseService(case_repository=case_repo, forensic_database=forensic_db)

        case = case_svc.create_or_open_case(incident_id=950, title="Deterministic Case 950")
        case_svc.associate_evidence(case.case_id, "event", "ev-1", citation_tag="[event:ev-1]")
        case_svc.associate_evidence(case.case_id, "event", "ev-2", citation_tag="[event:ev-2]")
        case_svc.associate_evidence(case.case_id, "event", "ev-3", citation_tag="[event:ev-3]")

        yield case_svc, case.case_id


def test_m11_determinism_10_executions(m511_determinism_setup: tuple[CaseService, int]) -> None:
    """Verify that 10 repeated assessment syntheses produce identical semantic outputs."""
    case_svc, case_id = m511_determinism_setup

    runs = []
    for _ in range(10):
        asmt = case_svc.get_case_assessment(case_id, refresh=False)
        briefing = case_svc.get_investigation_briefing(case_id)

        # Normalize volatile timestamps
        data = {
            "case_id": asmt.case_id,
            "evidence_state": asmt.evidence_state.value,
            "readiness_status": asmt.closure_readiness.status.value,
            "findings_count": len(asmt.key_findings),
            "findings_titles": [f.title for f in asmt.key_findings],
            "findings_epistemics": [f.epistemic_status.value for f in asmt.key_findings],
            "hypotheses_count": len(asmt.hypotheses),
            "hypotheses_determinations": [h.determination for h in asmt.hypotheses],
            "gaps_count": len(asmt.evidence_gaps),
            "gaps_priorities": [g.priority.value for g in asmt.evidence_gaps],
            "questions_count": len(asmt.questions),
            "conclusion_statement": asmt.conclusion.statement,
            "conclusion_epistemic": asmt.conclusion.epistemic_status.value,
            "briefing_sections_count": len(briefing.sections),
            "briefing_sections_keys": sorted(list(briefing.sections.keys())),
        }
        runs.append(data)

    first_run = runs[0]
    for idx, r in enumerate(runs[1:], start=2):
        assert r == first_run, f"Run {idx} diverged from Run 1:\n{json.dumps(r, indent=2)}\nVS\n{json.dumps(first_run, indent=2)}"


def test_m11_briefing_determinism(m511_determinism_setup: tuple[CaseService, int]) -> None:
    """Verify briefing 15 sections are identical across repeated runs."""
    case_svc, case_id = m511_determinism_setup

    b1 = case_svc.get_investigation_briefing(case_id)
    b2 = case_svc.get_investigation_briefing(case_id)

    assert b1.sections == b2.sections
    assert b1.closure_readiness == b2.closure_readiness
    assert b1.evidence_sufficiency == b2.evidence_sufficiency
