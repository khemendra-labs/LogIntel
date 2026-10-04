"""Milestone 5.12 Determinism Certification Test Suite.

Verifies:
1. 10 repeated full-stack syntheses produce strictly identical semantic outputs.
2. Invariance of evidence sufficiency evaluation across repeated runs.
3. Invariance of competing hypotheses determinations.
4. Invariance of prioritized evidence gaps and remedies.
5. Invariance of 15-section investigation briefing content.
6. Invariance of case handoff checklist and state package.
7. Invariance of deterministic SHA-256 provenance fingerprint.
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
def m512_determinism_setup() -> Generator[tuple[CaseService, int], None, None]:
    """Setup isolated dataset for M5.12 determinism certification."""
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
                (970, 'INC-970', 'Deterministic Intrusion', 'Multi-host attack sequence', 'ALERT', 'OPEN', 'host-dc1', 'opsadmin', '2026-10-04T12:00:00Z', '2026-10-04T12:30:00Z', 2, 3)
                """
            )
            cur.execute(
                """
                INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint, username, src_ip)
                VALUES
                ('ev-det-1', '2026-10-04T12:00:00Z', '2026-10-04T12:00:01Z', 'host-dc1', 'auth.log', 'login', 'ALERT', 'login', 'failure', 'Failed password opsadmin', 'msg', 'p', 'fp-1', 'opsadmin', '192.168.10.50'),
                ('ev-det-2', '2026-10-04T12:02:00Z', '2026-10-04T12:02:01Z', 'host-dc1', 'auth.log', 'login', 'INFORMATIONAL', 'login', 'success', 'Accepted publickey opsadmin', 'msg', 'p', 'fp-2', 'opsadmin', '192.168.10.50'),
                ('ev-det-3', '2026-10-04T12:15:00Z', '2026-10-04T12:15:01Z', 'host-dc1', 'audit.log', 'process', 'ALERT', 'exec', 'success', 'sudo /bin/bash', 'msg', 'p', 'fp-3', 'opsadmin', '192.168.10.50')
                """
            )
            conn.commit()

        case_repo = CaseRepository(db_path=cases_path, forensic_db=forensic_db)
        case_svc = CaseService(case_repository=case_repo, forensic_database=forensic_db)

        case = case_svc.create_or_open_case(incident_id=970, title="Deterministic Certification Case 970")
        case_svc.associate_evidence(case.case_id, "event", "ev-det-1", citation_tag="[event:ev-det-1]")
        case_svc.associate_evidence(case.case_id, "event", "ev-det-2", citation_tag="[event:ev-det-2]")
        case_svc.associate_evidence(case.case_id, "event", "ev-det-3", citation_tag="[event:ev-det-3]")

        yield case_svc, case.case_id


def test_m12_determinism_ten_executions(m512_determinism_setup: tuple[CaseService, int]) -> None:
    """M12-07: Verify 10 repeated syntheses on identical input yield strictly identical semantic output."""
    case_svc, case_id = m512_determinism_setup

    runs = []
    for _ in range(10):
        asmt = case_svc.get_case_assessment(case_id, refresh=False)
        briefing = case_svc.get_investigation_briefing(case_id)
        handoff = case_svc.get_case_handoff(case_id, actor="CertAnalyst")

        data = {
            "case_id": asmt.case_id,
            "evidence_state": asmt.evidence_state.value,
            "closure_readiness": asmt.closure_readiness.status.value,
            "findings_count": len(asmt.key_findings),
            "findings_ids": [f.finding_id for f in asmt.key_findings],
            "findings_titles": [f.title for f in asmt.key_findings],
            "findings_epistemics": [f.epistemic_status.value for f in asmt.key_findings],
            "hypotheses_count": len(asmt.hypotheses),
            "hypotheses_determinations": [h.determination for h in asmt.hypotheses],
            "gaps_count": len(asmt.evidence_gaps),
            "gaps_priorities": [g.priority.value for g in asmt.evidence_gaps],
            "questions_count": len(asmt.questions),
            "briefing_sections_count": len(briefing.sections),
            "briefing_sections_keys": sorted(list(briefing.sections.keys())),
            "handoff_findings_count": len(handoff.key_findings),
            "handoff_questions_count": len(handoff.open_questions),
            "fingerprint": asmt.provenance.fingerprint,
        }
        runs.append(data)

    first = runs[0]
    for idx, r in enumerate(runs[1:], start=2):
        assert r == first, f"Execution {idx} diverged from run 1:\n{json.dumps(r, indent=2)}\nVS\n{json.dumps(first, indent=2)}"


def test_m12_determinism_briefing_and_fingerprint_invariance(m512_determinism_setup: tuple[CaseService, int]) -> None:
    """M12-07: Verify 15-section briefing content and SHA-256 fingerprint invariance across calls."""
    case_svc, case_id = m512_determinism_setup

    b1 = case_svc.get_investigation_briefing(case_id)
    b2 = case_svc.get_investigation_briefing(case_id)

    assert b1.sections == b2.sections
    assert b1.closure_readiness == b2.closure_readiness
    assert b1.evidence_sufficiency == b2.evidence_sufficiency

    asmt1 = case_svc.get_case_assessment(case_id)
    asmt2 = case_svc.get_case_assessment(case_id)
    assert asmt1.provenance.fingerprint == asmt2.provenance.fingerprint
