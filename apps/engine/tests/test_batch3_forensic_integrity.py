"""Targeted regression tests for forensic integrity, transaction safety, and provenance preservation."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from logintel.ai.domain.case import CaseStatus, InvestigationCase
from logintel.ai.domain.epistemic import EpistemicStatus
from logintel.ai.domain.investigation_temporal import TransitionType
from logintel.ai.temporal.reconstruction_engine import TemporalReconstructionEngine
from logintel.comparison.service import CaseComparisonService, TemporalComparisonWindow
from logintel.models.incidents import Incident, IncidentRelationship, IncidentStatus, Severity
from logintel.reporting.models import CreateReportRequest
from logintel.reporting.service import ReportingAndHandoffService
from logintel.storage.case_repo import CaseRepository
from logintel.storage.db import Database
from logintel.storage.incidents_repo import IncidentsRepository
from logintel.storage.investigation_repo import InvestigationRepository


def _setup_repos(tmp_path: Path):
    fdb = Database(db_path=tmp_path / "forensic.db")
    fdb.initialize()
    crepo = CaseRepository(db_path=tmp_path / "cases.db", forensic_db=fdb)
    irepo = IncidentsRepository(database=fdb)
    inv_repo = InvestigationRepository(database=fdb, incidents_repository=irepo)
    return fdb, crepo, irepo, inv_repo


def test_exact_json_array_matching_no_substring_false_positive(tmp_path: Path):
    """Ensure get_event_forensics does not match substring event IDs in JSON arrays."""
    fdb, crepo, irepo, inv_repo = _setup_repos(tmp_path)

    with fdb.connection() as conn:
        # Insert events ev-1, ev-10, ev-100
        now_iso = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT INTO events (id, host, timestamp, severity, raw_message, event_type, ingested_at, source, outcome, summary, parser)
            VALUES
                ('ev-1', 'srv-alpha', ?, 'INFO', 'Event 1', 'AUTH', ?, 'syslog', 'SUCCESS', 'Ev 1', 'syslog'),
                ('ev-10', 'srv-alpha', ?, 'INFO', 'Event 10', 'AUTH', ?, 'syslog', 'SUCCESS', 'Ev 10', 'syslog'),
                ('ev-100', 'srv-alpha', ?, 'INFO', 'Event 100', 'AUTH', ?, 'syslog', 'SUCCESS', 'Ev 100', 'syslog')
            """,
            (now_iso, now_iso, now_iso, now_iso, now_iso, now_iso),
        )

        # Create incident
        conn.execute(
            """
            INSERT INTO incidents (id, incident_key, title, summary, primary_host, status, severity, first_seen, last_seen, created_at, updated_at)
            VALUES (1, 'INC-1', 'Test Incident', 'Test incident summary', 'srv-alpha', 'OPEN', 'WARNING', ?, ?, ?, ?)
            """,
            (now_iso, now_iso, now_iso, now_iso),
        )

        # Insert relationship referencing ONLY ev-10 and ev-100 (substring match for ev-1)
        conn.execute(
            """
            INSERT INTO incident_relationships (
                id, incident_id, source_entity_key, target_entity_key, relationship_type,
                confidence, evidence_event_ids_json, matched_at
            ) VALUES (
                1, 1, 'user:alice', 'host:srv-alpha', 'ACCESSED_FILE', 'STRONG', ?, ?
            )
            """,
            (json.dumps(["ev-10", "ev-100"]), now_iso),
        )

    # Query forensics for ev-1: MUST NOT match relationship
    forensics = inv_repo.get_event_forensics("ev-1")
    assert len(forensics.relationships) == 0, "ev-1 erroneously matched substring in ['ev-10', 'ev-100']"

    # Query forensics for ev-10: MUST match relationship
    forensics_10 = inv_repo.get_event_forensics("ev-10")
    assert len(forensics_10.relationships) == 1
    assert forensics_10.relationships[0]["id"] == 1


def test_incident_merge_utc_offset_comparisons(tmp_path: Path):
    """Ensure incident merge accurately orders timestamps with differing timezone offsets."""
    fdb, crepo, irepo, inv_repo = _setup_repos(tmp_path)

    # Incident 1 (source): first_seen at 10:00 UTC+2 (which is 08:00 UTC)
    # Incident 2 (target): first_seen at 09:00 UTC
    # Lexicographically, "2026-11-13T09:00:00Z" < "2026-11-13T10:00:00+02:00",
    # but chronologically 10:00+02:00 (08:00 UTC) occurred EARLIER than 09:00 UTC!
    with fdb.connection() as conn:
        conn.execute(
            """
            INSERT INTO incidents (id, incident_key, title, summary, primary_host, status, severity, first_seen, last_seen, created_at, updated_at)
            VALUES
                (101, 'INC-101', 'Source Incident', 'Source summary', 'srv-alpha', 'OPEN', 'WARNING', '2026-11-13T10:00:00+02:00', '2026-11-13T14:00:00+02:00', '2026-11-13T10:00:00Z', '2026-11-13T10:00:00Z'),
                (102, 'INC-102', 'Target Incident', 'Target summary', 'srv-alpha', 'OPEN', 'NOTICE', '2026-11-13T09:00:00Z', '2026-11-13T11:00:00Z', '2026-11-13T09:00:00Z', '2026-11-13T09:00:00Z')
            """
        )

    merged = irepo.merge_incidents(source_incident_id=101, target_incident_id=102)
    # Merged first_seen must be the earlier chronological instant (10:00:00+02:00)
    assert merged.first_seen == datetime.fromisoformat("2026-11-13T10:00:00+02:00")
    # Merged last_seen must be the later chronological instant (14:00:00+02:00 / 12:00 UTC vs 11:00 UTC)
    assert merged.last_seen == datetime.fromisoformat("2026-11-13T14:00:00+02:00")


def test_append_audit_log_transaction_safety(tmp_path: Path):
    """Ensure append_audit_log with conn does not commit prematurely and rolls back on failure."""
    fdb, crepo, irepo, inv_repo = _setup_repos(tmp_path)

    # Create a case
    case = crepo.create_case(incident_id=1, title="Audit Rollback Test")
    cid = case.case_id

    # Start an explicit transaction with conn
    conn = crepo._get_connection()
    try:
        with crepo._lock, conn:
            # Perform a change
            conn.execute(
                "UPDATE investigation_cases SET title = 'Changed In Tx' WHERE case_id = ?",
                (cid,),
            )
            # Append audit log passing conn
            crepo.append_audit_log(
                case_id=cid,
                actor="SecAnalyst-1",
                action="TEST_ACTION",
                conn=conn,
            )
            # Deliberately raise exception to force rollback
            raise RuntimeError("Forced transaction failure")
    except RuntimeError:
        pass

    # Verify that the case title and the audit entry rolled back atomically
    case_after = crepo.get_case(cid)
    assert case_after.title == "Audit Rollback Test", "Transaction failed to rollback case update"

    with crepo._get_connection() as c:
        row = c.execute("SELECT COUNT(*) as cnt FROM case_audit_log WHERE action = 'TEST_ACTION'").fetchone()
        assert row["cnt"] == 0, "Audit log committed prematurely despite outer transaction rollback"


def test_reconstruction_engine_epistemic_preservation(tmp_path: Path):
    """Ensure non-observed or unauthoritative items are NEVER promoted to OBSERVED in transitions."""
    engine = TemporalReconstructionEngine()
    case = SimpleNamespace(case_id=42, incident_id=100)

    # Inferred evidence items
    cur = {
        "id": "ev-1",
        "username": "admin",
        "host": "srv-1",
        "timestamp": "2026-11-13T10:00:00Z",
        "_source_type": "event",
        "_source_id": "ev-1",
        "_epistemic_status": "INFERRED",
        "_is_authoritative": False,
    }
    nxt = {
        "id": "ev-2",
        "username": "admin",
        "host": "srv-2",
        "timestamp": "2026-11-13T10:05:00Z",
        "_source_type": "event",
        "_source_id": "ev-2",
        "_epistemic_status": "INFERRED",
        "_is_authoritative": False,
        "source_host": "srv-1",  # explicit connection attribute
    }

    transitions = engine.detect_transitions(case, [cur, nxt], [])
    assert len(transitions) > 0
    for tr in transitions:
        # Even with explicit source_host, because cur/nxt are INFERRED, transition must NOT be OBSERVED
        assert tr.epistemic_status != EpistemicStatus.OBSERVED, f"Transition {tr.transition_id} was promoted to OBSERVED"
        assert tr.epistemic_status == EpistemicStatus.INFERRED


def test_reporting_manifest_epistemic_fallback(tmp_path: Path):
    """Ensure reporting manifest handles missing epistemic status by assigning UNKNOWN, not OBSERVED."""
    fdb, crepo, irepo, inv_repo = _setup_repos(tmp_path)
    service = ReportingAndHandoffService(case_repository=crepo, forensic_database=fdb)

    # Pinned evidence reference with missing epistemic_status
    mock_ref = SimpleNamespace(
        reference_id="ref-unknown",
        source_type="event",
        citation_tag="[event:ref-unknown]",
        analyst_annotation="Unverified artifact",
        created_at="2026-11-13T10:00:00Z",
        # epistemic_status attribute is missing
    )
    mock_case = SimpleNamespace(
        case_id=99,
        incident_id=10,
        title="Test Case",
        status=CaseStatus.OPEN,
        lead_investigator="Analyst",
        scope=SimpleNamespace(hosts=["srv-1"], users=["root"]),
        hypotheses=[],
        evidence_references=[mock_ref],
        key_findings=[],
    )

    manifest = service.generate_provenance_manifest(
        case_id=99,
        report_id="rep-99",
        report_version=1,
        included_references=[
            {
                "source_type": mock_ref.source_type,
                "source_id": mock_ref.reference_id,
                "citation_tag": mock_ref.citation_tag,
                # omitted epistemic_status
            }
        ],
    )

    entry = manifest.entries[0]
    assert entry.epistemic_status == "UNKNOWN", f"Expected UNKNOWN, got {entry.epistemic_status}"


def test_comparison_inverted_bounds(tmp_path: Path):
    """Ensure temporal overlap handles inverted start/end times safely without negative delta."""
    fdb, crepo, irepo, inv_repo = _setup_repos(tmp_path)
    comp_service = CaseComparisonService(case_repository=crepo, forensic_database=fdb)

    # Case 1 has inverted window: start_time > end_time
    w1 = TemporalComparisonWindow(
        case_id=1,
        start_time="2026-11-13T12:00:00Z",
        end_time="2026-11-13T10:00:00Z",  # Inverted!
    )
    # Case 2 has normal window
    w2 = TemporalComparisonWindow(
        case_id=2,
        start_time="2026-11-13T11:00:00Z",
        end_time="2026-11-13T13:00:00Z",
    )

    result = comp_service._compute_temporal_overlap([w1, w2])
    assert result.relationship == "OVERLAPPING"
    assert result.delta_seconds >= 0, f"Negative delta_seconds: {result.delta_seconds}"
    assert result.delta_seconds == 3600  # 11:00 to 12:00 is 1 hour = 3600s
