"""Persistent SQLite storage repository for LogIntel Milestone 5.5 Investigation Cases.

Provides isolated, ACID-compliant persistence for analyst cases, versioned state,
governed query history, versioned report drafts, evidence references with stale detection,
case handoff, and an immutable audit trail.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Tuple

from logintel.ai.domain.case import (
    ALLOWED_CASE_TRANSITIONS,
    CaseAuditRecord,
    CaseEvidenceReference,
    CaseHypothesis,
    CaseQueryRecord,
    CaseReportVersion,
    CaseStatus,
    ContentOrigin,
    InvestigationCase,
    ResolutionStatus,
)
from logintel.ai.domain.workspace import InvestigationScope
from logintel.config import settings
from logintel.logging import get_logger
from logintel.storage.db import Database, db as default_forensic_db

logger = get_logger("storage.cases")


class CaseRepository:
    """Repository managing persistent investigation cases in a dedicated SQLite database."""

    def __init__(
        self,
        db_path: Optional[Path] = None,
        forensic_db: Optional[Database] = None,
    ) -> None:
        self.db_path = db_path or (settings.data_dir / "cases.db")
        self.forensic_db = forensic_db or default_forensic_db
        self._local = threading.local()
        self._lock = threading.RLock()
        self._enforce_storage_permissions()
        self._initialize_schema()
        self._enforce_storage_permissions()

    def _enforce_storage_permissions(self) -> None:
        """Enforce owner-private 0600 on cases.db and 0700 on parent data directory."""
        try:
            if self.db_path.parent.exists():
                parent_mode = self.db_path.parent.stat().st_mode & 0o777
                if parent_mode != 0o700:
                    self.db_path.parent.chmod(0o700)
            if self.db_path.exists():
                db_mode = self.db_path.stat().st_mode & 0o777
                if db_mode != 0o600:
                    self.db_path.chmod(0o600)
            for extra in (f"{self.db_path.name}-wal", f"{self.db_path.name}-shm"):
                extra_path = self.db_path.parent / extra
                if extra_path.exists() and (extra_path.stat().st_mode & 0o777) != 0o600:
                    extra_path.chmod(0o600)
        except OSError as e:
            logger.warning("Could not enforce storage permissions on %s: %s", self.db_path, e)

    def _get_connection(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._enforce_storage_permissions()
            conn = sqlite3.connect(
                str(self.db_path),
                timeout=30.0,
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA busy_timeout = 10000;")
            self._local.conn = conn
            self._enforce_storage_permissions()
        return self._local.conn

    def _initialize_schema(self) -> None:
        """Create case storage tables, foreign keys, and performance indexes."""
        with self._lock:
            conn = self._get_connection()
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS investigation_cases (
                        case_id INTEGER PRIMARY KEY,
                        incident_id INTEGER NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT NOT NULL DEFAULT '',
                        status TEXT NOT NULL DEFAULT 'OPEN',
                        version INTEGER NOT NULL DEFAULT 1,
                        created_by TEXT NOT NULL DEFAULT 'SecAnalyst-1',
                        owner TEXT NOT NULL DEFAULT 'SecAnalyst-1',
                        scope_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS case_hypotheses (
                        hypothesis_id TEXT NOT NULL,
                        case_id INTEGER NOT NULL REFERENCES investigation_cases(case_id) ON DELETE CASCADE,
                        statement TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'OPEN',
                        supporting_evidence_tags_json TEXT NOT NULL DEFAULT '[]',
                        contradicting_evidence_tags_json TEXT NOT NULL DEFAULT '[]',
                        evidence_gaps_json TEXT NOT NULL DEFAULT '[]',
                        analyst_assessment TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        created_by TEXT NOT NULL DEFAULT 'SecAnalyst-1',
                        version INTEGER NOT NULL DEFAULT 1,
                        PRIMARY KEY (case_id, hypothesis_id)
                    );
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS case_evidence_references (
                        reference_id TEXT NOT NULL,
                        case_id INTEGER NOT NULL REFERENCES investigation_cases(case_id) ON DELETE CASCADE,
                        source_type TEXT NOT NULL,
                        source_id TEXT NOT NULL,
                        role TEXT NOT NULL DEFAULT 'SUPPORTING',
                        epistemic_status TEXT NOT NULL DEFAULT 'OBSERVED',
                        citation_tag TEXT NOT NULL,
                        analyst_annotation TEXT,
                        created_at TEXT NOT NULL,
                        PRIMARY KEY (case_id, reference_id)
                    );
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS case_query_history (
                        query_id TEXT NOT NULL PRIMARY KEY,
                        case_id INTEGER NOT NULL REFERENCES investigation_cases(case_id) ON DELETE CASCADE,
                        proposal_id TEXT NOT NULL,
                        query_template_id TEXT NOT NULL,
                        parameters_json TEXT NOT NULL DEFAULT '{}',
                        rationale TEXT NOT NULL,
                        executed_by TEXT NOT NULL,
                        executed_at TEXT NOT NULL,
                        result_count INTEGER NOT NULL DEFAULT 0,
                        execution_status TEXT NOT NULL DEFAULT 'SUCCESS',
                        evidence_candidates_count INTEGER NOT NULL DEFAULT 0
                    );
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS case_reports (
                        report_id TEXT NOT NULL,
                        case_id INTEGER NOT NULL REFERENCES investigation_cases(case_id) ON DELETE CASCADE,
                        version INTEGER NOT NULL DEFAULT 1,
                        title TEXT NOT NULL,
                        executive_summary TEXT NOT NULL,
                        facts_json TEXT NOT NULL DEFAULT '[]',
                        inferences_json TEXT NOT NULL DEFAULT '[]',
                        hypotheses_json TEXT NOT NULL DEFAULT '[]',
                        unknowns_json TEXT NOT NULL DEFAULT '[]',
                        recommendations_json TEXT NOT NULL DEFAULT '[]',
                        analyst_notes TEXT,
                        generated_by TEXT NOT NULL DEFAULT 'AI_GENERATED',
                        model_id TEXT,
                        model_digest TEXT,
                        context_version INTEGER NOT NULL DEFAULT 1,
                        created_at TEXT NOT NULL,
                        is_final INTEGER NOT NULL DEFAULT 0,
                        PRIMARY KEY (case_id, report_id, version)
                    );
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS case_audit_log (
                        audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        case_id INTEGER NOT NULL REFERENCES investigation_cases(case_id) ON DELETE CASCADE,
                        timestamp TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        action TEXT NOT NULL,
                        previous_value TEXT,
                        new_value TEXT,
                        reason TEXT,
                        details_json TEXT
                    );
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS case_finding_reviews (
                        review_id TEXT PRIMARY KEY,
                        case_id INTEGER NOT NULL REFERENCES investigation_cases(case_id) ON DELETE CASCADE,
                        finding_id TEXT NOT NULL,
                        review_state TEXT NOT NULL DEFAULT 'UNREVIEWED',
                        analyst_notes TEXT NOT NULL DEFAULT '',
                        reviewed_by TEXT NOT NULL,
                        reviewed_at TEXT NOT NULL,
                        UNIQUE (case_id, finding_id)
                    );
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_cases_incident ON investigation_cases(incident_id);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_cases_status ON investigation_cases(status);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_case_hypotheses_case ON case_hypotheses(case_id);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_case_evidence_case ON case_evidence_references(case_id);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_case_reports_case ON case_reports(case_id);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_case_audit_case ON case_audit_log(case_id);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_case_finding_reviews_case ON case_finding_reviews(case_id);")

                # Database-level enforcement of append-only audit log
                conn.execute(
                    """
                    CREATE TRIGGER IF NOT EXISTS trg_prevent_case_audit_update
                    BEFORE UPDATE ON case_audit_log
                    BEGIN
                        SELECT RAISE(ABORT, 'case_audit_log is append-only and cannot be modified');
                    END;
                    """
                )
                conn.execute(
                    """
                    CREATE TRIGGER IF NOT EXISTS trg_prevent_case_audit_delete
                    BEFORE DELETE ON case_audit_log
                    BEGIN
                        SELECT RAISE(ABORT, 'case_audit_log is append-only and records cannot be deleted');
                    END;
                    """
                )

                # Database-level enforcement that investigation cases cannot be physically deleted (ARCHIVED is retention state)
                conn.execute(
                    """
                    CREATE TRIGGER IF NOT EXISTS trg_prevent_case_delete
                    BEFORE DELETE ON investigation_cases
                    BEGIN
                        SELECT RAISE(ABORT, 'investigation_cases cannot be physically deleted; ARCHIVED is the retention state');
                    END;
                    """
                )

                # Database-level enforcement of immutable historical report versions
                conn.execute(
                    """
                    CREATE TRIGGER IF NOT EXISTS trg_prevent_case_report_update
                    BEFORE UPDATE ON case_reports
                    BEGIN
                        SELECT RAISE(ABORT, 'case_reports are immutable versioned records and cannot be updated');
                    END;
                    """
                )
                conn.execute(
                    """
                    CREATE TRIGGER IF NOT EXISTS trg_prevent_case_report_delete
                    BEFORE DELETE ON case_reports
                    BEGIN
                        SELECT RAISE(ABORT, 'case_reports are immutable versioned records and cannot be deleted');
                    END;
                    """
                )

    def create_case(
        self,
        incident_id: int,
        title: str,
        description: str = "",
        created_by: str = "SecAnalyst-1",
        scope: Optional[InvestigationScope] = None,
    ) -> InvestigationCase:
        """Create and persist a new investigation case."""
        with self._lock:
            conn = self._get_connection()
            case_id = incident_id
            now_iso = datetime.now(timezone.utc).isoformat()

            if scope is None:
                scope = InvestigationScope(
                    investigation_id=case_id,
                    subject_type="incident",
                    subject_id=str(incident_id),
                )

            with conn:
                conn.execute(
                    """
                    INSERT INTO investigation_cases (
                        case_id, incident_id, title, description, status, version,
                        created_by, owner, scope_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        case_id,
                        incident_id,
                        title,
                        description,
                        CaseStatus.OPEN.value,
                        1,
                        created_by,
                        created_by,
                        json.dumps(scope.model_dump(mode="json")),
                        now_iso,
                        now_iso,
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO case_audit_log (
                        case_id, timestamp, actor, action, new_value, reason
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        case_id,
                        now_iso,
                        created_by,
                        "CASE_CREATED",
                        CaseStatus.OPEN.value,
                        f"Created investigation case {case_id} for incident {incident_id}",
                    ),
                )

            return self.get_case(case_id)  # type: ignore

    def get_case(self, case_id: int, resolve_evidence: bool = True) -> Optional[InvestigationCase]:
        """Load an investigation case and all related records from SQLite."""
        with self._lock:
            conn = self._get_connection()
            row = conn.execute(
                "SELECT * FROM investigation_cases WHERE case_id = ?",
                (case_id,),
            ).fetchone()
            if not row:
                return None

            scope_dict = json.loads(row["scope_json"])
            scope = InvestigationScope.model_validate(scope_dict)

            # Load hypotheses
            hyp_rows = conn.execute(
                "SELECT * FROM case_hypotheses WHERE case_id = ? ORDER BY created_at ASC",
                (case_id,),
            ).fetchall()
            hypotheses = [
                CaseHypothesis(
                    hypothesis_id=h["hypothesis_id"],
                    case_id=h["case_id"],
                    statement=h["statement"],
                    status=h["status"],
                    supporting_evidence_tags=json.loads(h["supporting_evidence_tags_json"]),
                    contradicting_evidence_tags=json.loads(h["contradicting_evidence_tags_json"]),
                    evidence_gaps=json.loads(h["evidence_gaps_json"]),
                    analyst_assessment=h["analyst_assessment"],
                    created_at=h["created_at"],
                    updated_at=h["updated_at"],
                    created_by=h["created_by"],
                    version=h["version"],
                )
                for h in hyp_rows
            ]

            # Load evidence references
            ref_rows = conn.execute(
                "SELECT * FROM case_evidence_references WHERE case_id = ? ORDER BY created_at ASC",
                (case_id,),
            ).fetchall()
            raw_refs = [
                CaseEvidenceReference(
                    reference_id=r["reference_id"],
                    case_id=r["case_id"],
                    source_type=r["source_type"],
                    source_id=r["source_id"],
                    role=r["role"],
                    epistemic_status=r["epistemic_status"],
                    citation_tag=r["citation_tag"],
                    analyst_annotation=r["analyst_annotation"],
                    created_at=r["created_at"],
                )
                for r in ref_rows
            ]

            evidence_refs = self.resolve_evidence_references(raw_refs) if resolve_evidence else raw_refs

            # Load query history
            q_rows = conn.execute(
                "SELECT * FROM case_query_history WHERE case_id = ? ORDER BY executed_at ASC",
                (case_id,),
            ).fetchall()
            queries = [
                CaseQueryRecord(
                    query_id=q["query_id"],
                    case_id=q["case_id"],
                    proposal_id=q["proposal_id"],
                    query_template_id=q["query_template_id"],
                    parameters=json.loads(q["parameters_json"]),
                    rationale=q["rationale"],
                    executed_by=q["executed_by"],
                    executed_at=q["executed_at"],
                    result_count=q["result_count"],
                    execution_status=q["execution_status"],
                    evidence_candidates_count=q["evidence_candidates_count"],
                )
                for q in q_rows
            ]

            # Load reports
            rep_rows = conn.execute(
                "SELECT * FROM case_reports WHERE case_id = ? ORDER BY version DESC",
                (case_id,),
            ).fetchall()
            reports = [
                CaseReportVersion(
                    report_id=rep["report_id"],
                    case_id=rep["case_id"],
                    version=rep["version"],
                    title=rep["title"],
                    executive_summary=rep["executive_summary"],
                    facts=json.loads(rep["facts_json"]),
                    inferences=json.loads(rep["inferences_json"]),
                    hypotheses=json.loads(rep["hypotheses_json"]),
                    unknowns=json.loads(rep["unknowns_json"]),
                    recommendations=json.loads(rep["recommendations_json"]),
                    analyst_notes=rep["analyst_notes"],
                    generated_by=rep["generated_by"],
                    model_id=rep["model_id"],
                    model_digest=rep["model_digest"],
                    context_version=rep["context_version"],
                    created_at=rep["created_at"],
                    is_final=bool(rep["is_final"]),
                )
                for rep in rep_rows
            ]

            # Load audit log
            audit_rows = conn.execute(
                "SELECT * FROM case_audit_log WHERE case_id = ? ORDER BY timestamp ASC",
                (case_id,),
            ).fetchall()
            audits = [
                CaseAuditRecord(
                    audit_id=a["audit_id"],
                    case_id=a["case_id"],
                    timestamp=a["timestamp"],
                    actor=a["actor"],
                    action=a["action"],
                    previous_value=a["previous_value"],
                    new_value=a["new_value"],
                    reason=a["reason"],
                    details=json.loads(a["details_json"]) if a["details_json"] else None,
                )
                for a in audit_rows
            ]

            return InvestigationCase(
                case_id=row["case_id"],
                incident_id=row["incident_id"],
                title=row["title"],
                description=row["description"],
                status=CaseStatus(row["status"]),
                version=row["version"],
                created_by=row["created_by"],
                owner=row["owner"],
                scope=scope,
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                evidence_references=evidence_refs,
                hypotheses=hypotheses,
                query_history=queries,
                reports=reports,
                audit_history=audits,
            )

    def get_case_by_incident(self, incident_id: int, resolve_evidence: bool = True) -> Optional[InvestigationCase]:
        """Fetch investigation case by incident_id."""
        with self._lock:
            conn = self._get_connection()
            row = conn.execute(
                "SELECT case_id FROM investigation_cases WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
            if not row:
                return None
            return self.get_case(row["case_id"], resolve_evidence=resolve_evidence)

    def list_cases(
        self,
        status: Optional[CaseStatus] = None,
        owner: Optional[str] = None,
    ) -> List[InvestigationCase]:
        """List cases with optional status and owner filters."""
        with self._lock:
            conn = self._get_connection()
            query = "SELECT case_id FROM investigation_cases WHERE 1=1"
            params: List[Any] = []

            if status:
                query += " AND status = ?"
                params.append(status.value)
            if owner:
                query += " AND owner = ?"
                params.append(owner)

            query += " ORDER BY updated_at DESC"
            rows = conn.execute(query, params).fetchall()
            return [self.get_case(r["case_id"], resolve_evidence=False) for r in rows if r]  # type: ignore

    def update_case_status(
        self,
        case_id: int,
        target_status: CaseStatus,
        actor: str = "SecAnalyst-1",
        reason: Optional[str] = None,
    ) -> InvestigationCase:
        """Execute validated state machine transition, increment version, and record audit."""
        with self._lock:
            case = self.get_case(case_id, resolve_evidence=False)
            if not case:
                raise ValueError(f"Investigation case {case_id} not found")

            current_status = case.status
            if current_status == target_status:
                return case

            allowed = ALLOWED_CASE_TRANSITIONS.get(current_status, [])
            if target_status not in allowed:
                raise ValueError(
                    f"Invalid case state transition from {current_status.value} to {target_status.value}. "
                    f"Allowed transitions: {[s.value for s in allowed]}"
                )

            now_iso = datetime.now(timezone.utc).isoformat()
            new_version = case.version + 1
            conn = self._get_connection()

            with conn:
                conn.execute(
                    """
                    UPDATE investigation_cases
                    SET status = ?, version = ?, updated_at = ?
                    WHERE case_id = ?
                    """,
                    (target_status.value, new_version, now_iso, case_id),
                )
                conn.execute(
                    """
                    INSERT INTO case_audit_log (
                        case_id, timestamp, actor, action, previous_value, new_value, reason
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        case_id,
                        now_iso,
                        actor,
                        "STATE_TRANSITION",
                        current_status.value,
                        target_status.value,
                        reason or f"Transitioned from {current_status.value} to {target_status.value}",
                    ),
                )

            return self.get_case(case_id)  # type: ignore

    def update_case_scope(
        self,
        case_id: int,
        scope: InvestigationScope,
        actor: str = "SecAnalyst-1",
    ) -> InvestigationCase:
        """Update explicit scope boundaries, increment case version, and log audit."""
        with self._lock:
            case = self.get_case(case_id, resolve_evidence=False)
            if not case:
                raise ValueError(f"Investigation case {case_id} not found")

            now_iso = datetime.now(timezone.utc).isoformat()
            new_version = case.version + 1
            conn = self._get_connection()

            with conn:
                conn.execute(
                    """
                    UPDATE investigation_cases
                    SET scope_json = ?, version = ?, updated_at = ?
                    WHERE case_id = ?
                    """,
                    (json.dumps(scope.model_dump(mode="json")), new_version, now_iso, case_id),
                )
                conn.execute(
                    """
                    INSERT INTO case_audit_log (
                        case_id, timestamp, actor, action, previous_value, new_value, reason
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        case_id,
                        now_iso,
                        actor,
                        "SCOPE_UPDATED",
                        str(case.version),
                        str(new_version),
                        "Updated investigation scope boundaries",
                    ),
                )

            return self.get_case(case_id)  # type: ignore

    def transfer_case(
        self,
        case_id: int,
        new_owner: str,
        actor: str = "SecAnalyst-1",
        handoff_notes: Optional[str] = None,
    ) -> InvestigationCase:
        """Transfer case ownership during analyst handoff, incrementing version and auditing."""
        with self._lock:
            case = self.get_case(case_id, resolve_evidence=False)
            if not case:
                raise ValueError(f"Investigation case {case_id} not found")

            now_iso = datetime.now(timezone.utc).isoformat()
            new_version = case.version + 1
            conn = self._get_connection()

            with conn:
                conn.execute(
                    """
                    UPDATE investigation_cases
                    SET owner = ?, version = ?, updated_at = ?
                    WHERE case_id = ?
                    """,
                    (new_owner, new_version, now_iso, case_id),
                )
                conn.execute(
                    """
                    INSERT INTO case_audit_log (
                        case_id, timestamp, actor, action, previous_value, new_value, reason, details_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        case_id,
                        now_iso,
                        actor,
                        "CASE_HANDOFF",
                        case.owner,
                        new_owner,
                        handoff_notes or f"Handoff from {case.owner} to {new_owner}",
                        json.dumps({"previous_owner": case.owner, "new_owner": new_owner, "notes": handoff_notes}),
                    ),
                )

            return self.get_case(case_id)  # type: ignore

    def upsert_hypothesis(
        self,
        case_id: int,
        hypothesis: CaseHypothesis,
        actor: str = "SecAnalyst-1",
    ) -> CaseHypothesis:
        """Create or update an analyst hypothesis, incrementing hypothesis and case versions."""
        with self._lock:
            case = self.get_case(case_id, resolve_evidence=False)
            if not case:
                raise ValueError(f"Investigation case {case_id} not found")

            now_iso = datetime.now(timezone.utc).isoformat()
            conn = self._get_connection()

            # Check if hypothesis exists
            existing = conn.execute(
                "SELECT * FROM case_hypotheses WHERE case_id = ? AND hypothesis_id = ?",
                (case_id, hypothesis.hypothesis_id),
            ).fetchone()

            with conn:
                if existing:
                    new_hyp_version = existing["version"] + 1
                    action = "HYPOTHESIS_UPDATED"
                    conn.execute(
                        """
                        UPDATE case_hypotheses
                        SET statement = ?, status = ?, supporting_evidence_tags_json = ?,
                            contradicting_evidence_tags_json = ?, evidence_gaps_json = ?,
                            analyst_assessment = ?, updated_at = ?, version = ?
                        WHERE case_id = ? AND hypothesis_id = ?
                        """,
                        (
                            hypothesis.statement,
                            hypothesis.status.value,
                            json.dumps(hypothesis.supporting_evidence_tags),
                            json.dumps(hypothesis.contradicting_evidence_tags),
                            json.dumps(hypothesis.evidence_gaps),
                            hypothesis.analyst_assessment,
                            now_iso,
                            new_hyp_version,
                            case_id,
                            hypothesis.hypothesis_id,
                        ),
                    )
                else:
                    new_hyp_version = 1
                    action = "HYPOTHESIS_CREATED"
                    conn.execute(
                        """
                        INSERT INTO case_hypotheses (
                            hypothesis_id, case_id, statement, status, supporting_evidence_tags_json,
                            contradicting_evidence_tags_json, evidence_gaps_json, analyst_assessment,
                            created_at, updated_at, created_by, version
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            hypothesis.hypothesis_id,
                            case_id,
                            hypothesis.statement,
                            hypothesis.status.value,
                            json.dumps(hypothesis.supporting_evidence_tags),
                            json.dumps(hypothesis.contradicting_evidence_tags),
                            json.dumps(hypothesis.evidence_gaps),
                            hypothesis.analyst_assessment,
                            now_iso,
                            now_iso,
                            actor,
                            new_hyp_version,
                        ),
                    )

                # Increment case version and log audit
                new_case_version = case.version + 1
                conn.execute(
                    "UPDATE investigation_cases SET version = ?, updated_at = ? WHERE case_id = ?",
                    (new_case_version, now_iso, case_id),
                )
                conn.execute(
                    """
                    INSERT INTO case_audit_log (
                        case_id, timestamp, actor, action, previous_value, new_value, reason, details_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        case_id,
                        now_iso,
                        actor,
                        action,
                        existing["status"] if existing else None,
                        hypothesis.status.value,
                        f"Hypothesis {hypothesis.hypothesis_id} {action.lower()}",
                        json.dumps({"hypothesis_id": hypothesis.hypothesis_id, "statement": hypothesis.statement}),
                    ),
                )

            hypothesis.version = new_hyp_version
            hypothesis.updated_at = now_iso
            return hypothesis

    def add_evidence_reference(
        self,
        case_id: int,
        source_type: str,
        source_id: str,
        role: str,
        epistemic_status: str,
        citation_tag: str,
        analyst_annotation: Optional[str] = None,
        actor: str = "SecAnalyst-1",
        bump_version: bool = True,
    ) -> CaseEvidenceReference:
        """Add an evidence reference pointing to an authoritative record without duplicating event payloads."""
        with self._lock:
            case = self.get_case(case_id, resolve_evidence=False)
            if not case:
                raise ValueError(f"Investigation case {case_id} not found")

            conn = self._get_connection()
            ref_id = f"ref-{source_type}-{source_id}"
            now_iso = datetime.now(timezone.utc).isoformat()

            with conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO case_evidence_references (
                        reference_id, case_id, source_type, source_id, role,
                        epistemic_status, citation_tag, analyst_annotation, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ref_id,
                        case_id,
                        source_type,
                        source_id,
                        role,
                        epistemic_status,
                        citation_tag,
                        analyst_annotation,
                        now_iso,
                    ),
                )
                if bump_version:
                    new_case_version = case.version + 1
                    conn.execute(
                        "UPDATE investigation_cases SET version = ?, updated_at = ? WHERE case_id = ?",
                        (new_case_version, now_iso, case_id),
                    )
                    conn.execute(
                        """
                        INSERT INTO case_audit_log (
                            case_id, timestamp, actor, action, new_value, reason
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            case_id,
                            now_iso,
                            actor,
                            "EVIDENCE_ASSOCIATED",
                            citation_tag,
                            f"Associated evidence reference {citation_tag} (role: {role})",
                        ),
                    )

            raw_ref = CaseEvidenceReference(
                reference_id=ref_id,
                case_id=case_id,
                source_type=source_type,
                source_id=source_id,
                role=role,  # type: ignore
                epistemic_status=epistemic_status,
                citation_tag=citation_tag,
                analyst_annotation=analyst_annotation,
                created_at=now_iso,
            )
            return self.resolve_evidence_references([raw_ref])[0]

    def remove_evidence_reference(
        self,
        case_id: int,
        reference_id: str,
        actor: str = "SecAnalyst-1",
    ) -> bool:
        """Disassociate an evidence reference from a case."""
        with self._lock:
            case = self.get_case(case_id, resolve_evidence=False)
            if not case:
                return False

            conn = self._get_connection()
            now_iso = datetime.now(timezone.utc).isoformat()

            with conn:
                cur = conn.execute(
                    "DELETE FROM case_evidence_references WHERE case_id = ? AND reference_id = ?",
                    (case_id, reference_id),
                )
                if cur.rowcount > 0:
                    new_version = case.version + 1
                    conn.execute(
                        "UPDATE investigation_cases SET version = ?, updated_at = ? WHERE case_id = ?",
                        (new_version, now_iso, case_id),
                    )
                    conn.execute(
                        """
                        INSERT INTO case_audit_log (
                            case_id, timestamp, actor, action, previous_value, reason
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            case_id,
                            now_iso,
                            actor,
                            "EVIDENCE_DISASSOCIATED",
                            reference_id,
                            f"Disassociated evidence reference {reference_id}",
                        ),
                    )
                    return True
            return False

    def record_query(
        self,
        case_id: int,
        query: CaseQueryRecord,
    ) -> None:
        """Record a threat hunt query execution record in case query history."""
        with self._lock:
            conn = self._get_connection()
            with conn:
                conn.execute(
                    """
                    INSERT INTO case_query_history (
                        query_id, case_id, proposal_id, query_template_id, parameters_json,
                        rationale, executed_by, executed_at, result_count, execution_status,
                        evidence_candidates_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        query.query_id,
                        case_id,
                        query.proposal_id,
                        query.query_template_id,
                        json.dumps(query.parameters),
                        query.rationale,
                        query.executed_by,
                        query.executed_at,
                        query.result_count,
                        query.execution_status,
                        query.evidence_candidates_count,
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO case_audit_log (
                        case_id, timestamp, actor, action, new_value, reason
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        case_id,
                        query.executed_at,
                        query.executed_by,
                        "QUERY_EXECUTED",
                        query.query_template_id,
                        f"Executed threat query {query.query_template_id} producing {query.result_count} results",
                    ),
                )

    def save_report_version(
        self,
        case_id: int,
        report: CaseReportVersion,
        actor: str = "SecAnalyst-1",
    ) -> CaseReportVersion:
        """Save a new versioned report draft, preserving analyst annotations and AI provenance."""
        with self._lock:
            case = self.get_case(case_id, resolve_evidence=False)
            if not case:
                raise ValueError(f"Investigation case {case_id} not found")

            conn = self._get_connection()
            # Calculate next report version
            max_ver_row = conn.execute(
                "SELECT COALESCE(MAX(version), 0) FROM case_reports WHERE case_id = ? AND report_id = ?",
                (case_id, report.report_id),
            ).fetchone()
            next_version = (max_ver_row[0] + 1) if max_ver_row else 1
            now_iso = datetime.now(timezone.utc).isoformat()

            with conn:
                conn.execute(
                    """
                    INSERT INTO case_reports (
                        report_id, case_id, version, title, executive_summary, facts_json,
                        inferences_json, hypotheses_json, unknowns_json, recommendations_json,
                        analyst_notes, generated_by, model_id, model_digest, context_version,
                        created_at, is_final
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        report.report_id,
                        case_id,
                        next_version,
                        report.title,
                        report.executive_summary,
                        json.dumps(report.facts),
                        json.dumps(report.inferences),
                        json.dumps(report.hypotheses),
                        json.dumps(report.unknowns),
                        json.dumps(report.recommendations),
                        report.analyst_notes,
                        report.generated_by.value if isinstance(report.generated_by, ContentOrigin) else report.generated_by,
                        report.model_id,
                        report.model_digest,
                        case.version,
                        now_iso,
                        1 if report.is_final else 0,
                    ),
                )
                new_case_version = case.version + 1
                conn.execute(
                    "UPDATE investigation_cases SET version = ?, updated_at = ? WHERE case_id = ?",
                    (new_case_version, now_iso, case_id),
                )
                conn.execute(
                    """
                    INSERT INTO case_audit_log (
                        case_id, timestamp, actor, action, previous_value, new_value, reason
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        case_id,
                        now_iso,
                        actor,
                        "REPORT_VERSIONED",
                        str(next_version - 1) if next_version > 1 else None,
                        str(next_version),
                        f"Saved report draft version {next_version} ({'FINAL' if report.is_final else 'DRAFT'})",
                    ),
                )

            report.version = next_version
            report.created_at = now_iso
            return report

    def get_report_version(
        self,
        case_id: int,
        report_id: str,
        version: int,
    ) -> Optional[CaseReportVersion]:
        """Fetch a specific historical report version for comparison."""
        with self._lock:
            conn = self._get_connection()
            row = conn.execute(
                "SELECT * FROM case_reports WHERE case_id = ? AND report_id = ? AND version = ?",
                (case_id, report_id, version),
            ).fetchone()
            if not row:
                return None

            return CaseReportVersion(
                report_id=row["report_id"],
                case_id=row["case_id"],
                version=row["version"],
                title=row["title"],
                executive_summary=row["executive_summary"],
                facts=json.loads(row["facts_json"]),
                inferences=json.loads(row["inferences_json"]),
                hypotheses=json.loads(row["hypotheses_json"]),
                unknowns=json.loads(row["unknowns_json"]),
                recommendations=json.loads(row["recommendations_json"]),
                analyst_notes=row["analyst_notes"],
                generated_by=ContentOrigin(row["generated_by"]),
                model_id=row["model_id"],
                model_digest=row["model_digest"],
                context_version=row["context_version"],
                created_at=row["created_at"],
                is_final=bool(row["is_final"]),
            )

    def resolve_evidence_references(
        self,
        references: List[CaseEvidenceReference],
    ) -> List[CaseEvidenceReference]:
        """Resolve evidence references dynamically against protected authoritative SQLite tables.

        Distinguishes AVAILABLE from MISSING/STALE evidence without silently discarding references
        or fabricating replacement evidence.
        """
        resolved: List[CaseEvidenceReference] = []

        with self.forensic_db.connection() as conn:
            for ref in references:
                found_record: Optional[Dict[str, Any]] = None
                status = ResolutionStatus.MISSING

                try:
                    if ref.source_type in ("event", "events"):
                        row = conn.execute("SELECT * FROM events WHERE id = ?", (ref.source_id,)).fetchone()
                        if row:
                            found_record = dict(row)
                            status = ResolutionStatus.AVAILABLE
                    elif ref.source_type in ("alert", "alerts"):
                        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (ref.source_id,)).fetchone()
                        if row:
                            found_record = dict(row)
                            status = ResolutionStatus.AVAILABLE
                    elif ref.source_type in ("detection", "detections"):
                        row = conn.execute("SELECT * FROM detections WHERE id = ?", (ref.source_id,)).fetchone()
                        if row:
                            found_record = dict(row)
                            status = ResolutionStatus.AVAILABLE
                    elif ref.source_type in ("entity", "entities", "incident_entity", "incident_entities", "incident_entitie"):
                        row = conn.execute(
                            "SELECT * FROM incident_entities WHERE entity_key = ?",
                            (ref.source_id,),
                        ).fetchone()
                        if row:
                            found_record = dict(row)
                            status = ResolutionStatus.AVAILABLE
                    elif ref.source_type in ("incident", "incidents"):
                        row = conn.execute(
                            "SELECT * FROM incidents WHERE id = ? OR incident_key = ?",
                            (ref.source_id, str(ref.source_id)),
                        ).fetchone()
                        if row:
                            found_record = dict(row)
                            status = ResolutionStatus.AVAILABLE
                    else:
                        status = ResolutionStatus.UNRESOLVED
                except Exception as e:
                    logger.warning("Error resolving reference %s: %s", ref.citation_tag, e)
                    status = ResolutionStatus.UNRESOLVED

                resolved_ref = ref.model_copy()
                resolved_ref.resolution_status = status
                resolved_ref.resolved_record = found_record
                resolved.append(resolved_ref)

        return resolved

    def get_audit_log(self, case_id: int) -> List[CaseAuditRecord]:
        """Fetch audit log records for a case."""
        case = self.get_case(case_id, resolve_evidence=False)
        return case.audit_history if case else []

    def upsert_finding_review(
        self,
        case_id: int,
        finding_id: str,
        review_state: str,
        analyst_notes: str = "",
        reviewed_by: str = "SecAnalyst-1",
    ) -> Dict[str, Any]:
        """Persist an analyst review decision for an investigation finding and record in audit log."""
        case = self.get_case(case_id, resolve_evidence=False)
        if not case:
            raise ValueError(f"Case {case_id} not found")

        valid_states = {"UNREVIEWED", "UNDER_REVIEW", "ACCEPTED", "REJECTED", "NEEDS_MORE_EVIDENCE"}
        if review_state not in valid_states:
            raise ValueError(f"Invalid review state '{review_state}'. Must be one of: {sorted(valid_states)}")

        now_iso = datetime.now(timezone.utc).isoformat()
        review_id = f"rev-{case_id}-{finding_id}"

        with self._lock:
            conn = self._get_connection()
            with conn:
                existing = conn.execute(
                    "SELECT review_state FROM case_finding_reviews WHERE case_id = ? AND finding_id = ?",
                    (case_id, finding_id),
                ).fetchone()

                old_state = existing["review_state"] if existing else "UNREVIEWED"

                conn.execute(
                    """
                    INSERT INTO case_finding_reviews (
                        review_id, case_id, finding_id, review_state, analyst_notes, reviewed_by, reviewed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(case_id, finding_id) DO UPDATE SET
                        review_state = excluded.review_state,
                        analyst_notes = excluded.analyst_notes,
                        reviewed_by = excluded.reviewed_by,
                        reviewed_at = excluded.reviewed_at
                    """,
                    (review_id, case_id, finding_id, review_state, analyst_notes, reviewed_by, now_iso),
                )

                # Record in immutable audit log
                conn.execute(
                    """
                    INSERT INTO case_audit_log (
                        case_id, timestamp, actor, action, previous_value, new_value, reason, details_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        case_id,
                        now_iso,
                        reviewed_by,
                        "REVIEW_FINDING",
                        old_state,
                        review_state,
                        analyst_notes or f"Finding {finding_id} review state updated to {review_state}",
                        json.dumps({"finding_id": finding_id, "review_state": review_state, "analyst_notes": analyst_notes}),
                    ),
                )

        return {
            "review_id": review_id,
            "case_id": case_id,
            "finding_id": finding_id,
            "review_state": review_state,
            "analyst_notes": analyst_notes,
            "reviewed_by": reviewed_by,
            "reviewed_at": now_iso,
        }

    def get_finding_reviews(self, case_id: int) -> Dict[str, Dict[str, Any]]:
        """Retrieve all finding review records for a case keyed by finding_id."""
        conn = self._get_connection()
        rows = conn.execute(
            "SELECT * FROM case_finding_reviews WHERE case_id = ? ORDER BY reviewed_at ASC",
            (case_id,),
        ).fetchall()
        return {r["finding_id"]: dict(r) for r in rows}

    def get_finding_review(self, case_id: int, finding_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a specific finding review record."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM case_finding_reviews WHERE case_id = ? AND finding_id = ?",
            (case_id, finding_id),
        ).fetchone()
        return dict(row) if row else None

    def append_audit_log(
        self,
        case_id: int,
        actor: str,
        action: str,
        previous_value: Optional[str] = None,
        new_value: Optional[str] = None,
        reason: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Append an entry to the immutable case_audit_log table."""
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO case_audit_log (
                    case_id, timestamp, actor, action, previous_value, new_value, reason, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    now_iso,
                    actor,
                    action,
                    previous_value,
                    new_value,
                    reason,
                    json.dumps(details or {}),
                ),
            )


