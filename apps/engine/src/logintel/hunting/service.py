"""Threat Hunting Service orchestrating governed query building, preview, approval gate,
bounded execution, evidence pivots, sequence matching, and deterministic exports for M7.5.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone, timedelta
import hashlib
import io
import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple
import uuid

from logintel.hunting.models import (
    AIHuntProposalRequest,
    ApproveHuntRequest,
    ConvertHuntToCollectionRequest,
    ConvertHuntToFindingRequest,
    ConvertHuntToHypothesisEvidenceRequest,
    CreateHuntProposalRequest,
    EntityFilter,
    EpistemicStatusM75,
    FieldFilter,
    GovernedQueryModel,
    HuntApprovalState,
    HuntExecutionResult,
    HuntExecutionStatus,
    HuntExportResponse,
    HuntIntent,
    HuntQueryPreview,
    HuntResourceBounds,
    HuntResultItem,
    HuntSequenceProposal,
    HuntSequenceResult,
    HuntSequenceStep,
    QueryOperator,
    TemporalWindow,
)
from logintel.logging import get_logger
from logintel.storage.case_repo import CaseRepository
from logintel.storage.db import Database, db as default_forensic_db

logger = get_logger("hunting.service")

# Strict pattern for detecting SQL injection tokens in user-supplied strings
SQL_INJECTION_PATTERN = re.compile(
    r"(\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|ATTACH|PRAGMA|SHUTDOWN)\b|--|/\*|;|'\s*(OR|AND)\b|\b(OR|AND)\s+['\"0-9=])",
    re.IGNORECASE,
)


class ThreatHuntingService:
    """Core service for M7.5 Advanced Threat Hunting & Governed Analyst Queries."""

    def __init__(
        self,
        case_repo: Optional[CaseRepository] = None,
        forensic_db: Optional[Database] = None,
    ) -> None:
        self.case_repo = case_repo or CaseRepository()
        self.forensic_db = forensic_db or default_forensic_db
        # In-memory proposal and result cache keyed by (case_id, hunt_id)
        self._hunt_proposals: Dict[Tuple[int, str], GovernedQueryModel] = {}
        self._hunt_approvals: Dict[Tuple[int, str], Tuple[HuntApprovalState, Optional[str]]] = {}
        self._hunt_results: Dict[Tuple[int, str], HuntExecutionResult] = {}

    def _ensure_case_exists(self, case_id: int) -> None:
        """Verify case existence; raise ValueError on failure."""
        case = self.case_repo.get_case(case_id, resolve_evidence=False)
        if not case:
            raise ValueError(f"Case {case_id} not found")

    def _log_audit(
        self,
        case_id: int,
        action: str,
        actor: str,
        reason: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Append immutable audit log entry in cases.db."""
        try:
            self.case_repo.append_audit_log(
                case_id=case_id,
                actor=actor,
                action=action,
                reason=reason,
                details=details or {},
            )
        except Exception as e:
            logger.warning(f"Failed to record audit log for case {case_id}: {e}")

    # =========================================================================
    # 1. Query Validation & Preview
    # =========================================================================

    def validate_and_preview_hunt(
        self,
        case_id: int,
        req: CreateHuntProposalRequest,
    ) -> HuntQueryPreview:
        """Validate query syntax and generate dry-run preview without executing."""
        self._ensure_case_exists(case_id)
        errors: List[str] = []

        # Validate question length and content
        if len(req.question.strip()) < 3:
            errors.append("Hunt question must be at least 3 characters long.")
        if len(req.question) > 2000:
            errors.append("Hunt question exceeds maximum length of 2000 characters.")

        # Check for SQL injection in field filters
        for f in req.field_filters:
            if isinstance(f.value, str):
                if SQL_INJECTION_PATTERN.search(f.value):
                    errors.append(f"Potential SQL injection detected in filter '{f.field}': '{f.value}'")
            elif isinstance(f.value, list):
                for item in f.value:
                    if isinstance(item, str) and SQL_INJECTION_PATTERN.search(item):
                        errors.append(f"Potential SQL injection detected in filter list '{f.field}'")

        # Check entity filter values
        for ef in req.entity_filters:
            if SQL_INJECTION_PATTERN.search(ef.entity_value):
                errors.append(f"Potential SQL injection detected in entity filter '{ef.entity_type}'")

        # Validate complexity bounds
        total_predicates = len(req.field_filters) + len(req.entity_filters)
        if total_predicates > req.bounds.max_complexity_predicates:
            errors.append(f"Query complexity exceeded: {total_predicates} predicates > max {req.bounds.max_complexity_predicates}")

        # Validate time bounds
        time_desc = "All available case telemetry"
        if req.temporal_window:
            tw = req.temporal_window
            if tw.start_time and tw.end_time:
                time_desc = f"{tw.start_time} to {tw.end_time}"
            elif tw.relative_window_minutes:
                time_desc = f"Last {tw.relative_window_minutes} minutes relative to anchor"

        op_class = f"GOVERNED_HUNT:{req.intent.value}"
        summary_clauses = [f"{f.field} {f.operator.value} {f.value}" for f in req.field_filters]
        for ef in req.entity_filters:
            summary_clauses.append(f"ENTITY:{ef.entity_type} == {ef.entity_value}")
        sql_summary = "WHERE " + " AND ".join(summary_clauses) if summary_clauses else "WHERE 1=1 (Full Scope)"

        return HuntQueryPreview(
            case_id=case_id,
            intent=req.intent,
            question=req.question,
            scope={"sources": req.source_types, "predicates_count": total_predicates},
            sources=req.source_types,
            filter_count=total_predicates,
            time_range_description=time_desc,
            operation_class=op_class,
            estimated_resource_bounds={
                "max_results": req.bounds.max_results,
                "max_time_window_days": req.bounds.max_time_window_days,
                "timeout_seconds": req.bounds.timeout_seconds,
            },
            validation_status="VALID" if not errors else "INVALID",
            validation_errors=errors,
            requires_approval=True,
            preview_sql_summary=sql_summary,
        )

    # =========================================================================
    # 2. Proposal Creation & Approval Gate
    # =========================================================================

    def create_hunt_proposal(
        self,
        case_id: int,
        req: CreateHuntProposalRequest,
        actor: str = "SecAnalyst-1",
    ) -> Tuple[str, HuntQueryPreview]:
        """Create a validated hunt proposal, store it, and require analyst approval."""
        preview = self.validate_and_preview_hunt(case_id, req)
        hunt_id = f"HNT-{case_id}-{uuid.uuid4().hex[:8]}"

        governed_model = GovernedQueryModel(
            case_id=case_id,
            hunt_id=hunt_id,
            intent=req.intent,
            question=req.question,
            source_types=req.source_types,
            field_filters=req.field_filters,
            entity_filters=req.entity_filters,
            temporal_window=req.temporal_window,
            bounds=req.bounds,
            limit=req.limit,
            offset=req.offset,
        )

        initial_state = HuntApprovalState.VALIDATED if preview.validation_status == "VALID" else HuntApprovalState.DRAFT
        self._hunt_proposals[(case_id, hunt_id)] = governed_model
        self._hunt_approvals[(case_id, hunt_id)] = (initial_state, None)

        # Record in cases.db case_query_history
        now_iso = datetime.now(timezone.utc).isoformat()
        conn = self.case_repo._get_connection()
        with conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO case_query_history (
                    query_id, case_id, proposal_id, query_template_id,
                    parameters_json, rationale, executed_by, executed_at,
                    result_count, execution_status, evidence_candidates_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    hunt_id,
                    case_id,
                    hunt_id,
                    req.intent.value,
                    json.dumps(governed_model.model_dump(mode="json")),
                    req.question,
                    actor,
                    now_iso,
                    0,
                    initial_state.value,
                    0,
                ),
            )

        self._log_audit(
            case_id=case_id,
            action="HUNT_PROPOSAL_CREATED",
            actor=actor,
            reason=f"Created hunt proposal {hunt_id} for intent {req.intent.value}",
            details={"hunt_id": hunt_id, "intent": req.intent.value, "status": initial_state.value},
        )

        return hunt_id, preview

    def approve_hunt(
        self,
        case_id: int,
        hunt_id: str,
        req: ApproveHuntRequest,
    ) -> Dict[str, Any]:
        """Analyst approval gate. Transitions hunt to APPROVED state."""
        self._ensure_case_exists(case_id)
        key = (case_id, hunt_id)

        # If not in cache, load from case_query_history
        if key not in self._hunt_proposals:
            self._load_hunt_from_db(case_id, hunt_id)

        state, _ = self._hunt_approvals.get(key, (HuntApprovalState.DRAFT, None))
        if state not in (HuntApprovalState.VALIDATED, HuntApprovalState.READY, HuntApprovalState.DRAFT):
            if state == HuntApprovalState.APPROVED:
                return {"case_id": case_id, "hunt_id": hunt_id, "status": "ALREADY_APPROVED"}
            raise ValueError(f"Cannot approve hunt {hunt_id} in state {state.value}")

        self._hunt_approvals[key] = (HuntApprovalState.APPROVED, req.approved_by)

        now_iso = datetime.now(timezone.utc).isoformat()
        conn = self.case_repo._get_connection()
        with conn:
            conn.execute(
                """
                UPDATE case_query_history
                SET execution_status = 'APPROVED', executed_at = ?
                WHERE case_id = ? AND query_id = ?
                """,
                (now_iso, case_id, hunt_id),
            )

        self._log_audit(
            case_id=case_id,
            action="HUNT_APPROVED",
            actor=req.approved_by,
            reason=req.rationale or f"Analyst {req.approved_by} approved hunt {hunt_id}",
            details={"hunt_id": hunt_id, "approved_by": req.approved_by},
        )

        return {
            "case_id": case_id,
            "hunt_id": hunt_id,
            "approval_state": HuntApprovalState.APPROVED.value,
            "approved_by": req.approved_by,
            "approved_at": now_iso,
        }

    def _load_hunt_from_db(self, case_id: int, hunt_id: str) -> None:
        """Helper to load recorded hunt from SQLite into cache."""
        conn = self.case_repo._get_connection()
        row = conn.execute(
            "SELECT * FROM case_query_history WHERE case_id = ? AND query_id = ?",
            (case_id, hunt_id),
        ).fetchone()
        if not row:
            raise ValueError(f"Hunt {hunt_id} not found in case {case_id}")

        params = json.loads(row["parameters_json"])
        query_model = GovernedQueryModel.model_validate(params)
        self._hunt_proposals[(case_id, hunt_id)] = query_model
        st = HuntApprovalState(row["execution_status"]) if row["execution_status"] in HuntApprovalState._value2member_map_ else HuntApprovalState.VALIDATED
        self._hunt_approvals[(case_id, hunt_id)] = (st, row["executed_by"])

    # =========================================================================
    # 3. Bounded Query Execution
    # =========================================================================

    def execute_hunt(
        self,
        case_id: int,
        hunt_id: str,
        executed_by: str = "SecAnalyst-1",
    ) -> HuntExecutionResult:
        """Execute an approved threat hunt against authoritative forensic telemetry."""
        self._ensure_case_exists(case_id)
        key = (case_id, hunt_id)
        if key not in self._hunt_proposals:
            self._load_hunt_from_db(case_id, hunt_id)

        query = self._hunt_proposals[key]
        approval_state, approved_by = self._hunt_approvals.get(key, (HuntApprovalState.DRAFT, None))

        # Strict Approval Gate check
        if approval_state != HuntApprovalState.APPROVED:
            raise ValueError(
                f"Governed Threat Hunt {hunt_id} requires explicit analyst approval before execution. "
                f"Current state: {approval_state.value}"
            )

        t_start = time.perf_counter()
        now_iso = datetime.now(timezone.utc).isoformat()

        # Build parameterized SQL query safely
        where_clauses: List[str] = []
        sql_params: List[Any] = []

        # 1. Field Filters with allowlisted type-aware operators
        for f in query.field_filters:
            clause, params = self._build_filter_clause(f)
            if clause:
                where_clauses.append(clause)
                sql_params.extend(params)

        # 2. Entity Filters
        for ef in query.entity_filters:
            clause, params = self._build_entity_clause(ef)
            if clause:
                where_clauses.append(clause)
                sql_params.extend(params)

        # 3. Temporal Window
        if query.temporal_window:
            tw = query.temporal_window
            if tw.start_time:
                where_clauses.append("timestamp >= ?")
                sql_params.append(tw.start_time)
            if tw.end_time:
                where_clauses.append("timestamp <= ?")
                sql_params.append(tw.end_time)
            elif tw.relative_window_minutes and tw.anchor_timestamp:
                try:
                    anchor_dt = datetime.fromisoformat(tw.anchor_timestamp.replace("Z", "+00:00"))
                    delta = timedelta(minutes=tw.relative_window_minutes)
                    if tw.direction == "before":
                        where_clauses.append("timestamp <= ? AND timestamp >= ?")
                        sql_params.append(tw.anchor_timestamp)
                        sql_params.append((anchor_dt - delta).isoformat())
                    elif tw.direction == "after":
                        where_clauses.append("timestamp >= ? AND timestamp <= ?")
                        sql_params.append(tw.anchor_timestamp)
                        sql_params.append((anchor_dt + delta).isoformat())
                    else:  # around
                        where_clauses.append("timestamp >= ? AND timestamp <= ?")
                        sql_params.append((anchor_dt - delta).isoformat())
                        sql_params.append((anchor_dt + delta).isoformat())
                except Exception as e:
                    logger.warning(f"Failed to parse anchor timestamp: {e}")

        # Resource bounds
        limit = min(query.bounds.max_results, max(1, query.limit))
        where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"

        # Deterministic ordering: timestamp ASC, source ASC, id ASC
        sql = f"""
            SELECT id, timestamp, source, event_type, severity, host, username,
                   process_name, src_ip, dst_ip, action, outcome, summary, raw_message
            FROM events
            WHERE {where_sql}
            ORDER BY timestamp ASC, source ASC, id ASC
            LIMIT ?
        """
        sql_params.append(limit + 1)  # Query 1 extra to detect truncation

        raw_rows: List[Dict[str, Any]] = []
        is_limit_exceeded = False

        try:
            with self.forensic_db.connection() as conn:
                cur = conn.cursor()
                rows = cur.execute(sql, sql_params).fetchall()
                raw_rows = [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Error executing threat hunt query: {e}")
            duration_ms = (time.perf_counter() - t_start) * 1000
            return HuntExecutionResult(
                hunt_id=hunt_id,
                case_id=case_id,
                intent=query.intent,
                question=query.question,
                status=HuntExecutionStatus.FAILED,
                approval_state=HuntApprovalState.COMPLETED,
                approved_by=approved_by,
                executed_by=executed_by,
                executed_at=now_iso,
                duration_ms=duration_ms,
                result_count=0,
                total_matches=0,
                is_truncated=False,
                resource_limit_exceeded=False,
                results=[],
                query_fingerprint="",
                provenance_manifest={"error": str(e)},
            )

        duration_ms = (time.perf_counter() - t_start) * 1000
        is_truncated = len(raw_rows) > limit
        if is_truncated:
            raw_rows = raw_rows[:limit]
            is_limit_exceeded = True

        # Map to structured HuntResultItems
        results: List[HuntResultItem] = []
        for r in raw_rows:
            evt_id = str(r["id"])
            ts = r.get("timestamp", now_iso)
            s_type = "event"
            prov_hash = hashlib.sha256(f"{s_type}:{evt_id}:{ts}".encode()).hexdigest()[:16]
            item = HuntResultItem(
                result_id=f"HRES-{s_type}-{evt_id}",
                source_type=s_type,
                source_id=evt_id,
                host=r.get("host"),
                timestamp=ts,
                summary=r.get("summary") or f"{r.get('event_type', 'EVENT')} on {r.get('host')}",
                event_type=r.get("event_type"),
                action=r.get("action"),
                outcome=r.get("outcome"),
                username=r.get("username"),
                src_ip=r.get("src_ip"),
                dst_ip=r.get("dst_ip"),
                process_name=r.get("process_name"),
                epistemic_status=EpistemicStatusM75.OBSERVED,
                citation_tag=f"[{s_type}:{evt_id}]",
                provenance_hash=prov_hash,
                raw_preview={k: v for k, v in r.items() if v is not None and k not in ("raw_message",)},
            )
            results.append(item)

        # Deterministic result fingerprint
        fingerprint_content = json.dumps(
            [{"id": it.source_id, "ts": it.timestamp, "hash": it.provenance_hash} for it in results],
            sort_keys=True,
        )
        query_fp = hashlib.blake2b(fingerprint_content.encode(), digest_size=16).hexdigest()

        status = HuntExecutionStatus.SUCCESS if results else HuntExecutionStatus.NO_MATCH
        if is_limit_exceeded:
            status = HuntExecutionStatus.RESOURCE_LIMIT_EXCEEDED

        manifest = {
            "hunt_id": hunt_id,
            "case_id": case_id,
            "intent": query.intent.value,
            "executed_by": executed_by,
            "approved_by": approved_by,
            "executed_at": now_iso,
            "result_count": len(results),
            "fingerprint": query_fp,
            "bounded_limit": limit,
            "is_truncated": is_truncated,
        }

        exec_res = HuntExecutionResult(
            hunt_id=hunt_id,
            case_id=case_id,
            intent=query.intent,
            question=query.question,
            status=status,
            approval_state=HuntApprovalState.COMPLETED,
            approved_by=approved_by,
            executed_by=executed_by,
            executed_at=now_iso,
            duration_ms=duration_ms,
            result_count=len(results),
            total_matches=len(results),
            is_truncated=is_truncated,
            resource_limit_exceeded=is_limit_exceeded,
            results=results,
            query_fingerprint=query_fp,
            provenance_manifest=manifest,
        )

        self._hunt_results[key] = exec_res

        # Update case_query_history with execution outcome
        db_conn = self.case_repo._get_connection()
        with db_conn:
            db_conn.execute(
                """
                UPDATE case_query_history
                SET execution_status = ?, result_count = ?, executed_at = ?
                WHERE case_id = ? AND query_id = ?
                """,
                (status.value, len(results), now_iso, case_id, hunt_id),
            )

        self._log_audit(
            case_id=case_id,
            action="HUNT_EXECUTED",
            actor=executed_by,
            reason=f"Executed hunt {hunt_id} resulting in {len(results)} matches (status: {status.value})",
            details={
                "hunt_id": hunt_id,
                "matches": len(results),
                "fingerprint": query_fp,
                "status": status.value,
            },
        )

        return exec_res

    def _build_filter_clause(self, f: FieldFilter) -> Tuple[Optional[str], List[Any]]:
        """Construct parameterized SQL predicate for allowlisted field filter."""
        field = f.field
        op = f.operator
        val = f.value

        if op == QueryOperator.EQUALS:
            return f"{field} = ?", [val]
        elif op == QueryOperator.NOT_EQUALS:
            return f"{field} != ?", [val]
        elif op == QueryOperator.CONTAINS:
            return f"{field} LIKE ?", [f"%{val}%"]
        elif op == QueryOperator.PREFIX:
            return f"{field} LIKE ?", [f"{val}%"]
        elif op == QueryOperator.SUFFIX:
            return f"{field} LIKE ?", [f"%{val}"]
        elif op == QueryOperator.EXISTS:
            return f"{field} IS NOT NULL AND {field} != ''", []
        elif op == QueryOperator.IN and isinstance(val, list):
            if not val:
                return None, []
            ph = ",".join("?" for _ in val)
            return f"{field} IN ({ph})", list(val)
        elif op == QueryOperator.NOT_IN and isinstance(val, list):
            if not val:
                return None, []
            ph = ",".join("?" for _ in val)
            return f"{field} NOT IN ({ph})", list(val)
        elif op == QueryOperator.BEFORE:
            return f"{field} < ?", [val]
        elif op == QueryOperator.AFTER:
            return f"{field} > ?", [val]
        elif op in (QueryOperator.BETWEEN, QueryOperator.RANGE) and isinstance(val, list) and len(val) == 2:
            return f"{field} BETWEEN ? AND ?", [val[0], val[1]]
        return None, []

    def _build_entity_clause(self, ef: EntityFilter) -> Tuple[Optional[str], List[Any]]:
        """Map entity type to canonical event table columns."""
        etype = ef.entity_type
        val = ef.entity_value

        if etype == "USER":
            return "username = ?", [val]
        elif etype == "IP":
            return "(src_ip = ? OR dst_ip = ?)", [val, val]
        elif etype in ("PROCESS", "COMMAND"):
            return "(process_name = ? OR raw_message LIKE ?)", [val, f"%{val}%"]
        elif etype == "HOST":
            return "host = ?", [val]
        elif etype == "FILE":
            return "(raw_message LIKE ? OR summary LIKE ?)", [f"%{val}%", f"%{val}%"]
        elif etype in ("CONTAINER", "SERVICE"):
            return "(raw_message LIKE ? OR summary LIKE ?)", [f"%{val}%", f"%{val}%"]
        return None, []

    # =========================================================================
    # 4. Entity, Temporal, Sequence, & IOC Special Hunts
    # =========================================================================

    def pivot_hunt_by_entity(
        self,
        case_id: int,
        entity_type: str,
        entity_value: str,
        actor: str = "SecAnalyst-1",
    ) -> HuntExecutionResult:
        """Fast entity-centric threat hunt within case boundaries."""
        proposal_req = CreateHuntProposalRequest(
            intent=HuntIntent.ENTITY_ACTIVITY,
            question=f"Investigate all forensic activity for entity {entity_type}:{entity_value}",
            entity_filters=[EntityFilter(entity_type=entity_type, entity_value=entity_value)],
            limit=100,
        )
        hunt_id, _ = self.create_hunt_proposal(case_id, proposal_req, actor=actor)
        self.approve_hunt(case_id, hunt_id, ApproveHuntRequest(approved_by=actor, rationale=f"Entity pivot for {entity_type}"))
        return self.execute_hunt(case_id, hunt_id, executed_by=actor)

    def pivot_hunt_temporal(
        self,
        case_id: int,
        anchor_timestamp: str,
        window_minutes: int = 15,
        direction: str = "around",
        actor: str = "SecAnalyst-1",
    ) -> HuntExecutionResult:
        """Bounded temporal window threat hunt surrounding an anchor event."""
        proposal_req = CreateHuntProposalRequest(
            intent=HuntIntent.TEMPORAL_SEQUENCE,
            question=f"Investigate activity {direction} {anchor_timestamp} within {window_minutes} minutes",
            temporal_window=TemporalWindow(
                anchor_timestamp=anchor_timestamp,
                relative_window_minutes=window_minutes,
                direction=direction,
            ),
            limit=100,
        )
        hunt_id, _ = self.create_hunt_proposal(case_id, proposal_req, actor=actor)
        self.approve_hunt(case_id, hunt_id, ApproveHuntRequest(approved_by=actor, rationale="Temporal window investigation"))
        return self.execute_hunt(case_id, hunt_id, executed_by=actor)

    def execute_ioc_hunt(
        self,
        case_id: int,
        ioc_value: str,
        actor: str = "SecAnalyst-1",
    ) -> HuntExecutionResult:
        """Normalized IOC search across IPs, hostnames, usernames, processes, and commandlines."""
        clean_ioc = ioc_value.strip()
        proposal_req = CreateHuntProposalRequest(
            intent=HuntIntent.IOC_LOOKUP,
            question=f"Correlate IOC presence across case telemetry: '{clean_ioc}'",
            field_filters=[
                FieldFilter(field="raw_message", operator=QueryOperator.CONTAINS, value=clean_ioc),
            ],
            limit=100,
        )
        hunt_id, _ = self.create_hunt_proposal(case_id, proposal_req, actor=actor)
        self.approve_hunt(case_id, hunt_id, ApproveHuntRequest(approved_by=actor, rationale=f"IOC hunt: {clean_ioc}"))
        return self.execute_hunt(case_id, hunt_id, executed_by=actor)

    def execute_sequence_hunt(
        self,
        case_id: int,
        proposal: HuntSequenceProposal,
        actor: str = "SecAnalyst-1",
    ) -> HuntSequenceResult:
        """Evaluate a multi-step sequence proposal chronologically, identifying telemetry gaps."""
        self._ensure_case_exists(case_id)
        now_iso = datetime.now(timezone.utc).isoformat()
        items_by_step: Dict[int, List[HuntResultItem]] = {}
        missing_steps: List[int] = []

        last_timestamp: Optional[str] = None
        for step in sorted(proposal.steps, key=lambda s: s.step_number):
            step_filters = list(step.field_filters)
            if step.entity_filter:
                ef_clause, _ = self._build_entity_clause(step.entity_filter)

            tw = None
            if last_timestamp and step.max_time_delta_seconds:
                try:
                    dt = datetime.fromisoformat(last_timestamp.replace("Z", "+00:00"))
                    end_dt = dt + timedelta(seconds=step.max_time_delta_seconds)
                    tw = TemporalWindow(start_time=last_timestamp, end_time=end_dt.isoformat())
                except Exception:
                    pass

            step_req = CreateHuntProposalRequest(
                intent=HuntIntent.TEMPORAL_SEQUENCE,
                question=f"Sequence step {step.step_number}: {step.name}",
                field_filters=step_filters,
                entity_filters=[step.entity_filter] if step.entity_filter else [],
                temporal_window=tw,
                limit=20,
            )
            step_hunt_id, _ = self.create_hunt_proposal(case_id, step_req, actor=actor)
            self.approve_hunt(case_id, step_hunt_id, ApproveHuntRequest(approved_by=actor, rationale=f"Step {step.step_number}"))
            step_res = self.execute_hunt(case_id, step_hunt_id, executed_by=actor)

            if step_res.results:
                items_by_step[step.step_number] = step_res.results
                last_timestamp = step_res.results[-1].timestamp
            else:
                items_by_step[step.step_number] = []
                missing_steps.append(step.step_number)

        matched_count = len(proposal.steps) - len(missing_steps)
        seq_status = "COMPLETE" if not missing_steps else ("PARTIAL" if matched_count > 0 else "NO_MATCH")

        fp = hashlib.blake2b(
            f"{proposal.sequence_name}:{matched_count}:{len(proposal.steps)}".encode(),
            digest_size=16,
        ).hexdigest()

        return HuntSequenceResult(
            case_id=case_id,
            sequence_name=proposal.sequence_name,
            matched_steps=matched_count,
            total_steps=len(proposal.steps),
            sequence_status=seq_status,
            items_by_step=items_by_step,
            missing_telemetry_steps=missing_steps,
            evaluated_at=now_iso,
            query_fingerprint=fp,
        )

    # =========================================================================
    # 5. Result Actions: Findings, Hypotheses, Collections Integration
    # =========================================================================

    def convert_hunt_to_finding(
        self,
        case_id: int,
        req: ConvertHuntToFindingRequest,
        actor: str = "SecAnalyst-1",
    ) -> Dict[str, Any]:
        """Formulate a structured analyst finding from selected hunt result items."""
        from logintel.findings.service import findings_workbench_service
        from logintel.findings.models import CreateFindingRequest

        key = (case_id, req.hunt_id)
        hunt_res = self._hunt_results.get(key)
        if not hunt_res:
            raise ValueError(f"Hunt result {req.hunt_id} not found for case {case_id}")

        selected_items = [it for it in hunt_res.results if it.result_id in req.result_ids or it.source_id in req.result_ids]
        if not selected_items:
            raise ValueError("No matching hunt result items selected for finding conversion")

        supporting_refs = [
            {
                "source_type": it.source_type,
                "source_id": it.source_id,
                "citation_tag": it.citation_tag,
                "epistemic_status": it.epistemic_status.value,
                "host": it.host,
                "timestamp": it.timestamp,
                "analyst_note": f"Discovered via hunt {req.hunt_id}: {it.summary}",
            }
            for it in selected_items
        ]

        finding_req = CreateFindingRequest(
            title=req.title,
            statement=req.statement,
            severity=req.severity,
            supporting_evidence=supporting_refs,
            analyst_notes=req.analyst_notes,
        )

        finding = findings_workbench_service.create_finding(case_id, finding_req, actor=actor)

        self._log_audit(
            case_id=case_id,
            action="HUNT_CONVERTED_TO_FINDING",
            actor=actor,
            reason=f"Formulated finding {finding.finding_id} from hunt {req.hunt_id} with {len(selected_items)} evidence refs",
            details={"hunt_id": req.hunt_id, "finding_id": finding.finding_id, "refs": len(selected_items)},
        )

        return finding.model_dump(mode="json")

    def convert_hunt_to_hypothesis(
        self,
        case_id: int,
        req: ConvertHuntToHypothesisEvidenceRequest,
        actor: str = "SecAnalyst-1",
    ) -> Dict[str, Any]:
        """Attach selected hunt result items as evidence to an active hypothesis."""
        from logintel.findings.service import findings_workbench_service

        key = (case_id, req.hunt_id)
        hunt_res = self._hunt_results.get(key)
        if not hunt_res:
            raise ValueError(f"Hunt result {req.hunt_id} not found for case {case_id}")

        selected_items = [it for it in hunt_res.results if it.result_id in req.result_ids or it.source_id in req.result_ids]
        if not selected_items:
            raise ValueError("No matching hunt result items selected for hypothesis evaluation")

        for it in selected_items:
            evidence_tag = f"[{it.source_type}:{it.source_id}]"
            findings_workbench_service.add_hypothesis_evidence(
                case_id=case_id,
                hypothesis_id=req.hypothesis_id,
                evidence_tag=evidence_tag,
                role=req.role,
                actor=actor,
            )

        self._log_audit(
            case_id=case_id,
            action="HUNT_ATTACHED_TO_HYPOTHESIS",
            actor=actor,
            reason=f"Attached {len(selected_items)} hunt results to hypothesis {req.hypothesis_id} as {req.role}",
            details={"hunt_id": req.hunt_id, "hypothesis_id": req.hypothesis_id, "count": len(selected_items)},
        )

        return {
            "case_id": case_id,
            "hypothesis_id": req.hypothesis_id,
            "attached_count": len(selected_items),
            "role": req.role,
        }

    def convert_hunt_to_collection(
        self,
        case_id: int,
        req: ConvertHuntToCollectionRequest,
        actor: str = "SecAnalyst-1",
    ) -> Dict[str, Any]:
        """Add selected hunt result items to a logical evidence collection."""
        from logintel.collections.service import workbench_service
        from logintel.collections.models import AddCollectionItemRequest, EvidenceItemRole

        key = (case_id, req.hunt_id)
        hunt_res = self._hunt_results.get(key)
        if not hunt_res:
            raise ValueError(f"Hunt result {req.hunt_id} not found for case {case_id}")

        selected_items = [it for it in hunt_res.results if it.result_id in req.result_ids or it.source_id in req.result_ids]
        if not selected_items:
            raise ValueError("No matching hunt result items selected for collection")

        added_count = 0
        role_enum = EvidenceItemRole.CONTRADICTING if req.role.upper() == "CONTRADICTING" else EvidenceItemRole.SUPPORTING

        for it in selected_items:
            workbench_service.add_item_to_collection(
                case_id=case_id,
                collection_id=req.collection_id,
                source_type=it.source_type,
                source_id=it.source_id,
                role=role_enum.value,
                citation_tag=it.citation_tag,
                analyst_annotation=req.analyst_annotation or f"Imported from hunt {req.hunt_id}: {it.summary}",
                actor=actor,
            )
            added_count += 1

        self._log_audit(
            case_id=case_id,
            action="HUNT_ADDED_TO_COLLECTION",
            actor=actor,
            reason=f"Added {added_count} hunt results to collection {req.collection_id}",
            details={"hunt_id": req.hunt_id, "collection_id": req.collection_id, "count": added_count},
        )

        return {
            "case_id": case_id,
            "collection_id": req.collection_id,
            "added_count": added_count,
        }

    # =========================================================================
    # 6. Local AI Advisory Assistance
    # =========================================================================

    def ai_assisted_hunt_proposal(
        self,
        case_id: int,
        req: AIHuntProposalRequest,
    ) -> GovernedQueryModel:
        """Deterministic local AI parsing translating natural language into governed structured query."""
        self._ensure_case_exists(case_id)
        q_lower = req.natural_language_question.lower()

        # Deterministic intent classification
        intent = HuntIntent.PROCESS_EXECUTION
        field_filters: List[FieldFilter] = []
        entity_filters: List[EntityFilter] = []

        if any(w in q_lower for w in ("ssh", "login", "auth", "failed", "password")):
            intent = HuntIntent.AUTHENTICATION_ACTIVITY
            field_filters.append(FieldFilter(field="event_type", operator=QueryOperator.CONTAINS, value="auth"))
        elif any(w in q_lower for w in ("sudo", "root", "privilege", "escalat")):
            intent = HuntIntent.PRIVILEGE_ESCALATION
            field_filters.append(FieldFilter(field="action", operator=QueryOperator.CONTAINS, value="sudo"))
        elif any(w in q_lower for w in ("network", "socket", "connect", "port", "ip")):
            intent = HuntIntent.NETWORK_CONNECTION
            field_filters.append(FieldFilter(field="source", operator=QueryOperator.CONTAINS, value="network"))
        elif any(w in q_lower for w in ("file", "write", "modify", "delete", "hvt")):
            intent = HuntIntent.FILE_ACTIVITY
            field_filters.append(FieldFilter(field="action", operator=QueryOperator.CONTAINS, value="write"))
        elif any(w in q_lower for w in ("systemd", "service", "daemon")):
            intent = HuntIntent.SYSTEMD_SERVICE_ACTIVITY
            field_filters.append(FieldFilter(field="event_type", operator=QueryOperator.CONTAINS, value="systemd"))
        elif any(w in q_lower for w in ("container", "docker", "k8s", "namespace")):
            intent = HuntIntent.CONTAINER_ACTIVITY
            field_filters.append(FieldFilter(field="event_type", operator=QueryOperator.CONTAINS, value="container"))
        elif any(w in q_lower for w in ("across hosts", "multiple hosts", "cross host")):
            intent = HuntIntent.CROSS_HOST_ACTIVITY

        # Extract potential IP addresses
        ip_match = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", req.natural_language_question)
        if ip_match:
            entity_filters.append(EntityFilter(entity_type="IP", entity_value=ip_match.group(0)))

        # Extract potential usernames (e.g. user admin, root)
        user_match = re.search(r"\buser\s+([a-zA-Z0-9_\-]+)", q_lower)
        if user_match:
            entity_filters.append(EntityFilter(entity_type="USER", entity_value=user_match.group(1)))

        return GovernedQueryModel(
            case_id=case_id,
            intent=intent,
            question=req.natural_language_question,
            source_types=["events"],
            field_filters=field_filters,
            entity_filters=entity_filters,
            limit=100,
        )

    # =========================================================================
    # 7. Deterministic Export
    # =========================================================================

    def export_hunt(
        self,
        case_id: int,
        hunt_id: str,
        format_type: str = "json",
    ) -> HuntExportResponse:
        """Deterministic export of hunt definition, results, and manifest with Blake2b fingerprint."""
        self._ensure_case_exists(case_id)
        key = (case_id, hunt_id)
        if key not in self._hunt_results:
            # Try to execute if approved or fail
            self.execute_hunt(case_id, hunt_id)

        res = self._hunt_results[key]
        now_iso = datetime.now(timezone.utc).isoformat()

        if format_type.lower() == "csv":
            output = io.StringIO()
            writer = csv.writer(output, lineterminator="\n")
            writer.writerow(["result_id", "source_type", "source_id", "host", "timestamp", "summary", "action", "outcome", "username", "src_ip", "dst_ip", "epistemic_status", "provenance_hash"])
            for r in res.results:
                writer.writerow([r.result_id, r.source_type, r.source_id, r.host, r.timestamp, r.summary, r.action, r.outcome, r.username, r.src_ip, r.dst_ip, r.epistemic_status.value, r.provenance_hash])
            content = output.getvalue()
        else:
            manifest_dict = {
                "manifest_header": {
                    "case_id": case_id,
                    "hunt_id": hunt_id,
                    "executed_at": res.executed_at,
                    "format": "json",
                    "result_count": res.result_count,
                    "query_fingerprint": res.query_fingerprint,
                },
                "query": {
                    "intent": res.intent.value,
                    "question": res.question,
                    "status": res.status.value,
                    "approval_state": res.approval_state.value,
                    "approved_by": res.approved_by,
                    "executed_by": res.executed_by,
                },
                "results": [it.model_dump(mode="json") for it in res.results],
            }
            content = json.dumps(manifest_dict, indent=2, sort_keys=True)

        fp = hashlib.blake2b(content.encode(), digest_size=16).hexdigest()

        return HuntExportResponse(
            case_id=case_id,
            hunt_id=hunt_id,
            format=format_type.lower(),
            export_content=content,
            exported_at=now_iso,
            fingerprint=fp,
            result_count=res.result_count,
        )

    def list_hunts(self, case_id: int) -> List[Dict[str, Any]]:
        """List all hunt executions recorded for a case in case_query_history."""
        self._ensure_case_exists(case_id)
        conn = self.case_repo._get_connection()
        rows = conn.execute(
            """
            SELECT query_id, case_id, query_template_id, rationale, executed_by, executed_at, result_count, execution_status
            FROM case_query_history
            WHERE case_id = ?
            ORDER BY executed_at DESC, query_id ASC
            """,
            (case_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_hunt(self, case_id: int, hunt_id: str) -> Optional[HuntExecutionResult]:
        """Get cached execution result or return None."""
        self._ensure_case_exists(case_id)
        return self._hunt_results.get((case_id, hunt_id))


# Singleton instance
threat_hunting_service = ThreatHuntingService()
