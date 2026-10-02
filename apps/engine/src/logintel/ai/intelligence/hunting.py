"""Governed Threat Hunting Workflow Engine for LogIntel M5.6.

Implements strict proposal validation, parameter type checking, preview descriptions,
and safe execution against authoritative forensic tables with explicit result classification.
"""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional, Tuple
import uuid

from logintel.ai.domain.investigation_intel import (
    EpistemicStatus,
    GovernedThreatHuntExecution,
    GovernedThreatHuntProposal,
    InvestigationFinding,
    QueryResultStatus,
)
from logintel.storage.db import Database, db as default_db

# Strictly allowlisted threat hunt query templates
ALLOWED_HUNT_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "query_events": {
        "description": "General forensic event search with host, user, IP, and keyword filters.",
        "allowed_params": {"host", "username", "src_ip", "dst_ip", "process_name", "event_types", "search_text", "limit"},
    },
    "search_auth_failures": {
        "description": "Targeted hunt for failed authentication, sudo violations, and brute-force bursts.",
        "allowed_params": {"host", "username", "src_ip", "limit"},
    },
    "search_process_exec": {
        "description": "Process execution hunt targeting suspicious binary execution and parent lineage.",
        "allowed_params": {"host", "username", "process_name", "search_text", "limit"},
    },
    "search_network_conn": {
        "description": "Network connection hunt for lateral movement and outbound socket connections.",
        "allowed_params": {"host", "src_ip", "dst_ip", "limit"},
    },
}

SQL_INJECTION_PATTERN = re.compile(
    r"(\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|ATTACH|PRAGMA)\b|--|/\*|;|'\s*(OR|AND)\b|\b(OR|AND)\s+['\"0-9=])",
    re.IGNORECASE,
)


class GovernedThreatHuntManager:
    """Manages validation, preview, and execution of governed threat hunt queries."""

    def __init__(self, database: Optional[Database] = None) -> None:
        self.db = database or default_db

    def create_proposal(
        self,
        case_id: int,
        template_id: str,
        parameters: Dict[str, Any],
        rationale: str,
        suggested_by: str = "SecAnalyst-1",
    ) -> GovernedThreatHuntProposal:
        """Validate and create a threat hunt proposal with read-only preview."""
        errors: List[str] = []

        if template_id not in ALLOWED_HUNT_TEMPLATES:
            raise ValueError(f"Unknown or unapproved query template '{template_id}'. Allowed: {list(ALLOWED_HUNT_TEMPLATES.keys())}")

        template_def = ALLOWED_HUNT_TEMPLATES.get(template_id, {})
        allowed_params = template_def.get("allowed_params", set())

        # Check for disallowed parameters
        disallowed = set(parameters.keys()) - allowed_params
        if disallowed:
            errors.append(f"Disallowed parameters for template '{template_id}': {list(disallowed)}")

        # Check for SQL injection in parameter values
        for k, v in parameters.items():
            if isinstance(v, str) and SQL_INJECTION_PATTERN.search(v):
                errors.append(f"Potential SQL injection detected in parameter '{k}': {v}")

        # Limit bounds
        limit = parameters.get("limit", 50)
        if not isinstance(limit, int) or limit < 1 or limit > 500:
            errors.append("Parameter 'limit' must be an integer between 1 and 500.")

        preview_desc = f"Execute governed hunt '{template_id}' with parameters: {parameters}."

        return GovernedThreatHuntProposal(
            proposal_id=f"hunt-{case_id}-{uuid.uuid4().hex[:8]}",
            case_id=case_id,
            template_id=template_id,
            parameters=parameters,
            rationale=rationale,
            validation_status="VALID" if not errors else "INVALID",
            validation_errors=errors,
            preview_query_description=preview_desc,
            suggested_by=suggested_by,
        )

    def execute_hunt(
        self,
        proposal: GovernedThreatHuntProposal,
        approved_by: str = "SecAnalyst-1",
    ) -> GovernedThreatHuntExecution:
        """Execute an analyst-approved governed threat hunt query against authoritative events."""
        if not approved_by or not approved_by.strip():
            return GovernedThreatHuntExecution(
                case_id=proposal.case_id,
                proposal_id=proposal.proposal_id,
                template_id=proposal.template_id,
                parameters=proposal.parameters,
                executed_by=proposal.suggested_by,
                approved_by="",
                executed_at=datetime.now(timezone.utc).isoformat(),
                result_status=QueryResultStatus.UNAVAILABLE,
                result_count=0,
                matched_items=[],
                candidate_findings=[],
            )

        if proposal.validation_status != "VALID":
            return GovernedThreatHuntExecution(
                case_id=proposal.case_id,
                proposal_id=proposal.proposal_id,
                template_id=proposal.template_id,
                parameters=proposal.parameters,
                executed_by=proposal.suggested_by,
                approved_by=approved_by,
                executed_at=datetime.now(timezone.utc).isoformat(),
                result_status=QueryResultStatus.INVALID,
                result_count=0,
                matched_items=[],
                candidate_findings=[],
            )

        # Build parameterized query safely based on template
        conditions: List[str] = []
        params: List[Any] = []
        p = proposal.parameters

        if proposal.template_id == "search_auth_failures":
            conditions.append("(source = 'auth.log' OR event_type LIKE '%auth%')")
            conditions.append("(outcome = 'FAILURE' OR action LIKE '%failed%' OR summary LIKE '%failed%')")
        elif proposal.template_id == "search_process_exec":
            conditions.append("(process_name IS NOT NULL OR source = 'auditd')")
        elif proposal.template_id == "search_network_conn":
            conditions.append("(src_ip IS NOT NULL OR dst_ip IS NOT NULL)")

        if p.get("host"):
            conditions.append("host = ?")
            params.append(p["host"])
        if p.get("username"):
            conditions.append("username = ?")
            params.append(p["username"])
        if p.get("src_ip"):
            conditions.append("src_ip = ?")
            params.append(p["src_ip"])
        if p.get("dst_ip"):
            conditions.append("dst_ip = ?")
            params.append(p["dst_ip"])
        if p.get("process_name"):
            conditions.append("process_name = ?")
            params.append(p["process_name"])
        if p.get("search_text"):
            conditions.append("(summary LIKE ? OR raw_message LIKE ?)")
            params.append(f"%{p['search_text']}%")
            params.append(f"%{p['search_text']}%")
        if p.get("event_types") and isinstance(p["event_types"], list):
            ph = ",".join("?" for _ in p["event_types"])
            conditions.append(f"event_type IN ({ph})")
            params.extend(p["event_types"])

        limit = min(500, max(1, int(p.get("limit", 50))))
        where_sql = " AND ".join(conditions) if conditions else "1=1"
        sql = f"""
            SELECT id, timestamp, source, event_type, severity, host, username,
                   process_name, src_ip, dst_ip, action, outcome, summary, raw_message
            FROM events
            WHERE {where_sql}
            ORDER BY timestamp DESC
            LIMIT ?
        """
        params.append(limit)

        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            with self.db.connection() as conn:
                cur = conn.cursor()
                rows = cur.execute(sql, params).fetchall()
                matched = [dict(r) for r in rows]
        except Exception:
            return GovernedThreatHuntExecution(
                case_id=proposal.case_id,
                proposal_id=proposal.proposal_id,
                template_id=proposal.template_id,
                parameters=proposal.parameters,
                executed_by=proposal.suggested_by,
                approved_by=approved_by,
                executed_at=now_iso,
                result_status=QueryResultStatus.FAILED,
                result_count=0,
                matched_items=[],
                candidate_findings=[],
            )

        status = QueryResultStatus.MATCHED if matched else QueryResultStatus.NO_MATCH
        if len(matched) == limit:
            status = QueryResultStatus.PARTIAL

        # Generate candidate findings from matched events
        candidate_findings: List[InvestigationFinding] = []
        if matched:
            candidate_findings.append(
                InvestigationFinding(
                    case_id=proposal.case_id,
                    finding_type="THREAT_HUNT_RESULT",
                    title=f"Threat Hunt: {proposal.template_id}",
                    description=f"Discovered {len(matched)} matching authoritative events matching rationale '{proposal.rationale}'.",
                    epistemic_status=EpistemicStatus.OBSERVED,
                    confidence_basis=f"Direct query match against authoritative events ({len(matched)} events).",
                    source_references=[f"[event:{m['id']}]" for m in matched[:10]],
                    related_entities=[f"host:{m['host']}" for m in matched if m.get("host")] + [f"user:{m['username']}" for m in matched if m.get("username")],
                    related_events=[str(m["id"]) for m in matched[:20]],
                    created_at=now_iso,
                    generated_by=f"THREAT_HUNT:{proposal.template_id}",
                )
            )

        return GovernedThreatHuntExecution(
            case_id=proposal.case_id,
            proposal_id=proposal.proposal_id,
            template_id=proposal.template_id,
            parameters=proposal.parameters,
            executed_by=proposal.suggested_by,
            approved_by=approved_by,
            executed_at=now_iso,
            result_status=status,
            result_count=len(matched),
            matched_items=matched,
            candidate_findings=candidate_findings,
        )
