"""Investigation Workspace Service for LogIntel Milestone 5.4.

Coordinates analyst investigation workflow, explicit scope boundaries, validated lifecycle transitions,
analyst-owned hypotheses, approved query execution, explainability tracing, structured summaries,
and citation-grounded report drafting.
"""

from __future__ import annotations

from datetime import datetime, timezone
import threading
import uuid
from typing import Any, Dict, List, Optional

from logintel.ai.domain.bundle import EvidenceItem, EvidenceRole
from logintel.ai.domain.evidence import EvidenceType
from logintel.ai.domain.intelligence import QueryProposal
from logintel.ai.domain.workspace import (
    ALLOWED_INVESTIGATION_TRANSITIONS,
    AnalystHypothesis,
    ClaimTrace,
    HypothesisStatus,
    InvestigationScope,
    InvestigationState,
    InvestigationStateAudit,
    InvestigationSummary,
    InvestigationWorkspace,
    ReportDraft,
)
from logintel.ai.evidence.retriever import EvidenceRetriever
from logintel.logging import get_logger
from logintel.storage.db import Database, db as default_db
from logintel.storage.incidents_repo import IncidentsRepository
from logintel.storage.investigation_repo import InvestigationRepository

logger = get_logger("ai.workspace")


class WorkspaceService:
    """Service managing analyst investigation workspaces, lifecycle state, hypotheses, and explainability."""

    def __init__(
        self,
        database: Optional[Database] = None,
        incidents_repository: Optional[IncidentsRepository] = None,
        investigation_repository: Optional[InvestigationRepository] = None,
    ) -> None:
        self.database = database or default_db
        self.incidents_repo = incidents_repository or IncidentsRepository(self.database)
        self.investigation_repo = investigation_repository or InvestigationRepository(self.database, self.incidents_repo)
        self.retriever = EvidenceRetriever(database=self.database)
        self._lock = threading.RLock()

        # In-memory workspace registry keyed by incident_id (guarantees zero mutation of baseline SQLite tables)
        self._workspaces: Dict[int, InvestigationWorkspace] = {}

    def get_or_create_workspace(self, incident_id: int, user_id: str = "SecAnalyst-1") -> InvestigationWorkspace:
        """Retrieve existing investigation workspace or initialize one with default scope."""
        with self._lock:
            if incident_id in self._workspaces:
                return self._workspaces[incident_id]

            incident = self.incidents_repo.get_incident(incident_id)
            if not incident:
                raise ValueError(f"Incident {incident_id} not found")

            alerts = self.incidents_repo.get_incident_alerts(incident_id)
            entities = self.incidents_repo.get_incident_entities(incident_id)

            now_iso = datetime.now(timezone.utc).isoformat()
            first_seen_iso = incident.first_seen.isoformat() if incident.first_seen else now_iso
            last_seen_iso = incident.last_seen.isoformat() if incident.last_seen else now_iso

            initial_scope = InvestigationScope(
                investigation_id=incident_id,
                time_start=first_seen_iso,
                time_end=last_seen_iso,
                subject_type="incident",
                subject_id=str(incident_id),
                selected_entity_ids=[e.entity_key for e in entities],
                selected_alert_ids=[a.id for a in alerts if a.id is not None],
                selected_detection_ids=[],
                selected_event_ids=[],
            )

            initial_audit = InvestigationStateAudit(
                timestamp=now_iso,
                actor=user_id,
                previous_state="NONE",
                new_state=InvestigationState.OPEN.value,
                reason="Initial workspace creation",
            )

            workspace = InvestigationWorkspace(
                investigation_id=incident_id,
                incident_id=incident_id,
                state=InvestigationState.OPEN,
                scope=initial_scope,
                hypotheses=[],
                evidence_candidates=[],
                notes=[],
                state_history=[initial_audit],
                created_at=now_iso,
                updated_at=now_iso,
            )

            self._workspaces[incident_id] = workspace
            return workspace

    def update_state(
        self,
        incident_id: int,
        target_state: InvestigationState,
        actor: str = "SecAnalyst-1",
        reason: Optional[str] = None,
    ) -> InvestigationWorkspace:
        """Explicitly transition investigation state with strict validation and audit logging."""
        with self._lock:
            workspace = self.get_or_create_workspace(incident_id, user_id=actor)
            current_state = workspace.state

            if current_state == target_state:
                return workspace

            allowed = ALLOWED_INVESTIGATION_TRANSITIONS.get(current_state, [])
            if target_state not in allowed:
                raise ValueError(
                    f"Invalid investigation state transition from {current_state.value} to {target_state.value}. "
                    f"Allowed transitions: {[s.value for s in allowed]}"
                )

            now_iso = datetime.now(timezone.utc).isoformat()
            audit_entry = InvestigationStateAudit(
                timestamp=now_iso,
                actor=actor,
                previous_state=current_state.value,
                new_state=target_state.value,
                reason=reason or f"State transitioned by {actor}",
            )

            workspace.state = target_state
            workspace.state_history.append(audit_entry)
            workspace.updated_at = now_iso
            return workspace

    def set_scope(self, incident_id: int, scope: InvestigationScope) -> InvestigationWorkspace:
        """Update explicit reproducible scope bounds for an investigation."""
        with self._lock:
            workspace = self.get_or_create_workspace(incident_id)
            workspace.scope = scope
            workspace.updated_at = datetime.now(timezone.utc).isoformat()
            return workspace

    def create_hypothesis(
        self,
        incident_id: int,
        statement: str,
        status: HypothesisStatus = HypothesisStatus.OPEN,
        supporting_tags: Optional[List[str]] = None,
        contradicting_tags: Optional[List[str]] = None,
        gaps: Optional[List[str]] = None,
        assessment: Optional[str] = None,
        created_by: str = "SecAnalyst-1",
    ) -> AnalystHypothesis:
        """Create an analyst-owned investigative hypothesis."""
        with self._lock:
            workspace = self.get_or_create_workspace(incident_id, user_id=created_by)
            now_iso = datetime.now(timezone.utc).isoformat()
            h_id = f"hyp-{incident_id}-{len(workspace.hypotheses) + 1}"

            hypothesis = AnalystHypothesis(
                hypothesis_id=h_id,
                investigation_id=incident_id,
                statement=statement.strip(),
                status=status,
                supporting_evidence_tags=supporting_tags or [],
                contradicting_evidence_tags=contradicting_tags or [],
                evidence_gaps=gaps or [],
                analyst_assessment=assessment,
                created_at=now_iso,
                updated_at=now_iso,
                created_by=created_by,
            )

            workspace.hypotheses.append(hypothesis)
            workspace.updated_at = now_iso
            return hypothesis

    def update_hypothesis(
        self,
        incident_id: int,
        hypothesis_id: str,
        status: Optional[HypothesisStatus] = None,
        assessment: Optional[str] = None,
        supporting_tags: Optional[List[str]] = None,
        contradicting_tags: Optional[List[str]] = None,
        gaps: Optional[List[str]] = None,
    ) -> AnalystHypothesis:
        """Update status, evidence associations, or assessment of a hypothesis."""
        with self._lock:
            workspace = self.get_or_create_workspace(incident_id)
            for idx, hyp in enumerate(workspace.hypotheses):
                if hyp.hypothesis_id == hypothesis_id:
                    now_iso = datetime.now(timezone.utc).isoformat()
                    updated = hyp.model_copy(
                        update={
                            "status": status if status is not None else hyp.status,
                            "analyst_assessment": assessment if assessment is not None else hyp.analyst_assessment,
                            "supporting_evidence_tags": supporting_tags if supporting_tags is not None else hyp.supporting_evidence_tags,
                            "contradicting_evidence_tags": contradicting_tags if contradicting_tags is not None else hyp.contradicting_evidence_tags,
                            "evidence_gaps": gaps if gaps is not None else hyp.evidence_gaps,
                            "updated_at": now_iso,
                        }
                    )
                    workspace.hypotheses[idx] = updated
                    workspace.updated_at = now_iso
                    return updated

            raise ValueError(f"Hypothesis {hypothesis_id} not found in investigation {incident_id}")

    def list_hypotheses(self, incident_id: int) -> List[AnalystHypothesis]:
        """List all analyst hypotheses registered for an investigation."""
        with self._lock:
            workspace = self.get_or_create_workspace(incident_id)
            return list(workspace.hypotheses)

    def execute_approved_query(
        self,
        incident_id: int,
        proposal: QueryProposal,
        actor: str = "SecAnalyst-1",
    ) -> Dict[str, Any]:
        """Execute analyst-approved threat hunting query deterministically and collect evidence candidates."""
        with self._lock:
            workspace = self.get_or_create_workspace(incident_id, user_id=actor)

            # Build safe parameterized query (NO raw SQL from model)
            conditions: List[str] = []
            params: List[Any] = []

            if proposal.host:
                conditions.append("host = ?")
                params.append(proposal.host)
            if proposal.username:
                conditions.append("username = ?")
                params.append(proposal.username)
            if proposal.src_ip:
                conditions.append("src_ip = ?")
                params.append(proposal.src_ip)
            if proposal.dst_ip:
                conditions.append("dst_ip = ?")
                params.append(proposal.dst_ip)
            if proposal.process_name:
                conditions.append("process_name = ?")
                params.append(proposal.process_name)
            if proposal.event_types:
                ph = ",".join("?" for _ in proposal.event_types)
                conditions.append(f"event_type IN ({ph})")
                params.extend(proposal.event_types)
            if proposal.search_text:
                conditions.append("(summary LIKE ? OR raw_message LIKE ?)")
                params.append(f"%{proposal.search_text}%")
                params.append(f"%{proposal.search_text}%")

            where_clause = " AND ".join(conditions) if conditions else "1=1"
            sql = f"""
                SELECT id, timestamp, source, event_type, severity, host, username,
                       process_name, src_ip, dst_ip, action, outcome, summary, raw_message
                FROM events
                WHERE {where_clause}
                ORDER BY timestamp DESC
                LIMIT 50
            """

            with self.database.connection() as conn:
                cursor = conn.cursor()
                rows = cursor.execute(sql, params).fetchall()

            matched_items: List[Dict[str, Any]] = []
            new_candidates: List[EvidenceItem] = []

            for r in rows:
                ev_id = str(r["id"])
                ev_dict = dict(r)
                matched_items.append(ev_dict)

                # Wrap as evidence candidate
                candidate = EvidenceItem(
                    evidence_id=ev_id,
                    evidence_type=EvidenceType.EVENT,
                    source_id=ev_id,
                    source_table="events",
                    timestamp=str(r["timestamp"]),
                    relevance_score=0.80,
                    role=EvidenceRole.SUPPORTING,
                    citation_tag=f"[event:{ev_id}]",
                    summary=r["summary"] or r["raw_message"][:100],
                    metadata={
                        "host": r["host"],
                        "source": r["source"],
                        "event_type": r["event_type"],
                        "discovered_via_query": proposal.proposal_id,
                    },
                )
                new_candidates.append(candidate)

            # Deduplicate by evidence_id
            existing_ids = {c.evidence_id for c in workspace.evidence_candidates}
            for c in new_candidates:
                if c.evidence_id not in existing_ids:
                    workspace.evidence_candidates.append(c)
                    existing_ids.add(c.evidence_id)

            workspace.updated_at = datetime.now(timezone.utc).isoformat()

            return {
                "investigation_id": incident_id,
                "proposal_id": proposal.proposal_id,
                "title": proposal.title,
                "executed_at": datetime.now(timezone.utc).isoformat(),
                "actor": actor,
                "matched_events_count": len(matched_items),
                "matched_events": matched_items,
                "total_candidate_evidence": len(workspace.evidence_candidates),
            }

    def generate_investigation_summary(self, incident_id: int) -> InvestigationSummary:
        """Synthesize a complete deterministic investigation summary covering all required sections."""
        with self._lock:
            workspace = self.get_or_create_workspace(incident_id)
            dossier = self.investigation_repo.get_investigation_dossier(incident_id)
            if not dossier:
                raise ValueError(f"Investigation {incident_id} dossier not found")

            bundle = self.retriever.retrieve_bundle(incident_id=incident_id)

            key_obs = [
                f"Incident '{dossier['incident'].get('title')}' with severity {dossier['incident'].get('severity')}.",
                f"Primary host: {dossier['incident'].get('primary_host')}, primary user: {dossier['incident'].get('primary_user')}.",
                f"Correlated alerts count: {len(dossier.get('alerts', []))}, attack steps: {dossier.get('attack_path', {}).get('total_steps', 0)}.",
            ]

            supporting_evidence = [
                {"tag": item.citation_tag, "summary": item.summary, "role": item.role.value, "timestamp": item.timestamp}
                for item in bundle.items
                if item.role in (EvidenceRole.PRIMARY, EvidenceRole.SUPPORTING, EvidenceRole.CORROBORATING)
            ]

            contradicting_evidence = [
                {"tag": item.citation_tag, "summary": item.summary, "role": item.role.value, "timestamp": item.timestamp}
                for item in bundle.items
                if item.role == EvidenceRole.CONTRADICTING
            ]

            gaps = [
                {"gap_id": g.gap_id, "category": g.category, "gap_type": g.gap_type, "impact": g.impact}
                for g in bundle.gaps
            ]

            mitre_ctx = [
                {
                    "technique_id": m.get("technique_id"),
                    "technique_name": m.get("technique_name"),
                    "tactic": m.get("tactic"),
                    "evidence_count": m.get("evidence_event_count", 0),
                }
                for m in dossier.get("mitre_mappings", [])
            ]

            hyp_list = [h.model_dump() for h in workspace.hypotheses]

            open_questions = [
                "Are there additional credentials compromised on this host?",
                "What persistence mechanisms were established following initial access?",
                "Did lateral movement occur outside the current collection scope?",
            ]

            return InvestigationSummary(
                investigation_id=incident_id,
                scope=workspace.scope.model_dump(),
                subject=dossier["incident"],
                key_observations=key_obs,
                timeline=dossier.get("timeline", [])[:20],
                entities=dossier.get("entities", []),
                detections=[],
                alerts=dossier.get("alerts", []),
                attack_path=dossier.get("attack_path", {}),
                hypotheses=hyp_list,
                evidence_supporting=supporting_evidence,
                evidence_contradicting=contradicting_evidence,
                evidence_gaps=gaps,
                mitre_context=mitre_ctx,
                analyst_notes=dossier.get("notes", []),
                ai_assisted_analysis={
                    "total_evidence_items": len(bundle.items),
                    "coverage_ratio": round(len(bundle.coverage.available_evidence_types) / max(1, len(bundle.coverage.required_evidence_types)), 2),
                    "conflicts_identified": len(bundle.conflicts),
                },
                open_questions=open_questions,
            )

    def generate_report_draft(self, incident_id: int) -> ReportDraft:
        """Generate an explainable AI report draft distinguishing facts, inferences, hypotheses, and unknowns."""
        with self._lock:
            workspace = self.get_or_create_workspace(incident_id)
            dossier = self.investigation_repo.get_investigation_dossier(incident_id)
            if not dossier:
                raise ValueError(f"Investigation {incident_id} not found")

            bundle = self.retriever.retrieve_bundle(incident_id=incident_id)
            inc = dossier["incident"]
            now_iso = datetime.now(timezone.utc).isoformat()

            # 1. Facts (Directly supported by cited evidence tags)
            facts: List[Dict[str, Any]] = []
            for item in bundle.items[:8]:
                if item.role in (EvidenceRole.PRIMARY, EvidenceRole.SUPPORTING):
                    facts.append({
                        "statement": item.summary,
                        "evidence_tag": item.citation_tag,
                        "source": item.source_table,
                        "timestamp": item.timestamp,
                        "epistemic_status": "OBSERVED",
                    })

            # 2. Inferences (Analytical deductions requiring supporting citations)
            inferences: List[Dict[str, Any]] = []
            if bundle.conflicts:
                for c in bundle.conflicts:
                    inferences.append({
                        "statement": c.explanation,
                        "evidence_tags": [c.evidence_tag_a, c.evidence_tag_b],
                        "epistemic_status": "INFERRED",
                        "rationale": f"Identified {c.conflict_type} between cited telemetry records.",
                    })
            else:
                inferences.append({
                    "statement": f"Observed authentication events on host {inc.get('primary_host')} indicate targeted access activity.",
                    "evidence_tags": [i.citation_tag for i in bundle.items[:2]],
                    "epistemic_status": "INFERRED",
                    "rationale": "Temporal sequence aligns with known access patterns.",
                })

            # 3. Hypotheses (Potential explanations)
            hypotheses = [
                {
                    "statement": h.statement,
                    "status": h.status.value,
                    "supporting_evidence": h.supporting_evidence_tags,
                    "contradicting_evidence": h.contradicting_evidence_tags,
                    "assessment": h.analyst_assessment or "Pending analyst review",
                }
                for h in workspace.hypotheses
            ]

            # 4. Unknowns (Telemetry gaps & blind spots)
            unknowns = [f"{g.category} ({g.gap_type}): {g.impact}" for g in bundle.gaps]

            recommendations = [
                "Review primary host logs for unauthorized user account creation.",
                "Verify validity of credentials used during the reported timeframe.",
                "Deploy auditd monitoring on the target host to close process visibility gaps.",
            ]

            return ReportDraft(
                report_id=f"rep-{incident_id}-{uuid.uuid4().hex[:8]}",
                investigation_id=incident_id,
                generated_at=now_iso,
                title=f"Investigation Report: {inc.get('title')} ({inc.get('incident_key')})",
                executive_summary=(
                    f"Investigation into incident {inc.get('incident_key')} involving host {inc.get('primary_host')} "
                    f"and user {inc.get('primary_user')}. Analysis encompasses {len(bundle.items)} retrieved evidence "
                    f"records, {len(bundle.gaps)} telemetry gaps, and {len(workspace.hypotheses)} registered hypotheses."
                ),
                facts=facts,
                inferences=inferences,
                hypotheses=hypotheses,
                unknowns=unknowns,
                recommendations=recommendations,
                is_draft=True,
            )

    def trace_claim_explainability(
        self,
        incident_id: int,
        claim_text: str,
        citation_tags: List[str],
    ) -> List[ClaimTrace]:
        """Trace each cited evidence tag back to its authoritative database origin."""
        bundle = self.retriever.retrieve_bundle(incident_id=incident_id)
        tag_map = {item.citation_tag: item for item in bundle.items}

        traces: List[ClaimTrace] = []
        for tag in citation_tags:
            item = tag_map.get(tag)
            if item:
                # Query raw evidence dictionary from authoritative source
                raw_rec: Optional[Dict[str, Any]] = None
                with self.database.connection() as conn:
                    if item.source_table == "events":
                        row = conn.execute("SELECT * FROM events WHERE id = ?", (item.source_id,)).fetchone()
                        if row:
                            raw_rec = dict(row)
                    elif item.source_table == "alerts":
                        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (item.source_id,)).fetchone()
                        if row:
                            raw_rec = dict(row)

                traces.append(
                    ClaimTrace(
                        claim_text=claim_text,
                        epistemic_status="OBSERVED" if item.role == EvidenceRole.PRIMARY else "SUPPORTING",
                        citation_tag=tag,
                        evidence_type=item.evidence_type.value,
                        evidence_id=item.evidence_id,
                        source_table=item.source_table,
                        source_id=item.source_id,
                        timestamp=item.timestamp,
                        summary=item.summary,
                        raw_evidence=raw_rec,
                    )
                )
            else:
                traces.append(
                    ClaimTrace(
                        claim_text=claim_text,
                        epistemic_status="UNKNOWN",
                        citation_tag=tag,
                        evidence_type="UNKNOWN",
                        evidence_id="UNKNOWN",
                        source_table="UNKNOWN",
                        source_id="UNKNOWN",
                        summary="Citation tag not present in current investigation context",
                    )
                )

        return traces


# Global singleton instance
workspace_service = WorkspaceService()
