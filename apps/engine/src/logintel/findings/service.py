"""Findings & Hypothesis Workbench Service for LogIntel Milestone 7.4.

Provides case-scoped management of analyst-authored findings, hypotheses,
evidence relationships, versioning, review workflows, categorical comparisons,
and deterministic exports.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import io
import json
from typing import Any, Dict, List, Optional
import uuid

from logintel.ai.domain.case import CaseHypothesis
from logintel.ai.domain.workspace import HypothesisStatus
from logintel.config import settings
from logintel.findings.models import (
    AddFindingEvidenceRequest,
    AddHypothesisGapRequest,
    CreateFindingRequest,
    CreateHypothesisM74Request,
    EpistemicStatus,
    EvidenceGap,
    EvidenceGapType,
    Finding,
    FindingEvidenceReference,
    FindingEvidenceRole,
    FindingLifecycleStatus,
    FindingReviewStatus,
    FindingsExportResponse,
    FindingsWorkbenchResponse,
    FindingVersion,
    HypothesisAssessmentView,
    HypothesisComparisonItem,
    HypothesisComparisonResponse,
    HypothesisLifecycleStatus,
    ReviewFindingRequest,
    UpdateFindingRequest,
    UpdateHypothesisM74Request,
)
from logintel.logging import get_logger
from logintel.storage.case_repo import CaseRepository
from logintel.storage.db import Database, db as default_forensic_db

logger = get_logger("findings.service")


class FindingsWorkbenchService:
    """Service orchestrating findings, hypotheses, evidence evaluations, and exports."""

    def __init__(
        self,
        case_repo: Optional[CaseRepository] = None,
        forensic_db: Optional[Database] = None,
    ) -> None:
        self.case_repo = case_repo or CaseRepository()
        self.forensic_db = forensic_db or default_forensic_db

    def _ensure_case_exists(self, case_id: int) -> None:
        """Verify that case exists; raise ValueError if not found."""
        case = self.case_repo.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")

    def _log_audit(
        self,
        case_id: int,
        action: str,
        actor: str,
        reason: str,
        details: Dict[str, Any],
    ) -> None:
        """Append an audit record to the case audit log."""
        try:
            conn = self.case_repo._get_connection()
            now_iso = datetime.now(timezone.utc).isoformat()
            with conn:
                conn.execute(
                    """
                    INSERT INTO case_audit_log (
                        case_id, timestamp, actor, action, reason, details_json
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (case_id, now_iso, actor, action, reason, json.dumps(details)),
                )
        except Exception as e:
            logger.warning("Failed to record case audit log for case %s (%s): %s", case_id, action, e)

    # -------------------------------------------------------------------------
    # Findings CRUD & Lifecycle
    # -------------------------------------------------------------------------

    def get_findings(self, case_id: int) -> List[Finding]:
        """List all analyst-authored findings for a case."""
        self._ensure_case_exists(case_id)
        conn = self.case_repo._get_connection()

        rows = conn.execute(
            """
            SELECT * FROM case_evidence_references
            WHERE case_id = ? AND source_type = 'analyst_finding'
            ORDER BY created_at ASC
            """,
            (case_id,),
        ).fetchall()

        reviews_rows = conn.execute(
            "SELECT * FROM case_finding_reviews WHERE case_id = ?",
            (case_id,),
        ).fetchall()
        reviews_map = {r["finding_id"]: dict(r) for r in reviews_rows}

        findings: List[Finding] = []
        for row in rows:
            annotation_raw = row["analyst_annotation"]
            if not annotation_raw:
                continue
            try:
                data = json.loads(annotation_raw)
                finding_id = row["reference_id"]
                # Overlay latest review if present in case_finding_reviews
                if finding_id in reviews_map:
                    rev = reviews_map[finding_id]
                    data["review_status"] = rev["review_state"]
                    data["reviewed_by"] = rev["reviewed_by"]
                    data["reviewed_at"] = rev["reviewed_at"]
                    if rev.get("analyst_notes"):
                        data["analyst_notes"] = rev["analyst_notes"]
                findings.append(Finding(**data))
            except Exception as e:
                logger.error("Failed to parse finding %s: %s", row["reference_id"], e)

        return findings

    def get_finding(self, case_id: int, finding_id: str) -> Finding:
        """Retrieve a specific finding by ID."""
        self._ensure_case_exists(case_id)
        conn = self.case_repo._get_connection()

        row = conn.execute(
            """
            SELECT * FROM case_evidence_references
            WHERE case_id = ? AND reference_id = ? AND source_type = 'analyst_finding'
            """,
            (case_id, finding_id),
        ).fetchone()

        if not row:
            raise ValueError(f"Finding {finding_id} not found in case {case_id}")

        data = json.loads(row["analyst_annotation"])

        # Check review state
        rev_row = conn.execute(
            "SELECT * FROM case_finding_reviews WHERE case_id = ? AND finding_id = ?",
            (case_id, finding_id),
        ).fetchone()
        if rev_row:
            data["review_status"] = rev_row["review_state"]
            data["reviewed_by"] = rev_row["reviewed_by"]
            data["reviewed_at"] = rev_row["reviewed_at"]
            if rev_row["analyst_notes"]:
                data["analyst_notes"] = rev_row["analyst_notes"]

        return Finding(**data)

    def create_finding(
        self,
        case_id: int,
        req: CreateFindingRequest,
        actor: str = "analyst",
    ) -> Finding:
        """Create a new analyst-authored finding with strict epistemic separation."""
        self._ensure_case_exists(case_id)
        conn = self.case_repo._get_connection()
        now_iso = datetime.now(timezone.utc).isoformat()
        finding_id = f"FND-{case_id}-{uuid.uuid4().hex[:8]}"

        # Resolve initial supporting evidence
        supporting_items: List[FindingEvidenceReference] = []
        for raw in req.supporting_evidence:
            s_type = raw.get("source_type", "event")
            s_id = str(raw.get("source_id", ""))
            if not s_id:
                continue
            ref_item = FindingEvidenceReference(
                reference_id=f"REF-{uuid.uuid4().hex[:8]}",
                source_type=s_type,
                source_id=s_id,
                citation_tag=raw.get("citation_tag") or f"{s_type.upper()}-{s_id}",
                role=FindingEvidenceRole.SUPPORTING,
                epistemic_status=EpistemicStatus(raw.get("epistemic_status", EpistemicStatus.OBSERVED.value)),
                collection_id=raw.get("collection_id"),
                analyst_note=raw.get("analyst_note"),
                host=raw.get("host"),
                timestamp=raw.get("timestamp"),
                added_at=now_iso,
                provenance_hash=hashlib.sha256(f"{s_type}:{s_id}".encode()).hexdigest()[:16],
            )
            supporting_items.append(ref_item)

        # Resolve initial contradicting evidence
        contradicting_items: List[FindingEvidenceReference] = []
        for raw in req.contradicting_evidence:
            s_type = raw.get("source_type", "event")
            s_id = str(raw.get("source_id", ""))
            if not s_id:
                continue
            ref_item = FindingEvidenceReference(
                reference_id=f"REF-{uuid.uuid4().hex[:8]}",
                source_type=s_type,
                source_id=s_id,
                citation_tag=raw.get("citation_tag") or f"{s_type.upper()}-{s_id}",
                role=FindingEvidenceRole.CONTRADICTING,
                epistemic_status=EpistemicStatus(raw.get("epistemic_status", EpistemicStatus.OBSERVED.value)),
                collection_id=raw.get("collection_id"),
                analyst_note=raw.get("analyst_note"),
                host=raw.get("host"),
                timestamp=raw.get("timestamp"),
                added_at=now_iso,
                provenance_hash=hashlib.sha256(f"{s_type}:{s_id}".encode()).hexdigest()[:16],
            )
            contradicting_items.append(ref_item)

        finding = Finding(
            finding_id=finding_id,
            case_id=case_id,
            title=req.title,
            statement=req.statement,
            epistemic_status=req.epistemic_status,
            review_status=FindingReviewStatus.UNREVIEWED,
            lifecycle_status=FindingLifecycleStatus.ACTIVE,
            severity=req.severity,
            supporting_evidence=supporting_items,
            contradicting_evidence=contradicting_items,
            supporting_collections=req.supporting_collections,
            related_hypotheses=req.related_hypotheses,
            contradicting_hypotheses=req.contradicting_hypotheses,
            analyst_notes=req.analyst_notes,
            version=1,
            version_history=[],
            created_at=now_iso,
            updated_at=now_iso,
            created_by=actor,
            provenance={
                "origin": "ANALYST_AUTHORED",
                "case_id": case_id,
                "created_by": actor,
                "epistemic_status": req.epistemic_status.value,
            },
        )

        with conn:
            conn.execute(
                """
                INSERT INTO case_evidence_references (
                    reference_id, case_id, source_type, source_id, role,
                    epistemic_status, citation_tag, analyst_annotation, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    case_id,
                    "analyst_finding",
                    finding_id,
                    "PRIMARY",
                    req.epistemic_status.value,
                    "FINDING",
                    json.dumps(finding.model_dump(mode="json")),
                    now_iso,
                ),
            )

        self._log_audit(
            case_id=case_id,
            action="FINDING_CREATED",
            actor=actor,
            reason=f"Created finding {finding_id}",
            details={"finding_id": finding_id, "title": req.title, "epistemic_status": req.epistemic_status.value},
        )

        return finding

    def update_finding(
        self,
        case_id: int,
        finding_id: str,
        req: UpdateFindingRequest,
        actor: str = "analyst",
    ) -> Finding:
        """Update finding statement or attributes, creating a deterministic version."""
        finding = self.get_finding(case_id, finding_id)
        conn = self.case_repo._get_connection()
        now_iso = datetime.now(timezone.utc).isoformat()

        # Archive current state into version history
        old_version = FindingVersion(
            version=finding.version,
            title=finding.title,
            statement=finding.statement,
            epistemic_status=finding.epistemic_status,
            updated_at=finding.updated_at,
            updated_by=finding.created_by,
            change_summary=req.change_summary,
        )
        finding.version_history.append(old_version)
        finding.version += 1

        if req.title is not None:
            finding.title = req.title
        if req.statement is not None:
            finding.statement = req.statement
        if req.epistemic_status is not None:
            finding.epistemic_status = req.epistemic_status
        if req.severity is not None:
            finding.severity = req.severity
        if req.lifecycle_status is not None:
            finding.lifecycle_status = req.lifecycle_status
        if req.supporting_collections is not None:
            finding.supporting_collections = req.supporting_collections
        if req.related_hypotheses is not None:
            finding.related_hypotheses = req.related_hypotheses
        if req.contradicting_hypotheses is not None:
            finding.contradicting_hypotheses = req.contradicting_hypotheses
        if req.analyst_notes is not None:
            finding.analyst_notes = req.analyst_notes

        finding.updated_at = now_iso

        with conn:
            conn.execute(
                """
                UPDATE case_evidence_references
                SET epistemic_status = ?, analyst_annotation = ?
                WHERE case_id = ? AND reference_id = ? AND source_type = 'analyst_finding'
                """,
                (
                    finding.epistemic_status.value,
                    json.dumps(finding.model_dump(mode="json")),
                    case_id,
                    finding_id,
                ),
            )

        self._log_audit(
            case_id=case_id,
            action="FINDING_UPDATED",
            actor=actor,
            reason=f"Updated finding {finding_id} to version {finding.version}",
            details={"finding_id": finding_id, "version": finding.version, "summary": req.change_summary},
        )

        return finding

    def review_finding(
        self,
        case_id: int,
        finding_id: str,
        req: ReviewFindingRequest,
        actor: str = "analyst",
    ) -> Finding:
        """Perform analyst review on finding. Strictly decouples review from epistemic status."""
        finding = self.get_finding(case_id, finding_id)
        now_iso = datetime.now(timezone.utc).isoformat()
        conn = self.case_repo._get_connection()

        finding.review_status = req.review_status
        finding.reviewed_by = req.reviewed_by
        finding.reviewed_at = now_iso
        if req.analyst_notes:
            finding.analyst_notes = req.analyst_notes
        finding.updated_at = now_iso

        with conn:
            # 1. Update finding in case_evidence_references
            conn.execute(
                """
                UPDATE case_evidence_references
                SET analyst_annotation = ?
                WHERE case_id = ? AND reference_id = ? AND source_type = 'analyst_finding'
                """,
                (json.dumps(finding.model_dump(mode="json")), case_id, finding_id),
            )

            # 2. Upsert into case_finding_reviews
            review_id = f"REV-{case_id}-{finding_id}"
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
                (
                    review_id,
                    case_id,
                    finding_id,
                    req.review_status.value,
                    req.analyst_notes,
                    req.reviewed_by,
                    now_iso,
                ),
            )

        self._log_audit(
            case_id=case_id,
            action="FINDING_REVIEWED",
            actor=actor,
            reason=f"Reviewed finding {finding_id} -> {req.review_status.value}",
            details={"finding_id": finding_id, "review_status": req.review_status.value},
        )

        return finding

    def delete_finding(self, case_id: int, finding_id: str, actor: str = "analyst") -> bool:
        """Delete finding organizational record. Underlying authoritative evidence is preserved."""
        self._ensure_case_exists(case_id)
        conn = self.case_repo._get_connection()

        row = conn.execute(
            """
            SELECT * FROM case_evidence_references
            WHERE case_id = ? AND reference_id = ? AND source_type = 'analyst_finding'
            """,
            (case_id, finding_id),
        ).fetchone()

        if not row:
            raise ValueError(f"Finding {finding_id} not found in case {case_id}")

        with conn:
            conn.execute(
                """
                DELETE FROM case_evidence_references
                WHERE case_id = ? AND reference_id = ? AND source_type = 'analyst_finding'
                """,
                (case_id, finding_id),
            )
            conn.execute(
                "DELETE FROM case_finding_reviews WHERE case_id = ? AND finding_id = ?",
                (case_id, finding_id),
            )

        self._log_audit(
            case_id=case_id,
            action="FINDING_DELETED",
            actor=actor,
            reason=f"Deleted finding {finding_id} (underlying evidence preserved)",
            details={"finding_id": finding_id},
        )

        return True

    def add_finding_evidence(
        self,
        case_id: int,
        finding_id: str,
        req: AddFindingEvidenceRequest,
        actor: str = "analyst",
    ) -> Finding:
        """Attach supporting or contradicting evidence reference to a finding."""
        finding = self.get_finding(case_id, finding_id)
        now_iso = datetime.now(timezone.utc).isoformat()
        conn = self.case_repo._get_connection()

        # Target list selection
        target_list = (
            finding.contradicting_evidence
            if req.role == FindingEvidenceRole.CONTRADICTING
            else finding.supporting_evidence
        )

        # Idempotency check: don't duplicate identical (source_type, source_id, role)
        for existing in target_list:
            if existing.source_type == req.source_type and existing.source_id == req.source_id:
                return finding

        ref_item = FindingEvidenceReference(
            reference_id=f"REF-{uuid.uuid4().hex[:8]}",
            source_type=req.source_type,
            source_id=req.source_id,
            citation_tag=req.citation_tag or f"{req.source_type.upper()}-{req.source_id}",
            role=req.role,
            epistemic_status=req.epistemic_status,
            collection_id=req.collection_id,
            analyst_note=req.analyst_note,
            host=req.host,
            timestamp=req.timestamp,
            added_at=now_iso,
            provenance_hash=hashlib.sha256(f"{req.source_type}:{req.source_id}".encode()).hexdigest()[:16],
        )

        target_list.append(ref_item)
        finding.updated_at = now_iso

        with conn:
            conn.execute(
                """
                UPDATE case_evidence_references
                SET analyst_annotation = ?
                WHERE case_id = ? AND reference_id = ? AND source_type = 'analyst_finding'
                """,
                (json.dumps(finding.model_dump(mode="json")), case_id, finding_id),
            )

        self._log_audit(
            case_id=case_id,
            action="FINDING_EVIDENCE_ADDED",
            actor=actor,
            reason=f"Added {req.role.value} evidence {req.source_id} to finding {finding_id}",
            details={"finding_id": finding_id, "source_type": req.source_type, "source_id": req.source_id, "role": req.role.value},
        )

        return finding

    def remove_finding_evidence(
        self,
        case_id: int,
        finding_id: str,
        source_id: str,
        actor: str = "analyst",
    ) -> Finding:
        """Remove evidence reference from finding. Underlying evidence remains preserved."""
        finding = self.get_finding(case_id, finding_id)
        now_iso = datetime.now(timezone.utc).isoformat()
        conn = self.case_repo._get_connection()

        finding.supporting_evidence = [e for e in finding.supporting_evidence if e.source_id != source_id]
        finding.contradicting_evidence = [e for e in finding.contradicting_evidence if e.source_id != source_id]
        finding.updated_at = now_iso

        with conn:
            conn.execute(
                """
                UPDATE case_evidence_references
                SET analyst_annotation = ?
                WHERE case_id = ? AND reference_id = ? AND source_type = 'analyst_finding'
                """,
                (json.dumps(finding.model_dump(mode="json")), case_id, finding_id),
            )

        self._log_audit(
            case_id=case_id,
            action="FINDING_EVIDENCE_REMOVED",
            actor=actor,
            reason=f"Removed evidence reference {source_id} from finding {finding_id}",
            details={"finding_id": finding_id, "source_id": source_id},
        )

        return finding

    # -------------------------------------------------------------------------
    # Hypotheses & Evidence Assessment
    # -------------------------------------------------------------------------

    def get_hypotheses(self, case_id: int) -> List[HypothesisAssessmentView]:
        """List and enrich all persistent hypotheses recorded for a case."""
        self._ensure_case_exists(case_id)
        raw_list = self.case_repo.list_hypotheses(case_id)
        findings = self.get_findings(case_id)

        enriched: List[HypothesisAssessmentView] = []
        for h in raw_list:
            sup_items: List[FindingEvidenceReference] = []
            for tag in h.supporting_evidence_tags:
                tag_hash = hashlib.sha256(f"{h.hypothesis_id}:sup:{tag}".encode()).hexdigest()[:8]
                sup_items.append(
                    FindingEvidenceReference(
                        reference_id=f"REF-{h.hypothesis_id}-{tag_hash}",
                        source_type="evidence_reference",
                        source_id=tag,
                        citation_tag=tag,
                        role=FindingEvidenceRole.SUPPORTING,
                        epistemic_status=EpistemicStatus.OBSERVED,
                        added_at=h.created_at,
                    )
                )

            con_items: List[FindingEvidenceReference] = []
            for tag in h.contradicting_evidence_tags:
                tag_hash = hashlib.sha256(f"{h.hypothesis_id}:con:{tag}".encode()).hexdigest()[:8]
                con_items.append(
                    FindingEvidenceReference(
                        reference_id=f"REF-{h.hypothesis_id}-{tag_hash}",
                        source_type="evidence_reference",
                        source_id=tag,
                        citation_tag=tag,
                        role=FindingEvidenceRole.CONTRADICTING,
                        epistemic_status=EpistemicStatus.OBSERVED,
                        added_at=h.created_at,
                    )
                )

            gaps_items: List[EvidenceGap] = []
            for g_str in h.evidence_gaps:
                gap_hash = hashlib.sha256(f"{h.hypothesis_id}:gap:{g_str}".encode()).hexdigest()[:8]
                gaps_items.append(
                    EvidenceGap(
                        gap_id=f"GAP-{h.hypothesis_id}-{gap_hash}",
                        gap_type=EvidenceGapType.UNKNOWN,
                        description=g_str,
                        expected_source="telemetry",
                        affected_hypotheses=[h.hypothesis_id],
                    )
                )

            # Match linking findings
            sup_findings = [f.finding_id for f in findings if h.hypothesis_id in f.related_hypotheses]
            con_findings = [f.finding_id for f in findings if h.hypothesis_id in f.contradicting_hypotheses]

            enriched.append(
                HypothesisAssessmentView(
                    hypothesis_id=h.hypothesis_id,
                    case_id=h.case_id,
                    title=f"Hypothesis {h.hypothesis_id}",
                    statement=h.statement,
                    status=HypothesisLifecycleStatus(h.status.value if isinstance(h.status, HypothesisStatus) else h.status),
                    version=h.version,
                    supporting_evidence=sup_items,
                    contradicting_evidence=con_items,
                    evidence_gaps=gaps_items,
                    relevant_collections=[],
                    supporting_findings=sup_findings,
                    contradicting_findings=con_findings,
                    analyst_assessment=h.analyst_assessment,
                    created_by=h.created_by,
                    created_at=h.created_at,
                    updated_at=h.updated_at,
                )
            )

        return enriched

    def create_hypothesis(
        self,
        case_id: int,
        req: CreateHypothesisM74Request,
        actor: str = "SecAnalyst-1",
    ) -> HypothesisAssessmentView:
        """Create a new investigative hypothesis."""
        self._ensure_case_exists(case_id)
        now_iso = datetime.now(timezone.utc).isoformat()
        hypothesis_id = f"HYP-{case_id}-{uuid.uuid4().hex[:8]}"

        status_val = HypothesisStatus.OPEN
        try:
            status_val = HypothesisStatus(req.status.value)
        except ValueError:
            status_val = HypothesisStatus.OPEN

        case_hyp = CaseHypothesis(
            hypothesis_id=hypothesis_id,
            case_id=case_id,
            statement=req.statement,
            status=status_val,
            supporting_evidence_tags=req.supporting_evidence,
            contradicting_evidence_tags=req.contradicting_evidence,
            evidence_gaps=req.evidence_gaps,
            analyst_assessment=req.analyst_assessment,
            created_at=now_iso,
            updated_at=now_iso,
            created_by=actor,
            version=1,
        )

        self.case_repo.upsert_hypothesis(case_id, case_hyp, actor=actor)

        return HypothesisAssessmentView(
            hypothesis_id=hypothesis_id,
            case_id=case_id,
            title=req.title or f"Hypothesis {hypothesis_id}",
            statement=req.statement,
            status=req.status,
            version=1,
            supporting_evidence=[
                FindingEvidenceReference(
                    reference_id=f"REF-{hypothesis_id}-{hashlib.sha256(f'{hypothesis_id}:sup:{t}'.encode()).hexdigest()[:8]}",
                    source_type="evidence_reference",
                    source_id=t,
                    citation_tag=t,
                    role=FindingEvidenceRole.SUPPORTING,
                    epistemic_status=EpistemicStatus.OBSERVED,
                    added_at=now_iso,
                )
                for t in req.supporting_evidence
            ],
            contradicting_evidence=[
                FindingEvidenceReference(
                    reference_id=f"REF-{hypothesis_id}-{hashlib.sha256(f'{hypothesis_id}:con:{t}'.encode()).hexdigest()[:8]}",
                    source_type="evidence_reference",
                    source_id=t,
                    citation_tag=t,
                    role=FindingEvidenceRole.CONTRADICTING,
                    epistemic_status=EpistemicStatus.OBSERVED,
                    added_at=now_iso,
                )
                for t in req.contradicting_evidence
            ],
            evidence_gaps=[
                EvidenceGap(
                    gap_id=f"GAP-{hypothesis_id}-{hashlib.sha256(f'{hypothesis_id}:gap:{g}'.encode()).hexdigest()[:8]}",
                    gap_type=EvidenceGapType.UNKNOWN,
                    description=g,
                    expected_source="telemetry",
                    affected_hypotheses=[hypothesis_id],
                )
                for g in req.evidence_gaps
            ],
            relevant_collections=req.relevant_collections,
            supporting_findings=[],
            contradicting_findings=[],
            analyst_assessment=req.analyst_assessment,
            created_by=actor,
            created_at=now_iso,
            updated_at=now_iso,
        )

    def update_hypothesis(
        self,
        case_id: int,
        hypothesis_id: str,
        req: UpdateHypothesisM74Request,
        actor: str = "SecAnalyst-1",
    ) -> HypothesisAssessmentView:
        """Update hypothesis statement, status, or assessment."""
        self._ensure_case_exists(case_id)
        raw_list = self.case_repo.list_hypotheses(case_id)
        existing = next((h for h in raw_list if h.hypothesis_id == hypothesis_id), None)
        if not existing:
            raise ValueError(f"Hypothesis {hypothesis_id} not found in case {case_id}")

        now_iso = datetime.now(timezone.utc).isoformat()
        if req.statement is not None:
            existing.statement = req.statement
        if req.status is not None:
            try:
                existing.status = HypothesisStatus(req.status.value)
            except ValueError:
                pass
        if req.supporting_evidence is not None:
            existing.supporting_evidence_tags = req.supporting_evidence
        if req.contradicting_evidence is not None:
            existing.contradicting_evidence_tags = req.contradicting_evidence
        if req.evidence_gaps is not None:
            existing.evidence_gaps = req.evidence_gaps
        if req.analyst_assessment is not None:
            existing.analyst_assessment = req.analyst_assessment

        existing.updated_at = now_iso
        self.case_repo.upsert_hypothesis(case_id, existing, actor=actor)

        # Re-fetch enriched
        hypotheses = self.get_hypotheses(case_id)
        updated = next((h for h in hypotheses if h.hypothesis_id == hypothesis_id), None)
        if not updated:
            raise ValueError(f"Failed to retrieve updated hypothesis {hypothesis_id}")
        return updated

    def delete_hypothesis(self, case_id: int, hypothesis_id: str, actor: str = "SecAnalyst-1") -> bool:
        """Delete hypothesis proposition. Evidence, findings, and audit logs are preserved."""
        self._ensure_case_exists(case_id)
        conn = self.case_repo._get_connection()

        row = conn.execute(
            "SELECT * FROM case_hypotheses WHERE case_id = ? AND hypothesis_id = ?",
            (case_id, hypothesis_id),
        ).fetchone()

        if not row:
            raise ValueError(f"Hypothesis {hypothesis_id} not found in case {case_id}")

        with conn:
            conn.execute(
                "DELETE FROM case_hypotheses WHERE case_id = ? AND hypothesis_id = ?",
                (case_id, hypothesis_id),
            )

        self._log_audit(
            case_id=case_id,
            action="HYPOTHESIS_DELETED",
            actor=actor,
            reason=f"Deleted hypothesis {hypothesis_id} (evidence preserved)",
            details={"hypothesis_id": hypothesis_id},
        )

        return True

    def add_hypothesis_evidence(
        self,
        case_id: int,
        hypothesis_id: str,
        evidence_tag: str,
        is_contradicting: bool = False,
        actor: str = "SecAnalyst-1",
    ) -> HypothesisAssessmentView:
        """Add supporting or contradicting evidence tag to hypothesis."""
        self._ensure_case_exists(case_id)
        raw_list = self.case_repo.list_hypotheses(case_id)
        existing = next((h for h in raw_list if h.hypothesis_id == hypothesis_id), None)
        if not existing:
            raise ValueError(f"Hypothesis {hypothesis_id} not found in case {case_id}")

        target_tags = existing.contradicting_evidence_tags if is_contradicting else existing.supporting_evidence_tags
        if evidence_tag not in target_tags:
            target_tags.append(evidence_tag)
            self.case_repo.upsert_hypothesis(case_id, existing, actor=actor)

        hypotheses = self.get_hypotheses(case_id)
        return next((h for h in hypotheses if h.hypothesis_id == hypothesis_id), None)

    def remove_hypothesis_evidence(
        self,
        case_id: int,
        hypothesis_id: str,
        evidence_tag: str,
        actor: str = "SecAnalyst-1",
    ) -> HypothesisAssessmentView:
        """Remove evidence tag from hypothesis. Underlying evidence remains preserved."""
        self._ensure_case_exists(case_id)
        raw_list = self.case_repo.list_hypotheses(case_id)
        existing = next((h for h in raw_list if h.hypothesis_id == hypothesis_id), None)
        if not existing:
            raise ValueError(f"Hypothesis {hypothesis_id} not found in case {case_id}")

        existing.supporting_evidence_tags = [t for t in existing.supporting_evidence_tags if t != evidence_tag]
        existing.contradicting_evidence_tags = [t for t in existing.contradicting_evidence_tags if t != evidence_tag]
        self.case_repo.upsert_hypothesis(case_id, existing, actor=actor)

        hypotheses = self.get_hypotheses(case_id)
        return next((h for h in hypotheses if h.hypothesis_id == hypothesis_id), None)

    def add_hypothesis_gap(
        self,
        case_id: int,
        hypothesis_id: str,
        req: AddHypothesisGapRequest,
        actor: str = "SecAnalyst-1",
    ) -> HypothesisAssessmentView:
        """Record an explicit evidence gap on a hypothesis."""
        self._ensure_case_exists(case_id)
        raw_list = self.case_repo.list_hypotheses(case_id)
        existing = next((h for h in raw_list if h.hypothesis_id == hypothesis_id), None)
        if not existing:
            raise ValueError(f"Hypothesis {hypothesis_id} not found in case {case_id}")

        gap_str = f"[{req.gap_type.value}] {req.description} ({req.expected_source})"
        if gap_str not in existing.evidence_gaps:
            existing.evidence_gaps.append(gap_str)
            self.case_repo.upsert_hypothesis(case_id, existing, actor=actor)

        hypotheses = self.get_hypotheses(case_id)
        return next((h for h in hypotheses if h.hypothesis_id == hypothesis_id), None)

    # -------------------------------------------------------------------------
    # Competing Hypotheses Comparison
    # -------------------------------------------------------------------------

    def compare_hypotheses(self, case_id: int) -> HypothesisComparisonResponse:
        """Side-by-side categorical comparison of competing hypotheses without fake probabilities."""
        self._ensure_case_exists(case_id)
        hypotheses = self.get_hypotheses(case_id)
        now_iso = datetime.now(timezone.utc).isoformat()

        items: List[HypothesisComparisonItem] = []
        for h in hypotheses:
            items.append(
                HypothesisComparisonItem(
                    hypothesis_id=h.hypothesis_id,
                    title=h.title,
                    statement=h.statement,
                    status=h.status,
                    supporting_count=len(h.supporting_evidence),
                    contradicting_count=len(h.contradicting_evidence),
                    gaps_count=len(h.evidence_gaps),
                    supporting_evidence_ids=[e.source_id for e in h.supporting_evidence],
                    contradicting_evidence_ids=[e.source_id for e in h.contradicting_evidence],
                    gap_descriptions=[g.description for g in h.evidence_gaps],
                    analyst_assessment=h.analyst_assessment,
                )
            )

        return HypothesisComparisonResponse(
            case_id=case_id,
            hypotheses=items,
            total_hypotheses=len(items),
            generated_at=now_iso,
        )

    # -------------------------------------------------------------------------
    # Full Workbench State & Deterministic Export
    # -------------------------------------------------------------------------

    def get_findings_workbench(self, case_id: int) -> FindingsWorkbenchResponse:
        """Full aggregation of findings, hypotheses, and detected evidence gaps."""
        self._ensure_case_exists(case_id)
        findings = self.get_findings(case_id)
        hypotheses = self.get_hypotheses(case_id)

        # Aggregate unique gaps across hypotheses
        all_gaps: List[EvidenceGap] = []
        seen_gaps = set()
        for h in hypotheses:
            for g in h.evidence_gaps:
                if g.description not in seen_gaps:
                    seen_gaps.add(g.description)
                    all_gaps.append(g)

        return FindingsWorkbenchResponse(
            case_id=case_id,
            findings=findings,
            hypotheses=hypotheses,
            evidence_gaps=all_gaps,
            total_findings=len(findings),
            total_hypotheses=len(hypotheses),
            total_gaps=len(all_gaps),
        )

    def export_findings(self, case_id: int, format: str = "json") -> FindingsExportResponse:
        """Deterministic export of case findings and hypotheses in JSON or CSV format."""
        self._ensure_case_exists(case_id)
        wb = self.get_findings_workbench(case_id)

        if format.lower() == "csv":
            output = io.StringIO()
            writer = csv.writer(output, lineterminator="\n")
            writer.writerow([
                "type",
                "id",
                "case_id",
                "title",
                "statement",
                "epistemic_or_lifecycle_status",
                "review_status",
                "supporting_count",
                "contradicting_count",
                "gaps_count",
                "created_at",
            ])
            for f in wb.findings:
                writer.writerow([
                    "FINDING",
                    f.finding_id,
                    f.case_id,
                    f.title,
                    f.statement,
                    f.epistemic_status.value,
                    f.review_status.value,
                    len(f.supporting_evidence),
                    len(f.contradicting_evidence),
                    0,
                    f.created_at,
                ])
            for h in wb.hypotheses:
                writer.writerow([
                    "HYPOTHESIS",
                    h.hypothesis_id,
                    h.case_id,
                    h.title,
                    h.statement,
                    h.status.value,
                    "N/A",
                    len(h.supporting_evidence),
                    len(h.contradicting_evidence),
                    len(h.evidence_gaps),
                    h.created_at,
                ])
            content = output.getvalue()
            total_items = len(wb.findings) + len(wb.hypotheses)
        else:
            payload = {
                "case_id": case_id,
                "exported_at": "STATIC_DETERMINISTIC_EXPORT",
                "findings": [f.model_dump(mode="json") for f in wb.findings],
                "hypotheses": [h.model_dump(mode="json") for h in wb.hypotheses],
                "evidence_gaps": [g.model_dump(mode="json") for g in wb.evidence_gaps],
            }
            content = json.dumps(payload, indent=2, sort_keys=True)
            total_items = len(wb.findings) + len(wb.hypotheses)

        sha256 = hashlib.sha256(content.encode()).hexdigest()
        return FindingsExportResponse(
            case_id=case_id,
            format=format.lower(),
            item_count=total_items,
            content=content,
            sha256_digest=sha256,
        )


findings_workbench_service = FindingsWorkbenchService()
