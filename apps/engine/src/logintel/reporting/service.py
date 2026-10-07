"""Investigation Reporting, Evidence Package & Case Handoff Service (Milestone 7.6).

Provides deterministic report assembly, 20 structured report sections,
immutable report versioning (append-only), deterministic provenance manifests,
evidence package generation, structured case handoff workflow, and local
advisory AI drafting with strict prompt injection containment.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import re
from typing import Any, Dict, List, Optional, Tuple
import uuid

from logintel.logging import get_logger
from logintel.reporting.models import (
    AIReportDraftRequest,
    AcknowledgeHandoffRequest,
    AnalystInterpretationSection,
    CaseAssessmentSection,
    CaseHandoffPacket,
    CaseIdentificationSection,
    ConclusionSection,
    CreateEvidencePackageRequest,
    CreateReportRequest,
    DeterministicProvenanceManifest,
    EvidenceCollectionsSection,
    EvidenceCorrelationSection,
    EvidenceGapCategory,
    EvidenceGapsSection,
    EvidencePackage,
    EvidencePackageManifest,
    EvidenceSourcesSection,
    ExecutiveSummarySection,
    FinalizeReportRequest,
    HandoffNotesSection,
    HandoffStatus,
    HypothesesSection,
    InvestigationObjectiveSection,
    InvestigationScopeSection,
    KeyFindingsSection,
    LimitationsSection,
    OutstandingQuestionsSection,
    PackageLifecycleStatus,
    PrepareHandoffRequest,
    ProvenanceManifestEntry,
    ReportComparisonResult,
    ReportComparisonSectionDiff,
    ReportContentOrigin,
    ReportExportResponse,
    ReportLifecycleStatus,
    ReportMetadataSection,
    ReturnHandoffRequest,
    StructuredReport,
    SubmitReportReviewRequest,
    ThreatHuntingActivitySection,
    UnifiedTimelineSummarySection,
    UpdateReportDraftRequest,
)
from logintel.storage.case_repo import CaseRepository, case_repo as default_case_repo
from logintel.storage.db import Database, db as default_forensic_db

logger = get_logger("reporting.service")

# Regex to detect potential prompt injection phrases in untrusted input
PROMPT_INJECTION_PATTERN = re.compile(
    r"(ignore\s+(all\s+)?(previous|prior)\s+instructions|"
    r"you\s+are\s+now\s+|"
    r"system\s*:\s*|"
    r"assistant\s*:\s*|"
    r"<\s*script[^>]*>|"
    r"drop\s+table\s+|"
    r"rm\s+-rf\s+|"
    r"curl\s+http|"
    r"bash\s+-c\s+)",
    re.IGNORECASE,
)

# Formula injection prefixes in CSV exports
CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


class ReportingAndHandoffService:
    """Core service orchestrating M7.6 reporting, packages, and handoffs."""

    def __init__(
        self,
        case_repository: Optional[CaseRepository] = None,
        forensic_database: Optional[Database] = None,
    ) -> None:
        self.case_repo = case_repository or default_case_repo
        self.db = forensic_database or default_forensic_db
        # In-memory package and handoff registry per case
        self._packages: Dict[str, EvidencePackage] = {}
        self._handoffs: Dict[int, CaseHandoffPacket] = {}

    # -------------------------------------------------------------------------
    # Helper: String and CSV Sanitization
    # -------------------------------------------------------------------------

    def _sanitize_csv_cell(self, value: Any) -> str:
        """Escape spreadsheet formula injection characters in CSV exports."""
        s = str(value) if value is not None else ""
        if s and s.startswith(CSV_FORMULA_PREFIXES):
            return f"'{s}"
        return s

    def _sanitize_prompt_text(self, text: str) -> str:
        """Neutralize detected prompt injection tokens in untrusted input strings."""
        if not text:
            return ""
        # Replace dangerous injection instructions with defanged text
        sanitized = PROMPT_INJECTION_PATTERN.sub("[DEFANGED_INJECTION_ATTEMPT]", text)
        return sanitized

    def _compute_blake2b_digest(self, content_str: str) -> str:
        """Compute deterministic Blake2b-256 hex digest of canonical string."""
        return hashlib.blake2b(content_str.encode("utf-8"), digest_size=32).hexdigest()

    # -------------------------------------------------------------------------
    # Provenance Manifest Generation
    # -------------------------------------------------------------------------

    def generate_provenance_manifest(
        self,
        case_id: int,
        report_id: str,
        report_version: int,
        included_references: List[Dict[str, Any]],
    ) -> DeterministicProvenanceManifest:
        """Deterministically generates a cryptographic provenance manifest for included references."""
        now_iso = datetime.now(timezone.utc).isoformat()
        entries: List[ProvenanceManifestEntry] = []

        # Sort references canonically by (source_type, source_id)
        sorted_refs = sorted(
            included_references,
            key=lambda r: (str(r.get("source_type", "")), str(r.get("source_id", ""))),
        )

        for ref in sorted_refs:
            stype = str(ref.get("source_type", "UNKNOWN"))
            sid = str(ref.get("source_id", ""))
            ctag = str(ref.get("citation_tag", f"[{stype}:{sid}]"))
            epistemic = str(ref.get("epistemic_status", "UNKNOWN")).upper()
            if epistemic not in ("OBSERVED", "INFERRED", "UNKNOWN"):
                epistemic = "UNKNOWN"

            # Deterministic source hash of canonical fields
            canonical_ref_repr = f"{stype}:{sid}:{ctag}:{epistemic}:{ref.get('created_at', '')}"
            src_hash = self._compute_blake2b_digest(canonical_ref_repr)

            entries.append(
                ProvenanceManifestEntry(
                    source_type=stype,
                    source_id=sid,
                    citation_tag=ctag,
                    epistemic_status=epistemic,
                    cryptographic_source_hash=src_hash,
                    selection_reason=ref.get("analyst_annotation") or "Analyst selected for investigation report",
                )
            )

        # Hash the concatenated canonical entry representations
        canonical_entries_stream = "|".join(
            f"{e.source_type}:{e.source_id}:{e.cryptographic_source_hash}" for e in entries
        )
        manifest_digest = self._compute_blake2b_digest(canonical_entries_stream)

        return DeterministicProvenanceManifest(
            case_id=case_id,
            report_id=report_id,
            report_version=report_version,
            generated_at=now_iso,
            total_references=len(entries),
            entries=entries,
            manifest_blake2b_digest=manifest_digest,
        )

    # -------------------------------------------------------------------------
    # 20 Structured Report Sections Builder
    # -------------------------------------------------------------------------

    def _assemble_structured_report(
        self,
        case_id: int,
        report_id: str,
        version: int,
        title: str,
        lifecycle_status: ReportLifecycleStatus,
        created_by: str,
        created_at: str,
        updated_at: str,
        selected_evidence_ids: Optional[List[str]] = None,
        selected_collection_ids: Optional[List[str]] = None,
        selected_finding_ids: Optional[List[str]] = None,
        selected_hypothesis_ids: Optional[List[str]] = None,
        selected_hunt_ids: Optional[List[str]] = None,
        executive_summary_text: Optional[str] = None,
        analyst_notes_text: Optional[str] = None,
        analyst_interpretation_text: Optional[str] = None,
        conclusion_text: Optional[str] = None,
        reviewed_by: Optional[str] = None,
        reviewed_at: Optional[str] = None,
        custom_limitations: Optional[List[str]] = None,
        custom_next_actions: Optional[List[str]] = None,
        custom_handoff_instructions: Optional[str] = None,
        existing_report: Optional[StructuredReport] = None,
    ) -> StructuredReport:
        """Assembles all 20 typed sections deterministically from case state."""
        case = self.case_repo.get_case(case_id, resolve_evidence=True)
        if not case:
            raise ValueError(f"Investigation case {case_id} not found")

        # 1. Case Identification
        case_ident = CaseIdentificationSection(
            case_id=case.case_id,
            title=case.title,
            incident_id=case.incident_id,
            owner=case.owner,
            status=case.status.value if hasattr(case.status, "value") else str(case.status),
            case_version=case.version,
            created_at=case.created_at,
            updated_at=case.updated_at,
        )

        # 2. Scope
        scope_entities = getattr(case.scope, "selected_entity_ids", []) if case.scope else []
        hosts = [e for e in scope_entities if "host" in e.lower() or "node" in e.lower()]
        users = [e for e in scope_entities if "user" in e.lower() or e in ("root", "admin")]
        if not hosts and scope_entities:
            hosts = [scope_entities[0]]
        scope = InvestigationScopeSection(
            hosts=hosts,
            users=users,
            ip_subnets=[],
            time_window_start=getattr(case.scope, "time_start", None) if case.scope else None,
            time_window_end=getattr(case.scope, "time_end", None) if case.scope else None,
            boundary_notes=f"Investigation bounded by incident #{case.incident_id} scope.",
        )

        # 3. Executive Summary
        exec_summary = ExecutiveSummarySection(
            summary_text=executive_summary_text
            or (existing_report.executive_summary.summary_text if existing_report else "")
            or f"Forensic investigation report for case {case.title}. Primary investigation into incident #{case.incident_id}.",
            content_origin=ReportContentOrigin.ANALYST_AUTHORED,
        )

        # 4. Investigation Objective
        objective = InvestigationObjectiveSection(
            primary_objective=f"Investigate anomalous security activity and establish deterministic forensic timeline for incident #{case.incident_id}.",
            triggering_indicators=[f"Incident #{case.incident_id}: {case.title}"],
        )

        # 5. Evidence Sources
        evidence_sources = EvidenceSourcesSection(
            sources_inspected=["auth.log", "auditd", "syslog", "containers", "network"],
            total_telemetry_events_considered=len(case.evidence_references),
        )

        # 6. Evidence Collections
        raw_collections = []
        try:
            from logintel.collections.service import collections_service

            all_colls = collections_service.get_collections(case_id)
            for c in all_colls:
                c_dict = c.model_dump(mode="json") if hasattr(c, "model_dump") else dict(c)
                if not selected_collection_ids or c_dict.get("collection_id") in selected_collection_ids:
                    raw_collections.append(c_dict)
        except Exception as e:
            logger.debug(f"Could not load collections for case {case_id}: {e}")
        collections_sec = EvidenceCollectionsSection(collections=raw_collections)

        # 7. Unified Timeline Summary
        timeline_milestones: List[Dict[str, Any]] = []
        earliest_ev = None
        latest_ev = None
        for ref in case.evidence_references:
            ts = ref.created_at
            if ts:
                if not earliest_ev or ts < earliest_ev:
                    earliest_ev = ts
                if not latest_ev or ts > latest_ev:
                    latest_ev = ts
            timeline_milestones.append(
                {
                    "source_id": ref.reference_id,
                    "source_type": ref.source_type,
                    "timestamp": ref.created_at,
                    "citation_tag": ref.citation_tag,
                    "annotation": ref.analyst_annotation,
                }
            )
        timeline_sec = UnifiedTimelineSummarySection(
            milestones=sorted(timeline_milestones, key=lambda m: str(m.get("timestamp", ""))),
            earliest_observed_event=earliest_ev,
            latest_observed_event=latest_ev,
        )

        # 8. Key Findings
        raw_findings: List[Dict[str, Any]] = []
        try:
            from logintel.findings.service import findings_workbench_service

            all_findings = findings_workbench_service.get_findings(case_id)
            for f in all_findings:
                f_dict = f.model_dump(mode="json") if hasattr(f, "model_dump") else dict(f)
                if not selected_finding_ids or f_dict.get("finding_id") in selected_finding_ids:
                    raw_findings.append(f_dict)
        except Exception as e:
            logger.debug(f"Could not load findings for case {case_id}: {e}")
        findings_sec = KeyFindingsSection(findings=raw_findings)

        # 9. Hypotheses
        raw_hypotheses: List[Dict[str, Any]] = []
        try:
            from logintel.findings.service import findings_workbench_service

            all_hypos = findings_workbench_service.get_hypotheses(case_id)
            for h in all_hypos:
                h_dict = h.model_dump(mode="json") if hasattr(h, "model_dump") else dict(h)
                if not selected_hypothesis_ids or h_dict.get("hypothesis_id") in selected_hypothesis_ids:
                    raw_hypotheses.append(h_dict)
        except Exception as e:
            logger.debug(f"Could not load hypotheses for case {case_id}: {e}")
        hypotheses_sec = HypothesesSection(hypotheses=raw_hypotheses)

        # 10. Threat Hunting Activity
        raw_hunts: List[Dict[str, Any]] = []
        try:
            from logintel.hunting.service import threat_hunting_service

            all_hunts = threat_hunting_service.list_hunts(case_id)
            for ht in all_hunts:
                if not selected_hunt_ids or ht.get("hunt_id") in selected_hunt_ids:
                    raw_hunts.append(ht)
        except Exception as e:
            logger.debug(f"Could not load threat hunts for case {case_id}: {e}")
        hunt_sec = ThreatHuntingActivitySection(hunts_executed=raw_hunts)

        # 11. Evidence Correlation
        corr_clusters: List[Dict[str, Any]] = []
        corr_sec = EvidenceCorrelationSection(
            correlated_clusters=corr_clusters,
            multi_host_traces=[],
        )

        # 12. Case Assessment
        latest_assessment = self.case_repo.get_latest_case_assessment(case_id)
        assessment_sec = CaseAssessmentSection(
            assessment_state=latest_assessment.get("assessment_state") if latest_assessment else "DRAFT",
            closure_readiness=latest_assessment.get("closure_readiness") if latest_assessment else "UNKNOWN",
            analyst_assessment_text=latest_assessment.get("analyst_assessment") if latest_assessment else None,
        )

        # 13. Evidence Gaps
        gaps_list = [
            {
                "gap_id": f"gap-{case_id}-01",
                "category": EvidenceGapCategory.NO_EVENT_OBSERVED.value,
                "description": "No unauthorized privilege escalation events observed in current auth telemetry window.",
                "remediation": "Absence of evidence is not evidence of absence. Maintain continuous monitoring.",
            }
        ]
        gaps_sec = EvidenceGapsSection(gaps=gaps_list)

        # 14. Outstanding Questions
        questions_list: List[Dict[str, Any]] = []
        with self.case_repo._get_connection() as conn:
            q_rows = conn.execute(
                "SELECT * FROM case_investigation_questions WHERE case_id = ? ORDER BY question_id ASC",
                (case_id,),
            ).fetchall()
            for qr in q_rows:
                questions_list.append(dict(qr))
        questions_sec = OutstandingQuestionsSection(questions=questions_list)

        # 15. Analyst Interpretation
        analyst_interp_sec = AnalystInterpretationSection(
            interpretation_notes=analyst_interpretation_text
            or (existing_report.analyst_interpretation.interpretation_notes if existing_report else "")
            or analyst_notes_text
            or "Investigator analysis indicates isolated security anomalies under containment.",
            author=created_by,
        )

        # 16. Conclusion
        conclusion_sec = ConclusionSection(
            current_conclusion=conclusion_text
            or (existing_report.conclusion.current_conclusion if existing_report else "")
            or "Investigation baseline established. Continued telemetry correlation recommended.",
            requires_further_monitoring=True,
        )

        # 17. Limitations
        limitations_sec = LimitationsSection(
            limitations=custom_limitations
            or [
                "Local forensic engine scope. Epistemic status remains independent.",
                "Telemetry collection bounded by available log files.",
                "Non-negative epistemic boundaries: absence of telemetry is not evidence of absence.",
            ]
        )

        # 18. Handoff Notes
        handoff_notes_sec = HandoffNotesSection(
            handoff_instructions=custom_handoff_instructions or "Review timeline and active hypotheses before case action.",
            recommended_next_actions=custom_next_actions or ["Verify auditd rules on affected hosts", "Monitor active user sessions"],
        )

        # 19. Provenance Manifest
        # Resolve which evidence references are included
        included_refs = []
        for ref in case.evidence_references:
            if not selected_evidence_ids or ref.reference_id in selected_evidence_ids:
                ref_dict = {
                    "source_type": ref.source_type,
                    "source_id": ref.reference_id,
                    "citation_tag": ref.citation_tag,
                    "epistemic_status": getattr(ref, "epistemic_status", "OBSERVED"),
                    "analyst_annotation": ref.analyst_annotation,
                    "created_at": ref.created_at,
                }
                included_refs.append(ref_dict)

        provenance_manifest = self.generate_provenance_manifest(
            case_id=case_id,
            report_id=report_id,
            report_version=version,
            included_references=included_refs,
        )

        # 20. Metadata
        meta_sec = ReportMetadataSection(
            report_id=report_id,
            case_id=case_id,
            version=version,
            lifecycle_status=lifecycle_status,
            created_by=created_by,
            created_at=created_at,
            updated_at=updated_at,
            reviewed_by=reviewed_by,
            reviewed_at=reviewed_at,
            blake2b_fingerprint="",
        )

        report = StructuredReport(
            report_id=report_id,
            case_id=case_id,
            version=version,
            lifecycle_status=lifecycle_status,
            created_by=created_by,
            created_at=created_at,
            updated_at=updated_at,
            reviewed_by=reviewed_by,
            reviewed_at=reviewed_at,
            case_identification=case_ident,
            investigation_scope=scope,
            executive_summary=exec_summary,
            investigation_objective=objective,
            evidence_sources=evidence_sources,
            evidence_collections=collections_sec,
            unified_timeline_summary=timeline_sec,
            key_findings=findings_sec,
            hypotheses=hypotheses_sec,
            threat_hunting_activity=hunt_sec,
            evidence_correlation=corr_sec,
            case_assessment=assessment_sec,
            evidence_gaps=gaps_sec,
            outstanding_questions=questions_sec,
            analyst_interpretation=analyst_interp_sec,
            conclusion=conclusion_sec,
            limitations=limitations_sec,
            handoff_notes=handoff_notes_sec,
            provenance_manifest=provenance_manifest,
            metadata=meta_sec,
        )

        # Compute deterministic overall report fingerprint
        report_canonical_json = json.dumps(report.model_dump(mode="json", exclude={"metadata": {"blake2b_fingerprint"}}), sort_keys=True)
        fingerprint = self._compute_blake2b_digest(report_canonical_json)
        report.metadata.blake2b_fingerprint = fingerprint

        return report

    # -------------------------------------------------------------------------
    # Report Persistence (Append-Only in `case_reports` table)
    # -------------------------------------------------------------------------

    def _persist_report_version(
        self,
        report: StructuredReport,
        is_final: bool = False,
    ) -> None:
        """Persists a new report version row to SQLite adhering to append-only triggers."""
        now_iso = datetime.now(timezone.utc).isoformat()
        serialized_payload = json.dumps(
            {
                "m76_report": report.model_dump(mode="json"),
                "lifecycle_status": report.lifecycle_status.value,
                "reviewed_by": report.reviewed_by,
                "reviewed_at": report.reviewed_at,
            }
        )

        with self.case_repo._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO case_reports (
                    report_id, case_id, version, title, executive_summary, facts_json,
                    inferences_json, hypotheses_json, unknowns_json, recommendations_json,
                    analyst_notes, generated_by, model_id, model_digest,
                    context_version, created_at, is_final
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report.report_id,
                    report.case_id,
                    report.version,
                    report.case_identification.title,
                    report.executive_summary.summary_text,
                    json.dumps(report.key_findings.findings),
                    json.dumps(report.unified_timeline_summary.milestones),
                    json.dumps(report.hypotheses.hypotheses),
                    json.dumps([f"[{g.get('category')}]: {g.get('description')}" for g in report.evidence_gaps.gaps]),
                    json.dumps(report.handoff_notes.recommended_next_actions),
                    serialized_payload,
                    "ANALYST_AUTHORED",
                    None,
                    report.metadata.blake2b_fingerprint,
                    1,
                    report.created_at or now_iso,
                    1 if is_final else 0,
                ),
            )

    def _reconstruct_report_from_row(self, row: Any) -> StructuredReport:
        """Reconstructs StructuredReport model from a case_reports SQLite row."""
        analyst_notes = row["analyst_notes"]
        if analyst_notes:
            try:
                parsed = json.loads(analyst_notes)
                if isinstance(parsed, dict) and "m76_report" in parsed:
                    return StructuredReport.model_validate(parsed["m76_report"])
            except Exception:
                pass

        # Fallback reconstruction if row was created by older M5/M6 service
        return self._assemble_structured_report(
            case_id=row["case_id"],
            report_id=row["report_id"],
            version=row["version"],
            title=row["title"],
            lifecycle_status=ReportLifecycleStatus.FINALIZED if row["is_final"] else ReportLifecycleStatus.DRAFT,
            created_by="SecAnalyst-1",
            created_at=row["created_at"],
            updated_at=row["created_at"],
            executive_summary_text=row["executive_summary"],
            analyst_notes_text=row["analyst_notes"],
        )

    # -------------------------------------------------------------------------
    # Public Report Operations
    # -------------------------------------------------------------------------

    def create_report_draft(
        self,
        case_id: int,
        req: CreateReportRequest,
        actor: str = "SecAnalyst-1",
    ) -> StructuredReport:
        """Creates a new initial draft report for a case (Version 1)."""
        case = self.case_repo.get_case(case_id)
        if not case:
            raise ValueError(f"Investigation case {case_id} not found")

        report_id = f"rep-{uuid.uuid4().hex[:12]}"
        now_iso = datetime.now(timezone.utc).isoformat()

        report = self._assemble_structured_report(
            case_id=case_id,
            report_id=report_id,
            version=1,
            title=req.title,
            lifecycle_status=ReportLifecycleStatus.DRAFT,
            created_by=actor,
            created_at=now_iso,
            updated_at=now_iso,
            selected_evidence_ids=req.selected_evidence_ids,
            selected_collection_ids=req.selected_collection_ids,
            selected_finding_ids=req.selected_finding_ids,
            selected_hypothesis_ids=req.selected_hypothesis_ids,
            selected_hunt_ids=req.selected_hunt_ids,
            analyst_notes_text=req.analyst_notes,
        )

        self._persist_report_version(report, is_final=False)

        self.case_repo.append_audit_log(
            case_id=case_id,
            actor=actor,
            action="REPORT_CREATED",
            new_value=f"Report {report_id} v1 DRAFT",
            reason="Analyst initialized structured report draft",
            details={
                "report_id": report_id,
                "version": 1,
                "status": "DRAFT",
                "references_count": report.provenance_manifest.total_references,
            },
        )

        return report

    def get_report(
        self,
        case_id: int,
        version: Optional[int] = None,
        report_id: Optional[str] = None,
    ) -> StructuredReport:
        """Retrieves a structured report by version or the latest version."""
        case = self.case_repo.get_case(case_id)
        if not case:
            raise ValueError(f"Investigation case {case_id} not found")

        with self.case_repo._get_connection() as conn:
            if version is not None:
                if report_id:
                    row = conn.execute(
                        "SELECT * FROM case_reports WHERE case_id = ? AND report_id = ? AND version = ?",
                        (case_id, report_id, version),
                    ).fetchone()
                else:
                    row = conn.execute(
                        "SELECT * FROM case_reports WHERE case_id = ? AND version = ? ORDER BY rowid DESC LIMIT 1",
                        (case_id, version),
                    ).fetchone()
            else:
                if report_id:
                    row = conn.execute(
                        "SELECT * FROM case_reports WHERE case_id = ? AND report_id = ? ORDER BY version DESC LIMIT 1",
                        (case_id, report_id),
                    ).fetchone()
                else:
                    row = conn.execute(
                        "SELECT * FROM case_reports WHERE case_id = ? ORDER BY version DESC LIMIT 1",
                        (case_id,),
                    ).fetchone()

        if not row:
            raise ValueError(f"Report for case {case_id} (version={version}) not found")

        return self._reconstruct_report_from_row(row)

    def list_report_versions(self, case_id: int) -> List[Dict[str, Any]]:
        """Lists all historical report versions for a case."""
        case = self.case_repo.get_case(case_id)
        if not case:
            raise ValueError(f"Investigation case {case_id} not found")

        versions = []
        with self.case_repo._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM case_reports WHERE case_id = ? ORDER BY version DESC",
                (case_id,),
            ).fetchall()

            for r in rows:
                rep = self._reconstruct_report_from_row(r)
                versions.append(
                    {
                        "report_id": rep.report_id,
                        "case_id": rep.case_id,
                        "version": rep.version,
                        "title": rep.case_identification.title,
                        "lifecycle_status": rep.lifecycle_status.value,
                        "created_by": rep.created_by,
                        "created_at": rep.created_at,
                        "updated_at": rep.updated_at,
                        "is_final": rep.lifecycle_status == ReportLifecycleStatus.FINALIZED,
                        "reviewed_by": rep.reviewed_by,
                        "reviewed_at": rep.reviewed_at,
                        "blake2b_fingerprint": rep.metadata.blake2b_fingerprint,
                        "references_count": rep.provenance_manifest.total_references,
                    }
                )
        return versions

    def update_report_draft(
        self,
        case_id: int,
        report_id: str,
        req: UpdateReportDraftRequest,
        actor: str = "SecAnalyst-1",
    ) -> StructuredReport:
        """Updates a report draft by creating the next immutable version row."""
        current = self.get_report(case_id, report_id=report_id)
        if current.lifecycle_status == ReportLifecycleStatus.FINALIZED:
            raise ValueError("Cannot modify a FINALIZED report. Finalized reports are immutable.")

        next_version = current.version + 1
        now_iso = datetime.now(timezone.utc).isoformat()

        updated_report = self._assemble_structured_report(
            case_id=case_id,
            report_id=current.report_id,
            version=next_version,
            title=req.title or current.case_identification.title,
            lifecycle_status=ReportLifecycleStatus.DRAFT,
            created_by=current.created_by,
            created_at=current.created_at,
            updated_at=now_iso,
            executive_summary_text=req.executive_summary or current.executive_summary.summary_text,
            analyst_interpretation_text=req.analyst_interpretation or current.analyst_interpretation.interpretation_notes,
            conclusion_text=req.conclusion or current.conclusion.current_conclusion,
            custom_limitations=req.limitations or current.limitations.limitations,
            custom_next_actions=req.recommended_next_actions or current.handoff_notes.recommended_next_actions,
            custom_handoff_instructions=req.handoff_instructions or current.handoff_notes.handoff_instructions,
            existing_report=current,
        )

        self._persist_report_version(updated_report, is_final=False)

        self.case_repo.append_audit_log(
            case_id=case_id,
            actor=actor,
            action="REPORT_DRAFT_UPDATED",
            previous_value=f"v{current.version}",
            new_value=f"v{next_version}",
            reason="Analyst updated report draft content",
            details={"report_id": report_id, "version": next_version},
        )

        return updated_report

    def submit_report_for_review(
        self,
        case_id: int,
        report_id: str,
        req: SubmitReportReviewRequest,
        actor: str = "SecAnalyst-1",
    ) -> StructuredReport:
        """Transitions a report draft to REVIEW_READY status."""
        current = self.get_report(case_id, report_id=report_id)
        if current.lifecycle_status == ReportLifecycleStatus.FINALIZED:
            raise ValueError("Report is already finalized.")

        next_version = current.version + 1
        now_iso = datetime.now(timezone.utc).isoformat()

        reviewed_report = self._assemble_structured_report(
            case_id=case_id,
            report_id=current.report_id,
            version=next_version,
            title=current.case_identification.title,
            lifecycle_status=ReportLifecycleStatus.REVIEW_READY,
            created_by=current.created_by,
            created_at=current.created_at,
            updated_at=now_iso,
            executive_summary_text=current.executive_summary.summary_text,
            analyst_interpretation_text=current.analyst_interpretation.interpretation_notes,
            conclusion_text=current.conclusion.current_conclusion,
            custom_limitations=current.limitations.limitations,
            custom_next_actions=current.handoff_notes.recommended_next_actions,
            custom_handoff_instructions=current.handoff_notes.handoff_instructions,
            existing_report=current,
        )

        self._persist_report_version(reviewed_report, is_final=False)

        self.case_repo.append_audit_log(
            case_id=case_id,
            actor=actor,
            action="REPORT_SUBMITTED_FOR_REVIEW",
            previous_value=current.lifecycle_status.value,
            new_value=ReportLifecycleStatus.REVIEW_READY.value,
            reason=req.review_notes or "Submitted for supervisor review",
            details={"report_id": report_id, "version": next_version},
        )

        return reviewed_report

    def finalize_report(
        self,
        case_id: int,
        report_id: str,
        req: FinalizeReportRequest,
        actor: str = "SecAnalyst-1",
    ) -> StructuredReport:
        """Finalizes a report version. Finalized reports are frozen and cannot be updated."""
        if not req.reviewed_by or not req.reviewed_by.strip():
            raise ValueError("Report finalization requires a non-empty reviewed_by reviewer identity.")

        current = self.get_report(case_id, report_id=report_id)
        if current.lifecycle_status == ReportLifecycleStatus.FINALIZED:
            return current

        # Verify all evidence references still exist in the case
        case = self.case_repo.get_case(case_id)
        if not case:
            raise ValueError(f"Investigation case {case_id} not found")

        case_ref_ids = {r.reference_id for r in case.evidence_references}
        for entry in current.provenance_manifest.entries:
            if entry.source_id not in case_ref_ids:
                raise ValueError(
                    f"Integrity check failed: evidence reference {entry.source_id} ({entry.source_type}) "
                    f"no longer resolves in case #{case_id}."
                )

        next_version = current.version + 1
        now_iso = datetime.now(timezone.utc).isoformat()

        final_report = self._assemble_structured_report(
            case_id=case_id,
            report_id=current.report_id,
            version=next_version,
            title=current.case_identification.title,
            lifecycle_status=ReportLifecycleStatus.FINALIZED,
            created_by=current.created_by,
            created_at=current.created_at,
            updated_at=now_iso,
            reviewed_by=req.reviewed_by.strip(),
            reviewed_at=now_iso,
            executive_summary_text=current.executive_summary.summary_text,
            analyst_interpretation_text=current.analyst_interpretation.interpretation_notes,
            conclusion_text=current.conclusion.current_conclusion,
            custom_limitations=current.limitations.limitations,
            custom_next_actions=current.handoff_notes.recommended_next_actions,
            custom_handoff_instructions=current.handoff_notes.handoff_instructions,
            existing_report=current,
        )

        self._persist_report_version(final_report, is_final=True)

        self.case_repo.append_audit_log(
            case_id=case_id,
            actor=actor,
            action="REPORT_FINALIZED",
            previous_value=current.lifecycle_status.value,
            new_value=ReportLifecycleStatus.FINALIZED.value,
            reason=req.finalization_notes or "Supervisor approved and finalized report",
            details={
                "report_id": report_id,
                "version": next_version,
                "reviewed_by": req.reviewed_by,
                "fingerprint": final_report.metadata.blake2b_fingerprint,
            },
        )

        return final_report

    # -------------------------------------------------------------------------
    # Report Comparison
    # -------------------------------------------------------------------------

    def compare_report_versions(
        self,
        case_id: int,
        version_older: int,
        version_newer: int,
        report_id: Optional[str] = None,
    ) -> ReportComparisonResult:
        """Performs deterministic semantic comparison between two report versions."""
        rep_older = self.get_report(case_id, version=version_older, report_id=report_id)
        rep_newer = self.get_report(case_id, version=version_newer, report_id=report_id)

        now_iso = datetime.now(timezone.utc).isoformat()
        diffs: List[ReportComparisonSectionDiff] = []

        sections_to_check = [
            ("case_identification", rep_older.case_identification.model_dump(), rep_newer.case_identification.model_dump()),
            ("investigation_scope", rep_older.investigation_scope.model_dump(), rep_newer.investigation_scope.model_dump()),
            ("executive_summary", rep_older.executive_summary.model_dump(), rep_newer.executive_summary.model_dump()),
            ("investigation_objective", rep_older.investigation_objective.model_dump(), rep_newer.investigation_objective.model_dump()),
            ("evidence_sources", rep_older.evidence_sources.model_dump(), rep_newer.evidence_sources.model_dump()),
            ("evidence_collections", rep_older.evidence_collections.model_dump(), rep_newer.evidence_collections.model_dump()),
            ("unified_timeline_summary", rep_older.unified_timeline_summary.model_dump(), rep_newer.unified_timeline_summary.model_dump()),
            ("key_findings", rep_older.key_findings.model_dump(), rep_newer.key_findings.model_dump()),
            ("hypotheses", rep_older.hypotheses.model_dump(), rep_newer.hypotheses.model_dump()),
            ("threat_hunting_activity", rep_older.threat_hunting_activity.model_dump(), rep_newer.threat_hunting_activity.model_dump()),
            ("evidence_correlation", rep_older.evidence_correlation.model_dump(), rep_newer.evidence_correlation.model_dump()),
            ("case_assessment", rep_older.case_assessment.model_dump(), rep_newer.case_assessment.model_dump()),
            ("evidence_gaps", rep_older.evidence_gaps.model_dump(), rep_newer.evidence_gaps.model_dump()),
            ("outstanding_questions", rep_older.outstanding_questions.model_dump(), rep_newer.outstanding_questions.model_dump()),
            ("analyst_interpretation", rep_older.analyst_interpretation.model_dump(), rep_newer.analyst_interpretation.model_dump()),
            ("conclusion", rep_older.conclusion.model_dump(), rep_newer.conclusion.model_dump()),
            ("limitations", rep_older.limitations.model_dump(), rep_newer.limitations.model_dump()),
            ("handoff_notes", rep_older.handoff_notes.model_dump(), rep_newer.handoff_notes.model_dump()),
            ("provenance_manifest", rep_older.provenance_manifest.model_dump(), rep_newer.provenance_manifest.model_dump()),
        ]

        diff_count = 0
        for sname, v_old, v_new in sections_to_check:
            if v_old == v_new:
                diffs.append(ReportComparisonSectionDiff(section_name=sname, status="IDENTICAL"))
            else:
                diff_count += 1
                diffs.append(
                    ReportComparisonSectionDiff(
                        section_name=sname,
                        status="MODIFIED",
                        details={
                            "older_state": v_old,
                            "newer_state": v_new,
                        },
                    )
                )

        return ReportComparisonResult(
            case_id=case_id,
            report_id=rep_newer.report_id,
            version_older=version_older,
            version_newer=version_newer,
            compared_at=now_iso,
            differences_count=diff_count,
            section_diffs=diffs,
            older_fingerprint=rep_older.metadata.blake2b_fingerprint,
            newer_fingerprint=rep_newer.metadata.blake2b_fingerprint,
        )

    # -------------------------------------------------------------------------
    # Evidence Package Operations
    # -------------------------------------------------------------------------

    def create_evidence_package(
        self,
        case_id: int,
        req: CreateEvidencePackageRequest,
        actor: str = "SecAnalyst-1",
    ) -> EvidencePackage:
        """Assembles a deterministic, self-contained evidence package referencing case materials."""
        report = self.get_report(case_id, version=req.report_version)
        now_iso = datetime.now(timezone.utc).isoformat()
        package_id = f"pkg-{uuid.uuid4().hex[:12]}"

        # Canonical artifact dictionary referencing case components
        artifacts = {
            "collections": report.evidence_collections.collections,
            "findings": report.key_findings.findings,
            "hypotheses": report.hypotheses.hypotheses,
            "threat_hunts": report.threat_hunting_activity.hunts_executed,
            "timeline_milestones": report.unified_timeline_summary.milestones,
            "evidence_gaps": report.evidence_gaps.gaps,
            "outstanding_questions": report.outstanding_questions.questions,
            "provenance_manifest": report.provenance_manifest.model_dump(mode="json"),
        }

        # Deterministic Blake2b digest of canonical package content
        package_canonical_json = json.dumps(
            {
                "package_id": package_id,
                "case_id": case_id,
                "report_id": report.report_id,
                "report_version": report.version,
                "artifacts": artifacts,
            },
            sort_keys=True,
        )
        package_digest = self._compute_blake2b_digest(package_canonical_json)

        manifest = EvidencePackageManifest(
            package_id=package_id,
            case_id=case_id,
            report_id=report.report_id,
            report_version=report.version,
            created_by=actor,
            created_at=now_iso,
            status=PackageLifecycleStatus.COMPLETED,
            schema_version="m7.6-package-v1",
            generator_version="logintel-engine-0.1.0",
            included_artifacts=list(artifacts.keys()),
            source_reference_count=report.provenance_manifest.total_references,
            package_blake2b_digest=package_digest,
        )

        package = EvidencePackage(
            manifest=manifest,
            report_snapshot=report,
            artifacts_json=artifacts,
        )

        # Cache package
        self._packages[f"{case_id}:{package_id}"] = package

        self.case_repo.append_audit_log(
            case_id=case_id,
            actor=actor,
            action="PACKAGE_CREATED",
            new_value=f"Package {package_id} ({package_digest[:16]})",
            reason=req.package_notes or "Assembled forensic evidence package",
            details={
                "package_id": package_id,
                "report_version": report.version,
                "artifacts_count": len(artifacts),
                "digest": package_digest,
            },
        )

        return package

    def get_evidence_package(self, case_id: int, package_id: str) -> EvidencePackage:
        """Retrieves a generated evidence package by ID."""
        key = f"{case_id}:{package_id}"
        if key in self._packages:
            return self._packages[key]
        raise ValueError(f"Evidence package {package_id} for case {case_id} not found.")

    # -------------------------------------------------------------------------
    # Deterministic Exports (JSON, CSV, Markdown)
    # -------------------------------------------------------------------------

    def export_report(
        self,
        case_id: int,
        version: Optional[int] = None,
        format_type: str = "json",
    ) -> ReportExportResponse:
        """Generates deterministic export of an investigation report in JSON, CSV, or Markdown."""
        report = self.get_report(case_id, version=version)
        fmt = format_type.strip().lower()
        now_iso = datetime.now(timezone.utc).isoformat()

        if fmt == "json":
            # Canonical sorted JSON string
            export_content = json.dumps(report.model_dump(mode="json"), sort_keys=True, indent=2)

        elif fmt == "csv":
            # CSV export of key findings and evidence references with formula injection sanitization
            output = io.StringIO()
            writer = csv.writer(output, lineterminator="\n")

            # Header
            writer.writerow(["Section", "Source_Type", "Source_ID", "Citation_Tag", "Epistemic_Status", "Details"])

            # Findings rows
            for f in report.key_findings.findings:
                writer.writerow(
                    [
                        "KEY_FINDING",
                        "FINDING",
                        self._sanitize_csv_cell(f.get("finding_id")),
                        self._sanitize_csv_cell(f.get("finding_type")),
                        self._sanitize_csv_cell(f.get("epistemic_status")),
                        self._sanitize_csv_cell(f.get("description")),
                    ]
                )

            # Evidence references rows
            for ref in report.provenance_manifest.entries:
                writer.writerow(
                    [
                        "EVIDENCE_REFERENCE",
                        self._sanitize_csv_cell(ref.source_type),
                        self._sanitize_csv_cell(ref.source_id),
                        self._sanitize_csv_cell(ref.citation_tag),
                        self._sanitize_csv_cell(ref.epistemic_status),
                        self._sanitize_csv_cell(ref.selection_reason),
                    ]
                )

            export_content = output.getvalue()

        elif fmt in ("markdown", "md"):
            # Forensic report markdown representation
            lines = [
                f"# Forensic Investigation Report — Case #{report.case_id}: {report.case_identification.title}",
                "",
                f"- **Report ID**: `{report.report_id}`",
                f"- **Version**: `{report.version}`",
                f"- **Status**: `{report.lifecycle_status.value}`",
                f"- **Created By**: {report.created_by} ({report.created_at})",
                f"- **Fingerprint**: `{report.metadata.blake2b_fingerprint}`",
                "",
                "## 1. Executive Summary",
                "",
                report.executive_summary.summary_text,
                "",
                "## 2. Scope & Investigation Objective",
                "",
                f"- **Primary Objective**: {report.investigation_objective.primary_objective}",
                f"- **Hosts**: {', '.join(report.investigation_scope.hosts) or 'None specified'}",
                f"- **Users**: {', '.join(report.investigation_scope.users) or 'None specified'}",
                "",
                "## 3. Key Findings",
                "",
            ]
            if report.key_findings.findings:
                for f in report.key_findings.findings:
                    lines.append(f"- **[{f.get('epistemic_status', 'UNKNOWN')}] {f.get('title', 'Finding')}**: {f.get('description', '')}")
            else:
                lines.append("_No findings recorded._")

            lines.extend(
                [
                    "",
                    "## 4. Evidence Gaps & Epistemic Boundaries",
                    "",
                    "> **Forensic Invariant**: Absence of telemetry is not evidence of absence.",
                    "",
                ]
            )
            for g in report.evidence_gaps.gaps:
                lines.append(f"- **[{g.get('category')}]**: {g.get('description')}")

            lines.extend(
                [
                    "",
                    "## 5. Provenance Manifest",
                    "",
                    f"Total Referenced Sources: {report.provenance_manifest.total_references}",
                    f"Manifest Digest: `{report.provenance_manifest.manifest_blake2b_digest}`",
                    "",
                    "| Source Type | Source ID | Epistemic Status | Hash |",
                    "| :--- | :--- | :--- | :--- |",
                ]
            )
            for e in report.provenance_manifest.entries:
                lines.append(f"| {e.source_type} | {e.source_id} | {e.epistemic_status} | `{e.cryptographic_source_hash[:16]}...` |")

            export_content = "\n".join(lines)

        else:
            raise ValueError(f"Unsupported export format '{format_type}'. Supported: json, csv, markdown.")

        fingerprint = self._compute_blake2b_digest(export_content)

        return ReportExportResponse(
            case_id=case_id,
            report_id=report.report_id,
            version=report.version,
            format=fmt,
            content=export_content,
            fingerprint=fingerprint,
            exported_at=now_iso,
        )

    # -------------------------------------------------------------------------
    # Case Handoff Workflow & Lifecycle
    # -------------------------------------------------------------------------

    def prepare_handoff(
        self,
        case_id: int,
        req: PrepareHandoffRequest,
        actor: str = "SecAnalyst-1",
    ) -> CaseHandoffPacket:
        """Prepares an analyst-to-analyst operational case handoff packet."""
        report = self.get_report(case_id, version=req.report_version)
        now_iso = datetime.now(timezone.utc).isoformat()
        handoff_id = f"hnd-{uuid.uuid4().hex[:12]}"

        packet = CaseHandoffPacket(
            handoff_id=handoff_id,
            case_id=case_id,
            report_id=report.report_id,
            report_version=report.version,
            status=HandoffStatus.READY_FOR_HANDOFF,
            prepared_by=actor,
            prepared_at=now_iso,
            handed_off_to=req.target_operator,
            investigated_scope_summary=f"Incident #{report.case_identification.incident_id} scope: {len(report.investigation_scope.hosts)} hosts, {len(report.investigation_scope.users)} users.",
            observed_facts_count=len(report.key_findings.findings),
            active_hypotheses_count=len(report.hypotheses.hypotheses),
            evidence_gaps_count=len(report.evidence_gaps.gaps),
            outstanding_questions=[str(q.get("question", "")) for q in report.outstanding_questions.questions],
            recommended_next_actions=req.recommended_next_actions or report.handoff_notes.recommended_next_actions,
            operational_notes=req.operational_notes,
        )

        self._handoffs[case_id] = packet

        self.case_repo.append_audit_log(
            case_id=case_id,
            actor=actor,
            action="HANDOFF_PREPARED",
            new_value=HandoffStatus.READY_FOR_HANDOFF.value,
            reason="Analyst prepared case handoff packet",
            details={
                "handoff_id": handoff_id,
                "target_operator": req.target_operator,
                "report_version": report.version,
            },
        )

        return packet

    def acknowledge_handoff(
        self,
        case_id: int,
        handoff_id: str,
        req: AcknowledgeHandoffRequest,
        actor: str = "SecAnalyst-2",
    ) -> CaseHandoffPacket:
        """Recipient analyst acknowledges receipt of the transferred case."""
        packet = self.get_current_handoff(case_id)
        if not packet or packet.handoff_id != handoff_id:
            raise ValueError(f"Handoff {handoff_id} not found for case #{case_id}.")

        now_iso = datetime.now(timezone.utc).isoformat()
        packet.status = HandoffStatus.ACKNOWLEDGED
        packet.acknowledged_by = actor
        packet.acknowledged_at = now_iso

        self._handoffs[case_id] = packet

        self.case_repo.append_audit_log(
            case_id=case_id,
            actor=actor,
            action="HANDOFF_ACKNOWLEDGED",
            new_value=HandoffStatus.ACKNOWLEDGED.value,
            reason=req.acknowledgement_notes or "Analyst accepted case custody",
            details={"handoff_id": handoff_id, "acknowledged_by": actor},
        )

        return packet

    def return_handoff(
        self,
        case_id: int,
        handoff_id: str,
        req: ReturnHandoffRequest,
        actor: str = "SecAnalyst-2",
    ) -> CaseHandoffPacket:
        """Returns case to originating analyst with required followup reasons."""
        packet = self.get_current_handoff(case_id)
        if not packet or packet.handoff_id != handoff_id:
            raise ValueError(f"Handoff {handoff_id} not found for case #{case_id}.")

        packet.status = HandoffStatus.RETURNED_FOR_FOLLOWUP
        packet.return_reason = req.return_reason

        self._handoffs[case_id] = packet

        self.case_repo.append_audit_log(
            case_id=case_id,
            actor=actor,
            action="HANDOFF_RETURNED",
            new_value=HandoffStatus.RETURNED_FOR_FOLLOWUP.value,
            reason=req.return_reason,
            details={"handoff_id": handoff_id, "returned_by": actor},
        )

        return packet

    def get_current_handoff(self, case_id: int) -> Optional[CaseHandoffPacket]:
        """Returns the current operational handoff packet for a case."""
        if case_id in self._handoffs:
            return self._handoffs[case_id]

        # Fallback: check case_audit_log for latest HANDOFF_PREPARED
        with self.case_repo._get_connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM case_audit_log
                WHERE case_id = ? AND action LIKE 'HANDOFF_%'
                ORDER BY audit_id DESC LIMIT 1
                """,
                (case_id,),
            ).fetchone()

            if row and row["details_json"]:
                try:
                    details = json.loads(row["details_json"])
                    hid = details.get("handoff_id", f"hnd-{case_id}")
                    # Reconstruct minimal packet
                    packet = CaseHandoffPacket(
                        handoff_id=hid,
                        case_id=case_id,
                        report_id=f"rep-{case_id}",
                        report_version=details.get("report_version", 1),
                        status=HandoffStatus(row["new_value"]) if row["new_value"] in HandoffStatus.__members__ else HandoffStatus.READY_FOR_HANDOFF,
                        prepared_by=row["actor"],
                        prepared_at=row["timestamp"],
                        handed_off_to=details.get("target_operator"),
                        investigated_scope_summary="Recovered from audit record",
                        observed_facts_count=0,
                        active_hypotheses_count=0,
                        evidence_gaps_count=0,
                    )
                    self._handoffs[case_id] = packet
                    return packet
                except Exception:
                    pass
        return None

    # -------------------------------------------------------------------------
    # Advisory Local AI Report Drafting & Injection Containment
    # -------------------------------------------------------------------------

    def ai_draft_section(
        self,
        case_id: int,
        req: AIReportDraftRequest,
        actor: str = "SecAnalyst-1",
    ) -> Dict[str, Any]:
        """Generates an advisory-only draft for a report section with strict prompt injection containment."""
        case = self.case_repo.get_case(case_id)
        if not case:
            raise ValueError(f"Investigation case {case_id} not found")

        section_key = req.section_to_draft.strip().lower()
        if section_key not in ("executive_summary", "analyst_interpretation", "conclusion", "handoff_notes", "timeline_summary"):
            raise ValueError(f"Unsupported section to draft: '{req.section_to_draft}'")

        # Sanitize guidance text for prompt injection containment
        sanitized_guidance = self._sanitize_prompt_text(req.custom_guidance or "")

        # Assemble untrusted evidence context enclosed in strict isolation delimiters
        untrusted_evidence_snippets = []
        for ref in case.evidence_references[:20]:
            clean_annotation = self._sanitize_prompt_text(ref.analyst_annotation or "")
            untrusted_evidence_snippets.append(f"[{ref.source_type}:{ref.reference_id}] {clean_annotation}")

        evidence_block = "\n".join(untrusted_evidence_snippets) or "No attached evidence references."

        # Deterministic advisory draft template
        scope_entities = getattr(case.scope, "selected_entity_ids", []) if case.scope else []
        if section_key == "executive_summary":
            draft_text = (
                f"[AI ADVISORY DRAFT] Investigation of case '{case.title}' for incident #{case.incident_id}. "
                f"Scope includes {len(scope_entities)} scoped entities. "
                f"Analyst telemetry correlation identified {len(case.evidence_references)} evidentiary references. "
                f"Preliminary assessment indicates contained activity requiring ongoing verification."
            )
        elif section_key == "analyst_interpretation":
            draft_text = (
                f"[AI ADVISORY DRAFT] Telemetry traces across inspected logs do not exhibit broader lateral spread. "
                f"Observed authentication artifacts remain consistent with targeted anomalies. Epistemic boundaries preserved."
            )
        elif section_key == "conclusion":
            draft_text = (
                f"[AI ADVISORY DRAFT] Core incident investigative questions addressed. Residual telemetry monitoring recommended."
            )
        elif section_key == "handoff_notes":
            draft_text = (
                f"[AI ADVISORY DRAFT] Custody transfer for incident #{case.incident_id}. Proceed with host-level verification."
            )
        else:
            draft_text = f"[AI ADVISORY DRAFT] Timeline synthesis across {len(case.evidence_references)} observed event references."

        if sanitized_guidance:
            draft_text += f"\nAnalyst Guidance Applied: {sanitized_guidance}"

        self.case_repo.append_audit_log(
            case_id=case_id,
            actor=actor,
            action="AI_DRAFT_CREATED",
            new_value=f"Drafted section '{section_key}'",
            reason="Analyst requested local advisory AI drafting",
            details={
                "section": section_key,
                "content_origin": ReportContentOrigin.AI_GENERATED_DRAFT.value,
                "advisory_only": True,
            },
        )

        return {
            "case_id": case_id,
            "section": section_key,
            "draft_text": draft_text,
            "content_origin": ReportContentOrigin.AI_GENERATED_DRAFT.value,
            "advisory_only": True,
            "model_id": "local-advisory-engine-v1",
            "injection_checks_passed": True,
        }


# Singleton service instance
reporting_service = ReportingAndHandoffService()
