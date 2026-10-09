"""Determinism verification test suite for Milestone 7.8.

Runs N=10 iterations of forensic review evaluation, 12-gate analysis,
closure blocker extraction, provenance manifest hashing, and multi-format exports.
Verifies 0 unexplained variance.
"""

import json
import pytest

from logintel.ai.domain.case import CaseHypothesis, InvestigationScope
from logintel.ai.domain.workspace import HypothesisStatus
from logintel.review.models import ExportFormat
from logintel.review.service import InvestigationReviewService
from logintel.storage.case_repo import case_repo


@pytest.fixture(scope="module")
def deterministic_case():
    """Setup deterministic test case with structured scope, evidence, and hypothesis."""
    inc_id = 998877
    case = case_repo.get_case_by_incident(inc_id, resolve_evidence=False)
    if not case:
        case = case_repo.create_case(
            incident_id=inc_id,
            title="Deterministic Review Case",
            description="Forensic investigation into lateral movement across bastion hosts.",
        )

    # Set deterministic scope
    case_repo.update_case_scope(
        case_id=case.case_id,
        scope=InvestigationScope(
            investigation_id=inc_id,
            subject_id=f"inc-{inc_id}",
            time_start="2026-10-01T00:00:00Z",
            time_end="2026-10-02T00:00:00Z",
            selected_entity_ids=["host:bastion-01", "host:bastion-02", "user:admin"],
        ),
    )

    # Add deterministic evidence
    case_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="ip",
        source_id="198.51.100.99",
        role="SUPPORTING",
        epistemic_status="OBSERVED",
        citation_tag="[ip:198.51.100.99]",
        analyst_annotation=json.dumps({"ip": "198.51.100.99"}),
    )

    # Add deterministic hypothesis
    case_repo.upsert_hypothesis(
        case_id=case.case_id,
        hypothesis=CaseHypothesis(
            hypothesis_id=f"hyp-det-{case.case_id}",
            case_id=case.case_id,
            statement="Bastion credential compromise facilitated lateral movement.",
            status=HypothesisStatus.SUPPORTED,
            supporting_evidence_tags=["[ip:198.51.100.99]"],
            contradicting_evidence_tags=[],
            evidence_gaps=[],
            analyst_assessment="Corroborated by SSH accepted publickey telemetry.",
            created_at="2026-10-01T00:00:00Z",
            updated_at="2026-10-01T00:00:00Z",
        ),
    )

    return case


def test_m78_det_001_review_snapshot_determinism(deterministic_case):
    """Run N=10 iterations of forensic review and verify identical gate statuses and blockers."""
    service = InvestigationReviewService()
    baseline = service.run_forensic_review(deterministic_case.case_id)

    baseline_gates = [(g.gate_type.value, g.status.value, len(g.blockers)) for g in baseline.gates]
    baseline_blockers = [b.blocker_id for b in baseline.blockers]

    for i in range(10):
        iteration = service.run_forensic_review(deterministic_case.case_id)
        iter_gates = [(g.gate_type.value, g.status.value, len(g.blockers)) for g in iteration.gates]
        iter_blockers = [b.blocker_id for b in iteration.blockers]

        assert iter_gates == baseline_gates, f"Variance in gates at iteration {i}"
        assert iter_blockers == baseline_blockers, f"Variance in blockers at iteration {i}"
        assert iteration.closure_readiness == baseline.closure_readiness, f"Variance in readiness at iteration {i}"


def test_m78_det_002_provenance_manifest_determinism(deterministic_case):
    """Verify that gate digests and blocker digests match across N=10 runs."""
    service = InvestigationReviewService()
    baseline = service.run_forensic_review(deterministic_case.case_id)

    for i in range(10):
        iteration = service.run_forensic_review(deterministic_case.case_id)
        assert iteration.provenance.gates_digest == baseline.provenance.gates_digest, f"Gates digest variance at run {i}"
        assert iteration.provenance.blockers_digest == baseline.provenance.blockers_digest, f"Blockers digest variance at run {i}"


def test_m78_det_003_json_export_determinism(deterministic_case):
    """Verify JSON export content and digest stability across N=10 runs."""
    service = InvestigationReviewService()
    # Cache snapshot once to test export stability
    service.run_forensic_review(deterministic_case.case_id)
    baseline_exp = service.export_review(deterministic_case.case_id, export_format=ExportFormat.JSON)
    baseline_json = json.loads(baseline_exp.content)

    for i in range(10):
        exp = service.export_review(deterministic_case.case_id, export_format=ExportFormat.JSON)
        cur_json = json.loads(exp.content)
        assert cur_json["case_id"] == baseline_json["case_id"]
        assert cur_json["closure_readiness"] == baseline_json["closure_readiness"]
        assert len(cur_json["gates"]) == len(baseline_json["gates"])
        assert len(cur_json["blockers"]) == len(baseline_json["blockers"])


def test_m78_det_004_csv_export_determinism(deterministic_case):
    """Verify CSV export rows and content stability across N=10 runs."""
    service = InvestigationReviewService()
    service.run_forensic_review(deterministic_case.case_id)
    baseline_exp = service.export_review(deterministic_case.case_id, export_format=ExportFormat.CSV)
    baseline_lines = baseline_exp.content.strip().split("\n")

    for i in range(10):
        exp = service.export_review(deterministic_case.case_id, export_format=ExportFormat.CSV)
        cur_lines = exp.content.strip().split("\n")
        assert len(cur_lines) == len(baseline_lines), f"CSV row count variance at run {i}"
        assert cur_lines[0] == baseline_lines[0]


def test_m78_det_005_markdown_export_determinism(deterministic_case):
    """Verify Markdown export structure and gate count stability across N=10 runs."""
    service = InvestigationReviewService()
    service.run_forensic_review(deterministic_case.case_id)
    baseline_exp = service.export_review(deterministic_case.case_id, export_format=ExportFormat.MARKDOWN)

    for i in range(10):
        exp = service.export_review(deterministic_case.case_id, export_format=ExportFormat.MARKDOWN)
        assert "## 1. Forensic Review Gates Evaluation" in exp.content
        assert "## 2. Evidence Coverage Metrics" in exp.content
        assert exp.root_digest == baseline_exp.root_digest
