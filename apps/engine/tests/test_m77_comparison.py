"""Functional test suite for M7.7 Case Comparison, Campaign Correlation & Cross-Investigation Analysis."""

import json
import time
import pytest

from logintel.comparison.models import (
    ComparisonScopeDimension,
    CorrelationBasis,
    CorrelationReviewStatus,
    CorrelationType,
    CorroborationNature,
    CreateCaseComparisonRequest,
    EpistemicStatus,
    ReviewCorrelationRequest,
)
from logintel.comparison.service import case_comparison_service
from logintel.findings.models import AddFindingEvidenceRequest, CreateFindingRequest, FindingEvidenceRole
from logintel.findings.service import findings_workbench_service
from logintel.storage.case_repo import case_repo


@pytest.fixture
def comparison_cases():
    """Create two populated investigation cases with shared and disjoint attributes."""
    t_str = str(int(time.time() * 1000) % 1000000)
    inc_a = 910000 + int(t_str) % 50000
    inc_b = 960000 + int(t_str) % 50000

    case_a = case_repo.create_case(incident_id=inc_a, title=f"Case A Test {t_str}")
    case_b = case_repo.create_case(incident_id=inc_b, title=f"Case B Test {t_str}")

    # Case A: Entity references
    case_repo.add_evidence_reference(
        case_id=case_a.case_id,
        source_type="ip",
        source_id="198.51.100.42",
        role="SUPPORTING",
        epistemic_status="OBSERVED",
        citation_tag="[ip:198.51.100.42]",
        analyst_annotation=json.dumps({"ip": "198.51.100.42", "host": "prod-web-01"}),
    )
    case_repo.add_evidence_reference(
        case_id=case_a.case_id,
        source_type="mitre",
        source_id="T1059",
        role="SUPPORTING",
        epistemic_status="OBSERVED",
        citation_tag="[mitre:T1059]",
        analyst_annotation=json.dumps({"technique": "Command and Scripting Interpreter"}),
    )

    # Case B: Shared IP, shared mitre, but distinct host
    case_repo.add_evidence_reference(
        case_id=case_b.case_id,
        source_type="ip",
        source_id="198.51.100.42",
        role="SUPPORTING",
        epistemic_status="OBSERVED",
        citation_tag="[ip:198.51.100.42]",
        analyst_annotation=json.dumps({"ip": "198.51.100.42", "host": "db-srv-02"}),
    )
    case_repo.add_evidence_reference(
        case_id=case_b.case_id,
        source_type="mitre",
        source_id="T1059",
        role="SUPPORTING",
        epistemic_status="OBSERVED",
        citation_tag="[mitre:T1059]",
        analyst_annotation=json.dumps({"technique": "Command and Scripting Interpreter"}),
    )

    # Add findings to both cases
    f_a = findings_workbench_service.create_finding(
        case_a.case_id,
        CreateFindingRequest(
            title="Suspicious Remote Ingress",
            statement="Observed unauthorized ingress from external gateway 198.51.100.42",
        ),
    )
    f_b = findings_workbench_service.create_finding(
        case_b.case_id,
        CreateFindingRequest(
            title="Suspicious Remote Ingress",
            statement="Database connection attempted from external gateway 198.51.100.42",
        ),
    )

    return case_a.case_id, case_b.case_id


def test_m77_compare_cases_shared_entities(comparison_cases):
    """Test multi-case comparison discovers shared entities with provenance."""
    case_a_id, case_b_id = comparison_cases

    req = CreateCaseComparisonRequest(
        compared_case_ids=[case_b_id],
        dimensions=[ComparisonScopeDimension.ENTITIES, ComparisonScopeDimension.MITRE],
    )
    result = case_comparison_service.compare_cases(case_a_id, req)

    assert result.primary_case_id == case_a_id
    assert case_b_id in result.compared_case_ids
    assert len(result.shared_entities) >= 1

    shared_ips = [e for e in result.shared_entities if e.entity_type == "IP"]
    assert len(shared_ips) >= 1
    shared_ip = shared_ips[0]
    assert shared_ip.entity_value == "198.51.100.42"
    assert str(case_a_id) in shared_ip.case_occurrences
    assert str(case_b_id) in shared_ip.case_occurrences
    assert shared_ip.epistemic_status == EpistemicStatus.OBSERVED


def test_m77_campaign_correlation_candidates(comparison_cases):
    """Test campaign correlation candidate generation and categorical basis."""
    case_a_id, case_b_id = comparison_cases

    req = CreateCaseComparisonRequest(compared_case_ids=[case_b_id])
    result = case_comparison_service.compare_cases(case_a_id, req)

    assert len(result.correlation_candidates) >= 1
    ip_cands = [c for c in result.correlation_candidates if c.correlation_type == CorrelationType.SHARED_IP]
    assert len(ip_cands) >= 1
    cand = ip_cands[0]

    assert cand.correlation_basis == CorrelationBasis.NETWORK_CONTINUITY
    assert cand.corroboration_nature == CorroborationNature.ENTITY_LINK
    assert cand.analyst_review_status == CorrelationReviewStatus.UNREVIEWED
    assert cand.epistemic_status == EpistemicStatus.OBSERVED
    # Must NOT contain numeric confidence or probability fields
    cand_dict = cand.model_dump()
    assert "confidence" not in cand_dict
    assert "probability" not in cand_dict
    assert "score" not in cand_dict


def test_m77_review_correlation_candidate(comparison_cases):
    """Test analyst review workflow on correlation candidate."""
    case_a_id, case_b_id = comparison_cases

    req = CreateCaseComparisonRequest(compared_case_ids=[case_b_id])
    result = case_comparison_service.compare_cases(case_a_id, req)
    cand = result.correlation_candidates[0]

    review_req = ReviewCorrelationRequest(
        status=CorrelationReviewStatus.CORROBORATED,
        corroboration_nature=CorroborationNature.CORROBORATING,
        review_notes="Analyst verified common egress proxy infrastructure",
    )
    reviewed = case_comparison_service.review_correlation_candidate(
        case_id=case_a_id,
        comparison_id=result.comparison_id,
        candidate_id=cand.candidate_id,
        review=review_req,
        actor="SecAnalyst-1",
    )

    assert reviewed.analyst_review_status == CorrelationReviewStatus.CORROBORATED
    assert reviewed.corroboration_nature == CorroborationNature.CORROBORATING
    assert reviewed.reviewed_by == "SecAnalyst-1"
    assert "common egress proxy" in (reviewed.review_notes or "")


def test_m77_export_formats_and_csv_defanging(comparison_cases):
    """Test deterministic export across JSON, CSV (formula defanged), and Markdown."""
    case_a_id, case_b_id = comparison_cases

    req = CreateCaseComparisonRequest(compared_case_ids=[case_b_id])
    result = case_comparison_service.compare_cases(case_a_id, req)

    # JSON export
    exp_json = case_comparison_service.export_comparison(case_a_id, result.comparison_id, format="json")
    assert exp_json["media_type"] == "application/json"
    parsed = json.loads(exp_json["content"])
    assert parsed["comparison_id"] == result.comparison_id

    # CSV export with formula injection defanging check
    exp_csv = case_comparison_service.export_comparison(case_a_id, result.comparison_id, format="csv")
    assert exp_csv["media_type"] == "text/csv"
    assert "candidate_id,correlation_type" in exp_csv["content"]

    # Markdown export
    exp_md = case_comparison_service.export_comparison(case_a_id, result.comparison_id, format="markdown")
    assert exp_md["media_type"] == "text/markdown"
    assert "# LogIntel Case Comparison Report" in exp_md["content"]
    assert "## 1. Temporal Alignment" in exp_md["content"]
