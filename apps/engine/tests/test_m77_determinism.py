"""Determinism verification test suite for Milestone 7.7.

Runs N=10 iterations of case comparison, shared entity extraction,
temporal alignment, correlation candidate generation, provenance manifests,
and multi-format exports. Verifies 0 unexplained variance.
"""

import hashlib
import json
import time
import pytest

from logintel.comparison.models import (
    ComparisonScopeDimension,
    CreateCaseComparisonRequest,
)
from logintel.comparison.service import case_comparison_service
from logintel.storage.case_repo import case_repo


@pytest.fixture(scope="module")
def deterministic_cases():
    """Setup deterministic test cases with structured entity and technique references."""
    t_str = "det998"
    inc_a = 998001
    inc_b = 998002

    case_a = case_repo.get_case_by_incident(inc_a, resolve_evidence=False)
    if not case_a:
        case_a = case_repo.create_case(incident_id=inc_a, title="Deterministic Case A")
    case_b = case_repo.get_case_by_incident(inc_b, resolve_evidence=False)
    if not case_b:
        case_b = case_repo.create_case(incident_id=inc_b, title="Deterministic Case B")

    # Seed Case A
    case_repo.add_evidence_reference(
        case_id=case_a.case_id,
        source_type="ip",
        source_id="192.0.2.1",
        role="SUPPORTING",
        epistemic_status="OBSERVED",
        citation_tag="[ip:192.0.2.1]",
        analyst_annotation=json.dumps({"ip": "192.0.2.1", "host": "web-alpha"}),
    )
    case_repo.add_evidence_reference(
        case_id=case_a.case_id,
        source_type="mitre",
        source_id="T1078",
        role="SUPPORTING",
        epistemic_status="OBSERVED",
        citation_tag="[mitre:T1078]",
        analyst_annotation=json.dumps({"technique": "Valid Accounts"}),
    )

    # Seed Case B
    case_repo.add_evidence_reference(
        case_id=case_b.case_id,
        source_type="ip",
        source_id="192.0.2.1",
        role="SUPPORTING",
        epistemic_status="OBSERVED",
        citation_tag="[ip:192.0.2.1]",
        analyst_annotation=json.dumps({"ip": "192.0.2.1", "host": "db-beta"}),
    )
    case_repo.add_evidence_reference(
        case_id=case_b.case_id,
        source_type="mitre",
        source_id="T1078",
        role="SUPPORTING",
        epistemic_status="OBSERVED",
        citation_tag="[mitre:T1078]",
        analyst_annotation=json.dumps({"technique": "Valid Accounts"}),
    )

    return case_a.case_id, case_b.case_id


def test_m77_determinism_n10_shared_entities(deterministic_cases):
    """N=10 runs: Shared entity discovery and ordering must have 0 variance."""
    c1, c2 = deterministic_cases
    hashes = []

    for _ in range(10):
        entities = case_comparison_service._extract_shared_entities([c1, c2])
        dumped = json.dumps([e.model_dump() for e in entities], sort_keys=True)
        h = hashlib.sha256(dumped.encode("utf-8")).hexdigest()
        hashes.append(h)

    assert len(set(hashes)) == 1, f"Variance detected in shared entities: {len(set(hashes))} distinct hashes"


def test_m77_determinism_n10_temporal_alignment(deterministic_cases):
    """N=10 runs: Temporal overlap calculation must have 0 variance."""
    c1, c2 = deterministic_cases
    results = []

    for _ in range(10):
        t_res = case_comparison_service._compute_temporal_overlap([c1, c2])
        dumped = json.dumps(t_res.model_dump(), sort_keys=True)
        results.append(dumped)

    assert len(set(results)) == 1, "Variance detected in temporal alignment across N=10 runs"


def test_m77_determinism_n10_correlation_candidates(deterministic_cases):
    """N=10 runs: Correlation candidate IDs, types, and bases must have 0 variance."""
    c1, c2 = deterministic_cases
    candidate_id_sequences = []

    for _ in range(10):
        entities = case_comparison_service._extract_shared_entities([c1, c2])
        t_res = case_comparison_service._compute_temporal_overlap([c1, c2])
        mitre = case_comparison_service._extract_shared_mitre([c1, c2])
        candidates = case_comparison_service._generate_correlation_candidates(
            all_case_ids=[c1, c2],
            shared_entities=entities,
            temporal_overlap=t_res,
            shared_findings=[],
            shared_hunts=[],
            shared_mitre=mitre,
            evidence_gaps=[],
            now_iso="2026-10-08T00:00:00Z",
        )
        c_ids = [c.candidate_id for c in candidates]
        candidate_id_sequences.append(tuple(c_ids))

    assert len(set(candidate_id_sequences)) == 1, "Variance in correlation candidate sequence across N=10 runs"


def test_m77_determinism_n10_provenance_manifest(deterministic_cases):
    """N=10 runs: Provenance digest computation must produce identical Blake2b hashes."""
    c1, c2 = deterministic_cases
    digests = []

    entities = case_comparison_service._extract_shared_entities([c1, c2])
    t_res = case_comparison_service._compute_temporal_overlap([c1, c2])
    candidates = case_comparison_service._generate_correlation_candidates(
        all_case_ids=[c1, c2],
        shared_entities=entities,
        temporal_overlap=t_res,
        shared_findings=[],
        shared_hunts=[],
        shared_mitre=[],
        evidence_gaps=[],
        now_iso="2026-10-08T00:00:00Z",
    )

    for _ in range(10):
        manifest = case_comparison_service._build_provenance_manifest(
            comparison_id="cmp-static-1",
            all_case_ids=[c1, c2],
            shared_entities=entities,
            candidates=candidates,
            now_iso="2026-10-08T00:00:00Z",
        )
        digests.append(manifest.provenance_digest)

    assert len(set(digests)) == 1, "Variance in provenance digest across N=10 runs"


def test_m77_determinism_n10_exports(deterministic_cases):
    """N=10 runs: JSON, CSV, and Markdown exports must produce byte-identical output."""
    c1, c2 = deterministic_cases
    req = CreateCaseComparisonRequest(compared_case_ids=[c2])
    comp = case_comparison_service.compare_cases(c1, req)

    json_hashes = []
    csv_hashes = []
    md_hashes = []

    for _ in range(10):
        exp_j = case_comparison_service.export_comparison(c1, comp.comparison_id, format="json")
        exp_c = case_comparison_service.export_comparison(c1, comp.comparison_id, format="csv")
        exp_m = case_comparison_service.export_comparison(c1, comp.comparison_id, format="markdown")

        json_hashes.append(hashlib.sha256(exp_j["content"].encode("utf-8")).hexdigest())
        csv_hashes.append(hashlib.sha256(exp_c["content"].encode("utf-8")).hexdigest())
        md_hashes.append(hashlib.sha256(exp_m["content"].encode("utf-8")).hexdigest())

    assert len(set(json_hashes)) == 1, "JSON export variance detected across N=10 runs"
    assert len(set(csv_hashes)) == 1, "CSV export variance detected across N=10 runs"
    assert len(set(md_hashes)) == 1, "Markdown export variance detected across N=10 runs"
