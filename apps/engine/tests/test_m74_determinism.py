import hashlib
import json
import pytest

from logintel.findings.models import CreateFindingRequest, CreateHypothesisM74Request
from logintel.findings.service import findings_workbench_service
from logintel.storage.case_repo import case_repo


@pytest.fixture
def determinism_case():
    case = case_repo.get_case(100, resolve_evidence=False)
    if not case:
        case = case_repo.create_case(
            incident_id=100,
            title="M7.4 Determinism Test Case",
            description="Case for determinism verification",
            created_by="SecAnalyst-1",
        )
    # Seed finding and hypothesis
    findings_workbench_service.create_finding(
        case.case_id,
        CreateFindingRequest(
            title="Deterministic Finding",
            statement="Statement for testing determinism",
            epistemic_status="INFERRED",
            supporting_evidence=[{"source_type": "event", "source_id": "evt-det-1"}],
        ),
    )
    findings_workbench_service.create_hypothesis(
        case.case_id,
        CreateHypothesisM74Request(
            title="Deterministic Hypothesis",
            statement="Hypothesis statement for determinism",
            supporting_evidence=["evt-det-1"],
        ),
    )
    return case.case_id


def test_n10_identical_finding_listings(determinism_case):
    """Verify that N=10 repeated finding listings produce identical serialized JSON and Blake2b hashes."""
    hashes = []
    for _ in range(10):
        findings = findings_workbench_service.get_findings(determinism_case)
        serialized = json.dumps([f.model_dump(mode="json") for f in findings], sort_keys=True)
        h = hashlib.blake2b(serialized.encode()).hexdigest()
        hashes.append(h)

    assert len(set(hashes)) == 1, f"Found varying hashes across N=10 runs: {hashes}"


def test_n10_identical_hypothesis_comparisons(determinism_case):
    """Verify that N=10 repeated hypothesis comparisons produce identical serialized JSON and Blake2b hashes."""
    hashes = []
    for _ in range(10):
        comp = findings_workbench_service.compare_hypotheses(determinism_case)
        # Exclude dynamic timestamp from serialization test
        dump = comp.model_dump(mode="json")
        dump["generated_at"] = "STATIC"
        serialized = json.dumps(dump, sort_keys=True)
        h = hashlib.blake2b(serialized.encode()).hexdigest()
        hashes.append(h)

    assert len(set(hashes)) == 1, f"Found varying hashes across N=10 runs: {hashes}"


def test_n10_identical_workbench_exports(determinism_case):
    """Verify that N=10 repeated workbench exports produce identical SHA256 checksums."""
    checksums = []
    for _ in range(10):
        export_res = findings_workbench_service.export_findings(determinism_case, format="json")
        checksums.append(export_res.sha256_digest)

    assert len(set(checksums)) == 1, f"Found varying export checksums across N=10 runs: {checksums}"
