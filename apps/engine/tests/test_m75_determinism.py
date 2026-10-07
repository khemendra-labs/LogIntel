"""Determinism verification suite for M7.5 Advanced Threat Hunting & Governed Analyst Queries.

Executes N=10 repeated operations to verify byte-identical serializations, stable sorting,
and deterministic Blake2b content fingerprints.
"""

from __future__ import annotations

import pytest

from logintel.hunting.models import (
    CreateHuntProposalRequest,
    FieldFilter,
    HuntIntent,
    QueryOperator,
)
from logintel.hunting.service import threat_hunting_service
from logintel.storage.case_repo import case_repo


@pytest.fixture
def det_case():
    case = case_repo.get_case_by_incident(7521, resolve_evidence=False)
    if not case:
        case = case_repo.create_case(
            incident_id=7521,
            title="M7.5 Determinism Test Case",
            description="Case for validating deterministic hunt operations",
            created_by="SecAnalyst-1",
        )
    return case.case_id


def test_m75_query_preview_determinism(det_case):
    """Verify N=10 preview evaluations produce identical descriptions and summaries."""
    case_id = det_case
    req = CreateHuntProposalRequest(
        intent=HuntIntent.PROCESS_EXECUTION,
        question="Find all curl and wget executions",
        field_filters=[
            FieldFilter(field="process_name", operator=QueryOperator.IN, value=["curl", "wget"]),
            FieldFilter(field="host", operator=QueryOperator.EQUALS, value="srv-web-01"),
        ],
        limit=50,
    )

    previews = []
    for _ in range(10):
        prev = threat_hunting_service.validate_and_preview_hunt(case_id, req)
        previews.append(prev.model_dump_json())

    # All 10 runs must produce byte-identical JSON
    assert len(set(previews)) == 1, "Non-deterministic preview output detected"


def test_m75_execution_results_determinism(det_case):
    """Verify N=10 repeated hunt executions over unchanged telemetry produce identical results and fingerprints."""
    case_id = det_case

    fingerprints = []
    serialized_results = []
    for _ in range(10):
        res = threat_hunting_service.pivot_hunt_by_entity(case_id, "HOST", "srv-web-01")
        fingerprints.append(res.query_fingerprint)
        # Verify ordering: timestamp ASC, source ASC, id ASC
        for i in range(len(res.results) - 1):
            assert (res.results[i].timestamp, res.results[i].source_id) <= (res.results[i + 1].timestamp, res.results[i + 1].source_id)
        # Check canonical serialization of item IDs
        id_seq = [it.result_id for it in res.results]
        serialized_results.append(tuple(id_seq))

    assert len(set(fingerprints)) == 1, "Non-deterministic query fingerprint across N=10 runs"
    assert len(set(serialized_results)) == 1, "Non-deterministic item ordering across N=10 runs"


def test_m75_export_determinism(det_case):
    """Verify N=10 export operations produce byte-identical exports and fingerprints."""
    case_id = det_case
    hunt_res = threat_hunting_service.pivot_hunt_by_entity(case_id, "USER", "admin")
    hunt_id = hunt_res.hunt_id

    json_exports = []
    csv_exports = []
    for _ in range(10):
        exp_j = threat_hunting_service.export_hunt(case_id, hunt_id, format_type="json")
        json_exports.append(exp_j.fingerprint)

        exp_c = threat_hunting_service.export_hunt(case_id, hunt_id, format_type="csv")
        csv_exports.append(exp_c.fingerprint)

    assert len(set(json_exports)) == 1, "Non-deterministic JSON export fingerprint across N=10 runs"
    assert len(set(csv_exports)) == 1, "Non-deterministic CSV export fingerprint across N=10 runs"
