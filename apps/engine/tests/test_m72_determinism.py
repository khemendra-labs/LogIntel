"""Determinism tests for Milestone M7.2: N=10 identical reconstructions."""

from __future__ import annotations

import hashlib
import json
import pytest

from logintel.storage.case_repo import case_repo
from logintel.timeline.models import TimelineFilterParams
from logintel.timeline.service import timeline_service


@pytest.fixture
def determinism_case():
    case = case_repo.get_case(1)
    if not case:
        case = case_repo.create_case(
            incident_id=1,
            title="M7.2 Determinism Test Case",
            description="Case for verifying N=10 identical deterministic replays",
            created_by="SecAnalyst-1",
        )
    case_id = case.case_id

    # Populate multiple evidence items
    for i in range(1, 6):
        case_repo.add_evidence_reference(
            case_id=case_id,
            source_type="event",
            source_id=f"det-{i}",
            role="SUPPORTING",
            epistemic_status="OBSERVED",
            citation_tag=f"[event:det-{i}]",
            analyst_annotation=f"Determinism event {i}",
        )
    return case_id


def test_n10_identical_timeline_reconstructions(determinism_case):
    """Run N=10 reconstructions; verify identical ordering, hashes, and item IDs."""
    case_id = determinism_case
    N = 10
    results = []

    for _ in range(N):
        items = timeline_service.build_raw_timeline_items(case_id)
        ids = [i.timeline_id for i in items]
        timestamps = [i.timestamp for i in items]
        serialized = json.dumps([i.model_dump(mode="json") for i in items], sort_keys=True)
        h = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        results.append((ids, timestamps, h))

    # All N runs must match the first run exactly
    first_ids, first_ts, first_hash = results[0]
    for idx, (ids, ts, h) in enumerate(results[1:], start=2):
        assert ids == first_ids, f"Ordering mismatch in run {idx}"
        assert ts == first_ts, f"Timestamp mismatch in run {idx}"
        assert h == first_hash, f"Hash mismatch in run {idx}"


def test_n10_identical_replay_sessions(determinism_case):
    """Run N=10 replay session generations; verify identical fingerprint and frames."""
    case_id = determinism_case
    N = 10
    fingerprints = []

    for _ in range(N):
        session = timeline_service.get_replay_session(case_id)
        fingerprints.append(session.provenance_fingerprint)

    first_fp = fingerprints[0]
    for idx, fp in enumerate(fingerprints[1:], start=2):
        assert fp == first_fp, f"Replay session fingerprint mismatch on run {idx}"


def test_n10_identical_exports(determinism_case):
    """Run N=10 JSON and CSV exports; verify byte-for-byte identical output."""
    case_id = determinism_case
    N = 10

    json_hashes = []
    csv_hashes = []

    for _ in range(N):
        j_out, _ = timeline_service.export_timeline(case_id, export_format="json")
        c_out, _ = timeline_service.export_timeline(case_id, export_format="csv")

        json_hashes.append(hashlib.sha256(j_out.encode("utf-8")).hexdigest())
        csv_hashes.append(hashlib.sha256(c_out.encode("utf-8")).hexdigest())

    assert len(set(json_hashes)) == 1, "Non-deterministic JSON export output!"
    assert len(set(csv_hashes)) == 1, "Non-deterministic CSV export output!"
