"""Functional and integration tests for Milestone M7.2 Unified Timeline & Replay Engine."""

from __future__ import annotations

import csv
import json
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from logintel.api.app import app
from logintel.api.auth import get_current_token
from logintel.storage.case_repo import case_repo
from logintel.storage.db import db
from logintel.timeline.models import (
    CollectionStatus,
    EpistemicStatus,
    TimelineFilterParams,
    TimelineSourceLayer,
    TimestampPrecision,
)
from logintel.timeline.service import timeline_service


@pytest.fixture
def auth_client():
    token = get_current_token()
    client = TestClient(app)
    client.headers.update({"Authorization": f"Bearer {token}"})
    return client


@pytest.fixture
def setup_test_case():
    """Create a clean case with test evidence references and bookmarks."""
    case = case_repo.get_case(1)
    if not case:
        case = case_repo.create_case(
            incident_id=1,
            title="M7.2 Test Incident Case",
            description="Case for M7.2 unified timeline and replay verification",
            created_by="SecAnalyst-1",
        )
    case_id = case.case_id

    # Add evidence references of diverse layers
    case_repo.add_evidence_reference(
        case_id=case_id,
        source_type="event",
        source_id="101",
        role="PRIMARY",
        epistemic_status="OBSERVED",
        citation_tag="[event:101]",
        analyst_annotation="Initial SSH authentication failure",
    )
    case_repo.add_evidence_reference(
        case_id=case_id,
        source_type="alert",
        source_id="1",
        role="SUPPORTING",
        epistemic_status="OBSERVED",
        citation_tag="[alert:1]",
        analyst_annotation="Brute force alert triggered",
    )
    case_repo.add_evidence_reference(
        case_id=case_id,
        source_type="detection",
        source_id="2",
        role="SUPPORTING",
        epistemic_status="OBSERVED",
        citation_tag="[detection:2]",
        analyst_annotation="Sudo privilege escalation rule matched",
    )

    return case_id


def test_build_raw_timeline_items(setup_test_case):
    case_id = setup_test_case
    items = timeline_service.build_raw_timeline_items(case_id)
    assert len(items) >= 3

    # Check layer assignment
    layers = {i.layer for i in items}
    assert TimelineSourceLayer.ALERT in layers or TimelineSourceLayer.AUTH in layers

    # Check deterministic ordering
    for idx in range(len(items) - 1):
        k1 = timeline_service._timeline_sort_key(items[idx])
        k2 = timeline_service._timeline_sort_key(items[idx + 1])
        assert k1 <= k2


def test_timestamp_precision_and_epistemic_preservation(setup_test_case):
    case_id = setup_test_case
    items = timeline_service.build_raw_timeline_items(case_id)

    for item in items:
        assert item.timestamp_precision in (
            TimestampPrecision.SECOND,
            TimestampPrecision.MILLISECOND,
            TimestampPrecision.UNKNOWN,
        )
        assert item.epistemic_status in (
            EpistemicStatus.OBSERVED,
            EpistemicStatus.INFERRED,
            EpistemicStatus.UNKNOWN,
        )
        assert item.collection_status in (
            CollectionStatus.SOURCE_AVAILABLE,
            CollectionStatus.RULE_NOT_CONFIGURED,
            CollectionStatus.NO_EVENT_OBSERVED,
        )
        assert item.provenance.strip() != ""


def test_timeline_filtering_and_search(setup_test_case):
    case_id = setup_test_case

    # Query with layer filter
    params = TimelineFilterParams(layer=TimelineSourceLayer.ALERT.value, limit=50)
    res = timeline_service.query_timeline(case_id, params)
    for it in res.items:
        assert it.layer == TimelineSourceLayer.ALERT

    # Query with search
    search_params = TimelineFilterParams(search="Brute", limit=50)
    res_search = timeline_service.query_timeline(case_id, search_params)
    assert res_search.total >= 0


def test_bookmark_lifecycle(setup_test_case):
    case_id = setup_test_case
    items = timeline_service.build_raw_timeline_items(case_id)
    target_item = items[0]

    # Add bookmark
    bm_res = timeline_service.bookmark_item(
        case_id=case_id,
        timeline_id=target_item.timeline_id,
        analyst_note="Critical persistence pivot point",
        actor="SecAnalyst-1",
    )
    assert bm_res["status"] == "BOOKMARKED"
    assert bm_res["timeline_id"] == target_item.timeline_id

    # Verify query returns item as bookmarked
    res = timeline_service.query_timeline(case_id, TimelineFilterParams(bookmarked_only=True))
    assert any(i.timeline_id == target_item.timeline_id and i.is_bookmarked for i in res.items)

    # Remove bookmark
    rm_res = timeline_service.remove_bookmark(case_id, target_item.timeline_id, actor="SecAnalyst-1")
    assert rm_res["status"] == "REMOVED"

    # Verify removed
    res_after = timeline_service.query_timeline(case_id, TimelineFilterParams(bookmarked_only=True))
    assert not any(i.timeline_id == target_item.timeline_id for i in res_after.items)


def test_replay_session_and_fingerprint(setup_test_case):
    case_id = setup_test_case
    session = timeline_service.get_replay_session(case_id)

    assert session.case_id == case_id
    assert session.total_items == len(session.items)
    assert len(session.frames) == session.total_items
    assert session.provenance_fingerprint.startswith("sha256:")

    # Verify frame sequence indexes
    for idx, frame in enumerate(session.frames):
        assert frame.frame_index == idx
        assert frame.timeline_id == session.items[idx].timeline_id
        assert frame.timestamp == session.items[idx].timestamp


def test_timeline_context_synchronization(setup_test_case):
    case_id = setup_test_case
    items = timeline_service.build_raw_timeline_items(case_id)
    target_item = items[0]

    ctx = timeline_service.get_timeline_context(case_id, target_item.timeline_id)
    assert ctx.item.timeline_id == target_item.timeline_id
    assert isinstance(ctx.related_graph_nodes, list)
    assert isinstance(ctx.related_evidence, list)
    assert isinstance(ctx.source_record, dict)


def test_export_timeline_deterministic(setup_test_case):
    case_id = setup_test_case

    # Export JSON
    json_out1, ct1 = timeline_service.export_timeline(case_id, export_format="json")
    json_out2, ct2 = timeline_service.export_timeline(case_id, export_format="json")
    assert ct1 == "application/json"
    assert json_out1 == json_out2
    data = json.loads(json_out1)
    assert data["case_id"] == case_id
    assert "items" in data

    # Export CSV
    csv_out1, ct3 = timeline_service.export_timeline(case_id, export_format="csv")
    csv_out2, ct4 = timeline_service.export_timeline(case_id, export_format="csv")
    assert ct3 == "text/csv"
    assert csv_out1 == csv_out2
    lines = csv_out1.strip().split("\n")
    assert lines[0].startswith("timeline_id,timestamp")


def test_api_endpoints_unified_timeline(auth_client, setup_test_case):
    case_id = setup_test_case

    # 1. GET unified timeline
    resp = auth_client.get(f"/api/v1/cases/{case_id}/timeline/unified?limit=20")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert "epistemic_breakdown" in data
    assert "layer_breakdown" in data

    # 2. GET replay session
    resp_replay = auth_client.get(f"/api/v1/cases/{case_id}/timeline/replay")
    assert resp_replay.status_code == 200
    rep_data = resp_replay.json()
    assert rep_data["case_id"] == case_id
    assert "frames" in rep_data
    assert "provenance_fingerprint" in rep_data

    # 3. GET context
    if data["items"]:
        t_id = data["items"][0]["timeline_id"]
        resp_ctx = auth_client.get(f"/api/v1/cases/{case_id}/timeline/context/{t_id}")
        assert resp_ctx.status_code == 200
        ctx_data = resp_ctx.json()
        assert ctx_data["item"]["timeline_id"] == t_id

        # 4. POST bookmark
        resp_bm = auth_client.post(
            f"/api/v1/cases/{case_id}/timeline/{t_id}/bookmark",
            json={"analyst_note": "API bookmark test", "actor": "SecAnalyst-1"},
        )
        assert resp_bm.status_code == 200
        assert resp_bm.json()["status"] == "BOOKMARKED"

        # 5. DELETE bookmark
        resp_del = auth_client.delete(f"/api/v1/cases/{case_id}/timeline/{t_id}/bookmark")
        assert resp_del.status_code == 200
        assert resp_del.json()["status"] == "REMOVED"

    # 6. GET export
    resp_exp = auth_client.get(f"/api/v1/cases/{case_id}/timeline/unified/export?format=json")
    assert resp_exp.status_code == 200
    assert resp_exp.headers["content-type"] == "application/json"
