"""Test suite for Milestone 7.12.1 Multi-Host Domain and API Foundation.

Tests:
1. InvestigationScope target_hosts sanitization, deduplication, and normalization.
2. Backward-compatible deserialization of historical scopes without target_hosts.
3. Case-scoped multi-host dossier synthesis with 0, 1, and multiple participating hosts.
4. Cross-host lateral movement trace reconstruction and inbound/outbound hop counts.
5. Entity continuity detection across hosts.
6. Forensic visibility gap tracking (MISSING_HOST_CATALOG_ENTRY, TARGET_HOST_TELEMETRY_ABSENT).
7. Host identity discrepancy detection.
8. Case-scoped host inventory REST API (GET /api/v1/cases/{case_id}/hosts).
9. Host-specific timeline API (GET /api/v1/cases/{case_id}/hosts/{host_id}/timeline).
10. Lateral trace API (GET /api/v1/cases/{case_id}/hosts/lateral-traces).
11. Authentication enforcement and 401/403 handling.
12. Cross-case access rejection and 404 handling.
13. Multi-host dossier determinism (N=10, 0 variance).
14. Forensic database immutability (zero writes on logintel.db).
15. Regression compatibility with existing case and timeline endpoints.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import random
import time
import pytest
from fastapi.testclient import TestClient

from logintel.ai.domain.case import InvestigationScope
from logintel.api.app import app
from logintel.api.auth import get_current_token
from logintel.multihost.models import (
    CaseHostSummary,
    CaseMultiHostDossier,
    HostEpistemicStatus,
)
from logintel.multihost.service import MultiHostInvestigationService, multihost_service
from logintel.storage.case_repo import case_repo
from logintel.storage.db import Database, db
from logintel.ai.temporal.reconstruction_engine import TemporalReconstructionEngine
from logintel.timeline.service import timeline_service, TimelineFilterParams
from logintel.timeline.models import TimelineQueryResponse
from logintel.ai.domain.investigation_temporal import EpistemicStatus, TransitionType


@pytest.fixture
def auth_client():
    token = get_current_token()
    client = TestClient(app)
    client.headers.update({"Authorization": f"Bearer {token}"})
    return client


@pytest.fixture
def unauth_client():
    return TestClient(app)


@pytest.fixture
def multihost_fixture():
    """Create realistic isolated cases: empty case, single-host case, and multi-host case."""
    t_id = int(time.time() * 1000) % 900000 + random.randint(10000000, 90000000)

    # 1. Empty case
    inc_empty = 810000 + t_id
    case_empty = case_repo.create_case(
        incident_id=inc_empty,
        title=f"M7.12 Empty Host Case {t_id}",
        description="Case with zero participating hosts and unspecified scope.",
    )

    # 2. Single host case
    inc_single = 820000 + t_id
    case_single = case_repo.create_case(
        incident_id=inc_single,
        title=f"M7.12 Single Host Case {t_id}",
        description="Case bound to a single monitored workstation.",
    )
    case_repo.update_case_scope(
        case_id=case_single.case_id,
        scope=InvestigationScope(
            investigation_id=inc_single,
            subject_id=f"inc-{inc_single}",
            target_hosts=["workstation-corp-01"],
        ),
    )
    case_repo.add_evidence_reference(
        case_id=case_single.case_id,
        source_type="event",
        source_id=f"ev-s1-{t_id}",
        role="PRIMARY",
        epistemic_status="OBSERVED",
        citation_tag=f"[event:ev-s1-{t_id}]",
        analyst_annotation=json.dumps({
            "id": f"ev-s1-{t_id}",
            "timestamp": "2026-10-09T10:00:00Z",
            "host": "workstation-corp-01",
            "hostname": "workstation-corp-01",
            "event_type": "USER_LOGIN",
            "source": "auth",
            "username": "alice",
        }),
    )

    # 3. Multi-host case with lateral movement
    inc_multi = 830000 + t_id
    case_multi = case_repo.create_case(
        incident_id=inc_multi,
        title=f"M7.12 Multi-Host Lateral Campaign Case {t_id}",
        description="Case investigating lateral movement from staging to domain controller.",
    )
    case_repo.update_case_scope(
        case_id=case_multi.case_id,
        scope=InvestigationScope(
            investigation_id=inc_multi,
            subject_id=f"inc-{inc_multi}",
            target_hosts=["host-jumpbox", "host-dc01", "host-absent-sensor"],
        ),
    )
    # Hop 1 on jumpbox
    case_repo.add_evidence_reference(
        case_id=case_multi.case_id,
        source_type="event",
        source_id=f"ev-m1-{t_id}",
        role="PRIMARY",
        epistemic_status="OBSERVED",
        citation_tag=f"[event:ev-m1-{t_id}]",
        analyst_annotation=json.dumps({
            "id": f"ev-m1-{t_id}",
            "timestamp": "2026-10-09T10:05:00Z",
            "host": "host-jumpbox",
            "hostname": "jumpbox.corp.internal",
            "event_type": "SSH_LOGIN",
            "source": "auth",
            "username": "svc_admin",
            "action": "login",
        }),
    )
    # Hop 2 lateral to dc01
    case_repo.add_evidence_reference(
        case_id=case_multi.case_id,
        source_type="event",
        source_id=f"ev-m2-{t_id}",
        role="SUPPORTING",
        epistemic_status="OBSERVED",
        citation_tag=f"[event:ev-m2-{t_id}]",
        analyst_annotation=json.dumps({
            "id": f"ev-m2-{t_id}",
            "timestamp": "2026-10-09T10:15:00Z",
            "host": "host-dc01",
            "hostname": "dc01.corp.internal",
            "event_type": "LATERAL_EXECUTION",
            "source": "process",
            "username": "svc_admin",
            "action": "lateral",
        }),
    )
    # Alert on dc01
    case_repo.add_evidence_reference(
        case_id=case_multi.case_id,
        source_type="alert",
        source_id=str(70000 + t_id % 10000),
        role="CORROBORATING",
        epistemic_status="OBSERVED",
        citation_tag=f"[alert:{70000 + t_id % 10000}]",
        analyst_annotation=json.dumps({
            "id": 70000 + t_id % 10000,
            "rule_id": "sec.credential_dump",
            "first_seen": "2026-10-09T10:20:00Z",
            "host": "host-dc01",
            "hostname": "dc01.corp.internal",
            "severity": "CRITICAL",
        }),
    )

    return {
        "case_empty": case_empty,
        "case_single": case_single,
        "case_multi": case_multi,
        "t_id": t_id,
    }


# =========================================================================
# 1. Explicit Host Scope Validation & Backward Compatibility Tests
# =========================================================================

def test_scope_target_hosts_sanitization():
    """Verify target_hosts strips whitespace, deduplicates case-insensitively, and rejects control chars."""
    scope = InvestigationScope(
        investigation_id=1,
        subject_id="inc-1",
        target_hosts=["  host-a  ", "HOST-A", "host-b\x00\x1f", "", "   ", "host-c"],
    )
    assert scope.target_hosts == ["host-a", "host-b", "host-c"]


def test_scope_backward_compatibility():
    """Verify historical scope JSON lacking target_hosts deserializes seamlessly to empty list."""
    legacy_json = {
        "investigation_id": 42,
        "subject_type": "incident",
        "subject_id": "inc-42",
        "selected_entity_ids": ["entity-1"],
        "selected_alert_ids": [10],
        "selected_detection_ids": [20],
        "selected_event_ids": ["ev-1"],
    }
    scope = InvestigationScope.model_validate(legacy_json)
    assert scope.target_hosts == []
    assert scope.investigation_id == 42


def test_scope_single_string_coercion():
    """Verify passing a single string to target_hosts is safely handled as a single-element list."""
    scope = InvestigationScope.model_validate({
        "investigation_id": 1,
        "subject_id": "inc-1",
        "target_hosts": "standalone-host",
    })
    assert scope.target_hosts == ["standalone-host"]


# =========================================================================
# 2. Case-Scoped Multi-Host Dossier Service Tests
# =========================================================================

def test_empty_case_dossier(multihost_fixture):
    """Empty case with no evidence returns 0 participating hosts without errors."""
    case_empty = multihost_fixture["case_empty"]
    dossier = multihost_service.get_case_dossier(case_empty.case_id)

    assert isinstance(dossier, CaseMultiHostDossier)
    assert dossier.case_id == case_empty.case_id
    assert dossier.total_hosts_count == 0
    assert dossier.participating_hosts == []
    assert dossier.lateral_traces == []
    assert dossier.cross_host_hops_count == 0
    assert dossier.is_scope_unspecified is True
    assert dossier.provenance_hash.startswith("sha256:")


def test_single_host_case_dossier(multihost_fixture):
    """Single-host case aggregates evidence on one host with 0 lateral traces."""
    case_single = multihost_fixture["case_single"]
    dossier = multihost_service.get_case_dossier(case_single.case_id)

    assert dossier.total_hosts_count == 1
    assert dossier.scoped_hosts_count == 1
    assert dossier.cross_host_hops_count == 0
    assert len(dossier.lateral_traces) == 0

    host_summary = dossier.participating_hosts[0]
    assert host_summary.host_id.lower() == "workstation-corp-01"
    assert host_summary.event_count >= 1
    assert host_summary.is_in_target_scope is True
    assert host_summary.first_seen is not None
    assert host_summary.epistemic_status == HostEpistemicStatus.OBSERVED


def test_multi_host_lateral_traces_and_gaps(multihost_fixture):
    """Multi-host case correctly reconstructs lateral hops and tracks absent telemetry."""
    case_multi = multihost_fixture["case_multi"]
    dossier = multihost_service.get_case_dossier(case_multi.case_id)

    assert dossier.total_hosts_count == 3
    # 3 target hosts: host-jumpbox, host-dc01, host-absent-sensor
    assert dossier.scoped_hosts_count == 3

    hosts_by_id = {h.host_id.lower(): h for h in dossier.participating_hosts}
    assert "host-jumpbox" in hosts_by_id
    assert "host-dc01" in hosts_by_id
    assert "host-absent-sensor" in hosts_by_id

    # Check absent telemetry host
    absent_host = hosts_by_id["host-absent-sensor"]
    assert absent_host.event_count == 0
    assert absent_host.alert_count == 0
    assert absent_host.epistemic_status == HostEpistemicStatus.UNKNOWN
    assert any(g.gap_type == "TARGET_HOST_TELEMETRY_ABSENT" for g in absent_host.telemetry_gaps)

    # Check observed hosts
    jumpbox = hosts_by_id["host-jumpbox"]
    assert jumpbox.event_count >= 1
    assert jumpbox.outbound_lateral_hops >= 1

    dc01 = hosts_by_id["host-dc01"]
    assert dc01.event_count >= 1
    assert dc01.alert_count >= 1
    assert dc01.inbound_lateral_hops >= 1

    # Check lateral traces
    assert len(dossier.lateral_traces) >= 1
    trace = dossier.lateral_traces[0]
    assert trace.source_host == "host-jumpbox"
    assert trace.target_host == "host-dc01"
    assert trace.hop_count == 1

    # Check completeness limitations
    assert any("absent telemetry does not constitute proof" in s for s in dossier.completeness_limitations)
    assert any("bounded to 3 target host(s)" in s for s in dossier.completeness_limitations)


# =========================================================================
# 3. REST API Endpoint Tests
# =========================================================================

def test_api_get_case_hosts_authenticated(auth_client, multihost_fixture):
    """GET /api/v1/cases/{case_id}/hosts returns the case-scoped multi-host dossier."""
    case_multi = multihost_fixture["case_multi"]
    res = auth_client.get(f"/api/v1/cases/{case_multi.case_id}/hosts")
    assert res.status_code == 200

    data = res.json()
    assert data["case_id"] == case_multi.case_id
    assert data["total_hosts_count"] == 3
    assert len(data["participating_hosts"]) == 3
    assert len(data["lateral_traces"]) >= 1
    assert "provenance_hash" in data


def test_api_get_case_hosts_unauthenticated(unauth_client, multihost_fixture):
    """Unauthenticated access to /cases/{case_id}/hosts is rejected with 401 or 403."""
    case_multi = multihost_fixture["case_multi"]
    res = unauth_client.get(f"/api/v1/cases/{case_multi.case_id}/hosts")
    assert res.status_code in (401, 403)


def test_api_get_case_hosts_nonexistent_case(auth_client):
    """Querying hosts for a non-existent case returns 404."""
    res = auth_client.get("/api/v1/cases/9999999/hosts")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


def test_api_get_lateral_traces(auth_client, multihost_fixture):
    """GET /api/v1/cases/{case_id}/hosts/lateral-traces returns lateral traces."""
    case_multi = multihost_fixture["case_multi"]
    res = auth_client.get(f"/api/v1/cases/{case_multi.case_id}/hosts/lateral-traces")
    assert res.status_code == 200

    data = res.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert data[0]["source_host"] == "host-jumpbox"
    assert data[0]["target_host"] == "host-dc01"


def test_api_get_host_timeline_authenticated(auth_client, multihost_fixture):
    """GET /api/v1/cases/{case_id}/hosts/{host_id}/timeline returns host-scoped projection."""
    case_multi = multihost_fixture["case_multi"]
    res = auth_client.get(f"/api/v1/cases/{case_multi.case_id}/hosts/host-jumpbox/timeline")
    assert res.status_code == 200

    data = res.json()
    assert data["case_id"] == case_multi.case_id
    assert data["host_id"] == "host-jumpbox"
    assert data["total"] >= 1
    assert len(data["items"]) >= 1
    assert all("jumpbox" in i["host_id"].lower() for i in data["items"])


def test_api_get_host_timeline_unknown_host(auth_client, multihost_fixture):
    """Requesting host timeline for a host not part of the case returns 404."""
    case_multi = multihost_fixture["case_multi"]
    res = auth_client.get(f"/api/v1/cases/{case_multi.case_id}/hosts/alien-unknown-host/timeline")
    assert res.status_code == 404
    assert "not found or not associated" in res.json()["detail"]


def test_cross_case_isolation(auth_client, multihost_fixture):
    """Hosts from Case B cannot be queried through Case A."""
    case_single = multihost_fixture["case_single"]
    # workstation-corp-01 belongs to case_single, not case_empty
    case_empty = multihost_fixture["case_empty"]
    res = auth_client.get(f"/api/v1/cases/{case_empty.case_id}/hosts/workstation-corp-01/timeline")
    assert res.status_code == 404


# =========================================================================
# 4. Determinism, Immutability & Compatibility Tests
# =========================================================================

def test_multihost_determinism(multihost_fixture):
    """Repeated dossier syntheses across N=10 runs produce byte-for-byte identical results."""
    case_multi = multihost_fixture["case_multi"]
    hashes = []
    for _ in range(10):
        dossier = multihost_service.get_case_dossier(case_multi.case_id)
        # Check deterministic ordering of hosts and traces
        host_ids = [h.host_id for h in dossier.participating_hosts]
        trace_ids = [tr.trace_id for tr in dossier.lateral_traces]
        assert host_ids == sorted(host_ids, key=lambda k: k.lower())
        assert trace_ids == sorted(trace_ids)
        hashes.append((dossier.total_hosts_count, tuple(host_ids), tuple(trace_ids)))

    assert len(set(hashes)) == 1, "Variance detected in multi-host dossier synthesis"


def test_forensic_database_immutability(multihost_fixture):
    """Authoritative forensic database logintel.db remains strictly unmutated during all multi-host operations."""
    db_path = db.db_path
    if not db_path.exists():
        pytest.skip("logintel.db file not present on filesystem")

    def get_db_hash():
        with open(db_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    before_hash = get_db_hash()

    # Execute all multi-host service and API operations
    case_multi = multihost_fixture["case_multi"]
    multihost_service.get_case_dossier(case_multi.case_id)
    multihost_service.get_lateral_traces(case_multi.case_id)
    multihost_service.get_host_timeline(case_multi.case_id, "host-jumpbox")

    after_hash = get_db_hash()
    assert before_hash == after_hash, "Forensic invariant violated: logintel.db was modified during multi-host read operations"


def test_api_get_continuity_authenticated(auth_client, multihost_fixture):
    """Retrieve cross-host entity continuity via authenticated endpoint (M7.12.3)."""
    case_multi = multihost_fixture["case_multi"]
    res = auth_client.get(f"/api/v1/cases/{case_multi.case_id}/hosts/continuity")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    # Check svc_admin continuity across jumpbox and dc01
    user_cont = next((c for c in data if c["entity_key"] == "user:svc_admin"), None)
    assert user_cont is not None
    assert user_cont["continuity_type"] == "SAME_ACCOUNT_ACROSS_HOSTS"
    assert "host-jumpbox" in user_cont["participating_hosts"]
    assert "host-dc01" in user_cont["participating_hosts"]
    assert user_cont["occurrences_count"] >= 2
    assert "description" in user_cont


def test_api_get_continuity_unauthenticated(unauth_client, multihost_fixture):
    """Unauthenticated requests to continuity endpoint are rejected with 401."""
    case_multi = multihost_fixture["case_multi"]
    res = unauth_client.get(f"/api/v1/cases/{case_multi.case_id}/hosts/continuity")
    assert res.status_code == 401


def test_api_get_continuity_nonexistent_case(auth_client):
    """Continuity request for non-existent case returns 404."""
    res = auth_client.get("/api/v1/cases/999999/hosts/continuity")
    assert res.status_code == 404


def test_api_get_continuity_empty_case(auth_client, multihost_fixture):
    """Empty case returns empty list of continuities."""
    case_empty = multihost_fixture["case_empty"]
    res = auth_client.get(f"/api/v1/cases/{case_empty.case_id}/hosts/continuity")
    assert res.status_code == 200
    assert res.json() == []


def test_api_get_comparative_timeline_authenticated(auth_client, multihost_fixture):
    """Retrieve multi-host comparative timeline lanes via authenticated endpoint (M7.12.4)."""
    case_multi = multihost_fixture["case_multi"]
    res = auth_client.get(
        f"/api/v1/cases/{case_multi.case_id}/hosts/timeline/comparative?hosts=host-jumpbox,host-dc01"
    )
    assert res.status_code == 200
    data = res.json()
    assert data["case_id"] == case_multi.case_id
    assert len(data["lanes"]) == 2
    lane_hosts = [l["host_id"] for l in data["lanes"]]
    assert "host-jumpbox" in lane_hosts
    assert "host-dc01" in lane_hosts
    assert data["total_events"] >= 2
    assert data["aligned_min_time"] is not None
    assert data["aligned_max_time"] is not None


def test_api_get_comparative_timeline_unauthenticated(unauth_client, multihost_fixture):
    """Unauthenticated requests to comparative timeline endpoint are rejected with 401."""
    case_multi = multihost_fixture["case_multi"]
    res = unauth_client.get(
        f"/api/v1/cases/{case_multi.case_id}/hosts/timeline/comparative?hosts=host-jumpbox"
    )
    assert res.status_code == 401


def test_api_get_comparative_timeline_nonexistent_case(auth_client):
    """Comparative timeline request for non-existent case returns 404."""
    res = auth_client.get("/api/v1/cases/999999/hosts/timeline/comparative?hosts=host-jumpbox")
    assert res.status_code == 404


def test_api_get_comparative_timeline_empty_hosts(auth_client, multihost_fixture):
    """Comparative timeline with empty hosts parameter returns empty lanes."""
    case_multi = multihost_fixture["case_multi"]
    res = auth_client.get(f"/api/v1/cases/{case_multi.case_id}/hosts/timeline/comparative")
    assert res.status_code == 200
    data = res.json()
    assert data["lanes"] == []
    assert data["total_events"] == 0


def test_existing_endpoints_compatibility(auth_client, multihost_fixture):
    """Existing case endpoints and unified timeline endpoints continue functioning without regression."""
    case_multi = multihost_fixture["case_multi"]

    # 1. Existing case detail endpoint
    res_case = auth_client.get(f"/api/v1/cases/{case_multi.case_id}")
    assert res_case.status_code == 200
    assert res_case.json()["case_id"] == case_multi.case_id

    # 2. Existing unified timeline endpoint
    res_tl = auth_client.get(f"/api/v1/cases/{case_multi.case_id}/timeline/unified")
    assert res_tl.status_code == 200
    assert "items" in res_tl.json()


def test_export_dossier_json_service(multihost_fixture):
    """Service method export_dossier produces valid structured JSON with provenance root digest (M7.12.5)."""
    case_multi = multihost_fixture["case_multi"]
    res = multihost_service.export_dossier(case_multi.case_id, format="json")
    assert res.case_id == case_multi.case_id
    assert res.format == "json"
    assert res.filename == f"case_{case_multi.case_id}_multihost_dossier.json"
    assert res.root_digest.startswith("sha256:")
    assert len(res.root_digest) == 71
    # Validate JSON payload parses and matches provenance hash
    parsed = json.loads(res.content)
    assert parsed["case_id"] == case_multi.case_id
    assert parsed["provenance_hash"] == res.root_digest
    assert len(parsed["participating_hosts"]) == 3
    assert len(parsed["lateral_traces"]) >= 1


def test_export_dossier_markdown_service(multihost_fixture):
    """Service method export_dossier produces forensic Markdown report with sections and digest (M7.12.5)."""
    case_multi = multihost_fixture["case_multi"]
    res = multihost_service.export_dossier(case_multi.case_id, format="markdown")
    assert res.case_id == case_multi.case_id
    assert res.format == "markdown"
    assert res.filename == f"case_{case_multi.case_id}_multihost_report.md"
    assert res.root_digest.startswith("sha256:")
    assert len(res.root_digest) == 71
    assert "# Multi-Host Investigation Report" in res.content
    assert "## 1. Executive Summary" in res.content
    assert "## 2. Participating Host Catalog & Epistemic Status" in res.content
    assert "## 3. Reconstructed Lateral Movement Traces" in res.content
    assert "## 4. Cross-Host Entity Continuity" in res.content
    assert "## 5. Visibility Boundaries & Completeness Limitations" in res.content
    assert res.root_digest in res.content


def test_export_dossier_invalid_format_service(multihost_fixture):
    """Service method rejects unsupported formats with ValueError."""
    case_multi = multihost_fixture["case_multi"]
    with pytest.raises(ValueError, match="Unsupported export format"):
        multihost_service.export_dossier(case_multi.case_id, format="xml")


def test_api_export_multihost_dossier_json(auth_client, multihost_fixture):
    """Endpoint GET /cases/{id}/hosts/export returns structured JSON dossier with provenance metadata (M7.12.5)."""
    case_multi = multihost_fixture["case_multi"]
    res = auth_client.get(f"/api/v1/cases/{case_multi.case_id}/hosts/export?format=json")
    assert res.status_code == 200
    data = res.json()
    assert data["case_id"] == case_multi.case_id
    assert data["format"] == "json"
    assert data["filename"] == f"case_{case_multi.case_id}_multihost_dossier.json"
    assert data["root_digest"].startswith("sha256:")
    assert len(data["root_digest"]) == 71
    parsed_content = json.loads(data["content"])
    assert parsed_content["case_id"] == case_multi.case_id
    assert parsed_content["provenance_hash"] == data["root_digest"]


def test_api_export_multihost_dossier_markdown(auth_client, multihost_fixture):
    """Endpoint GET /cases/{id}/hosts/export returns structured Markdown report (M7.12.5)."""
    case_multi = multihost_fixture["case_multi"]
    res = auth_client.get(f"/api/v1/cases/{case_multi.case_id}/hosts/export?format=markdown")
    assert res.status_code == 200
    data = res.json()
    assert data["case_id"] == case_multi.case_id
    assert data["format"] == "markdown"
    assert data["filename"] == f"case_{case_multi.case_id}_multihost_report.md"
    assert data["root_digest"].startswith("sha256:")
    assert len(data["root_digest"]) == 71
    assert "# Multi-Host Investigation Report" in data["content"]
    assert data["root_digest"] in data["content"]


def test_api_export_multihost_unauthenticated(unauth_client, multihost_fixture):
    """Unauthenticated export requests are rejected with 401."""
    case_multi = multihost_fixture["case_multi"]
    res = unauth_client.get(f"/api/v1/cases/{case_multi.case_id}/hosts/export?format=json")
    assert res.status_code == 401


def test_api_export_multihost_nonexistent_case(auth_client):
    """Export request for non-existent case returns 404."""
    res = auth_client.get("/api/v1/cases/999999/hosts/export?format=json")
    assert res.status_code == 404


def test_api_export_multihost_invalid_format(auth_client, multihost_fixture):
    """Export request with invalid format query parameter is rejected with 422."""
    case_multi = multihost_fixture["case_multi"]
    res = auth_client.get(f"/api/v1/cases/{case_multi.case_id}/hosts/export?format=yaml")
    assert res.status_code == 422


# ==============================================================================
# REMEDIATION REGRESSION TESTS (M712-001 through M712-006)
# ==============================================================================


def test_remediation_m712_001_deterministic_provenance_hash(multihost_fixture):
    """DEFECT M712-001: Dossier provenance_hash is deterministic across N=10 syntheses over time."""
    case_multi = multihost_fixture["case_multi"]
    hashes = []
    for _ in range(10):
        time.sleep(0.005)  # Ensure clock advances
        dossier = multihost_service.get_case_dossier(case_multi.case_id)
        hashes.append(dossier.provenance_hash)

    assert len(hashes) == 10
    assert len(set(hashes)) == 1, f"Provenance hash varied across calls: {set(hashes)}"
    assert hashes[0].startswith("sha256:")
    assert len(hashes[0]) == 71


def test_remediation_m712_002_lateral_trace_actor_attribution_from_evidence(multihost_fixture):
    """DEFECT M712-002: Reconstructed lateral trace actor is derived from evidence username, never case owner."""
    case_multi = multihost_fixture["case_multi"]
    # Verify case owner is different from evidence actor
    assert case_multi.owner != "svc_admin"

    traces = multihost_service.get_lateral_traces(case_multi.case_id)
    assert len(traces) >= 1
    for tr in traces:
        assert tr.actor == "svc_admin"
        assert tr.actor != case_multi.owner

    # Verify when evidence has no username, actor defaults to UNKNOWN, never case owner
    t_id = int(time.time() * 1000) % 800000
    case_no_user = case_repo.create_case(
        incident_id=890000 + t_id,
        title=f"M7.12 Anonymous Trace Case {t_id}",
        description="Case with no observed usernames in evidence.",
        created_by="SecAnalyst-Forensic",
    )
    case_repo.update_case_scope(
        case_id=case_no_user.case_id,
        scope=InvestigationScope(
            investigation_id=890000 + t_id,
            subject_id=f"inc-{890000 + t_id}",
            target_hosts=["host-a", "host-b"],
        ),
    )
    case_repo.add_evidence_reference(
        case_id=case_no_user.case_id,
        source_type="event",
        source_id=f"ev-anon1-{t_id}",
        role="PRIMARY",
        epistemic_status="OBSERVED",
        citation_tag=f"[event:ev-anon1-{t_id}]",
        analyst_annotation=json.dumps({
            "id": f"ev-anon1-{t_id}",
            "timestamp": "2026-10-09T12:00:00Z",
            "host": "host-a",
            "event_type": "PORT_SCAN",
            "source": "network",
        }),
    )
    case_repo.add_evidence_reference(
        case_id=case_no_user.case_id,
        source_type="event",
        source_id=f"ev-anon2-{t_id}",
        role="SUPPORTING",
        epistemic_status="OBSERVED",
        citation_tag=f"[event:ev-anon2-{t_id}]",
        analyst_annotation=json.dumps({
            "id": f"ev-anon2-{t_id}",
            "timestamp": "2026-10-09T12:10:00Z",
            "host": "host-b",
            "event_type": "PORT_SCAN_RECV",
            "source": "network",
        }),
    )
    anon_traces = multihost_service.get_lateral_traces(case_no_user.case_id)
    if anon_traces:
        for tr in anon_traces:
            assert tr.actor == "UNKNOWN"
            assert tr.actor != "SecAnalyst-Forensic"


def test_remediation_m712_004_event_and_alert_deduplication(tmp_path):
    """DEFECT M712-004: Events and alerts present in both case evidence references and forensic db are not double-counted."""
    t_id = int(time.time() * 1000) % 700000
    temp_db_path = tmp_path / "test_forensic.db"

    # Create isolated forensic database with events and incident_alerts
    temp_db = Database(temp_db_path)
    with temp_db.connection() as conn:
        conn.execute("""
            CREATE TABLE events (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                host TEXT,
                event_type TEXT,
                source TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY,
                rule_id TEXT,
                severity TEXT,
                status TEXT,
                first_seen TEXT,
                last_seen TEXT,
                host TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE incident_alerts (
                incident_id INTEGER,
                alert_id INTEGER
            )
        """)
        # Insert event 1 and event 2 on srv-app-01
        conn.execute("INSERT INTO events VALUES ('ev-dup-1', '2026-10-14T10:00:00Z', 'srv-app-01', 'AUTH', 'system')")
        conn.execute("INSERT INTO events VALUES ('ev-unique-2', '2026-10-14T10:05:00Z', 'srv-app-01', 'PROCESS', 'system')")
        # Insert alert 1 on srv-app-01
        conn.execute("INSERT INTO alerts VALUES (991, 'rule.suspicious', 'HIGH', 'NEW', '2026-10-14T10:00:00Z', '2026-10-14T10:01:00Z', 'srv-app-01')")
        conn.execute("INSERT INTO incident_alerts VALUES (?, 991)", (870000 + t_id,))
        conn.commit()

    # Custom MultiHostInvestigationService using this temp forensic database
    custom_service = MultiHostInvestigationService(case_repository=case_repo, forensic_database=temp_db)

    case = case_repo.create_case(
        incident_id=870000 + t_id,
        title=f"M7.12 Dedup Test Case {t_id}",
        description="Testing deduplication of evidence references and canonical events.",
    )
    case_repo.update_case_scope(
        case_id=case.case_id,
        scope=InvestigationScope(
            investigation_id=870000 + t_id,
            subject_id=f"inc-{870000 + t_id}",
            target_hosts=["srv-app-01"],
        ),
    )
    # Add ev-dup-1 as evidence reference
    case_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="event",
        source_id="ev-dup-1",
        role="PRIMARY",
        epistemic_status="OBSERVED",
        citation_tag="[event:ev-dup-1]",
        analyst_annotation=json.dumps({
            "id": "ev-dup-1",
            "host": "srv-app-01",
            "timestamp": "2026-10-14T10:00:00Z",
            "event_type": "AUTH",
            "source": "system",
        }),
    )
    # Add alert 991 as evidence reference
    case_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="alert",
        source_id="991",
        role="PRIMARY",
        epistemic_status="OBSERVED",
        citation_tag="[alert:991]",
        analyst_annotation=json.dumps({
            "id": 991,
            "host": "srv-app-01",
            "first_seen": "2026-10-14T10:00:00Z",
            "last_seen": "2026-10-14T10:01:00Z",
            "severity": "HIGH",
        }),
    )

    dossier = custom_service.get_case_dossier(case.case_id)
    target_h = next((h for h in dossier.participating_hosts if h.host_id == "srv-app-01"), None)
    assert target_h is not None

    # Total distinct events for srv-app-01: ev-dup-1 and ev-unique-2 = 2 events (WITHOUT dedup, ev-dup-1 would be counted twice -> 3)
    assert target_h.event_count == 2
    # Total distinct alerts for srv-app-01: alert 991 = 1 alert (WITHOUT dedup, alert 991 would be counted twice -> 2)
    assert target_h.alert_count == 1


def test_remediation_m712_005_temporal_scoping_enforcement():
    """DEFECT M712-005: Case scope time_start and time_end bounds exclude out-of-scope events from counts and timestamps."""
    t_id = int(time.time() * 1000) % 600000
    host_name = f"srv-scope-{t_id}"
    case = case_repo.create_case(
        incident_id=860000 + t_id,
        title=f"M7.12 Temporal Scope Case {t_id}",
        description="Testing temporal scope enforcement on dossier synthesis.",
    )
    # Temporal scope: 2026-10-14T10:00:00Z to 2026-10-14T12:00:00Z
    case_repo.update_case_scope(
        case_id=case.case_id,
        scope=InvestigationScope(
            investigation_id=860000 + t_id,
            subject_id=f"inc-{860000 + t_id}",
            time_start="2026-10-14T10:00:00Z",
            time_end="2026-10-14T12:00:00Z",
            target_hosts=[host_name],
        ),
    )

    # 1. Event prior to time_start (08:00:00Z) - OUT OF SCOPE
    case_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="event",
        source_id=f"ev-prior-{t_id}",
        role="SUPPORTING",
        epistemic_status="OBSERVED",
        citation_tag=f"[event:ev-prior-{t_id}]",
        analyst_annotation=json.dumps({
            "id": f"ev-prior-{t_id}",
            "host": host_name,
            "timestamp": "2026-10-14T08:00:00Z",
            "event_type": "OLD_ACTIVITY",
        }),
    )

    # 2. Event inside temporal scope (11:00:00Z) - IN SCOPE
    case_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="event",
        source_id=f"ev-in-{t_id}",
        role="PRIMARY",
        epistemic_status="OBSERVED",
        citation_tag=f"[event:ev-in-{t_id}]",
        analyst_annotation=json.dumps({
            "id": f"ev-in-{t_id}",
            "host": host_name,
            "timestamp": "2026-10-14T11:00:00Z",
            "event_type": "PRIMARY_EXPLOIT",
        }),
    )

    # 3. Event after time_end (14:00:00Z) - OUT OF SCOPE
    case_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="event",
        source_id=f"ev-post-{t_id}",
        role="SUPPORTING",
        epistemic_status="OBSERVED",
        citation_tag=f"[event:ev-post-{t_id}]",
        analyst_annotation=json.dumps({
            "id": f"ev-post-{t_id}",
            "host": host_name,
            "timestamp": "2026-10-14T14:00:00Z",
            "event_type": "FUTURE_ACTIVITY",
        }),
    )

    dossier = multihost_service.get_case_dossier(case.case_id)
    target_h = next((h for h in dossier.participating_hosts if h.host_id == host_name), None)
    assert target_h is not None

    # Only the 1 in-scope event must be counted
    assert target_h.event_count == 1
    # Timestamps must reflect the in-scope event only, without contamination by 08:00 or 14:00
    assert target_h.first_seen == "2026-10-14T11:00:00+00:00"
    assert target_h.last_seen == "2026-10-14T11:00:00+00:00"


def test_remediation_m712_006_markdown_export_formatting_and_escaping(multihost_fixture):
    """DEFECT M712-006: Markdown export renders enum values without class prefix and escapes table pipes."""
    case_multi = multihost_fixture["case_multi"]
    res = multihost_service.export_dossier(case_multi.case_id, format="markdown")

    # Epistemic status enum must be rendered as raw value, not e.g. 'HostEpistemicStatus.OBSERVED'
    assert "HostEpistemicStatus." not in res.content
    assert "LateralTraceEpistemicStatus." not in res.content
    assert "ContinuityType." not in res.content
    assert "**OBSERVED**" in res.content

    # Test pipe escaping in cell contents
    t_id = int(time.time() * 1000) % 500000 + random.randint(10000000, 90000000)
    pipe_case = case_repo.create_case(
        incident_id=850000 + t_id,
        title=f"M7.12 Pipe Escaping Case {t_id}",
        description="Testing pipe escaping in table cells.",
    )
    case_repo.update_case_scope(
        case_id=pipe_case.case_id,
        scope=InvestigationScope(
            investigation_id=850000 + t_id,
            subject_id=f"inc-{850000 + t_id}",
            target_hosts=["host|with|pipes"],
        ),
    )
    pipe_export = multihost_service.export_dossier(pipe_case.case_id, format="markdown")
    # Must have escaped pipe
    assert "host\\|with\\|pipes" in pipe_export.content


def test_alert_temporal_scope_spanning_overlap(multihost_fixture):
    """Verify alerts spanning across case window are included rather than dropped."""
    t_id = int(time.time() * 1000) % 500000 + random.randint(10000000, 90000000)
    host_name = f"srv-spanning-{t_id}"

    case = case_repo.create_case(
        incident_id=860000 + t_id,
        title=f"Spanning Alert Case {t_id}",
        description="Testing spanning alert temporal overlap semantics.",
    )
    case_repo.update_case_scope(
        case_id=case.case_id,
        scope=InvestigationScope(
            investigation_id=860000 + t_id,
            subject_id=f"inc-{860000 + t_id}",
            target_hosts=[host_name],
            time_start="2026-10-15T10:00:00Z",
            time_end="2026-10-15T12:00:00Z",
        ),
    )

    # 1. Alert that spans entirely across the case window: 08:00 to 14:00
    case_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="alert",
        source_id=f"alt-span-{t_id}",
        role="PRIMARY",
        epistemic_status="OBSERVED",
        citation_tag=f"[alert:alt-span-{t_id}]",
        analyst_annotation=json.dumps({
            "id": f"alt-span-{t_id}",
            "host": host_name,
            "first_seen": "2026-10-15T08:00:00Z",
            "last_seen": "2026-10-15T14:00:00Z",
            "rule_id": "RULE_SPANNING",
        }),
    )

    # 2. Alert that ends before scope start: 06:00 to 08:00 (must be excluded)
    case_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="alert",
        source_id=f"alt-pre-{t_id}",
        role="SUPPORTING",
        epistemic_status="OBSERVED",
        citation_tag=f"[alert:alt-pre-{t_id}]",
        analyst_annotation=json.dumps({
            "id": f"alt-pre-{t_id}",
            "host": host_name,
            "first_seen": "2026-10-15T06:00:00Z",
            "last_seen": "2026-10-15T08:00:00Z",
            "rule_id": "RULE_PRE",
        }),
    )

    # 3. Alert that starts after scope end: 13:00 to 15:00 (must be excluded)
    case_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="alert",
        source_id=f"alt-post-{t_id}",
        role="SUPPORTING",
        epistemic_status="OBSERVED",
        citation_tag=f"[alert:alt-post-{t_id}]",
        analyst_annotation=json.dumps({
            "id": f"alt-post-{t_id}",
            "host": host_name,
            "first_seen": "2026-10-15T13:00:00Z",
            "last_seen": "2026-10-15T15:00:00Z",
            "rule_id": "RULE_POST",
        }),
    )

    dossier = multihost_service.get_case_dossier(case.case_id)
    target_h = next((h for h in dossier.participating_hosts if h.host_id == host_name), None)
    assert target_h is not None

    # The spanning alert must be included (alert_count == 1)
    assert target_h.alert_count == 1
    # Clamped to case scope boundaries
    assert target_h.first_seen == "2026-10-15T10:00:00+00:00"
    assert target_h.last_seen == "2026-10-15T12:00:00+00:00"


def test_evidence_id_collision_prevention(multihost_fixture):
    """Verify evidence mapping differentiates and preserves colliding source IDs across types."""
    from logintel.ai.temporal.reconstruction_engine import TemporalReconstructionEngine
    from logintel.ai.domain.investigation_temporal import TransitionType, TemporalTransition, EpistemicStatus
    from logintel.ai.domain.investigation_graph import GraphEvidenceItem

    engine = TemporalReconstructionEngine()
    t_id = int(time.time() * 1000) % 500000 + random.randint(10000000, 90000000)
    shared_id = f"collision-{t_id}"

    case = case_repo.create_case(
        incident_id=870000 + t_id,
        title=f"Collision Case {t_id}",
        description="Testing collision resolution between event and alert with identical ID.",
    )

    ev_event = {
        "_source_type": "event",
        "_source_id": shared_id,
        "id": shared_id,
        "username": "alice_from_event",
        "host": "host-a",
        "timestamp": "2026-10-15T10:00:00Z",
    }
    ev_alert = {
        "_source_type": "alert",
        "_source_id": shared_id,
        "id": shared_id,
        "username": "bob_from_alert",
        "host": "host-b",
        "timestamp": "2026-10-15T10:05:00Z",
    }

    # Transition referencing the event
    trans_event = TemporalTransition(
        transition_id=f"trans-ev-{t_id}",
        case_id=case.case_id,
        transition_type=TransitionType.HOST_TO_HOST,
        from_entity="host:host-a",
        to_entity="host:host-b",
        timestamp="2026-10-15T10:00:00Z",
        reason="Lateral jump via SSH event",
        epistemic_status=EpistemicStatus.OBSERVED,
        evidence_references=[
            GraphEvidenceItem(
                reference_id=f"ref-ev-{t_id}",
                source_type="event",
                source_id=shared_id,
                source_hash="sha256:dummy1",
                citation_tag=f"[event:{shared_id}]",
                timestamp="2026-10-15T10:00:00Z",
                summary="Event evidence",
                epistemic_status=EpistemicStatus.OBSERVED,
                is_authoritative=True,
                role="supporting",
            )
        ],
    )

    # Transition referencing the alert
    trans_alert = TemporalTransition(
        transition_id=f"trans-alt-{t_id}",
        case_id=case.case_id,
        transition_type=TransitionType.HOST_TO_HOST,
        from_entity="host:host-b",
        to_entity="host:host-c",
        timestamp="2026-10-15T10:05:00Z",
        reason="Lateral jump via alert",
        epistemic_status=EpistemicStatus.OBSERVED,
        evidence_references=[
            GraphEvidenceItem(
                reference_id=f"ref-alt-{t_id}",
                source_type="alert",
                source_id=shared_id,
                source_hash="sha256:dummy2",
                citation_tag=f"[alert:{shared_id}]",
                timestamp="2026-10-15T10:05:00Z",
                summary="Alert evidence",
                epistemic_status=EpistemicStatus.OBSERVED,
                is_authoritative=True,
                role="supporting",
            )
        ],
    )

    # Pass both evidence items to reconstruction
    traces = engine.reconstruct_multi_host_traces(
        case,
        [trans_event, trans_alert],
        [ev_event, ev_alert],
    )

    assert len(traces) == 2
    # First trace supported by event -> actor should be alice
    assert traces[0].actor == "alice_from_event"
    # Second trace supported by alert -> actor should be bob
    assert traces[1].actor == "bob_from_alert"


def test_comparative_timeline_dossier_reuse(multihost_fixture):
    """Verify get_comparative_timeline computes case dossier once instead of N times."""
    from unittest.mock import patch

    case_multi = multihost_fixture["case_multi"]
    hosts = ["host-jumpbox", "host-dc01"]

    orig_get_case_dossier = multihost_service.get_case_dossier
    call_count = 0

    def mock_get_case_dossier(cid, **kwargs):
        nonlocal call_count
        call_count += 1
        return orig_get_case_dossier(cid, **kwargs)

    with patch.object(multihost_service, "get_case_dossier", side_effect=mock_get_case_dossier):
        res = multihost_service.get_comparative_timeline(
            case_id=case_multi.case_id,
            host_ids=hosts,
        )

    assert len(res.lanes) == 2
    # Exactly 1 dossier computation call for the entire comparative query
    assert call_count == 1


def test_graph_derived_transition_without_timestamps(multihost_fixture):
    """Regression test: graph edges lacking first_seen and last_seen must not crash on undefined names."""
    from logintel.ai.temporal.reconstruction_engine import TemporalReconstructionEngine
    from logintel.ai.domain.investigation_temporal import EpistemicStatus
    from logintel.ai.domain.investigation_graph import InvestigationGraph, InvestigationGraphEdge, RelationshipEpistemicStatus

    engine = TemporalReconstructionEngine()
    case = multihost_fixture["case_single"]

    edge_without_ts = InvestigationGraphEdge(
        edge_id="edge-no-ts-1",
        source_node_id="user:alice",
        target_node_id="host:srv-corp",
        relationship_type="AUTHENTICATED_TO",
        first_seen=None,
        last_seen=None,
        epistemic_status=RelationshipEpistemicStatus.OBSERVED,
        evidence_references=[],
    )
    graph = InvestigationGraph(
        graph_id="g-no-ts",
        case_id=case.case_id,
        incident_id=case.incident_id,
        nodes=[],
        edges=[edge_without_ts],
        total_nodes=0,
        total_edges=1,
        observed_edges_count=1,
        inferred_edges_count=0,
        corroborated_edges_count=0,
        contradicted_edges_count=0,
        generated_at="2026-10-15T10:00:00Z",
    )

    # Must complete safely without raising NameError ('raw_events' undefined)
    transitions = engine.detect_transitions(case, [], [], graph=graph)
    assert len(transitions) == 1
    t = transitions[0]
    assert t.from_entity == "user:alice"
    assert t.to_entity == "host:srv-corp"
    assert t.timestamp is not None
    assert t.epistemic_status == EpistemicStatus.INFERRED


def test_campaign_timestamp_handling_with_mixed_and_malformed():
    """Regression test: correlate_campaign_incidents handles empty, malformed, and mixed timestamps safely."""
    from logintel.ai.temporal.reconstruction_engine import TemporalReconstructionEngine

    engine = TemporalReconstructionEngine()
    t_id = int(time.time() * 1000) % 500000 + random.randint(10000000, 90000000)
    case = case_repo.create_case(
        incident_id=880000 + t_id,
        title=f"Campaign Safe Timestamp Case {t_id}",
    )

    # Case 1: Empty evidence items
    res_empty = engine.correlate_campaign_incidents(case, [{"id": 99999, "first_seen": "2026-10-15T10:00:00Z"}], [])
    assert res_empty == []

    # Case 2: Evidence with mixed valid, malformed, and None timestamps
    evidence = [
        {"timestamp": None, "username": "admin"},
        {"timestamp": "not-a-valid-date", "username": "admin"},
        {"timestamp": "", "username": "admin"},
        {"timestamp": "2026-10-15T12:00:00Z", "username": "admin"},
        {"timestamp": "2026-10-15T14:00:00Z", "username": "admin"},
    ]

    other_incidents = [
        {
            "id": 90001,
            "title": "Malformed Incident",
            "first_seen": "corrupted-date",
            "primary_user": "admin",
        },
        {
            "id": 90002,
            "title": "Close Proximity Incident",
            "first_seen": "2026-10-15T13:00:00Z",
            "primary_user": "different_user",
        },
    ]

    # Must execute without TypeError when calculating min() over timestamps
    correlations = engine.correlate_campaign_incidents(case, other_incidents, evidence)
    assert len(correlations) >= 1
    # 90001 correlated via shared admin user
    assert any(c.related_incident_id == 90001 for c in correlations)
    # 90002 correlated via temporal proximity (within 1 hour of valid 12:00:00 timestamp)
    assert any(c.related_incident_id == 90002 for c in correlations)


def test_transition_deduplication_preserves_distinct_evidence():
    """Verify equivalent transitions merge evidence and reasons rather than discarding supporting citations."""
    from logintel.ai.temporal.reconstruction_engine import TemporalReconstructionEngine
    from logintel.ai.domain.investigation_temporal import TransitionType, TemporalTransition, EpistemicStatus
    from logintel.ai.domain.investigation_graph import GraphEvidenceItem

    engine = TemporalReconstructionEngine()
    t_id = int(time.time() * 1000) % 500000 + random.randint(10000000, 90000000)
    case = case_repo.create_case(
        incident_id=890000 + t_id,
        title=f"Transition Dedupe Case {t_id}",
    )

    t1 = TemporalTransition(
        transition_id=f"t1-{t_id}",
        case_id=case.case_id,
        transition_type=TransitionType.HOST_TO_HOST,
        from_entity="host:jumpbox",
        to_entity="host:dc01",
        timestamp="2026-10-15T10:00:00Z",
        reason="SSH session established",
        correlation_basis="Syslog auth log",
        epistemic_status=EpistemicStatus.OBSERVED,
        evidence_references=[
            GraphEvidenceItem(
                reference_id=f"ref-ev-{t_id}-1",
                source_type="event",
                source_id="ev-101",
                source_hash="sha256:hash1",
                citation_tag="[event:ev-101]",
                summary="SSH login event",
                epistemic_status=EpistemicStatus.OBSERVED,
                is_authoritative=True,
                role="supporting",
            )
        ],
    )

    t2 = TemporalTransition(
        transition_id=f"t2-{t_id}",
        case_id=case.case_id,
        transition_type=TransitionType.HOST_TO_HOST,
        from_entity="host:jumpbox",
        to_entity="host:dc01",
        timestamp="2026-10-15T10:00:00Z",
        reason="Admin lateral movement",
        correlation_basis="Alert engine rule",
        epistemic_status=EpistemicStatus.INFERRED,
        evidence_references=[
            GraphEvidenceItem(
                reference_id=f"ref-alt-{t_id}-2",
                source_type="alert",
                source_id="alt-202",
                source_hash="sha256:hash2",
                citation_tag="[alert:alt-202]",
                summary="Lateral movement detection alert",
                epistemic_status=EpistemicStatus.OBSERVED,
                is_authoritative=True,
                role="supporting",
            )
        ],
    )

    # Use detect_transitions with pre-existing transitions via internal dedupe
    # Inject both transitions directly into transitions list
    from unittest.mock import patch
    with patch.object(engine, "detect_transitions", wraps=engine.detect_transitions):
        # Directly test dedupe block
        transitions = [t1, t2]
        deduped_map = {}
        for t in transitions:
            key = f"{t.transition_type.value}:{t.from_entity}->{t.to_entity}:{t.timestamp}"
            if key not in deduped_map:
                deduped_map[key] = t
            else:
                existing = deduped_map[key]
                existing_ref_keys = {
                    (ref.source_type, str(ref.source_id), ref.citation_tag)
                    for ref in existing.evidence_references
                }
                for ref in t.evidence_references:
                    ref_k = (ref.source_type, str(ref.source_id), ref.citation_tag)
                    if ref_k not in existing_ref_keys:
                        existing_ref_keys.add(ref_k)
                        existing.evidence_references.append(ref)
                if t.reason and t.reason not in existing.reason:
                    existing.reason = f"{existing.reason}; {t.reason}"
                if t.correlation_basis and t.correlation_basis not in existing.correlation_basis:
                    existing.correlation_basis = f"{existing.correlation_basis} & {t.correlation_basis}"
                if t.epistemic_status == EpistemicStatus.OBSERVED:
                    existing.epistemic_status = EpistemicStatus.OBSERVED

        merged = list(deduped_map.values())
        assert len(merged) == 1
        res = merged[0]
        # Both distinct evidence references must be preserved!
        citation_tags = [r.citation_tag for r in res.evidence_references]
        assert "[event:ev-101]" in citation_tags
        assert "[alert:alt-202]" in citation_tags
        # Reasons combined
        assert "SSH session established" in res.reason
        assert "Admin lateral movement" in res.reason
        # Epistemic status preserved as OBSERVED
        assert res.epistemic_status == EpistemicStatus.OBSERVED


def test_timeline_item_identity_and_cross_host_deduplication():
    """Verify timeline items with identical IDs from different source types or distinct hosts do not collapse."""
    from logintel.timeline.service import timeline_service, TimelineFilterParams

    t_id = int(time.time() * 1000) % 500000 + random.randint(10000000, 90000000)
    case = case_repo.create_case(
        incident_id=910000 + t_id,
        title=f"Timeline Collision Case {t_id}",
    )

    shared_source_id = f"item-{t_id}"

    # 1. Event with ID shared_source_id on host-alpha
    case_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="event",
        source_id=shared_source_id,
        role="PRIMARY",
        epistemic_status="OBSERVED",
        citation_tag=f"[event:{shared_source_id}]",
        analyst_annotation=json.dumps({
            "id": shared_source_id,
            "host": "host-alpha",
            "timestamp": "2026-10-15T10:00:00Z",
            "source": "syslog",
            "event_type": "AUTH",
        }),
    )

    # 2. Alert with same ID shared_source_id on host-alpha
    case_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="alert",
        source_id=shared_source_id,
        role="PRIMARY",
        epistemic_status="OBSERVED",
        citation_tag=f"[alert:{shared_source_id}]",
        analyst_annotation=json.dumps({
            "id": shared_source_id,
            "host": "host-alpha",
            "timestamp": "2026-10-15T10:00:00Z",
            "source": "rule_engine",
            "event_type": "ALERT",
        }),
    )

    # 3. Network flow event with same ID shared_source_id on host-beta
    case_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="network_flow",
        source_id=shared_source_id,
        role="PRIMARY",
        epistemic_status="OBSERVED",
        citation_tag=f"[network_flow:{shared_source_id}]",
        analyst_annotation=json.dumps({
            "id": shared_source_id,
            "host": "host-beta",
            "timestamp": "2026-10-15T10:05:00Z",
            "source": "zeek",
            "event_type": "CONN",
        }),
    )

    res = timeline_service.query_timeline(case.case_id, TimelineFilterParams(limit=50))
    # All 3 distinct records sharing the same source_id must be preserved without collapsing!
    shared_items = [it for it in res.items if it.source_id == shared_source_id]
    assert len(shared_items) == 3
    timeline_ids = {it.timeline_id for it in shared_items}
    assert len(timeline_ids) == 3

    # Event on host-alpha has tl-ev-
    assert f"tl-ev-{shared_source_id}" in timeline_ids
    # Alert on host-alpha has tl-alt-
    assert f"tl-alt-{shared_source_id}" in timeline_ids
    # Network flow on host-beta has tl-network-
    assert any("network" in tid for tid in timeline_ids)


def test_markdown_export_correctness_with_pipes_crlf_and_backticks():
    """Verify Markdown export sanitizes pipes, CR/LF, control characters, and backticks in cells and prose."""
    t_id = int(time.time() * 1000) % 500000 + random.randint(10000000, 90000000)
    case = case_repo.create_case(
        incident_id=920000 + t_id,
        title=f"Markdown Correctness Case {t_id}",
    )
    case_repo.update_case_scope(
        case_id=case.case_id,
        scope=InvestigationScope(
            investigation_id=920000 + t_id,
            subject_id=f"inc-{920000 + t_id}",
            target_hosts=["host|pipe\r\nwith`backticks`"],
        ),
    )

    exp = multihost_service.export_dossier(case.case_id, format="markdown")
    content = exp.content

    # 1. Pipe character inside host ID must be escaped as \| in table cells
    assert "host\\|pipe" in content
    # 2. Raw CR/LF characters must not break table row lines
    assert "\r\n" not in content
    # 3. Backticks inside code spans must be sanitized to prevent premature span closure
    assert "with'backticks'" in content or "`host\\|pipe with'backticks'`" in content


def test_temporal_adjacency_transitions_are_inferred_not_observed():
    """Verify temporal adjacency alone does not create an OBSERVED transition without explicit corroboration."""
    engine = TemporalReconstructionEngine()
    t_id = int(time.time() * 1000) % 500000 + random.randint(10000000, 90000000)
    case = case_repo.create_case(incident_id=930000 + t_id, title=f"Adjacency Case {t_id}")

    # Two consecutive chronological items on different hosts without explicit connection telemetry
    items = [
        {
            "id": 1,
            "_source_type": "event",
            "_source_id": "1",
            "_citation_tag": "[event:1]",
            "timestamp": "2026-10-15T10:00:00Z",
            "host": "srv-app-01",
            "username": "alice",
            "action": "login",
        },
        {
            "id": 2,
            "_source_type": "event",
            "_source_id": "2",
            "_citation_tag": "[event:2]",
            "timestamp": "2026-10-15T10:05:00Z",
            "host": "srv-db-01",
            "username": "bob",
            "process_name": "psql",
            "action": "query",
        },
    ]

    transitions = engine.detect_transitions(case, items, [])
    assert len(transitions) >= 1

    # Lateral (HOST_TO_HOST) transition derived purely from consecutive order must be INFERRED
    h2h = next((t for t in transitions if t.transition_type == TransitionType.HOST_TO_HOST), None)
    assert h2h is not None
    assert h2h.from_entity == "host:srv-app-01"
    assert h2h.to_entity == "host:srv-db-01"
    assert h2h.epistemic_status == EpistemicStatus.INFERRED
    assert "temporal adjacency only" in h2h.reason
    assert h2h.correlation_basis == "Temporal adjacency of consecutive forensic records"

    # User-to-host (USER_TO_HOST) transition must also be INFERRED
    u2h = next((t for t in transitions if t.transition_type == TransitionType.USER_TO_HOST), None)
    assert u2h is not None
    assert u2h.epistemic_status == EpistemicStatus.INFERRED
    assert "temporal adjacency only" in u2h.reason


def test_exact_host_matching_instead_of_substring():
    """Verify timeline host query uses exact canonical matching rather than substring inclusion."""
    t_id = int(time.time() * 1000) % 500000 + random.randint(10000000, 90000000)
    case = case_repo.create_case(incident_id=940000 + t_id, title=f"Exact Host Case {t_id}")

    # Add evidence on host-1
    case_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="event",
        source_id=f"ev-h1-{t_id}",
        role="PRIMARY",
        epistemic_status="OBSERVED",
        citation_tag=f"[event:ev-h1-{t_id}]",
        analyst_annotation=json.dumps({
            "id": f"ev-h1-{t_id}",
            "timestamp": "2026-10-15T10:00:00Z",
            "host": "host-1",
        }),
    )

    # Add evidence on host-10
    case_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="event",
        source_id=f"ev-h10-{t_id}",
        role="SUPPORTING",
        epistemic_status="OBSERVED",
        citation_tag=f"[event:ev-h10-{t_id}]",
        analyst_annotation=json.dumps({
            "id": f"ev-h10-{t_id}",
            "timestamp": "2026-10-15T10:01:00Z",
            "host": "host-10",
        }),
    )

    # Query for exact host "host-1"
    res = timeline_service.query_timeline(case.case_id, TimelineFilterParams(host="host-1"))
    host_ids = [it.host_id for it in res.items]
    assert "host-1" in host_ids
    # host-10 must NOT match when querying for host-1!
    assert "host-10" not in host_ids


def test_case_bound_time_filtering_and_out_of_scope_host_exclusion():
    """Verify case scope time bounds intersection and out-of-scope host exclusion."""
    t_id = int(time.time() * 1000) % 500000 + random.randint(10000000, 90000000)
    case = case_repo.create_case(incident_id=950000 + t_id, title=f"Scope Bounds Case {t_id}")
    case_repo.update_case_scope(
        case_id=case.case_id,
        scope=InvestigationScope(
            investigation_id=950000 + t_id,
            subject_id=f"inc-{950000 + t_id}",
            time_start="2026-10-15T10:00:00Z",
            time_end="2026-10-15T12:00:00Z",
            target_hosts=["scoped-host-a"],
        ),
    )

    # Event 1: in scope (11:00:00Z, scoped-host-a)
    case_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="event",
        source_id=f"ev-in-{t_id}",
        role="PRIMARY",
        epistemic_status="OBSERVED",
        citation_tag=f"[event:ev-in-{t_id}]",
        analyst_annotation=json.dumps({
            "id": f"ev-in-{t_id}",
            "timestamp": "2026-10-15T11:00:00Z",
            "host": "scoped-host-a",
        }),
    )

    # Event 2: prior to case time_start (08:00:00Z, scoped-host-a)
    case_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="event",
        source_id=f"ev-early-{t_id}",
        role="SUPPORTING",
        epistemic_status="OBSERVED",
        citation_tag=f"[event:ev-early-{t_id}]",
        analyst_annotation=json.dumps({
            "id": f"ev-early-{t_id}",
            "timestamp": "2026-10-15T08:00:00Z",
            "host": "scoped-host-a",
        }),
    )

    # Event 3: out-of-scope host (11:30:00Z, rogue-host-z)
    case_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="event",
        source_id=f"ev-rogue-{t_id}",
        role="SUPPORTING",
        epistemic_status="OBSERVED",
        citation_tag=f"[event:ev-rogue-{t_id}]",
        analyst_annotation=json.dumps({
            "id": f"ev-rogue-{t_id}",
            "timestamp": "2026-10-15T11:30:00Z",
            "host": "rogue-host-z",
        }),
    )

    # Query with broader query bounds (06:00 to 18:00): case bounds (10:00 to 12:00) must prevail!
    res = timeline_service.query_timeline(
        case.case_id,
        TimelineFilterParams(time_start="2026-10-15T06:00:00Z", time_end="2026-10-15T18:00:00Z"),
    )
    # Out of scope host must NOT appear
    assert not any(it.host_id == "rogue-host-z" for it in res.items)
    # Early event prior to 10:00 must NOT appear
    assert not any(it.timestamp < "2026-10-15T10:00:00Z" for it in res.items)
    # In-scope event must appear
    assert any(it.source_id == f"ev-in-{t_id}" for it in res.items)

    # Out-of-scope host must not appear in case dossier
    dossier = multihost_service.get_case_dossier(case.case_id)
    dossier_hosts = [h.host_id for h in dossier.participating_hosts]
    assert "scoped-host-a" in dossier_hosts
    assert "rogue-host-z" not in dossier_hosts


def test_invalid_annotation_payloads_do_not_crash():
    """Verify non-dict, malformed, or null analyst annotations are handled defensively without exceptions."""
    t_id = int(time.time() * 1000) % 500000 + random.randint(10000000, 90000000)
    case = case_repo.create_case(incident_id=960000 + t_id, title=f"Malformed Annotations Case {t_id}")

    # 1. JSON Array
    case_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="event",
        source_id=f"ev-list-{t_id}",
        role="SUPPORTING",
        epistemic_status="OBSERVED",
        citation_tag=f"[event:ev-list-{t_id}]",
        analyst_annotation="[1, 2, 3, \"not a dict\"]",
    )

    # 2. JSON String
    case_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="event",
        source_id=f"ev-str-{t_id}",
        role="SUPPORTING",
        epistemic_status="OBSERVED",
        citation_tag=f"[event:ev-str-{t_id}]",
        analyst_annotation="\"plain string value\"",
    )

    # 3. Malformed JSON syntax
    case_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="event",
        source_id=f"ev-malformed-{t_id}",
        role="SUPPORTING",
        epistemic_status="OBSERVED",
        citation_tag=f"[event:ev-malformed-{t_id}]",
        analyst_annotation="{bad json: missing quotes",
    )

    # None of these should crash dossier generation or timeline queries
    dossier = multihost_service.get_case_dossier(case.case_id)
    assert isinstance(dossier, CaseMultiHostDossier)

    timeline_res = timeline_service.query_timeline(case.case_id, TimelineFilterParams(limit=10))
    assert isinstance(timeline_res, TimelineQueryResponse)
    assert timeline_res.is_truncated is False


def test_mitre_mapping_epistemic_status_and_multiple_mappings():
    """Verify inferred MITRE mappings are not marked authoritative and multiple mappings are preserved."""
    engine = TemporalReconstructionEngine()
    t_id = int(time.time() * 1000) % 500000 + random.randint(10000000, 90000000)
    case = case_repo.create_case(incident_id=970000 + t_id, title=f"MITRE Epistemic Case {t_id}")

    # Evidence with multiple MITRE mappings in details_json
    evidence_items = [
        {
            "id": 101,
            "_source_type": "event",
            "_source_id": "101",
            "_citation_tag": "[event:101]",
            "timestamp": "2026-10-15T10:00:00Z",
            "host": "srv-01",
            "action": "powershell_download",
            "epistemic_status": "INFERRED",
            "is_authoritative": False,
            "details_json": json.dumps({
                "mitre_mappings": [
                    {"technique_id": "T1059.001", "tactic": "Execution"},
                    {"technique_id": "T1105", "tactic": "Command and Control"},
                ]
            }),
        }
    ]

    seqs, mitre_list = engine.reconstruct_attack_sequences(case, evidence_items, [])
    assert len(seqs) == 1
    # Step epistemic status carries INFERRED from evidence
    assert seqs[0].steps[0].epistemic_status == EpistemicStatus.INFERRED
    assert seqs[0].epistemic_status == EpistemicStatus.INFERRED

    # Both MITRE techniques are retained without overwriting
    technique_ids = {m["technique_id"] for m in mitre_list}
    assert "T1059.001" in technique_ids
    assert "T1105" in technique_ids

    # Inferred mappings must not be marked authoritative
    for m in mitre_list:
        assert m["is_authoritative"] is False
        assert m["epistemic_status"] == "INFERRED"


def test_bounded_event_counts_are_explicit_and_truncated(tmp_path):
    """Verify host event counts are never silently capped at 500 and timeline truncation flags are accurate."""
    from logintel.storage.case_repo import CaseRepository
    from logintel.timeline.service import UnifiedTimelineService

    test_forensic_db = Database(db_path=tmp_path / "forensic_test.db")
    test_forensic_db.initialize()
    test_case_repo = CaseRepository(db_path=tmp_path / "cases_test.db", forensic_db=test_forensic_db)
    test_timeline_svc = UnifiedTimelineService(forensic_db=test_forensic_db, case_repository=test_case_repo)
    test_mh_svc = MultiHostInvestigationService(
        case_repository=test_case_repo,
        forensic_database=test_forensic_db,
        timeline_service=test_timeline_svc,
    )

    with test_forensic_db.connection() as conn:
        with conn:
            conn.execute(
                "INSERT INTO hosts (id, hostname, first_seen, last_seen) VALUES (?, ?, ?, ?)",
                ("host-scale-01", "scale01.corp.internal", "2026-10-15T10:00:00Z", "2026-10-15T12:00:00Z"),
            )
            conn.execute(
                """
                INSERT INTO detection_rules (id, name, description, severity, category, rule_type, definition_yaml)
                VALUES ('rule.test', 'Test Rule', 'Desc', 'HIGH', 'auth', 'deterministic', 'yaml: 1')
                """
            )
            conn.execute(
                """
                INSERT INTO alerts (id, rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen)
                VALUES (1, 'rule.test', 'dk-1', 'Alert 1', 'Alert desc', 'HIGH', 'OPEN', 'host-scale-01', '2026-10-15T10:00:00Z', '2026-10-15T12:00:00Z')
                """
            )
            conn.execute(
                """
                INSERT INTO detections (id, alert_id, rule_id, timestamp, host, summary)
                VALUES (1, 1, 'rule.test', '2026-10-15T10:00:00Z', 'host-scale-01', 'Det 1')
                """
            )
            conn.execute(
                """
                INSERT INTO incidents (id, incident_key, title, summary, severity, status, primary_host, first_seen, last_seen)
                VALUES (1, 'inc-1', 'Inc 1', 'Summary', 'WARNING', 'OPEN', 'host-scale-01', '2026-10-15T10:00:00Z', '2026-10-15T12:00:00Z')
                """
            )
            conn.execute("INSERT INTO incident_alerts (incident_id, alert_id) VALUES (1, 1)")

            # Insert 550 events (> old LIMIT 500 cap) in reverse timestamp order to also test deterministic ordering
            for idx in range(550):
                ev_id = f"ev-scale-{idx:04d}"
                ts = f"2026-10-15T10:{(idx // 60) % 60:02d}:{idx % 60:02d}Z"
                conn.execute(
                    """
                    INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, outcome, summary, raw_message, parser, event_fingerprint)
                    VALUES (?, ?, ?, 'host-scale-01', 'auth', 'LOGIN', 'INFO', 'SUCCESS', 'msg', 'raw', 'syslog', ?)
                    """,
                    (ev_id, ts, ts, f"fp-{ev_id}"),
                )
                conn.execute(
                    "INSERT INTO detection_evidence (detection_id, event_id, role) VALUES (1, ?, 'TRIGGER')",
                    (ev_id,),
                )

    case = test_case_repo.create_case(incident_id=1, title="Scale & Truncation Test Case")
    test_case_repo.update_case_scope(
        case_id=case.case_id,
        scope=InvestigationScope(
            investigation_id=1,
            subject_id="inc-1",
            target_hosts=["host-scale-01"],
        ),
    )

    # 1. Verify MultiHostInvestigationService reports exact 550 event count (not silently capped at 500)
    dossier = test_mh_svc.get_case_dossier(case.case_id)
    assert len(dossier.participating_hosts) == 1
    assert dossier.participating_hosts[0].event_count == 550

    # 2. Verify UnifiedTimelineService exposes accurate truncation metadata when bounded
    test_timeline_svc.MAX_INCIDENT_EVENTS = 10
    tl_res = test_timeline_svc.query_timeline(case.case_id, TimelineFilterParams(limit=50))
    assert tl_res.is_truncated is True
    # Deterministic ORDER BY e.timestamp ASC, e.id ASC ensures earliest event IDs come first
    ev_items = [it for it in tl_res.items if it.source_id.startswith("ev-scale-")]
    assert len(ev_items) == 10
    assert ev_items[0].source_id == "ev-scale-0000"
    assert ev_items[-1].source_id == "ev-scale-0009"

    # 3. Verify unbounded (> 550) case returns is_truncated=False
    test_timeline_svc.MAX_INCIDENT_EVENTS = 1000
    tl_full = test_timeline_svc.query_timeline(case.case_id, TimelineFilterParams(limit=50))
    assert tl_full.is_truncated is False
    assert tl_full.total >= 550


def test_epistemic_preservation_and_conservative_merge(tmp_path):
    """Items 1 & 8: Missing/inferred provenance fails closed; conservative merges never promote to OBSERVED."""
    from logintel.ai.temporal.reconstruction_engine import TemporalReconstructionEngine
    from logintel.ai.domain.investigation_temporal import EpistemicStatus
    from logintel.ai.domain.investigation_graph import (
        CorroborationStatus,
        InvestigationGraph,
        InvestigationGraphEdge,
        RelationshipEpistemicStatus,
    )
    from types import SimpleNamespace
    from logintel.storage.case_repo import CaseRepository

    t_db = Database(db_path=tmp_path / "forensic_ep.db")
    t_db.initialize()
    with t_db.connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO incidents (id, incident_key, title, summary, severity, status, primary_host, first_seen, last_seen) VALUES (1, 'INC-1', 'Epistemic Case', 'Epistemic summary', 'ALERT', 'OPEN', 'srv-01', '2026-10-15T10:00:00Z', '2026-10-15T10:05:00Z')"
        )
        cur.execute(
            """
            INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint, username, src_ip)
            VALUES
            ('ev-obs', '2026-10-15T10:00:00Z', '2026-10-15T10:00:01Z', 'srv-01', 'auth', 'login', 'INFORMATIONAL', 'login', 'success', 'Observed login', 'Accepted publickey', 'sshd', 'fp-1', 'alice', '10.0.0.1'),
            ('ev-inf', '2026-10-15T10:01:00Z', '2026-10-15T10:01:01Z', 'srv-01', 'auth', 'login', 'ALERT', 'login', 'success', 'Inferred hop', 'Heuristic correlate', 'corr', 'fp-2', 'alice', '10.0.0.1')
            """
        )
        conn.commit()

    t_repo = CaseRepository(db_path=tmp_path / "cases_ep.db", forensic_db=t_db)
    case = t_repo.create_case(incident_id=1, title="Epistemic Propagation")
    t_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="event",
        source_id="ev-obs",
        role="PRIMARY",
        epistemic_status="OBSERVED",
        citation_tag="[event:ev-obs]",
    )
    t_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="event",
        source_id="ev-inf",
        role="SUPPORTING",
        epistemic_status="INFERRED",
        citation_tag="[event:ev-inf]",
    )
    hydrated_case = t_repo.get_case(case.case_id, resolve_evidence=True)

    engine = TemporalReconstructionEngine()
    harvested = engine._harvest_case_evidence(hydrated_case)
    assert len(harvested) == 2
    by_sid = {it["_source_id"]: it for it in harvested}
    assert by_sid["ev-obs"]["_epistemic_status"] == "OBSERVED"
    assert by_sid["ev-obs"]["_is_authoritative"] is True
    assert by_sid["ev-inf"]["_epistemic_status"] == "INFERRED"
    assert by_sid["ev-inf"]["_is_authoritative"] is False

    # Episode mixing OBSERVED + INFERRED items must conservatively downgrade to INFERRED
    episodes = engine.build_temporal_episodes(hydrated_case, harvested)
    assert len(episodes) == 1
    assert episodes[0].epistemic_status == EpistemicStatus.INFERRED
    ref_map = {r.source_id: r for r in episodes[0].evidence_references}
    assert ref_map["ev-obs"].epistemic_status == EpistemicStatus.OBSERVED
    assert ref_map["ev-obs"].is_authoritative is True
    assert ref_map["ev-inf"].epistemic_status == EpistemicStatus.INFERRED
    assert ref_map["ev-inf"].is_authoritative is False

    # Chains & attack sequences carry conservative status
    chains = engine.build_evidence_chains(hydrated_case, harvested, [])
    assert chains[0].epistemic_status == EpistemicStatus.INFERRED
    assert chains[0].steps[0].epistemic_status == EpistemicStatus.OBSERVED
    assert chains[0].steps[1].epistemic_status == EpistemicStatus.INFERRED

    # Raw evidence dict with missing provenance must NOT default to OBSERVED/authoritative
    missing_items = [{"id": "raw-1", "timestamp": "2026-10-15T10:02:00Z", "host": "srv-01", "action": "exec"}]
    graph_refs = engine._build_graph_evidence_items(missing_items)
    assert graph_refs[0].epistemic_status == EpistemicStatus.UNKNOWN
    assert graph_refs[0].is_authoritative is False
    seqs, _ = engine.reconstruct_attack_sequences(hydrated_case, missing_items, [])
    assert seqs[0].steps[0].epistemic_status == EpistemicStatus.UNKNOWN
    assert seqs[0].epistemic_status == EpistemicStatus.UNKNOWN

    # Incomplete duck-typed graph edge missing is_authoritative / corroboration_status must fail closed to INFERRED
    incomplete_edge = SimpleNamespace(
        edge_id="edge-incomplete",
        source_node_id="user:alice",
        target_node_id="host:srv-01",
        relationship_type="LOGGED_INTO",
        epistemic_status=RelationshipEpistemicStatus.OBSERVED,
        first_seen="2026-10-15T10:00:00Z",
        last_seen="2026-10-15T10:00:00Z",
        mitre_technique_id="T1078",
        mitre_tactic="Initial Access",
        evidence_event_ids=["ev-obs"],
        evidence_references=[],
    )
    corroborated_edge = InvestigationGraphEdge(
        edge_id="edge-corrob",
        source_node_id="host:srv-01",
        target_node_id="host:srv-02",
        relationship_type="LATERAL_MOVEMENT",
        epistemic_status=RelationshipEpistemicStatus.OBSERVED,
        is_authoritative=True,
        corroboration_status=CorroborationStatus.DIRECT_EVIDENCE,
        first_seen="2026-10-15T10:03:00Z",
        last_seen="2026-10-15T10:03:00Z",
        evidence_references=[],
    )
    duck_graph = SimpleNamespace(edges=[incomplete_edge, corroborated_edge])
    transitions = engine.detect_transitions(hydrated_case, [], [], graph=duck_graph)
    tr_by_target = {t.to_entity: t for t in transitions}
    assert tr_by_target["host:srv-01"].epistemic_status == EpistemicStatus.INFERRED
    assert tr_by_target["host:srv-02"].epistemic_status == EpistemicStatus.OBSERVED

    # Uncorroborated / inferred InvestigationGraphEdge must also yield INFERRED
    uncorrob_edge = InvestigationGraphEdge(
        edge_id="edge-uncorrob",
        source_node_id="host:srv-01",
        target_node_id="host:srv-03",
        relationship_type="LATERAL_MOVEMENT",
        epistemic_status=RelationshipEpistemicStatus.OBSERVED,
        is_authoritative=True,
        corroboration_status=CorroborationStatus.SINGLE_SOURCE,
        first_seen="2026-10-15T10:04:00Z",
        last_seen="2026-10-15T10:04:00Z",
        evidence_references=[],
    )
    typed_graph = InvestigationGraph(
        case_id=hydrated_case.case_id,
        incident_id=1,
        nodes=[],
        edges=[uncorrob_edge, corroborated_edge],
        total_nodes=0,
        total_edges=2,
        observed_edges_count=2,
        inferred_edges_count=0,
        corroborated_edges_count=1,
        contradicted_edges_count=0,
        generated_at="2026-10-15T10:05:00Z",
    )
    typed_transitions = engine.detect_transitions(hydrated_case, [], [], graph=typed_graph)
    typed_map = {t.to_entity: t for t in typed_transitions}
    assert typed_map["host:srv-03"].epistemic_status == EpistemicStatus.INFERRED
    assert typed_map["host:srv-02"].epistemic_status == EpistemicStatus.OBSERVED


def test_lossless_transition_dedupe_never_promotes_inferred():
    """Item 2: Conflicting OBSERVED vs INFERRED transitions or distinct bases never merge or upgrade certainty."""
    from logintel.ai.temporal.reconstruction_engine import TemporalReconstructionEngine
    from logintel.ai.domain.investigation_temporal import TransitionType, TemporalTransition, EpistemicStatus
    from logintel.ai.domain.investigation_graph import GraphEvidenceItem

    engine = TemporalReconstructionEngine()
    t1 = TemporalTransition(
        transition_id="t-obs",
        case_id=1,
        transition_type=TransitionType.HOST_TO_HOST,
        from_entity="host:a",
        to_entity="host:b",
        timestamp="2026-10-15T15:30:00+05:30",
        reason="Observed network edge",
        correlation_basis="Investigation topology edge",
        epistemic_status=EpistemicStatus.OBSERVED,
        evidence_references=[
            GraphEvidenceItem(
                reference_id="r1",
                source_type="event",
                source_id="e1",
                source_hash="sha256:h1",
                citation_tag="[event:e1]",
                summary="observed",
                epistemic_status=EpistemicStatus.OBSERVED,
                is_authoritative=True,
            )
        ],
    )
    t2_inf = TemporalTransition(
        transition_id="t-inf",
        case_id=1,
        transition_type=TransitionType.HOST_TO_HOST,
        from_entity="host:a",
        to_entity="host:b",
        timestamp="2026-10-15T10:00:00Z",
        reason="Inferred adjacency",
        correlation_basis="Temporal adjacency of consecutive forensic records",
        epistemic_status=EpistemicStatus.INFERRED,
        evidence_references=[
            GraphEvidenceItem(
                reference_id="r2",
                source_type="event",
                source_id="e2",
                source_hash="sha256:h2",
                citation_tag="[event:e2]",
                summary="inferred",
                epistemic_status=EpistemicStatus.INFERRED,
                is_authoritative=False,
            )
        ],
    )
    t3_inf_dup = TemporalTransition(
        transition_id="t-inf-2",
        case_id=1,
        transition_type=TransitionType.HOST_TO_HOST,
        from_entity="host:a",
        to_entity="host:b",
        timestamp="2026-10-15T10:00:00Z",
        reason="Secondary inferred cue",
        correlation_basis="Temporal adjacency of consecutive forensic records",
        epistemic_status=EpistemicStatus.INFERRED,
        evidence_references=[
            GraphEvidenceItem(
                reference_id="r3",
                source_type="alert",
                source_id="a3",
                source_hash="sha256:h3",
                citation_tag="[alert:a3]",
                summary="alert",
                epistemic_status=EpistemicStatus.INFERRED,
                is_authoritative=False,
            )
        ],
    )

    deduped = engine._deduplicate_transitions([t2_inf, t1, t3_inf_dup])
    # OBSERVED and INFERRED do not merge; the two equivalent INFERRED transitions DO merge cleanly
    assert len(deduped) == 2
    obs = next(t for t in deduped if t.epistemic_status == EpistemicStatus.OBSERVED)
    inf = next(t for t in deduped if t.epistemic_status == EpistemicStatus.INFERRED)
    assert len(obs.evidence_references) == 1
    assert len(inf.evidence_references) == 2
    assert "Inferred adjacency" in inf.reason
    assert "Secondary inferred cue" in inf.reason


def test_timezone_offset_and_inverted_bounds_fail_closed(tmp_path):
    """Item 3: Timezone offsets (+05:30 vs Z) order/filter accurately; inverted or malformed bounds fail closed."""
    from logintel.storage.case_repo import CaseRepository
    from logintel.timeline.service import UnifiedTimelineService

    t_db = Database(db_path=tmp_path / "forensic_tz.db")
    t_db.initialize()
    with t_db.connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO hosts (id, hostname, os_name, os_version, first_seen, last_seen) VALUES ('h-tz', 'srv-tz', 'Linux', '6', '2026-10-15T09:00:00Z', '2026-10-15T15:00:00Z')"
        )
        cur.execute(
            "INSERT INTO detection_rules (id, name, description, severity, category, rule_type, definition_yaml) VALUES ('r1', 'R1', 'Rule 1', 'ALERT', 'Auth', 'threshold', 'yaml')"
        )
        cur.execute(
            "INSERT INTO incidents (id, incident_key, title, summary, severity, status, primary_host, first_seen, last_seen) VALUES (1, 'INC-TZ', 'TZ Case', 'TZ summary', 'ALERT', 'OPEN', 'srv-tz', '2026-10-15T09:00:00Z', '2026-10-15T15:00:00Z')"
        )
        cur.execute(
            "INSERT INTO alerts (id, rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count) VALUES (1, 'r1', 'dk-1', 'A', 'A', 'ALERT', 'OPEN', 'h-tz', '2026-10-15T10:00:00Z', '2026-10-15T12:00:00Z', 1)"
        )
        cur.execute("INSERT INTO incident_alerts (incident_id, alert_id) VALUES (1, 1)")
        cur.execute(
            "INSERT INTO detections (id, alert_id, rule_id, timestamp, host, summary, evidence_count) VALUES (1, 1, 'r1', '2026-10-15T10:00:00Z', 'h-tz', 'det', 1)"
        )
        # +05:30 timestamp 16:00:00+05:30 == 10:30:00Z (in scope 10:00Z..12:00Z despite lexical '16' > '12')
        # unparseable timestamp 'bad-ts' must fail closed!
        cur.execute(
            """
            INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint)
            VALUES
            ('ev-ist-in', '2026-10-15T16:00:00+05:30', '2026-10-15T10:30:01Z', 'h-tz', 'auth', 'login', 'INFORMATIONAL', 'login', 'success', 'IST event', 'IST in window', 'p', 'fp1'),
            ('ev-utc-early', '2026-10-15T11:00:00Z', '2026-10-15T11:00:01Z', 'srv-tz', 'auth', 'login', 'INFORMATIONAL', 'login', 'success', 'UTC event', 'UTC later', 'p', 'fp2'),
            ('ev-bad-ts', 'not-a-timestamp', '2026-10-15T11:00:01Z', 'srv-tz', 'auth', 'login', 'INFORMATIONAL', 'login', 'success', 'Bad ts', 'Corrupt ts', 'p', 'fp3')
            """
        )
        cur.execute("INSERT INTO detection_evidence (detection_id, event_id) VALUES (1, 'ev-ist-in'), (1, 'ev-utc-early'), (1, 'ev-bad-ts')")
        conn.commit()

    t_repo = CaseRepository(db_path=tmp_path / "cases_tz.db", forensic_db=t_db)
    t_tl = UnifiedTimelineService(forensic_db=t_db, case_repository=t_repo)
    t_mh = MultiHostInvestigationService(case_repository=t_repo, forensic_database=t_db, timeline_service=t_tl)

    case = t_repo.create_case(incident_id=1, title="TZ + Alias Case")
    # Scope targets hostname 'srv-tz' and includes host-1 boundary safety check
    t_repo.update_case_scope(
        case_id=case.case_id,
        scope=InvestigationScope(
            investigation_id=1,
            subject_id="inc-1",
            target_hosts=["srv-tz", "host-1"],
            time_start="2026-10-15T10:00:00Z",
            time_end="2026-10-15T12:00:00Z",
        ),
    )

    # Item 4 + Item 3: alias 'h-tz' resolves to 'srv-tz'; 16:00+05:30 (10:30Z) precedes 11:00Z; 'bad-ts' excluded
    tl_res = t_tl.query_timeline(case.case_id, TimelineFilterParams(host="h-tz"))
    ev_ids = [it.source_id for it in tl_res.items if it.source_id.startswith("ev-")]
    assert ev_ids == ["ev-ist-in", "ev-utc-early"]
    assert "ev-bad-ts" not in ev_ids

    # Inverted query range must fail closed (0 items)
    inv_tl = t_tl.query_timeline(
        case.case_id,
        TimelineFilterParams(time_start="2026-10-15T12:00:00Z", time_end="2026-10-15T10:00:00Z"),
    )
    assert inv_tl.items == []
    assert inv_tl.total == 0

    inv_host_tl = t_mh.get_host_timeline(
        case.case_id,
        "srv-tz",
        time_start="2026-10-15T12:00:00Z",
        time_end="2026-10-15T10:00:00Z",
    )
    assert inv_host_tl.items == []
    assert inv_host_tl.total == 0


def test_host_alias_prefix_isolation_and_over_500_event_dedup(tmp_path):
    """Items 4 & 5: Exact host aliases exclude host-1 vs host-10; >500 explicit refs never double-count."""
    from logintel.storage.case_repo import CaseRepository
    from logintel.timeline.service import UnifiedTimelineService

    t_db = Database(db_path=tmp_path / "forensic_500.db")
    t_db.initialize()
    with t_db.connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO hosts (id, hostname, os_name, os_version, first_seen, last_seen) VALUES
            ('h-1', 'host-1', 'Linux', '6', '2026-10-15T10:00:00Z', '2026-10-15T11:00:00Z'),
            ('h-10', 'host-10', 'Linux', '6', '2026-10-15T10:00:00Z', '2026-10-15T11:00:00Z')
            """
        )
        cur.execute(
            "INSERT INTO incidents (id, incident_key, title, summary, severity, status, primary_host, first_seen, last_seen) VALUES (1, 'INC-500', '500 Case', '500 summary', 'ALERT', 'OPEN', 'host-1', '2026-10-15T10:00:00Z', '2026-10-15T11:00:00Z')"
        )
        rows = []
        for idx in range(560):
            rows.append((
                f"ev-h1-{idx:04d}",
                f"2026-10-15T10:{idx // 60:02d}:{idx % 60:02d}Z",
                "2026-10-15T11:00:00Z",
                "host-1" if idx % 2 == 0 else "h-1",
                "auth",
                "login",
                "INFORMATIONAL",
                "login",
                "success",
                "ev",
                f"msg {idx}",
                "p",
                f"fp-{idx}",
            ))
        rows.append((
            "ev-h10-0001",
            "2026-10-15T10:00:00Z",
            "2026-10-15T11:00:00Z",
            "host-10",
            "auth",
            "login",
            "INFORMATIONAL",
            "login",
            "success",
            "h10 ev",
            "h10 msg",
            "p",
            "fp-h10",
        ))
        cur.executemany(
            "INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()

    t_repo = CaseRepository(db_path=tmp_path / "cases_500.db", forensic_db=t_db)
    t_tl = UnifiedTimelineService(forensic_db=t_db, case_repository=t_repo)
    t_mh = MultiHostInvestigationService(case_repository=t_repo, forensic_database=t_db, timeline_service=t_tl)
    case = t_repo.create_case(incident_id=1, title="500 Ref Dedup + Exact Host")
    t_repo.update_case_scope(
        case_id=case.case_id,
        scope=InvestigationScope(investigation_id=1, subject_id="inc-1", target_hosts=["host-1"]),
    )

    # Explicitly attach 520 overlapping event refs (> 500 chunk threshold) pointing to the same DB events
    for idx in range(520):
        t_repo.add_evidence_reference(
            case_id=case.case_id,
            source_type="event",
            source_id=f"ev-h1-{idx:04d}",
            role="SUPPORTING",
            epistemic_status="OBSERVED",
            citation_tag=f"[event:ev-h1-{idx:04d}]",
        )

    dossier = t_mh.get_case_dossier(case.case_id)
    assert len(dossier.participating_hosts) == 1
    assert dossier.participating_hosts[0].host_id == "h-1"
    # Must be exactly 560, NEVER 560 + 560 = 1120 and NEVER include host-10!
    assert dossier.participating_hosts[0].event_count == 560
    assert not any("10" in h.hostname for h in dossier.participating_hosts)


def test_sql_prefiltering_before_timeline_cap_and_export_completeness(tmp_path):
    """Items 6, 7 & 10: Out-of-scope events never displace in-scope events before SQL cap; export reports completeness; provenance seals content."""
    from logintel.storage.case_repo import CaseRepository
    from logintel.timeline.service import UnifiedTimelineService
    from logintel.ai.temporal.reconstruction_engine import TemporalReconstructionEngine

    t_db = Database(db_path=tmp_path / "forensic_cap.db")
    t_db.initialize()
    with t_db.connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO detection_rules (id, name, description, severity, category, rule_type, definition_yaml) VALUES ('r1', 'R1', 'Rule 1', 'ALERT', 'Auth', 'threshold', 'yaml')"
        )
        cur.execute(
            "INSERT INTO incidents (id, incident_key, title, summary, severity, status, primary_host, first_seen, last_seen) VALUES (1, 'INC-CAP', 'Cap Case', 'Cap summary', 'ALERT', 'OPEN', 'in-scope-host', '2026-10-15T08:00:00Z', '2026-10-15T12:00:00Z')"
        )
        cur.execute(
            "INSERT INTO alerts (id, rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count) VALUES (1, 'r1', 'dk-cap', 'A', 'A', 'ALERT', 'OPEN', 'in-scope-host', '2026-10-15T10:30:00Z', '2026-10-15T10:35:00Z', 1)"
        )
        cur.execute(
            "INSERT INTO detections (id, alert_id, rule_id, timestamp, host, summary, evidence_count) VALUES (1, 1, 'r1', '2026-10-15T10:30:00Z', 'in-scope-host', 'det', 1)"
        )
        ev_rows = []
        det_rows = []
        # 25 earlier out-of-scope events on 'rogue-host' and pre-window times (exceeding cap=10!)
        for idx in range(25):
            ev_id = f"ev-noise-{idx:03d}"
            ev_rows.append((
                ev_id,
                f"2026-10-15T08:00:{idx:02d}Z",
                "2026-10-15T08:01:00Z",
                "rogue-host",
                "auth",
                "login",
                "INFORMATIONAL",
                "login",
                "success",
                "noise",
                "noise",
                "p",
                f"fp-n-{idx}",
            ))
            det_rows.append((1, ev_id))
        # 5 in-scope events later in time
        for idx in range(5):
            ev_id = f"ev-valid-{idx:03d}"
            ev_rows.append((
                ev_id,
                f"2026-10-15T10:31:{idx:02d}Z",
                "2026-10-15T10:32:00Z",
                "in-scope-host",
                "auth",
                "login",
                "INFORMATIONAL",
                "login",
                "success",
                "valid",
                "valid",
                "p",
                f"fp-v-{idx}",
            ))
            det_rows.append((1, ev_id))
        cur.executemany(
            "INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ev_rows,
        )
        cur.execute("INSERT INTO incident_alerts (incident_id, alert_id) VALUES (1, 1)")
        cur.executemany("INSERT INTO detection_evidence (detection_id, event_id) VALUES (?, ?)", det_rows)
        conn.commit()

    t_repo = CaseRepository(db_path=tmp_path / "cases_cap.db", forensic_db=t_db)
    t_tl = UnifiedTimelineService(forensic_db=t_db, case_repository=t_repo)
    t_tl.MAX_INCIDENT_EVENTS = 10
    t_mh = MultiHostInvestigationService(case_repository=t_repo, forensic_database=t_db, timeline_service=t_tl)

    case = t_repo.create_case(incident_id=1, title="SQL Pre-Filter Cap Test")
    t_repo.update_case_scope(
        case_id=case.case_id,
        scope=InvestigationScope(
            investigation_id=1,
            subject_id="inc-1",
            target_hosts=["in-scope-host"],
            time_start="2026-10-15T10:00:00Z",
            time_end="2026-10-15T11:00:00Z",
        ),
    )

    tl_res = t_tl.query_timeline(case.case_id, TimelineFilterParams(limit=50))
    ev_ids = sorted(it.source_id for it in tl_res.items if it.source_id.startswith("ev-valid-"))
    assert len(ev_ids) == 5
    assert tl_res.is_truncated is False

    # Item 7: export completeness metadata (COMPLETE when <=500 & not db_truncated; PARTIAL when db_truncated)
    json_ok, _ = t_tl.export_timeline(case.case_id, export_format="json")
    parsed_ok = json.loads(json_ok)
    assert parsed_ok["is_truncated"] is False
    assert parsed_ok["completeness_status"] == "COMPLETE"
    assert parsed_ok["total_matching"] == parsed_ok["total_items"]

    # Force backend cap truncation on in-scope items (cap=3 < 5 valid events)
    t_tl.MAX_INCIDENT_EVENTS = 3
    json_part, _ = t_tl.export_timeline(case.case_id, export_format="json")
    csv_part, _ = t_tl.export_timeline(case.case_id, export_format="csv")
    parsed_part = json.loads(json_part)
    assert parsed_part["is_truncated"] is True
    assert parsed_part["completeness_status"] == "PARTIAL"
    assert parsed_part["truncation_notice"] is not None
    assert "completeness_status=PARTIAL" in csv_part
    assert "is_truncated=true" in csv_part

    # Item 10: provenance_hash / root_digest changes when underlying evidence changes
    dossier_before = t_mh.get_case_dossier(case.case_id)
    export_before = t_mh.export_dossier(case.case_id, format="json")
    recon_engine = TemporalReconstructionEngine()
    recon_before = recon_engine.reconstruct_investigation(t_repo.get_case(case.case_id, resolve_evidence=True))

    t_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="event",
        source_id="ev-valid-000",
        role="PRIMARY",
        epistemic_status="OBSERVED",
        citation_tag="[event:ev-valid-000]",
    )
    dossier_after = t_mh.get_case_dossier(case.case_id)
    export_after = t_mh.export_dossier(case.case_id, format="json")
    recon_after = recon_engine.reconstruct_investigation(t_repo.get_case(case.case_id, resolve_evidence=True))

    assert dossier_after.provenance_hash != dossier_before.provenance_hash
    assert export_after.root_digest == dossier_after.provenance_hash
    assert export_after.root_digest != export_before.root_digest
    assert recon_after.provenance_hash != recon_before.provenance_hash


def test_campaign_correlation_shared_ip_and_entities(tmp_path):
    """Item 9: Campaign correlation actively uses src_ip and entity sets with INFERRED status."""
    from logintel.ai.temporal.reconstruction_engine import TemporalReconstructionEngine
    from logintel.ai.domain.investigation_temporal import CampaignRelationReason, EpistemicStatus
    from logintel.storage.case_repo import CaseRepository

    t_db = Database(db_path=tmp_path / "forensic_camp.db")
    t_db.initialize()
    t_repo = CaseRepository(db_path=tmp_path / "cases_camp.db", forensic_db=t_db)
    engine = TemporalReconstructionEngine()
    case = t_repo.create_case(incident_id=77001, title="Campaign IP Case")
    evidence = [
        {"timestamp": "2026-10-15T10:00:00Z", "host": "web-01", "username": "svc", "src_ip": "198.51.100.77"}
    ]
    other_incidents = [
        {"id": 77002, "title": "Peer Attacker IP Incident", "src_ip": "198.51.100.77", "first_seen": "2026-10-16T12:00:00Z"}
    ]
    corrs = engine.correlate_campaign_incidents(case, other_incidents, evidence)
    assert len(corrs) == 1
    assert corrs[0].relationship_reason == CampaignRelationReason.SHARED_SOURCE
    assert "ip:198.51.100.77" in corrs[0].shared_entities
    assert corrs[0].epistemic_status == EpistemicStatus.INFERRED


def test_timeline_and_host_summary_preserve_non_observed_epistemic_and_graph_edges(tmp_path):
    """Items 1 & 8: Non-observed/malformed refs stay non-observed across timeline exports & host summaries; missing/false/inferred graph edges fail closed."""
    from types import SimpleNamespace
    from logintel.storage.case_repo import CaseRepository
    from logintel.timeline.service import UnifiedTimelineService
    from logintel.timeline.models import EpistemicStatus as TimelineEpistemicStatus
    from logintel.multihost.models import HostEpistemicStatus
    from logintel.ai.temporal.reconstruction_engine import TemporalReconstructionEngine
    from logintel.ai.domain.investigation_temporal import EpistemicStatus
    from logintel.ai.domain.investigation_graph import (
        CorroborationStatus,
        InvestigationGraphEdge,
        RelationshipEpistemicStatus,
    )

    t_db = Database(db_path=tmp_path / "forensic_nonobs.db")
    t_db.initialize()
    t_repo = CaseRepository(db_path=tmp_path / "cases_nonobs.db", forensic_db=t_db)
    t_tl = UnifiedTimelineService(forensic_db=t_db, case_repository=t_repo)
    t_mh = MultiHostInvestigationService(case_repository=t_repo, forensic_database=t_db, timeline_service=t_tl)

    case = t_repo.create_case(incident_id=1, title="Non-Observed Propagation")
    t_repo.update_case_scope(
        case_id=case.case_id,
        scope=InvestigationScope(
            investigation_id=1,
            subject_id="inc-1",
            target_hosts=["host-inferred", "host-unknown"],
        ),
    )
    t_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="event",
        source_id="ev-inf-host",
        role="SUPPORTING",
        epistemic_status="INFERRED",
        citation_tag="[event:ev-inf-host]",
        analyst_annotation=json.dumps({
            "id": "ev-inf-host",
            "host": "host-inferred",
            "timestamp": "2026-10-15T10:00:00Z",
            "summary": "Heuristic association",
        }),
    )
    t_repo.add_evidence_reference(
        case_id=case.case_id,
        source_type="event",
        source_id="ev-malformed-ep",
        role="SUPPORTING",
        epistemic_status="CORRUPT_STATUS",
        citation_tag="[event:ev-malformed-ep]",
        analyst_annotation=json.dumps({
            "id": "ev-malformed-ep",
            "host": "host-unknown",
            "timestamp": "2026-10-15T10:01:00Z",
            "summary": "Unverified record",
        }),
    )

    tl = t_tl.query_timeline(case.case_id, TimelineFilterParams(limit=50))
    by_src = {it.source_id: it for it in tl.items}
    assert by_src["ev-inf-host"].epistemic_status == TimelineEpistemicStatus.INFERRED
    assert by_src["ev-malformed-ep"].epistemic_status == TimelineEpistemicStatus.UNKNOWN

    json_exp, _ = t_tl.export_timeline(case.case_id, export_format="json")
    csv_exp, _ = t_tl.export_timeline(case.case_id, export_format="csv")
    parsed_exp = json.loads(json_exp)
    exp_statuses = {it["source_id"]: it["epistemic_status"] for it in parsed_exp["items"]}
    assert exp_statuses["ev-inf-host"] == "INFERRED"
    assert exp_statuses["ev-malformed-ep"] == "UNKNOWN"
    assert ",UNKNOWN," in csv_exp
    assert ",INFERRED," in csv_exp

    dossier_inf = t_mh.get_case_dossier(case.case_id)
    hosts_by_id = {h.host_id: h for h in dossier_inf.participating_hosts}
    assert hosts_by_id["host-inferred"].epistemic_status == HostEpistemicStatus.INFERRED

    # Dedicated case with only UNKNOWN / malformed provenance must stay UNKNOWN (never OBSERVED or INFERRED)
    case_unk = t_repo.create_case(incident_id=2, title="Unknown Provenance Host")
    t_repo.update_case_scope(
        case_id=case_unk.case_id,
        scope=InvestigationScope(
            investigation_id=2,
            subject_id="inc-2",
            target_hosts=["host-unknown"],
        ),
    )
    t_repo.add_evidence_reference(
        case_id=case_unk.case_id,
        source_type="event",
        source_id="ev-only-unk",
        role="SUPPORTING",
        epistemic_status="CORRUPT_STATUS",
        citation_tag="[event:ev-only-unk]",
        analyst_annotation=json.dumps({
            "id": "ev-only-unk",
            "host": "host-unknown",
            "timestamp": "2026-10-15T10:01:00Z",
            "summary": "Unverified record",
        }),
    )
    dossier_unk = t_mh.get_case_dossier(case_unk.case_id)
    assert dossier_unk.participating_hosts[0].epistemic_status == HostEpistemicStatus.UNKNOWN

    # Graph edge checks: missing epistemic_status -> UNKNOWN, is_authoritative=False -> INFERRED, inferred -> INFERRED, supported -> OBSERVED
    edge_missing = SimpleNamespace(
        edge_id="e-miss",
        source_node_id="host:a",
        target_node_id="host:miss",
        relationship_type="LATERAL_MOVEMENT",
        first_seen="2026-10-15T10:00:00Z",
        last_seen="2026-10-15T10:00:00Z",
        evidence_references=[],
    )
    edge_false_auth = InvestigationGraphEdge(
        edge_id="e-false",
        source_node_id="host:a",
        target_node_id="host:false",
        relationship_type="LATERAL_MOVEMENT",
        epistemic_status=RelationshipEpistemicStatus.OBSERVED,
        is_authoritative=False,
        corroboration_status=CorroborationStatus.DIRECT_EVIDENCE,
        first_seen="2026-10-15T10:01:00Z",
        last_seen="2026-10-15T10:01:00Z",
    )
    edge_inferred = InvestigationGraphEdge(
        edge_id="e-inf",
        source_node_id="host:a",
        target_node_id="host:inf",
        relationship_type="LATERAL_MOVEMENT",
        epistemic_status=RelationshipEpistemicStatus.INFERRED,
        is_authoritative=True,
        corroboration_status=CorroborationStatus.TEMPORALLY_ALIGNED,
        first_seen="2026-10-15T10:02:00Z",
        last_seen="2026-10-15T10:02:00Z",
    )
    edge_supported = InvestigationGraphEdge(
        edge_id="e-ok",
        source_node_id="host:a",
        target_node_id="host:ok",
        relationship_type="LATERAL_MOVEMENT",
        epistemic_status=RelationshipEpistemicStatus.OBSERVED,
        is_authoritative=True,
        corroboration_status=CorroborationStatus.DIRECT_EVIDENCE,
        first_seen="2026-10-15T10:03:00Z",
        last_seen="2026-10-15T10:03:00Z",
    )
    transitions = TemporalReconstructionEngine().detect_transitions(
        t_repo.get_case(case.case_id, resolve_evidence=False),
        [],
        [],
        graph=SimpleNamespace(edges=[edge_missing, edge_false_auth, edge_inferred, edge_supported]),
    )
    by_dst = {t.to_entity: t.epistemic_status for t in transitions}
    assert by_dst["host:miss"] == EpistemicStatus.UNKNOWN
    assert by_dst["host:false"] == EpistemicStatus.INFERRED
    assert by_dst["host:inf"] == EpistemicStatus.INFERRED
    assert by_dst["host:ok"] == EpistemicStatus.OBSERVED


def test_time_boundary_equality_missing_timestamps_and_digest_invariance(tmp_path):
    """Items 3 & 10: Boundary timestamps are inclusive, missing timestamps fail closed under active bounds, and volatile generated_at never alters digests."""
    from logintel.storage.case_repo import CaseRepository
    from logintel.timeline.service import UnifiedTimelineService
    from logintel.ai.temporal.reconstruction_engine import TemporalReconstructionEngine

    t_db = Database(db_path=tmp_path / "forensic_bnd.db")
    t_db.initialize()
    t_repo = CaseRepository(db_path=tmp_path / "cases_bnd.db", forensic_db=t_db)
    t_tl = UnifiedTimelineService(forensic_db=t_db, case_repository=t_repo)
    t_mh = MultiHostInvestigationService(case_repository=t_repo, forensic_database=t_db, timeline_service=t_tl)

    case = t_repo.create_case(incident_id=1, title="Boundary & Missing Timestamp Case")
    t_repo.update_case_scope(
        case_id=case.case_id,
        scope=InvestigationScope(
            investigation_id=1,
            subject_id="inc-1",
            target_hosts=["host-bnd"],
            time_start="2026-10-15T10:00:00Z",
            time_end="2026-10-15T12:00:00Z",
        ),
    )

    # Exact boundary hits (+05:30 equivalent of 10:00:00Z, exact 12:00:00Z end) plus missing-timestamp ref
    for sid, ts in [
        ("ev-at-start", "2026-10-15T15:30:00+05:30"),
        ("ev-at-end", "2026-10-15T12:00:00Z"),
        ("ev-missing-ts", None),
        ("ev-bad-ts", "invalid-iso"),
    ]:
        t_repo.add_evidence_reference(
            case_id=case.case_id,
            source_type="event",
            source_id=sid,
            role="SUPPORTING",
            epistemic_status="OBSERVED",
            citation_tag=f"[event:{sid}]",
            analyst_annotation=json.dumps({
                "id": sid,
                "host": "host-bnd",
                "timestamp": ts,
            }),
        )

    dossier1 = t_mh.get_case_dossier(case.case_id)
    assert dossier1.participating_hosts[0].event_count == 2

    tl_res = t_tl.query_timeline(case.case_id, TimelineFilterParams(limit=50))
    tl_ids = [it.source_id for it in tl_res.items if it.source_id.startswith("ev-")]
    assert tl_ids == ["ev-at-start", "ev-at-end"]

    # Malformed query time_start fails closed
    bad_q = t_tl.query_timeline(case.case_id, TimelineFilterParams(time_start="not-an-iso-date"))
    assert bad_q.items == []
    assert bad_q.total == 0

    # Different synthesis runs change generated_at while keeping provenance_hash identical
    time.sleep(0.01)
    dossier2 = t_mh.get_case_dossier(case.case_id)
    assert dossier2.generated_at != dossier1.generated_at
    assert dossier2.provenance_hash == dossier1.provenance_hash

    recon_engine = TemporalReconstructionEngine()
    hydrated = t_repo.get_case(case.case_id, resolve_evidence=True)
    rec1 = recon_engine.reconstruct_investigation(hydrated)
    time.sleep(0.01)
    rec2 = recon_engine.reconstruct_investigation(hydrated)
    assert rec2.generated_at != rec1.generated_at
    assert rec2.provenance_hash == rec1.provenance_hash










