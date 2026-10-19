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
    t_id = int(time.time() * 1000) % 900000

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
    t_id = int(time.time() * 1000) % 500000
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




