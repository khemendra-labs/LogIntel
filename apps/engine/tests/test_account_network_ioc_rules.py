"""Comprehensive test suite for LogIntel M2.6 Account, Network & IOC Detection Rules."""

from datetime import datetime, timedelta, timezone
from typing import List, Optional
import pytest

from logintel.models import Actor, CanonicalEvent, EventType, Network, Outcome, Process, Severity
from logintel.detection import (
    DetectionEngine,
    DetectionResult,
    EvidenceRole,
    RuleCategory,
    RuleRegistry,
    RuleType,
    load_default_rules,
)


def _make_account_event(
    event_id: str,
    ts: datetime,
    event_type: EventType = EventType.USER_CREATE,
    outcome: Outcome = Outcome.SUCCESS,
    host: str = "srv-01",
    username: Optional[str] = "testuser",
    uid: Optional[int] = 1001,
    summary: str = "Account event",
    parser: str = "user_management",
    iocs: Optional[List[str]] = None,
) -> CanonicalEvent:
    """Helper to construct realistic account management CanonicalEvents."""
    actor = Actor(username=username, uid=uid) if username else None
    return CanonicalEvent(
        id=event_id,
        timestamp=ts,
        ingested_at=ts,
        host=host,
        source="/var/log/auth.log",
        event_type=event_type,
        severity=Severity.CRITICAL if uid == 0 and event_type == EventType.USER_CREATE else Severity.NOTICE,
        actor=actor,
        process=Process(name="useradd", executable="/usr/sbin/useradd"),
        network=Network(),
        action="account_management",
        outcome=outcome,
        summary=summary,
        raw_message=summary,
        parser=parser,
        iocs=iocs or [],
        metadata={},
    )


def _make_network_event(
    event_id: str,
    ts: datetime,
    event_type: EventType = EventType.KERNEL_MESSAGE,
    outcome: Outcome = Outcome.FAILURE,
    host: str = "gateway-01",
    src_ip: Optional[str] = "203.0.113.5",
    dst_ip: Optional[str] = "192.168.1.1",
    dst_port: Optional[int] = 22,
    summary: str = "UFW Firewall blocked inbound connection",
    iocs: Optional[List[str]] = None,
) -> CanonicalEvent:
    """Helper to construct realistic network CanonicalEvents."""
    extracted_iocs = iocs if iocs is not None else ([src_ip] if src_ip else [])
    return CanonicalEvent(
        id=event_id,
        timestamp=ts,
        ingested_at=ts,
        host=host,
        source="/var/log/kern.log",
        event_type=event_type,
        severity=Severity.WARNING,
        actor=Actor(),
        process=Process(name="kernel"),
        network=Network(src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port, protocol="tcp"),
        action="firewall_block",
        outcome=outcome,
        summary=summary,
        raw_message=summary,
        parser="linux_kernel",
        iocs=extracted_iocs,
        metadata={},
    )


# ============================================================================
# 1. RULE LOADING & REGISTRY CATEGORY TESTS
# ============================================================================

def test_load_account_and_network_rules():
    """Verify that all default account, network, and IOC rules load cleanly."""
    rules = load_default_rules()
    rule_map = {r.id: r for r in rules}

    expected_account_ids = {
        "account.root_creation",
        "account.deletion_burst",
    }
    expected_network_ids = {
        "network.firewall_scan_burst",
        "network.sensitive_port_probe",
        "network.threat_intel_ioc_match",
    }

    assert expected_account_ids.issubset(set(rule_map.keys())), "Missing account rules"
    assert expected_network_ids.issubset(set(rule_map.keys())), "Missing network rules"

    for r_id in expected_account_ids:
        r = rule_map[r_id]
        assert r.category == RuleCategory.ACCOUNT
        assert r.enabled is True

    for r_id in expected_network_ids:
        r = rule_map[r_id]
        assert r.category == RuleCategory.NETWORK
        assert r.enabled is True

    assert rule_map["account.root_creation"].rule_type == RuleType.ATOMIC
    assert rule_map["account.deletion_burst"].rule_type == RuleType.THRESHOLD
    assert rule_map["network.firewall_scan_burst"].rule_type == RuleType.THRESHOLD
    assert rule_map["network.sensitive_port_probe"].rule_type == RuleType.ATOMIC
    assert rule_map["network.threat_intel_ioc_match"].rule_type == RuleType.ATOMIC


def test_registry_category_filtering_account_and_network():
    """Verify registry queries rules specifically by ACCOUNT and NETWORK categories."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())

    account_rules = registry.get_rules_by_category(RuleCategory.ACCOUNT)
    network_rules = registry.get_rules_by_category(RuleCategory.NETWORK)

    assert len(account_rules) == 2
    assert {r.id for r in account_rules} == {
        "account.root_creation",
        "account.deletion_burst",
    }

    assert len(network_rules) == 3
    assert {r.id for r in network_rules} == {
        "network.firewall_scan_burst",
        "network.sensitive_port_probe",
        "network.threat_intel_ioc_match",
    }


# ============================================================================
# 2. ACCOUNT MANAGEMENT DETECTION RULES
# ============================================================================

def test_account_root_creation_positive():
    """Positive test: Creation of local account with UID 0 triggers CRITICAL alert."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    event = _make_account_event(
        event_id="acc-root-pos",
        ts=datetime(2026, 9, 30, 14, 0, 0, tzinfo=timezone.utc),
        event_type=EventType.USER_CREATE,
        username="toor",
        uid=0,
        summary="New local user account created: 'toor' (UID: 0)",
    )
    results = [r for r in engine.evaluate_event(event) if r.rule_id == "account.root_creation"]

    assert len(results) == 1
    det = results[0]
    assert det.rule_id == "account.root_creation"
    assert registry.get("account.root_creation").severity == Severity.CRITICAL
    assert det.get_trigger_event_id() == "acc-root-pos"
    assert det.evidence_roles["acc-root-pos"] == EvidenceRole.TRIGGER


def test_account_root_creation_negative_normal_uid():
    """Negative test: Normal user creation with unprivileged UID does not trigger."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    event = _make_account_event(
        event_id="acc-norm-uid",
        ts=datetime(2026, 9, 30, 14, 0, 0, tzinfo=timezone.utc),
        event_type=EventType.USER_CREATE,
        username="charlie",
        uid=1005,
        summary="New local user account created: 'charlie' (UID: 1005)",
    )
    results = [r for r in engine.evaluate_event(event) if r.rule_id == "account.root_creation"]
    assert len(results) == 0


def test_account_root_creation_negative_different_event_type():
    """Negative test: Account deletion or other event with uid 0 does not trigger creation rule."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    event = _make_account_event(
        event_id="acc-del-root",
        ts=datetime(2026, 9, 30, 14, 0, 0, tzinfo=timezone.utc),
        event_type=EventType.USER_DELETE,
        username="root",
        uid=0,
        summary="Local user account deleted: 'root'",
    )
    results = [r for r in engine.evaluate_event(event) if r.rule_id == "account.root_creation"]
    assert len(results) == 0


def test_account_deletion_burst_positive():
    """Positive test: 3 account deletions on a host in 180s triggers WARNING burst alert."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    base_time = datetime(2026, 9, 30, 14, 0, 0, tzinfo=timezone.utc)
    results: List[DetectionResult] = []

    for i in range(3):
        event = _make_account_event(
            event_id=f"acc-del-{i}",
            ts=base_time + timedelta(seconds=i * 20),
            event_type=EventType.USER_DELETE,
            outcome=Outcome.SUCCESS,
            username=f"victim_user_{i}",
            host="srv-prod-01",
            summary=f"Local user account deleted: 'victim_user_{i}'",
        )
        res = engine.evaluate_event(event)
        results.extend([r for r in res if r.rule_id == "account.deletion_burst"])

    assert len(results) == 1
    det = results[0]
    assert det.rule_id == "account.deletion_burst"
    assert det.get_trigger_event_id() == "acc-del-2"
    assert len(det.evidence_event_ids) == 3


def test_account_deletion_burst_negative_sub_threshold():
    """Negative test: 2 account deletions (threshold=3) produces 0 detections."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    base_time = datetime(2026, 9, 30, 14, 0, 0, tzinfo=timezone.utc)
    results: List[DetectionResult] = []

    for i in range(2):
        event = _make_account_event(
            event_id=f"acc-del-sub-{i}",
            ts=base_time + timedelta(seconds=i * 20),
            event_type=EventType.USER_DELETE,
            outcome=Outcome.SUCCESS,
            username=f"victim_user_{i}",
        )
        res = engine.evaluate_event(event)
        results.extend([r for r in res if r.rule_id == "account.deletion_burst"])

    assert len(results) == 0


def test_account_deletion_burst_negative_separated_hosts():
    """Negative test: Deletions partitioned across different hosts do not cross-accumulate."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    base_time = datetime(2026, 9, 30, 14, 0, 0, tzinfo=timezone.utc)
    results: List[DetectionResult] = []

    for i in range(2):
        e1 = _make_account_event(f"e-h1-{i}", base_time + timedelta(seconds=i * 10), event_type=EventType.USER_DELETE, host="host-A")
        e2 = _make_account_event(f"e-h2-{i}", base_time + timedelta(seconds=i * 10), event_type=EventType.USER_DELETE, host="host-B")
        results.extend([r for r in engine.evaluate_event(e1) if r.rule_id == "account.deletion_burst"])
        results.extend([r for r in engine.evaluate_event(e2) if r.rule_id == "account.deletion_burst"])

    assert len(results) == 0


# ============================================================================
# 3. NETWORK & IOC DETECTION RULES
# ============================================================================

def test_network_firewall_scan_burst_positive():
    """Positive test: 5 firewall blocked packets from single IP in 120s triggers scan alert."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    base_time = datetime(2026, 9, 30, 15, 0, 0, tzinfo=timezone.utc)
    results: List[DetectionResult] = []

    for i in range(5):
        event = _make_network_event(
            event_id=f"fw-scan-{i}",
            ts=base_time + timedelta(seconds=i * 15),
            src_ip="198.51.100.77",
            dst_port=1000 + i,
            host="edge-firewall",
            summary=f"UFW Firewall blocked inbound connection from 198.51.100.77 to 192.168.1.1:{1000 + i}",
        )
        res = engine.evaluate_event(event)
        results.extend([r for r in res if r.rule_id == "network.firewall_scan_burst"])

    assert len(results) == 1
    det = results[0]
    assert det.rule_id == "network.firewall_scan_burst"
    assert det.get_trigger_event_id() == "fw-scan-4"
    assert len(det.evidence_event_ids) == 5
    roles = list(det.evidence_roles.values())
    assert roles.count(EvidenceRole.TRIGGER) == 1
    assert roles.count(EvidenceRole.AGGREGATE) == 4


def test_network_firewall_scan_burst_negative_sub_threshold():
    """Negative test: 4 blocked packets (threshold=5) produces 0 detections."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    base_time = datetime(2026, 9, 30, 15, 0, 0, tzinfo=timezone.utc)
    results: List[DetectionResult] = []

    for i in range(4):
        event = _make_network_event(
            event_id=f"fw-scan-sub-{i}",
            ts=base_time + timedelta(seconds=i * 15),
            src_ip="198.51.100.77",
            dst_port=1000 + i,
        )
        res = engine.evaluate_event(event)
        results.extend([r for r in res if r.rule_id == "network.firewall_scan_burst"])

    assert len(results) == 0


def test_network_firewall_scan_burst_negative_separated_ips():
    """Negative test: Drops from distinct source IPs do not accumulate together."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    base_time = datetime(2026, 9, 30, 15, 0, 0, tzinfo=timezone.utc)
    results: List[DetectionResult] = []

    for i in range(3):
        e1 = _make_network_event(f"e-ip1-{i}", base_time + timedelta(seconds=i * 10), src_ip="10.0.0.1")
        e2 = _make_network_event(f"e-ip2-{i}", base_time + timedelta(seconds=i * 10), src_ip="10.0.0.2")
        results.extend([r for r in engine.evaluate_event(e1) if r.rule_id == "network.firewall_scan_burst"])
        results.extend([r for r in engine.evaluate_event(e2) if r.rule_id == "network.firewall_scan_burst"])

    assert len(results) == 0


def test_network_sensitive_port_probe_positive():
    """Positive test: Blocked packet targeting critical service port triggers WARNING."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    sensitive_ports = [22, 3389, 3306, 5432, 6379, 6443]
    for idx, port in enumerate(sensitive_ports):
        event = _make_network_event(
            event_id=f"probe-pos-{idx}",
            ts=datetime(2026, 9, 30, 15, idx, 0, tzinfo=timezone.utc),
            dst_port=port,
            summary=f"UFW Firewall blocked inbound connection from 203.0.113.9 to 192.168.1.1:{port}",
        )
        results = [r for r in engine.evaluate_event(event) if r.rule_id == "network.sensitive_port_probe"]
        assert len(results) == 1, f"Failed to detect probe on port {port}"
        assert results[0].rule_id == "network.sensitive_port_probe"
        assert results[0].get_trigger_event_id() == f"probe-pos-{idx}"


def test_network_sensitive_port_probe_negative_benign_port():
    """Negative test: Blocked packet targeting unlisted ports does not match sensitive_port_probe."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    benign_ports = [80, 443, 8080, 53, 50000]
    for idx, port in enumerate(benign_ports):
        event = _make_network_event(
            event_id=f"probe-neg-{idx}",
            ts=datetime(2026, 9, 30, 15, idx, 0, tzinfo=timezone.utc),
            dst_port=port,
            summary=f"UFW Firewall blocked inbound connection from 203.0.113.9 to 192.168.1.1:{port}",
        )
        results = [r for r in engine.evaluate_event(event) if r.rule_id == "network.sensitive_port_probe"]
        assert len(results) == 0, f"False positive for unlisted port {port}"


def test_network_threat_intel_ioc_match_positive():
    """Positive test: Canonical event exhibiting known malicious IOC triggers CRITICAL alert."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    known_malicious_iocs = ["198.51.100.66", "203.0.113.199", "192.0.2.100"]
    for idx, ioc in enumerate(known_malicious_iocs):
        event = _make_network_event(
            event_id=f"ioc-pos-{idx}",
            ts=datetime(2026, 9, 30, 16, idx, 0, tzinfo=timezone.utc),
            src_ip=ioc,
            iocs=[ioc, "10.0.0.1"],
            summary=f"Network activity involving {ioc}",
        )
        results = [r for r in engine.evaluate_event(event) if r.rule_id == "network.threat_intel_ioc_match"]
        assert len(results) == 1, f"Failed to detect known IOC: {ioc}"
        assert results[0].rule_id == "network.threat_intel_ioc_match"
        assert registry.get("network.threat_intel_ioc_match").severity == Severity.CRITICAL
        assert results[0].get_trigger_event_id() == f"ioc-pos-{idx}"
        assert results[0].evidence_roles[f"ioc-pos-{idx}"] == EvidenceRole.TRIGGER


def test_network_threat_intel_ioc_match_negative():
    """Negative test: Benign IPs/IOCs do not match threat intel rule."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    event = _make_network_event(
        event_id="ioc-neg-benign",
        ts=datetime(2026, 9, 30, 16, 0, 0, tzinfo=timezone.utc),
        src_ip="192.168.1.100",
        iocs=["192.168.1.100", "10.0.0.5"],
    )
    results = [r for r in engine.evaluate_event(event) if r.rule_id == "network.threat_intel_ioc_match"]
    assert len(results) == 0
