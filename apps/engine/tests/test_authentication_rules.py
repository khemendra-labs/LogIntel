"""Comprehensive test suite for LogIntel M2.4 Authentication Detection Rules."""

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


def _make_auth_event(
    event_id: str,
    ts: datetime,
    event_type: EventType = EventType.AUTH_LOGIN_FAILURE,
    outcome: Outcome = Outcome.FAILURE,
    host: str = "srv-01",
    username: Optional[str] = "alice",
    src_ip: Optional[str] = "192.168.1.50",
    parser: str = "openssh_auth",
    summary: str = "SSH authentication failure for user alice",
    raw_message: str = "Failed password for alice from 192.168.1.50 port 22 ssh2",
) -> CanonicalEvent:
    """Helper to construct realistic authentication CanonicalEvents."""
    actor = Actor(username=username, uid=1000 if username != "root" else 0) if username else None
    network = Network(src_ip=src_ip, src_port=54321) if src_ip else None
    return CanonicalEvent(
        id=event_id,
        timestamp=ts,
        ingested_at=ts,
        host=host,
        source="/var/log/auth.log",
        event_type=event_type,
        severity=Severity.ALERT if outcome == Outcome.FAILURE else Severity.INFORMATIONAL,
        actor=actor,
        process=Process(name="sshd", executable="/usr/sbin/sshd"),
        network=network,
        action="LOGIN",
        outcome=outcome,
        summary=summary,
        raw_message=raw_message,
        parser=parser,
        metadata={},
    )


# ============================================================================
# 1. RULE LOADING & VALIDATION TESTS
# ============================================================================

def test_load_default_authentication_rules():
    """Verify that all default authentication rules load cleanly from the rules directory."""
    rules = load_default_rules()
    assert len(rules) >= 5, f"Expected at least 5 default rules, found {len(rules)}"

    rule_map = {r.id: r for r in rules}
    expected_ids = {
        "auth.ssh_bruteforce",
        "auth.invalid_user",
        "auth.root_login",
        "auth.password_spray",
        "auth.repeated_failures",
    }
    missing = expected_ids - set(rule_map.keys())
    assert not missing, f"Missing canonical authentication rules: {missing}"

    # Verify all are in the AUTH category and enabled
    for rule_id in expected_ids:
        rule = rule_map[rule_id]
        assert rule.category == RuleCategory.AUTH
        assert rule.enabled is True
        assert len(rule.conditions.all) >= 1

    # Verify specific types
    assert rule_map["auth.root_login"].rule_type == RuleType.ATOMIC
    assert rule_map["auth.ssh_bruteforce"].rule_type == RuleType.THRESHOLD
    assert rule_map["auth.invalid_user"].rule_type == RuleType.THRESHOLD
    assert rule_map["auth.password_spray"].rule_type == RuleType.THRESHOLD
    assert rule_map["auth.repeated_failures"].rule_type == RuleType.THRESHOLD


def test_registry_registration_of_default_rules():
    """Verify all default rules can be registered in RuleRegistry without error."""
    rules = load_default_rules()
    registry = RuleRegistry()
    count = registry.register_many(rules)
    assert count == len(rules)
    assert len(registry) == len(rules)
    assert registry.get("auth.ssh_bruteforce") is not None


# ============================================================================
# 2. SSH BRUTE FORCE RULE TESTS (auth.ssh_bruteforce)
# ============================================================================

def test_auth_ssh_bruteforce_positive():
    """Positive test: 5 failed logins from single IP within 300s triggers alert."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    base_time = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)
    results: List[DetectionResult] = []

    for i in range(5):
        event = _make_auth_event(
            event_id=f"bf-pos-{i}",
            ts=base_time + timedelta(seconds=i * 30),
            src_ip="203.0.113.5",
            host="srv-prod-01",
        )
        res = engine.evaluate_event(event)
        results.extend([r for r in res if r.rule_id == "auth.ssh_bruteforce"])

    # Must produce exactly 1 detection on the 5th event
    assert len(results) == 1
    det = results[0]
    assert det.rule_id == "auth.ssh_bruteforce"
    assert det.get_trigger_event_id() == "bf-pos-4"
    assert len(det.evidence_event_ids) == 5

    roles = list(det.evidence_roles.values())
    assert roles.count(EvidenceRole.TRIGGER) == 1
    assert roles.count(EvidenceRole.AGGREGATE) == 4


def test_auth_ssh_bruteforce_negative_below_threshold():
    """Negative test: 4 failed logins (threshold=5) produces 0 detections."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    base_time = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)
    results: List[DetectionResult] = []

    for i in range(4):
        event = _make_auth_event(
            event_id=f"bf-sub-{i}",
            ts=base_time + timedelta(seconds=i * 30),
            src_ip="203.0.113.6",
            host="srv-prod-01",
        )
        res = engine.evaluate_event(event)
        results.extend([r for r in res if r.rule_id == "auth.ssh_bruteforce"])

    assert len(results) == 0


def test_auth_ssh_bruteforce_negative_separated_ips():
    """Negative test: Failures partitioned by IP do not cross-accumulate."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    base_time = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)
    results: List[DetectionResult] = []

    # 4 from IP A, 4 from IP B
    for i in range(4):
        e1 = _make_auth_event(f"bf-ipA-{i}", base_time + timedelta(seconds=i * 20), src_ip="10.0.0.1")
        e2 = _make_auth_event(f"bf-ipB-{i}", base_time + timedelta(seconds=i * 20), src_ip="10.0.0.2")
        results.extend([r for r in engine.evaluate_event(e1) if r.rule_id == "auth.ssh_bruteforce"])
        results.extend([r for r in engine.evaluate_event(e2) if r.rule_id == "auth.ssh_bruteforce"])

    assert len(results) == 0


def test_auth_ssh_bruteforce_negative_outside_window():
    """Negative test: Events outside 300s window do not trigger threshold."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    base_time = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)
    results: List[DetectionResult] = []

    # 2 events early
    for i in range(2):
        ev = _make_auth_event(f"bf-win-early-{i}", base_time + timedelta(seconds=i * 10), src_ip="203.0.113.7")
        results.extend([r for r in engine.evaluate_event(ev) if r.rule_id == "auth.ssh_bruteforce"])

    # 2 events 400s later (early events expired from 300s window)
    for i in range(2):
        ev = _make_auth_event(f"bf-win-late-{i}", base_time + timedelta(seconds=400 + i * 10), src_ip="203.0.113.7")
        results.extend([r for r in engine.evaluate_event(ev) if r.rule_id == "auth.ssh_bruteforce"])

    assert len(results) == 0


# ============================================================================
# 3. INVALID USER BURST RULE TESTS (auth.invalid_user)
# ============================================================================

def test_auth_invalid_user_positive():
    """Positive test: 3 invalid user attempts from single IP within 180s triggers alert."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    base_time = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)
    results: List[DetectionResult] = []

    for i in range(3):
        event = _make_auth_event(
            event_id=f"inv-pos-{i}",
            ts=base_time + timedelta(seconds=i * 20),
            username=f"fakeuser{i}",
            src_ip="198.51.100.40",
            summary=f"SSH login attempt for invalid user fakeuser{i} from 198.51.100.40",
        )
        res = engine.evaluate_event(event)
        results.extend([r for r in res if r.rule_id == "auth.invalid_user"])

    assert len(results) == 1
    assert results[0].rule_id == "auth.invalid_user"
    assert len(results[0].evidence_event_ids) == 3


def test_auth_invalid_user_negative_normal_failures():
    """Negative test: Normal failed logins for valid users do not match contains 'invalid user'."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    base_time = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)
    results: List[DetectionResult] = []

    # 5 failed logins for existing user, no "invalid user" in summary
    for i in range(5):
        event = _make_auth_event(
            event_id=f"inv-neg-{i}",
            ts=base_time + timedelta(seconds=i * 20),
            username="validuser",
            src_ip="198.51.100.41",
            summary="SSH authentication failure for user validuser",
        )
        res = engine.evaluate_event(event)
        results.extend([r for r in res if r.rule_id == "auth.invalid_user"])

    assert len(results) == 0


# ============================================================================
# 4. DIRECT ROOT LOGIN RULE TESTS (auth.root_login)
# ============================================================================

def test_auth_root_login_positive():
    """Positive test: Successful SSH login for root triggers atomic alert."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    event = _make_auth_event(
        event_id="root-pos-1",
        ts=datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc),
        event_type=EventType.AUTH_LOGIN_SUCCESS,
        outcome=Outcome.SUCCESS,
        username="root",
        parser="openssh_auth",
        summary="SSH login successful for root from 192.168.1.100",
    )
    results = [r for r in engine.evaluate_event(event) if r.rule_id == "auth.root_login"]

    assert len(results) == 1
    det = results[0]
    assert det.rule_id == "auth.root_login"
    assert registry.get("auth.root_login").severity == Severity.WARNING
    assert det.get_trigger_event_id() == "root-pos-1"
    assert len(det.evidence_event_ids) == 1
    assert det.evidence_roles["root-pos-1"] == EvidenceRole.TRIGGER


def test_auth_root_login_negative_non_root():
    """Negative test: Successful SSH login for non-root user does not trigger."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    event = _make_auth_event(
        event_id="root-neg-user",
        ts=datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc),
        event_type=EventType.AUTH_LOGIN_SUCCESS,
        outcome=Outcome.SUCCESS,
        username="ubuntu",
        parser="openssh_auth",
    )
    results = [r for r in engine.evaluate_event(event) if r.rule_id == "auth.root_login"]
    assert len(results) == 0


def test_auth_root_login_negative_failed_login():
    """Negative test: Failed SSH login for root does not match root_login rule."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    event = _make_auth_event(
        event_id="root-neg-fail",
        ts=datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc),
        event_type=EventType.AUTH_LOGIN_FAILURE,
        outcome=Outcome.FAILURE,
        username="root",
        parser="openssh_auth",
    )
    results = [r for r in engine.evaluate_event(event) if r.rule_id == "auth.root_login"]
    assert len(results) == 0


def test_auth_root_login_negative_different_parser():
    """Negative test: Root login through non-openssh parser (e.g., sudo/pam) does not trigger SSH rule."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    event = _make_auth_event(
        event_id="root-neg-sudo",
        ts=datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc),
        event_type=EventType.AUTH_LOGIN_SUCCESS,
        outcome=Outcome.SUCCESS,
        username="root",
        parser="sudo",
    )
    results = [r for r in engine.evaluate_event(event) if r.rule_id == "auth.root_login"]
    assert len(results) == 0


# ============================================================================
# 5. PASSWORD SPRAY RULE TESTS (auth.password_spray)
# ============================================================================

def test_auth_password_spray_positive():
    """Positive test: 10 failed logins across different users from 1 IP within 600s triggers spray alert."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    base_time = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)
    results: List[DetectionResult] = []

    for i in range(10):
        event = _make_auth_event(
            event_id=f"spray-pos-{i}",
            ts=base_time + timedelta(seconds=i * 20),
            username=f"target_user_{i}",
            src_ip="198.51.100.99",
        )
        res = engine.evaluate_event(event)
        results.extend([r for r in res if r.rule_id == "auth.password_spray"])

    assert len(results) == 1
    assert results[0].rule_id == "auth.password_spray"
    assert registry.get("auth.password_spray").severity == Severity.CRITICAL
    assert len(results[0].evidence_event_ids) == 10


def test_auth_password_spray_negative_sub_threshold():
    """Negative test: 9 failed logins (threshold=10) produces 0 detections."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    base_time = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)
    results: List[DetectionResult] = []

    for i in range(9):
        event = _make_auth_event(
            event_id=f"spray-sub-{i}",
            ts=base_time + timedelta(seconds=i * 20),
            username=f"target_user_{i}",
            src_ip="198.51.100.100",
        )
        res = engine.evaluate_event(event)
        results.extend([r for r in res if r.rule_id == "auth.password_spray"])

    assert len(results) == 0


# ============================================================================
# 6. REPEATED FAILURES FOR ACCOUNT RULE TESTS (auth.repeated_failures)
# ============================================================================

def test_auth_repeated_failures_positive():
    """Positive test: 5 failed logins targeting single user on a host triggers alert."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    base_time = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)
    results: List[DetectionResult] = []

    for i in range(5):
        event = _make_auth_event(
            event_id=f"rep-pos-{i}",
            ts=base_time + timedelta(seconds=i * 30),
            username="victim_account",
            host="app-server-01",
            src_ip=f"10.0.0.{i+10}",  # different IPs targeting same user
        )
        res = engine.evaluate_event(event)
        results.extend([r for r in res if r.rule_id == "auth.repeated_failures"])

    assert len(results) == 1
    assert results[0].rule_id == "auth.repeated_failures"
    assert results[0].get_trigger_event_id() == "rep-pos-4"
    assert len(results[0].evidence_event_ids) == 5


def test_auth_repeated_failures_negative_scattered_users():
    """Negative test: Failures targeting different users do not trigger repeated_failures rule."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    base_time = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)
    results: List[DetectionResult] = []

    # 2 attempts per user across 3 users on same host
    for u in ["userA", "userB", "userC"]:
        for i in range(2):
            event = _make_auth_event(
                event_id=f"rep-scat-{u}-{i}",
                ts=base_time + timedelta(seconds=i * 10),
                username=u,
                host="app-server-01",
            )
            res = engine.evaluate_event(event)
            results.extend([r for r in res if r.rule_id == "auth.repeated_failures"])

    assert len(results) == 0
