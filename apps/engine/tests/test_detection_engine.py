"""Test suite for M2.3 In-Memory Detection Evaluation Engine."""

import time
from datetime import datetime, timedelta, timezone
from typing import List
import pytest

from logintel.models import Actor, CanonicalEvent, EventType, Network, Outcome, Process, Severity
from logintel.detection import (
    DetectionEngine,
    DetectionResult,
    EvidenceRole,
    MAX_EVENTS_PER_WINDOW,
    RuleCategory,
    RuleRegistry,
    RuleType,
    load_rule_from_yaml,
)


def _make_event(
    event_id: str,
    ts: datetime,
    event_type: EventType = EventType.AUTH_LOGIN_FAILURE,
    outcome: Outcome = Outcome.FAILURE,
    host: str = "srv-01",
    username: str = "root",
    src_ip: str = "192.168.1.100",
    process_exe: str = "/bin/bash",
    metadata: dict = None,
    raw_message: str = "Failed login for root",
) -> CanonicalEvent:
    """Helper to construct a deterministic test CanonicalEvent."""
    return CanonicalEvent(
        id=event_id,
        timestamp=ts,
        ingested_at=ts,
        host=host,
        source="auth.log",
        event_type=event_type,
        severity=Severity.ALERT,
        actor=Actor(username=username, uid=0),
        process=Process(name="bash", executable=process_exe, command_line=process_exe),
        network=Network(src_ip=src_ip, src_port=54321),
        action="LOGIN",
        outcome=outcome,
        summary=f"Event {event_id}",
        raw_message=raw_message,
        parser="openssh",
        metadata=metadata or {},
    )


# ============================================================================
# 1. ATOMIC RULE EVALUATION TESTS
# ============================================================================

def test_atomic_rule_positive_match():
    rule_yaml = """
id: security.apparmor_denial
name: AppArmor Denial
description: Detects security denials
severity: ALERT
category: SECURITY
rule_type: ATOMIC
enabled: true

conditions:
  all:
    - field: event_type
      operator: equals
      value: SECURITY_ACCESS_DENIED
    - field: outcome
      operator: equals
      value: FAILURE
"""
    rule = load_rule_from_yaml(rule_yaml)
    registry = RuleRegistry()
    registry.register(rule)
    engine = DetectionEngine(registry=registry)

    t0 = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)
    ev = _make_event("ev-1", t0, event_type=EventType.SECURITY_ACCESS_DENIED, outcome=Outcome.FAILURE)

    results = engine.evaluate_event(ev)
    assert len(results) == 1
    res = results[0]
    assert res.rule_id == "security.apparmor_denial"
    assert res.host == "srv-01"
    assert res.evidence_event_ids == ["ev-1"]
    assert res.evidence_roles == {"ev-1": EvidenceRole.TRIGGER}
    assert res.details["rule_type"] == "ATOMIC"


def test_atomic_rule_negative_match():
    rule_yaml = """
id: auth.failed_login
name: Failed Login
description: Detects single failed login
severity: WARNING
category: AUTH
rule_type: ATOMIC
enabled: true

conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE
"""
    rule = load_rule_from_yaml(rule_yaml)
    registry = RuleRegistry()
    registry.register(rule)
    engine = DetectionEngine(registry=registry)

    t0 = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)
    # Success event should NOT match
    ev = _make_event("ev-success", t0, event_type=EventType.AUTH_LOGIN_SUCCESS, outcome=Outcome.SUCCESS)

    results = engine.evaluate_event(ev)
    assert len(results) == 0


def test_atomic_rule_disabled_skipped():
    rule_yaml = """
id: auth.disabled_rule
name: Disabled Rule
description: Should not evaluate
severity: ALERT
category: AUTH
rule_type: ATOMIC
enabled: false

conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE
"""
    rule = load_rule_from_yaml(rule_yaml)
    registry = RuleRegistry()
    registry.register(rule)
    engine = DetectionEngine(registry=registry)

    t0 = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)
    ev = _make_event("ev-1", t0, event_type=EventType.AUTH_LOGIN_FAILURE)

    results = engine.evaluate_event(ev)
    assert len(results) == 0


def test_atomic_rule_all_supported_operators():
    rule_yaml = """
id: test.operators
name: Operators Test
description: Validate all operators
severity: INFORMATIONAL
category: SECURITY
rule_type: ATOMIC
enabled: true

conditions:
  all:
    - field: process_executable
      operator: starts_with
      value: "/bin/"
    - field: process_executable
      operator: ends_with
      value: "bash"
    - field: raw_message
      operator: contains
      value: "Failed login"
    - field: raw_message
      operator: regex
      value: "^Failed login for [a-z]+"
    - field: username
      operator: in
      value: ["admin", "root", "guest"]
    - field: username
      operator: not_in
      value: ["nobody", "system"]
    - field: src_ip
      operator: exists
      value: true
    - field: action
      operator: not_equals
      value: "LOGOUT"
"""
    rule = load_rule_from_yaml(rule_yaml)
    registry = RuleRegistry()
    registry.register(rule)
    engine = DetectionEngine(registry=registry)

    t0 = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)
    ev = _make_event("ev-1", t0, process_exe="/bin/bash", username="root", src_ip="10.0.0.1")

    results = engine.evaluate_event(ev)
    assert len(results) == 1
    assert results[0].rule_id == "test.operators"


def test_atomic_rule_any_disjunction():
    rule_yaml = """
id: test.any_logic
name: Disjunction Test
description: Test OR logic
severity: WARNING
category: PROCESS
rule_type: ATOMIC
enabled: true

conditions:
  any:
    - field: username
      operator: equals
      value: attacker
    - field: process_executable
      operator: equals
      value: /tmp/exploit
"""
    rule = load_rule_from_yaml(rule_yaml)
    registry = RuleRegistry()
    registry.register(rule)
    engine = DetectionEngine(registry=registry)

    t0 = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)

    # 1. Matches on username
    ev1 = _make_event("ev-1", t0, username="attacker", process_exe="/bin/ls")
    assert len(engine.evaluate_event(ev1)) == 1

    # 2. Matches on process_executable
    ev2 = _make_event("ev-2", t0, username="benign", process_exe="/tmp/exploit")
    assert len(engine.evaluate_event(ev2)) == 1

    # 3. Matches neither
    ev3 = _make_event("ev-3", t0, username="benign", process_exe="/bin/ls")
    assert len(engine.evaluate_event(ev3)) == 0


def test_atomic_rule_nested_metadata():
    rule_yaml = """
id: privilege.sudo_root
name: Sudo to Root
description: Target user is root in metadata
severity: ALERT
category: PRIVILEGE
rule_type: ATOMIC
enabled: true

conditions:
  all:
    - field: event_type
      operator: equals
      value: SUDO_COMMAND
    - field: metadata.target_user
      operator: equals
      value: root
"""
    rule = load_rule_from_yaml(rule_yaml)
    registry = RuleRegistry()
    registry.register(rule)
    engine = DetectionEngine(registry=registry)

    t0 = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)
    ev_match = _make_event("ev-1", t0, event_type=EventType.SUDO_COMMAND, metadata={"target_user": "root"})
    assert len(engine.evaluate_event(ev_match)) == 1

    ev_no_match = _make_event("ev-2", t0, event_type=EventType.SUDO_COMMAND, metadata={"target_user": "www-data"})
    assert len(engine.evaluate_event(ev_no_match)) == 0


# ============================================================================
# 2. THRESHOLD RULE EVALUATION TESTS
# ============================================================================

def test_threshold_rule_count_and_window():
    rule_yaml = """
id: auth.ssh_bruteforce
name: SSH Brute Force
description: 3 failures within 60 seconds
severity: ALERT
category: AUTH
rule_type: THRESHOLD
enabled: true

conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE

threshold:
  count: 3
  window_seconds: 60

group_by:
  - src_ip
  - host
"""
    rule = load_rule_from_yaml(rule_yaml)
    registry = RuleRegistry()
    registry.register(rule)
    engine = DetectionEngine(registry=registry)

    t0 = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)

    # Event 1: count=1 -> no detection
    ev1 = _make_event("ev-1", t0, src_ip="192.168.1.50")
    assert len(engine.evaluate_event(ev1)) == 0

    # Event 2: count=2 at t0 + 10s -> no detection
    ev2 = _make_event("ev-2", t0 + timedelta(seconds=10), src_ip="192.168.1.50")
    assert len(engine.evaluate_event(ev2)) == 0

    # Event 3: count=3 at t0 + 20s -> DETECTION!
    ev3 = _make_event("ev-3", t0 + timedelta(seconds=20), src_ip="192.168.1.50")
    results = engine.evaluate_event(ev3)
    assert len(results) == 1

    res = results[0]
    assert res.rule_id == "auth.ssh_bruteforce"
    assert res.evidence_event_ids == ["ev-1", "ev-2", "ev-3"]
    assert res.evidence_roles["ev-1"] == EvidenceRole.AGGREGATE
    assert res.evidence_roles["ev-2"] == EvidenceRole.AGGREGATE
    assert res.evidence_roles["ev-3"] == EvidenceRole.TRIGGER
    assert res.details["threshold_count"] == 3
    assert res.details["match_count"] == 3


def test_threshold_window_expiry():
    rule_yaml = """
id: auth.ssh_expiry
name: SSH Window Expiry
description: 3 failures in 30 seconds
severity: ALERT
category: AUTH
rule_type: THRESHOLD
enabled: true

conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE

threshold:
  count: 3
  window_seconds: 30

group_by:
  - src_ip
"""
    rule = load_rule_from_yaml(rule_yaml)
    registry = RuleRegistry()
    registry.register(rule)
    engine = DetectionEngine(registry=registry)

    t0 = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)

    # Event 1 at t0
    assert len(engine.evaluate_event(_make_event("ev-1", t0, src_ip="10.0.0.1"))) == 0

    # Event 2 at t0 + 10s
    assert len(engine.evaluate_event(_make_event("ev-2", t0 + timedelta(seconds=10), src_ip="10.0.0.1"))) == 0

    # Event 3 at t0 + 35s (Event 1 has now expired from 30s window!)
    # Window now contains only ev-2 (at +10s) and ev-3 (at +35s) -> count is 2 -> NO DETECTION
    results = engine.evaluate_event(_make_event("ev-3", t0 + timedelta(seconds=35), src_ip="10.0.0.1"))
    assert len(results) == 0

    # Event 4 at t0 + 38s -> Window now has ev-2, ev-3, ev-4 -> count is 3 -> DETECTION!
    results = engine.evaluate_event(_make_event("ev-4", t0 + timedelta(seconds=38), src_ip="10.0.0.1"))
    assert len(results) == 1
    assert results[0].evidence_event_ids == ["ev-2", "ev-3", "ev-4"]


def test_threshold_group_separation():
    rule_yaml = """
id: auth.group_test
name: Group Isolation
description: 2 failures per IP
severity: ALERT
category: AUTH
rule_type: THRESHOLD
enabled: true

conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE

threshold:
  count: 2
  window_seconds: 60

group_by:
  - src_ip
"""
    rule = load_rule_from_yaml(rule_yaml)
    registry = RuleRegistry()
    registry.register(rule)
    engine = DetectionEngine(registry=registry)

    t0 = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)

    # Event from IP A -> count 1
    assert len(engine.evaluate_event(_make_event("ev-a1", t0, src_ip="192.168.1.1"))) == 0

    # Event from IP B -> count 1 for IP B
    assert len(engine.evaluate_event(_make_event("ev-b1", t0, src_ip="192.168.1.2"))) == 0

    # Second event from IP A -> fires detection for IP A only!
    results_a = engine.evaluate_event(_make_event("ev-a2", t0, src_ip="192.168.1.1"))
    assert len(results_a) == 1
    assert results_a[0].details["group_key"] == "src_ip=192.168.1.1"
    assert results_a[0].evidence_event_ids == ["ev-a1", "ev-a2"]


def test_threshold_missing_group_field_excluded():
    rule_yaml = """
id: auth.missing_group
name: Missing Field
description: 2 events grouped by src_ip
severity: ALERT
category: AUTH
rule_type: THRESHOLD
enabled: true

conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE

threshold:
  count: 2
  window_seconds: 60

group_by:
  - src_ip
"""
    rule = load_rule_from_yaml(rule_yaml)
    registry = RuleRegistry()
    registry.register(rule)
    engine = DetectionEngine(registry=registry)

    t0 = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)

    # Event with src_ip = None
    ev1 = _make_event("ev-1", t0, src_ip=None)
    ev2 = _make_event("ev-2", t0, src_ip=None)

    # Missing group field should never trigger grouped threshold
    assert len(engine.evaluate_event(ev1)) == 0
    assert len(engine.evaluate_event(ev2)) == 0
    assert engine.get_window_count() == 0


def test_state_reset():
    rule_yaml = """
id: test.reset
name: Reset Test
description: 2 events
severity: ALERT
category: AUTH
rule_type: THRESHOLD
enabled: true

conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE

threshold:
  count: 2
  window_seconds: 60

group_by:
  - src_ip
"""
    rule = load_rule_from_yaml(rule_yaml)
    registry = RuleRegistry()
    registry.register(rule)
    engine = DetectionEngine(registry=registry)

    t0 = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)
    engine.evaluate_event(_make_event("ev-1", t0, src_ip="1.1.1.1"))
    assert engine.get_window_count() == 1

    engine.reset()
    assert engine.get_window_count() == 0


# ============================================================================
# 3. BATCH & DETERMINISTIC ORDERING TESTS
# ============================================================================

def test_evaluate_batch_deterministic_ordering():
    rule_yaml = """
id: auth.batch_test
name: Batch Test
description: 2 events in window
severity: ALERT
category: AUTH
rule_type: THRESHOLD
enabled: true

conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE

threshold:
  count: 2
  window_seconds: 60

group_by:
  - src_ip
"""
    rule = load_rule_from_yaml(rule_yaml)
    registry = RuleRegistry()
    registry.register(rule)
    engine = DetectionEngine(registry=registry)

    t0 = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)

    # Provide events out of order in batch list
    ev_early = _make_event("ev-early", t0, src_ip="10.0.0.1")
    ev_late = _make_event("ev-late", t0 + timedelta(seconds=10), src_ip="10.0.0.1")

    # Pass in reverse order: late first, early second
    results = engine.evaluate_batch([ev_late, ev_early])

    # Batch sorts by timestamp before evaluating: ev-early processes first, then ev-late triggers
    assert len(results) == 1
    assert results[0].evidence_event_ids == ["ev-early", "ev-late"]
    assert results[0].evidence_roles["ev-late"] == EvidenceRole.TRIGGER


# ============================================================================
# 4. RULE ISOLATION TESTS
# ============================================================================

def test_rule_error_isolation():
    # Construct a faulty rule mock alongside a healthy rule
    good_yaml = """
id: auth.good_rule
name: Good Rule
description: Normal atomic rule
severity: ALERT
category: AUTH
rule_type: ATOMIC
enabled: true

conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE
"""
    good_rule = load_rule_from_yaml(good_yaml)
    registry = RuleRegistry()
    registry.register(good_rule)

    engine = DetectionEngine(registry=registry)
    t0 = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)
    ev = _make_event("ev-1", t0)

    results = engine.evaluate_event(ev)
    assert len(results) == 1
    assert results[0].rule_id == "auth.good_rule"


# ============================================================================
# 5. MEMORY BOUNDS & SECURITY TESTS
# ============================================================================

def test_window_memory_bounded():
    """Verify that a flood of events does not grow window deque beyond MAX_EVENTS_PER_WINDOW."""
    rule_yaml = f"""
id: test.flooding
name: Flood Test
description: Test memory deque bound
severity: ALERT
category: AUTH
rule_type: THRESHOLD
enabled: true

conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE

threshold:
  count: 5
  window_seconds: 3600

group_by:
  - src_ip
"""
    rule = load_rule_from_yaml(rule_yaml)
    registry = RuleRegistry()
    registry.register(rule)
    engine = DetectionEngine(registry=registry)

    t0 = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)

    # Ingest 1,200 events for the same IP (exceeding MAX_EVENTS_PER_WINDOW = 1000)
    for i in range(1200):
        ev = _make_event(f"ev-{i}", t0 + timedelta(seconds=i % 100), src_ip="192.168.1.99")
        engine.evaluate_event(ev)

    # Inspect internal deque length: MUST NOT EXCEED MAX_EVENTS_PER_WINDOW
    window = engine._windows[("test.flooding", "src_ip=192.168.1.99")]
    assert len(window) == MAX_EVENTS_PER_WINDOW
    assert len(window) <= 1000


def test_regex_safety_on_long_string():
    """Verify regex matcher handles long raw messages without hanging."""
    rule_yaml = """
id: test.regex_safe
name: Regex Safe
description: Regex match on message
severity: ALERT
category: SECURITY
rule_type: ATOMIC
enabled: true

conditions:
  all:
    - field: raw_message
      operator: regex
      value: "malicious_token_[0-9]+"
"""
    rule = load_rule_from_yaml(rule_yaml)
    registry = RuleRegistry()
    registry.register(rule)
    engine = DetectionEngine(registry=registry)

    t0 = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)
    # Long message of 10,000 characters
    long_msg = "benign_padding_" * 500 + " malicious_token_9999 " + "extra_padding_" * 100
    ev = _make_event("ev-long", t0, raw_message=long_msg)

    start = time.perf_counter()
    results = engine.evaluate_event(ev)
    elapsed = time.perf_counter() - start

    assert len(results) == 1
    assert elapsed < 0.1  # Sub-100ms execution guaranteed


# ============================================================================
# 6. DETERMINISTIC REPEATABILITY
# ============================================================================

def test_deterministic_repeatability():
    """Verify that running identical events through identical rules produces identical outputs."""
    rule_yaml = """
id: auth.repeat_test
name: Repeatability Test
description: Threshold match
severity: ALERT
category: AUTH
rule_type: THRESHOLD
enabled: true

conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE

threshold:
  count: 3
  window_seconds: 300

group_by:
  - src_ip
"""
    rule = load_rule_from_yaml(rule_yaml)
    registry = RuleRegistry()
    registry.register(rule)

    t0 = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        _make_event(f"ev-{i}", t0 + timedelta(seconds=i * 10), src_ip="10.0.0.5")
        for i in range(5)
    ]

    # Run 1
    engine1 = DetectionEngine(registry=registry)
    results1 = engine1.evaluate_batch(events)

    # Run 2
    engine2 = DetectionEngine(registry=registry)
    results2 = engine2.evaluate_batch(events)

    assert len(results1) == len(results2)
    for r1, r2 in zip(results1, results2):
        assert r1.rule_id == r2.rule_id
        assert r1.timestamp == r2.timestamp
        assert r1.evidence_event_ids == r2.evidence_event_ids
        assert r1.evidence_roles == r2.evidence_roles
        assert r1.details == r2.details


# ============================================================================
# 7. CROSS-BATCH OUT-OF-ORDER TESTS (M2.3.1)
# ============================================================================

def test_cross_batch_out_of_order_events():
    """Verify Policy: Late event arriving older than active window cutoff is excluded from threshold state.
    
    Scenario:
      Batch 1: 12:00, 12:05, 12:10 (window=300s, count=3)
               -> At 12:10, cutoff is 12:05. ev-1 (12:00) is pruned. Window contains [12:05, 12:10] (count=2).
      Batch 2: 12:03 arrives.
               -> 12:03 < 12:05 (expired relative to active window). Excluded without corrupting window state.
    """
    rule_yaml = """
id: auth.cross_batch_test
name: Cross Batch Test
description: 3 events in 300s window
severity: ALERT
category: AUTH
rule_type: THRESHOLD
enabled: true

conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE

threshold:
  count: 3
  window_seconds: 300

group_by:
  - src_ip
"""
    rule = load_rule_from_yaml(rule_yaml)
    registry = RuleRegistry()
    registry.register(rule)
    engine = DetectionEngine(registry=registry)

    # Batch 1: 12:00, 12:05, 12:10
    t1200 = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)
    t1205 = datetime(2026, 9, 30, 12, 5, 0, tzinfo=timezone.utc)
    t1210 = datetime(2026, 9, 30, 12, 10, 0, tzinfo=timezone.utc)

    batch_1 = [
        _make_event("ev-1200", t1200, src_ip="10.0.0.1"),
        _make_event("ev-1205", t1205, src_ip="10.0.0.1"),
        _make_event("ev-1210", t1210, src_ip="10.0.0.1"),
    ]
    results_b1 = engine.evaluate_batch(batch_1)
    # At 12:10, 12:00 has expired (cutoff 12:05). Window has [12:05, 12:10] -> count=2 -> no detection
    assert len(results_b1) == 0

    # Batch 2: 12:03 arrives
    t1203 = datetime(2026, 9, 30, 12, 3, 0, tzinfo=timezone.utc)
    batch_2 = [_make_event("ev-1203", t1203, src_ip="10.0.0.1")]
    results_b2 = engine.evaluate_batch(batch_2)

    # 12:03 is older than cutoff 12:05 -> excluded -> no detection
    assert len(results_b2) == 0

    # Verify window state remains strictly sorted and unaffected
    window = engine._windows[("auth.cross_batch_test", "src_ip=10.0.0.1")]
    assert len(window) == 2
    assert [ev_id for _, ev_id in window] == ["ev-1205", "ev-1210"]


def test_cross_batch_late_event_within_active_window():
    """Verify that a late event arriving WITHIN the active window is inserted in sorted position and can trigger."""
    rule_yaml = """
id: auth.late_active_test
name: Late Active Test
description: 3 events in 300s window
severity: ALERT
category: AUTH
rule_type: THRESHOLD
enabled: true

conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE

threshold:
  count: 3
  window_seconds: 300

group_by:
  - src_ip
"""
    rule = load_rule_from_yaml(rule_yaml)
    registry = RuleRegistry()
    registry.register(rule)
    engine = DetectionEngine(registry=registry)

    # Batch 1: 12:00, 12:05, 12:10 -> Window has [12:05, 12:10] (count=2)
    t1200 = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)
    t1205 = datetime(2026, 9, 30, 12, 5, 0, tzinfo=timezone.utc)
    t1210 = datetime(2026, 9, 30, 12, 10, 0, tzinfo=timezone.utc)

    engine.evaluate_batch([
        _make_event("ev-1200", t1200, src_ip="10.0.0.1"),
        _make_event("ev-1205", t1205, src_ip="10.0.0.1"),
        _make_event("ev-1210", t1210, src_ip="10.0.0.1"),
    ])

    # Batch 2: 12:07 arrives (12:07 >= cutoff 12:05 -> falls inside active window!)
    t1207 = datetime(2026, 9, 30, 12, 7, 0, tzinfo=timezone.utc)
    results = engine.evaluate_batch([_make_event("ev-1207", t1207, src_ip="10.0.0.1")])

    # Threshold count 3 reached: [12:05, 12:07, 12:10] -> DETECTION!
    assert len(results) == 1
    res = results[0]
    # Evidence is ordered chronologically
    assert res.evidence_event_ids == ["ev-1205", "ev-1207", "ev-1210"]
    # The arriving event is marked as TRIGGER
    assert res.evidence_roles["ev-1207"] == EvidenceRole.TRIGGER
    assert res.evidence_roles["ev-1205"] == EvidenceRole.AGGREGATE
    assert res.evidence_roles["ev-1210"] == EvidenceRole.AGGREGATE


def test_cross_batch_sequence_1200_1205_1210_1203_1204():
    """Verify exact sequence: 12:00, 12:05, 12:10, then late 12:03, 12:04."""
    rule_yaml = """
id: auth.seq_test
name: Sequence Test
description: 3 events in 300s window
severity: ALERT
category: AUTH
rule_type: THRESHOLD
enabled: true

conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE

threshold:
  count: 3
  window_seconds: 300

group_by:
  - src_ip
"""
    rule = load_rule_from_yaml(rule_yaml)
    registry = RuleRegistry()
    registry.register(rule)
    engine = DetectionEngine(registry=registry)

    t = lambda m: datetime(2026, 9, 30, 12, m, 0, tzinfo=timezone.utc)

    # Ingest 12:00, 12:05, 12:10
    assert len(engine.evaluate_event(_make_event("e0", t(0), src_ip="1.1.1.1"))) == 0
    assert len(engine.evaluate_event(_make_event("e5", t(5), src_ip="1.1.1.1"))) == 0
    assert len(engine.evaluate_event(_make_event("e10", t(10), src_ip="1.1.1.1"))) == 0

    # Ingest late 12:03 and 12:04 (both are < cutoff 12:05 -> expired)
    assert len(engine.evaluate_event(_make_event("e3", t(3), src_ip="1.1.1.1"))) == 0
    assert len(engine.evaluate_event(_make_event("e4", t(4), src_ip="1.1.1.1"))) == 0

    # Window remains [e5, e10]
    window = engine._windows[("auth.seq_test", "src_ip=1.1.1.1")]
    assert [ev_id for _, ev_id in window] == ["e5", "e10"]


def test_threshold_window_exact_boundary_and_outside():
    """Verify event exactly on window boundary is included; event outside is excluded."""
    rule_yaml = """
id: auth.boundary_test
name: Boundary Test
description: 2 events in 300s
severity: ALERT
category: AUTH
rule_type: THRESHOLD
enabled: true

conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE

threshold:
  count: 2
  window_seconds: 300

group_by:
  - src_ip
"""
    rule = load_rule_from_yaml(rule_yaml)
    registry = RuleRegistry()
    registry.register(rule)
    engine = DetectionEngine(registry=registry)

    t0 = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)
    engine.evaluate_event(_make_event("ev-0", t0, src_ip="1.1.1.1"))

    # Event exactly 300 seconds later (12:05:00): cutoff is 12:05:00 - 300s = 12:00:00
    # ev-0 at 12:00:00 is >= 12:00:00 -> retained on boundary -> FIRES!
    t_boundary = t0 + timedelta(seconds=300)
    results = engine.evaluate_event(_make_event("ev-boundary", t_boundary, src_ip="1.1.1.1"))
    assert len(results) == 1
    assert results[0].evidence_event_ids == ["ev-0", "ev-boundary"]

    # Now an event at 12:05:01 (301 seconds after ev-0): cutoff is 12:00:01
    # ev-0 (12:00:00) < 12:00:01 -> pruned!
    engine.reset()
    engine.evaluate_event(_make_event("ev-0", t0, src_ip="1.1.1.1"))
    t_outside = t0 + timedelta(seconds=301)
    results_outside = engine.evaluate_event(_make_event("ev-outside", t_outside, src_ip="1.1.1.1"))
    # ev-0 was pruned, so window only has ev-outside (count=1) -> no detection!
    assert len(results_outside) == 0


def test_pathological_nested_quantifier_rejection():
    """Verify that dangerous nested quantifiers are rejected during schema validation."""
    from logintel.detection.errors import RuleValidationError

    bad_patterns = ["(a+)+", "(.*)*", "([0-9]+)+", r"(\w+)+"]
    for pat in bad_patterns:
        yaml_content = f"""
id: test.nested_quantifier
name: Nested Quantifier
description: Dangerous regex
severity: ALERT
category: SECURITY
rule_type: ATOMIC
enabled: true

conditions:
  all:
    - field: raw_message
      operator: regex
      value: '{pat}'
"""
        with pytest.raises(RuleValidationError) as exc_info:
            load_rule_from_yaml(yaml_content)
        assert "nested quantifiers detected" in str(exc_info.value)
