"""Comprehensive test suite for M2.1 Detection Core Specification & Rule Schema."""

import re
import pytest
from pathlib import Path

from logintel.models.events import Severity
from logintel.detection import (
    Condition,
    ConditionsBlock,
    DetectionRule,
    DuplicateRuleError,
    Operator,
    RuleCategory,
    RuleParseError,
    RuleRegistry,
    RuleType,
    RuleValidationError,
    ThresholdConfig,
    UnknownFieldError,
    load_rule_from_dict,
    load_rule_from_yaml,
    load_rules_from_yaml,
)


# ============================================================================
# 1. VALID RULES
# ============================================================================

def test_valid_atomic_rule():
    yaml_content = """
id: security.apparmor_denial
name: AppArmor Access Denial
description: Detect AppArmor access denial events
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
    rule = load_rule_from_yaml(yaml_content)
    assert rule.id == "security.apparmor_denial"
    assert rule.name == "AppArmor Access Denial"
    assert rule.severity == Severity.ALERT
    assert rule.category == RuleCategory.SECURITY
    assert rule.rule_type == RuleType.ATOMIC
    assert rule.enabled is True
    assert rule.threshold is None
    assert rule.group_by is None
    assert len(rule.conditions.all) == 2


def test_valid_threshold_rule():
    yaml_content = """
id: auth.ssh_bruteforce
name: SSH Brute Force
description: Detect repeated SSH authentication failures
severity: ALERT
category: AUTH
rule_type: THRESHOLD
enabled: true

conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE
    - field: outcome
      operator: equals
      value: FAILURE

threshold:
  count: 5
  window_seconds: 300

group_by:
  - src_ip
  - host

cooldown_seconds: 3600
"""
    rule = load_rule_from_yaml(yaml_content)
    assert rule.id == "auth.ssh_bruteforce"
    assert rule.rule_type == RuleType.THRESHOLD
    assert rule.threshold is not None
    assert rule.threshold.count == 5
    assert rule.threshold.window_seconds == 300
    assert rule.group_by == ["src_ip", "host"]
    assert rule.cooldown_seconds == 3600


def test_valid_rule_with_any_conditions_and_disabled_state():
    yaml_content = """
id: process.suspicious_shells
name: Suspicious Shell Spawn
description: Detects interactive shell execution by web server user
severity: CRITICAL
category: PROCESS
rule_type: ATOMIC
enabled: false

conditions:
  all:
    - field: username
      operator: equals
      value: www-data
  any:
    - field: process_name
      operator: in
      value: ["sh", "bash", "zsh", "dash"]
    - field: process_command_line
      operator: contains
      value: "/bin/sh"
"""
    rule = load_rule_from_yaml(yaml_content)
    assert rule.id == "process.suspicious_shells"
    assert rule.enabled is False
    assert len(rule.conditions.all) == 1
    assert len(rule.conditions.any) == 2
    assert rule.conditions.any[0].operator == Operator.IN
    assert rule.conditions.any[0].value == ["sh", "bash", "zsh", "dash"]


def test_valid_all_supported_operators():
    yaml_content = """
id: test.all_operators
name: Test All Operators
description: Rule validating all operator enumerations
severity: INFORMATIONAL
category: SECURITY
rule_type: ATOMIC
enabled: true

conditions:
  all:
    - field: process_executable
      operator: starts_with
      value: "/tmp/"
    - field: process_command_line
      operator: ends_with
      value: ".sh"
    - field: summary
      operator: contains
      value: "unauthorized"
    - field: raw_message
      operator: regex
      value: "^Failed password for .* from [0-9.]+"
    - field: src_ip
      operator: exists
      value: true
    - field: action
      operator: not_equals
      value: "LOGIN"
    - field: src_port
      operator: in
      value: [22, 2222, 8022]
    - field: dst_port
      operator: not_in
      value: [80, 443]
"""
    rule = load_rule_from_yaml(yaml_content)
    assert len(rule.conditions.all) == 8
    ops = [c.operator for c in rule.conditions.all]
    assert Operator.STARTS_WITH in ops
    assert Operator.ENDS_WITH in ops
    assert Operator.CONTAINS in ops
    assert Operator.REGEX in ops
    assert Operator.EXISTS in ops
    assert Operator.NOT_EQUALS in ops
    assert Operator.IN in ops
    assert Operator.NOT_IN in ops


def test_valid_nested_metadata_field():
    yaml_content = """
id: privilege.sudo_target
name: Sudo Elevation to Root
description: Detects sudo execution targeting root user
severity: WARNING
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
    rule = load_rule_from_yaml(yaml_content)
    assert rule.conditions.all[1].field == "metadata.target_user"


def test_valid_field_aliases_normalized():
    yaml_content = """
id: auth.alias_normalization
name: Alias Normalization Test
description: Ensures aliases like source_ip and actor.username are normalized
severity: INFORMATIONAL
category: AUTH
rule_type: ATOMIC
enabled: true

conditions:
  all:
    - field: source_ip
      operator: equals
      value: "10.0.0.1"
    - field: actor.username
      operator: equals
      value: "admin"
    - field: process.executable
      operator: starts_with
      value: "/usr/bin/"
    - field: executable
      operator: ends_with
      value: "/nc"
"""
    rule = load_rule_from_yaml(yaml_content)
    fields = [c.field for c in rule.conditions.all]
    assert fields == ["src_ip", "username", "process_executable", "process_executable"]


# ============================================================================
# 2. INVALID RULE DEFINITIONS & REJECTIONS
# ============================================================================

def test_reject_missing_id():
    yaml_content = """
name: No ID Rule
description: Missing ID field
severity: ALERT
category: AUTH
rule_type: ATOMIC
conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE
"""
    with pytest.raises(RuleValidationError):
        load_rule_from_yaml(yaml_content)


def test_reject_empty_or_whitespace_id():
    yaml_content = """
id: "   "
name: Whitespace ID
description: Invalid whitespace ID
severity: ALERT
category: AUTH
rule_type: ATOMIC
conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE
"""
    with pytest.raises(RuleValidationError) as exc_info:
        load_rule_from_yaml(yaml_content)
    assert "Rule ID must not be empty" in str(exc_info.value)


@pytest.mark.parametrize("invalid_id", [
    "UpperCase.Rule",
    "single_token",
    "path/traversal",
    "path\\traversal",
    "../rule.dot",
    "has whitespace.rule",
    "special!char.rule",
    "a" * 65,  # Exceeds max length
])
def test_reject_invalid_rule_ids(invalid_id):
    yaml_content = f"""
id: "{invalid_id}"
name: Invalid ID Rule
description: Test ID validation
severity: ALERT
category: AUTH
rule_type: ATOMIC
conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE
"""
    with pytest.raises(RuleValidationError):
        load_rule_from_yaml(yaml_content)


def test_reject_unknown_severity():
    yaml_content = """
id: test.invalid_sev
name: Invalid Severity
description: Test severity rejection
severity: SUPER_CRITICAL
category: AUTH
rule_type: ATOMIC
conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE
"""
    with pytest.raises(RuleValidationError):
        load_rule_from_yaml(yaml_content)


def test_reject_unknown_category():
    yaml_content = """
id: test.invalid_cat
name: Invalid Category
description: Test category rejection
severity: ALERT
category: CLOUD_AI
rule_type: ATOMIC
conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE
"""
    with pytest.raises(RuleValidationError):
        load_rule_from_yaml(yaml_content)


def test_reject_unknown_event_field_with_suggestion():
    yaml_content = """
id: test.unknown_field
name: Unknown Field
description: Test field suggestion
severity: ALERT
category: AUTH
rule_type: ATOMIC
conditions:
  all:
    - field: src_ipp
      operator: equals
      value: "1.1.1.1"
"""
    with pytest.raises(UnknownFieldError) as exc_info:
        load_rule_from_yaml(yaml_content)
    assert "src_ipp" in str(exc_info.value)
    assert "src_ip" in str(exc_info.value)


def test_reject_unsafe_nested_attributes():
    yaml_content = """
id: test.unsafe_nested
name: Unsafe Traversal
description: Test attribute traversal block
severity: ALERT
category: SECURITY
rule_type: ATOMIC
conditions:
  all:
    - field: metadata.__class__
      operator: equals
      value: "malicious"
"""
    with pytest.raises(RuleValidationError) as exc_info:
        load_rule_from_yaml(yaml_content)
    assert "Forbidden attribute access" in str(exc_info.value)


def test_reject_arbitrary_nested_dot_path():
    yaml_content = """
id: test.arbitrary_path
name: Arbitrary Path
description: Test dot path block
severity: ALERT
category: SECURITY
rule_type: ATOMIC
conditions:
  all:
    - field: actor.parent.identity.foo
      operator: equals
      value: "bar"
"""
    with pytest.raises(RuleValidationError):
        load_rule_from_yaml(yaml_content)


def test_reject_threshold_supplied_to_atomic_rule():
    yaml_content = """
id: test.atomic_with_threshold
name: Inconsistent Rule
description: Atomic rule must not have threshold
severity: ALERT
category: AUTH
rule_type: ATOMIC
conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE
threshold:
  count: 5
  window_seconds: 60
"""
    with pytest.raises(RuleValidationError) as exc_info:
        load_rule_from_yaml(yaml_content)
    assert "Rule type is ATOMIC but 'threshold' was provided" in str(exc_info.value)


def test_reject_threshold_rule_missing_threshold():
    yaml_content = """
id: test.threshold_missing_config
name: Missing Threshold
description: Threshold rule missing threshold block
severity: ALERT
category: AUTH
rule_type: THRESHOLD
group_by:
  - src_ip
conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE
"""
    with pytest.raises(RuleValidationError) as exc_info:
        load_rule_from_yaml(yaml_content)
    assert "Rule type is THRESHOLD but 'threshold' configuration" in str(exc_info.value)


def test_reject_threshold_rule_missing_group_by():
    yaml_content = """
id: test.threshold_missing_groupby
name: Missing Group By
description: Threshold rule missing group_by
severity: ALERT
category: AUTH
rule_type: THRESHOLD
threshold:
  count: 10
  window_seconds: 60
conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE
"""
    with pytest.raises(RuleValidationError) as exc_info:
        load_rule_from_yaml(yaml_content)
    assert "group_by' is missing or empty" in str(exc_info.value)


@pytest.mark.parametrize("bad_count,bad_window", [
    (0, 60),
    (-5, 60),
    (5, 0),
    (5, -60),
    (2_000_000, 60),  # Exceeds max count
    (5, 100_000),     # Exceeds 24hr window
])
def test_reject_invalid_threshold_values(bad_count, bad_window):
    yaml_content = f"""
id: test.invalid_threshold_vals
name: Bad Thresholds
description: Testing threshold boundaries
severity: ALERT
category: AUTH
rule_type: THRESHOLD
threshold:
  count: {bad_count}
  window_seconds: {bad_window}
group_by:
  - src_ip
conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE
"""
    with pytest.raises(RuleValidationError):
        load_rule_from_yaml(yaml_content)


def test_reject_invalid_group_by_field():
    yaml_content = """
id: test.bad_group_by
name: Bad Group Field
description: Unknown field in group_by
severity: ALERT
category: AUTH
rule_type: THRESHOLD
threshold:
  count: 5
  window_seconds: 60
group_by:
  - not_a_real_field
conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE
"""
    with pytest.raises(UnknownFieldError) as exc_info:
        load_rule_from_yaml(yaml_content)
    assert "not_a_real_field" in str(exc_info.value)


def test_reject_malformed_regex():
    yaml_content = """
id: test.malformed_regex
name: Bad Regex
description: Unclosed parenthesis in regex
severity: ALERT
category: AUTH
rule_type: ATOMIC
conditions:
  all:
    - field: raw_message
      operator: regex
      value: "([a-z+"
"""
    with pytest.raises(RuleValidationError) as exc_info:
        load_rule_from_yaml(yaml_content)
    assert "Malformed regex pattern" in str(exc_info.value)


def test_reject_excessive_regex_length():
    huge_pattern = "a" * 300
    yaml_content = f"""
id: test.huge_regex
name: Huge Regex
description: Exceeds 256 chars
severity: ALERT
category: AUTH
rule_type: ATOMIC
conditions:
  all:
    - field: raw_message
      operator: regex
      value: "{huge_pattern}"
"""
    with pytest.raises(RuleValidationError) as exc_info:
        load_rule_from_yaml(yaml_content)
    assert "exceeds maximum length of 256 characters" in str(exc_info.value)


def test_reject_invalid_port_number():
    yaml_content = """
id: test.bad_port
name: Bad Port
description: Port out of range
severity: ALERT
category: NETWORK
rule_type: ATOMIC
conditions:
  all:
    - field: src_port
      operator: equals
      value: 70000
"""
    with pytest.raises(RuleValidationError) as exc_info:
        load_rule_from_yaml(yaml_content)
    assert "between 0 and 65535" in str(exc_info.value)


def test_reject_invalid_event_type_value():
    yaml_content = """
id: test.bad_event_type
name: Bad Event Type
description: Non-existent EventType enum member
severity: ALERT
category: AUTH
rule_type: ATOMIC
conditions:
  all:
    - field: event_type
      operator: equals
      value: NON_EXISTENT_EVENT_TYPE
"""
    with pytest.raises(RuleValidationError) as exc_info:
        load_rule_from_yaml(yaml_content)
    assert "Invalid event_type" in str(exc_info.value)


# ============================================================================
# 3. YAML SAFETY & CODE EXECUTION PREVENTIONS
# ============================================================================

def test_reject_yaml_python_code_execution():
    # Attempt to execute arbitrary python using YAML tags
    malicious_yaml = """
id: test.exploit
name: !!python/object/apply:os.system ["echo EXPLOITED > /tmp/exploited"]
description: Attempted code injection
severity: CRITICAL
category: SECURITY
rule_type: ATOMIC
conditions:
  all:
    - field: event_type
      operator: equals
      value: SYSTEM_GENERIC
"""
    with pytest.raises(RuleParseError) as exc_info:
        load_rule_from_yaml(malicious_yaml)
    assert "Malformed YAML" in str(exc_info.value) or "could not determine a constructor" in str(exc_info.value)


def test_reject_non_mapping_yaml():
    with pytest.raises(RuleParseError) as exc_info:
        load_rule_from_yaml("just a random scalar string")
    assert "Root YAML document must be a mapping" in str(exc_info.value)


def test_reject_empty_yaml():
    with pytest.raises(RuleParseError) as exc_info:
        load_rule_from_yaml("")
    assert "YAML content is empty" in str(exc_info.value)


# ============================================================================
# 4. RULE REGISTRY & DUPLICATE PREVENTION
# ============================================================================

def test_registry_registration_and_lookup():
    registry = RuleRegistry()
    rule = load_rule_from_yaml("""
id: auth.rule_one
name: Rule One
description: First test rule
severity: INFORMATIONAL
category: AUTH
rule_type: ATOMIC
conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_SUCCESS
""")
    registry.register(rule)
    assert registry.count() == 1
    retrieved = registry.get("auth.rule_one")
    assert retrieved is not None
    assert retrieved.id == "auth.rule_one"
    assert registry.get("non_existent") is None


def test_registry_rejects_duplicate_rule_id():
    registry = RuleRegistry()
    yaml_str = """
id: auth.duplicate_test
name: Duplicate Test
description: Test duplicate prevention
severity: INFORMATIONAL
category: AUTH
rule_type: ATOMIC
conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_SUCCESS
"""
    rule1 = load_rule_from_yaml(yaml_str)
    rule2 = load_rule_from_yaml(yaml_str)

    registry.register(rule1)
    with pytest.raises(DuplicateRuleError) as exc_info:
        registry.register(rule2)
    assert "Duplicate rule ID 'auth.duplicate_test'" in str(exc_info.value)
    assert registry.count() == 1


def test_registry_batch_duplicate_prevention():
    registry = RuleRegistry()
    yaml_docs = """
id: auth.rule_a
name: Rule A
description: First
severity: INFORMATIONAL
category: AUTH
rule_type: ATOMIC
conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_SUCCESS
---
id: auth.rule_a
name: Rule A Duplicate
description: Second with same ID
severity: INFORMATIONAL
category: AUTH
rule_type: ATOMIC
conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE
"""
    rules = load_rules_from_yaml(yaml_docs)
    with pytest.raises(DuplicateRuleError) as exc_info:
        registry.register_many(rules)
    assert "Duplicate rule ID 'auth.rule_a'" in str(exc_info.value)
    assert registry.count() == 0  # Atomic: no partial commit


def test_registry_enabled_and_category_filtering():
    registry = RuleRegistry()
    yaml_docs = """
id: auth.enabled_rule
name: Enabled Auth Rule
description: Desc
severity: INFORMATIONAL
category: AUTH
rule_type: ATOMIC
enabled: true
conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_SUCCESS
---
id: auth.disabled_rule
name: Disabled Auth Rule
description: Desc
severity: INFORMATIONAL
category: AUTH
rule_type: ATOMIC
enabled: false
conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE
---
id: privilege.enabled_rule
name: Enabled Privilege Rule
description: Desc
severity: ALERT
category: PRIVILEGE
rule_type: ATOMIC
enabled: true
conditions:
  all:
    - field: event_type
      operator: equals
      value: SUDO_COMMAND
"""
    rules = load_rules_from_yaml(yaml_docs)
    registry.register_many(rules)
    assert registry.count() == 3

    enabled = registry.get_enabled_rules()
    assert len(enabled) == 2
    assert {r.id for r in enabled} == {"auth.enabled_rule", "privilege.enabled_rule"}

    auth_rules = registry.get_rules_by_category(RuleCategory.AUTH)
    assert len(auth_rules) == 2
    assert {r.id for r in auth_rules} == {"auth.enabled_rule", "auth.disabled_rule"}
