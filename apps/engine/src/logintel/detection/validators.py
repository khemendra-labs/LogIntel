"""Semantic and security validators for detection rules and condition predicates."""

import re
from typing import Any, List, Optional

from logintel.models.events import EventType, Outcome, Severity
from logintel.detection.errors import RuleValidationError
from logintel.detection.fields import FieldType, get_field_type
from logintel.detection.models import (
    Condition,
    DetectionRule,
    MAX_REGEX_LENGTH,
    Operator,
)

# Pre-computed lookup sets for fast enum validation
VALID_EVENT_TYPES = {e.value for e in EventType}
VALID_SEVERITIES = {s.value for s in Severity}
VALID_OUTCOMES = {o.value for o in Outcome}

# Detect dangerous nested quantifiers: (group containing +, *, or {n,m}) followed by +, *, or {n,m}
DANGEROUS_NESTED_QUANTIFIERS = re.compile(r"\([^)]*[\+\*\{][^)]*\)[\+\*\{]")


def validate_condition_semantics(condition: Condition, rule_id: Optional[str] = None) -> None:
    """Validate that condition operator and value match the canonical field type."""
    field = condition.field
    op = condition.operator
    val = condition.value
    f_type = get_field_type(field)

    # 1. EXISTS operator: value should be None or bool
    if op == Operator.EXISTS:
        if val is not None and not isinstance(val, bool):
            raise RuleValidationError(
                rule_id=rule_id,
                message=f"Operator 'exists' for field '{field}' expects boolean (true/false) or no value, got '{type(val).__name__}'",
                field=field,
            )
        return

    # All other operators require a non-None value
    if val is None:
        raise RuleValidationError(
            rule_id=rule_id,
            message=f"Operator '{op.value}' requires a non-null 'value'",
            field=field,
        )

    # 2. IN / NOT_IN operator: value must be a non-empty list of literals
    if op in (Operator.IN, Operator.NOT_IN):
        if not isinstance(val, (list, tuple)) or len(val) == 0:
            raise RuleValidationError(
                rule_id=rule_id,
                message=f"Operator '{op.value}' for field '{field}' expects a non-empty list of values",
                field=field,
            )
        if len(val) > 100:
            raise RuleValidationError(
                rule_id=rule_id,
                message=f"Operator '{op.value}' for field '{field}' exceeds maximum list size of 100 elements",
                field=field,
            )
        for item in val:
            _validate_scalar_for_field(field, f_type, item, rule_id=rule_id)
        return

    # 3. REGEX operator: string value, bounded length, valid compilation, no nested quantifiers
    if op == Operator.REGEX:
        if not isinstance(val, str):
            raise RuleValidationError(
                rule_id=rule_id,
                message=f"Operator 'regex' for field '{field}' requires a string pattern",
                field=field,
            )
        if len(val) > MAX_REGEX_LENGTH:
            raise RuleValidationError(
                rule_id=rule_id,
                message=f"Regex pattern for field '{field}' exceeds maximum length of {MAX_REGEX_LENGTH} characters",
                field=field,
            )
        if DANGEROUS_NESTED_QUANTIFIERS.search(val):
            raise RuleValidationError(
                rule_id=rule_id,
                message=f"Potentially pathological regex pattern '{val}' for field '{field}': nested quantifiers detected",
                field=field,
            )
        try:
            re.compile(val)
        except re.error as e:
            raise RuleValidationError(
                rule_id=rule_id,
                message=f"Malformed regex pattern '{val}' for field '{field}': {e}",
                field=field,
            )
        return

    # 4. String-specific operators: starts_with, ends_with, contains
    if op in (Operator.STARTS_WITH, Operator.ENDS_WITH, Operator.CONTAINS):
        if not isinstance(val, str):
            raise RuleValidationError(
                rule_id=rule_id,
                message=f"Operator '{op.value}' for field '{field}' requires a string value",
                field=field,
            )
        return

    # 5. EQUALS / NOT_EQUALS
    if op in (Operator.EQUALS, Operator.NOT_EQUALS):
        _validate_scalar_for_field(field, f_type, val, rule_id=rule_id)


def _validate_scalar_for_field(field: str, field_type: FieldType, val: Any, rule_id: Optional[str]) -> None:
    """Validate that a single scalar value conforms to field specifications."""
    if field_type == FieldType.ENUM_EVENT_TYPE:
        str_val = str(val)
        if str_val not in VALID_EVENT_TYPES:
            raise RuleValidationError(
                rule_id=rule_id,
                message=f"Invalid event_type '{val}'. Must be one of known EventType values (e.g. AUTH_LOGIN_FAILURE, SUDO_COMMAND)",
                field=field,
            )

    elif field_type == FieldType.ENUM_SEVERITY:
        str_val = str(val)
        if str_val not in VALID_SEVERITIES:
            raise RuleValidationError(
                rule_id=rule_id,
                message=f"Invalid severity '{val}'. Must be one of: {', '.join(sorted(VALID_SEVERITIES))}",
                field=field,
            )

    elif field_type == FieldType.ENUM_OUTCOME:
        str_val = str(val)
        if str_val not in VALID_OUTCOMES:
            raise RuleValidationError(
                rule_id=rule_id,
                message=f"Invalid outcome '{val}'. Must be one of: {', '.join(sorted(VALID_OUTCOMES))}",
                field=field,
            )

    elif field_type == FieldType.INTEGER:
        if not isinstance(val, int) or isinstance(val, bool):
            raise RuleValidationError(
                rule_id=rule_id,
                message=f"Field '{field}' expects an integer, got '{type(val).__name__}'",
                field=field,
            )
        if field in ("src_port", "dst_port"):
            if val < 0 or val > 65535:
                raise RuleValidationError(
                    rule_id=rule_id,
                    message=f"Port field '{field}' value {val} must be between 0 and 65535",
                    field=field,
                )
        elif field in ("uid", "process_pid", "process_ppid"):
            if val < 0:
                raise RuleValidationError(
                    rule_id=rule_id,
                    message=f"Identifier field '{field}' value {val} cannot be negative",
                    field=field,
                )


def validate_rule(rule: DetectionRule) -> None:
    """Run full semantic and security validation over an entire DetectionRule."""
    rule_id = rule.id

    # Validate condition tree
    if rule.conditions.all:
        for cond in rule.conditions.all:
            validate_condition_semantics(cond, rule_id=rule_id)

    if rule.conditions.any:
        for cond in rule.conditions.any:
            validate_condition_semantics(cond, rule_id=rule_id)
