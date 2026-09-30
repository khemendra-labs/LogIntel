"""Canonical field extraction and condition predicate evaluation."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from logintel.models import CanonicalEvent
from logintel.detection.fields import normalize_field_name
from logintel.detection.models import Condition, ConditionsBlock, Operator


# Cache for compiled regexes to eliminate recompilation overhead
_REGEX_CACHE: Dict[str, re.Pattern] = {}


def extract_field_value(event: CanonicalEvent, field_name: str) -> Any:
    """Extract the normalized value of a canonical event field."""
    norm = normalize_field_name(field_name)

    # 1. Nested metadata access: metadata.<key>
    if norm.startswith("metadata."):
        key = norm[len("metadata."):]
        if not isinstance(event.metadata, dict):
            return None
        return event.metadata.get(key)

    # 2. Top-level and grouped canonical fields
    if norm == "event_type":
        return event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type)
    elif norm == "severity":
        return event.severity.value if hasattr(event.severity, "value") else str(event.severity)
    elif norm == "outcome":
        return event.outcome.value if hasattr(event.outcome, "value") else str(event.outcome)
    elif norm == "action":
        return event.action
    elif norm == "host":
        return event.host
    elif norm == "source":
        return event.source
    elif norm == "username":
        return event.actor.username if event.actor else None
    elif norm == "uid":
        return event.actor.uid if event.actor else None
    elif norm == "session_id":
        return event.actor.session_id if event.actor else None
    elif norm == "terminal":
        return event.actor.terminal if event.actor else None
    elif norm == "process_name":
        return event.process.name if event.process else None
    elif norm == "process_pid":
        return event.process.pid if event.process else None
    elif norm == "process_ppid":
        return event.process.ppid if event.process else None
    elif norm == "process_executable":
        return event.process.executable if event.process else None
    elif norm == "process_command_line":
        return event.process.command_line if event.process else None
    elif norm == "src_ip":
        return event.network.src_ip if event.network else None
    elif norm == "src_port":
        return event.network.src_port if event.network else None
    elif norm == "dst_ip":
        return event.network.dst_ip if event.network else None
    elif norm == "dst_port":
        return event.network.dst_port if event.network else None
    elif norm == "protocol":
        return event.network.protocol if event.network else None
    elif norm == "summary":
        return event.summary
    elif norm == "raw_message":
        return event.raw_message
    elif norm == "parser":
        return event.parser
    elif norm == "source_file":
        return event.source_file
    elif norm == "source_offset":
        return event.source_offset
    elif norm == "iocs":
        return event.iocs
    elif norm == "metadata":
        return event.metadata

    return None


def evaluate_condition(condition: Condition, event: CanonicalEvent) -> bool:
    """Evaluate a single atomic condition against a canonical event."""
    extracted = extract_field_value(event, condition.field)
    op = condition.operator
    target_val = condition.value

    # 1. EXISTS
    if op == Operator.EXISTS:
        is_meaningful = (
            extracted is not None
            and extracted != ""
            and extracted != []
            and extracted != {}
        )
        if target_val is False:
            return not is_meaningful
        return is_meaningful

    # If extracted is None and operator is not EXISTS, condition fails
    if extracted is None:
        return False

    # 2. EQUALS
    if op == Operator.EQUALS:
        if isinstance(extracted, str) and not isinstance(target_val, str):
            return extracted == str(target_val)
        return extracted == target_val

    # 3. NOT_EQUALS
    elif op == Operator.NOT_EQUALS:
        if isinstance(extracted, str) and not isinstance(target_val, str):
            return extracted != str(target_val)
        return extracted != target_val

    # 4. IN
    elif op == Operator.IN:
        if not isinstance(target_val, (list, tuple, set)):
            return False
        if isinstance(extracted, list):
            # If extracted is a list (like iocs), check intersection
            target_set = set(target_val)
            return any(item in target_set for item in extracted)
        return extracted in target_val

    # 5. NOT_IN
    elif op == Operator.NOT_IN:
        if not isinstance(target_val, (list, tuple, set)):
            return True
        if isinstance(extracted, list):
            target_set = set(target_val)
            return not any(item in target_set for item in extracted)
        return extracted not in target_val

    # 6. STARTS_WITH
    elif op == Operator.STARTS_WITH:
        if not isinstance(extracted, str) or not isinstance(target_val, str):
            return False
        return extracted.startswith(target_val)

    # 7. ENDS_WITH
    elif op == Operator.ENDS_WITH:
        if not isinstance(extracted, str) or not isinstance(target_val, str):
            return False
        return extracted.endswith(target_val)

    # 8. CONTAINS
    elif op == Operator.CONTAINS:
        if isinstance(extracted, str):
            return str(target_val) in extracted
        elif isinstance(extracted, (list, tuple)):
            return target_val in extracted
        return False

    # 9. REGEX
    elif op == Operator.REGEX:
        if not isinstance(extracted, str) or not isinstance(target_val, str):
            return False
        # Bound target string search window to max 65536 characters (64KB max syslog frame) to mitigate ReDoS
        search_target = extracted[:65536] if len(extracted) > 65536 else extracted
        pattern = _REGEX_CACHE.get(target_val)
        if pattern is None:
            try:
                pattern = re.compile(target_val)
                _REGEX_CACHE[target_val] = pattern
            except re.error:
                return False
        try:
            return bool(pattern.search(search_target))
        except Exception:
            return False

    return False


def evaluate_conditions_block(conditions: ConditionsBlock, event: CanonicalEvent) -> bool:
    """Evaluate a ConditionsBlock (conjunction and/or disjunction) against an event."""
    # 1. Conjunction (all): all conditions must match
    if conditions.all:
        for cond in conditions.all:
            if not evaluate_condition(cond, event):
                return False

    # 2. Disjunction (any): at least one condition must match
    if conditions.any:
        any_matched = False
        for cond in conditions.any:
            if evaluate_condition(cond, event):
                any_matched = True
                break
        if not any_matched:
            return False

    return True
