"""Domain models and schemas for declarative detection rules."""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from logintel.models.events import Severity
from logintel.detection.errors import RuleValidationError, UnknownFieldError
from logintel.detection.fields import (
    CANONICAL_FIELDS,
    get_field_type,
    normalize_field_name,
    validate_field_name,
)


class RuleCategory(str, Enum):
    """Closed enum of supported detection categories."""
    AUTH = "AUTH"
    PRIVILEGE = "PRIVILEGE"
    PROCESS = "PROCESS"
    NETWORK = "NETWORK"
    ACCOUNT = "ACCOUNT"
    SECURITY = "SECURITY"


class RuleType(str, Enum):
    """Execution type for a detection rule."""
    ATOMIC = "ATOMIC"
    THRESHOLD = "THRESHOLD"


class Operator(str, Enum):
    """Closed enum of condition operators."""
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    IN = "in"
    NOT_IN = "not_in"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    CONTAINS = "contains"
    REGEX = "regex"
    EXISTS = "exists"


# Strict Rule ID regex: e.g. auth.ssh_bruteforce or process.tmp_execution
# Must consist of at least two dot-separated segments of lowercase alphanumerics and underscores.
RULE_ID_PATTERN = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+)+$")
MAX_RULE_ID_LENGTH = 64
MIN_RULE_ID_LENGTH = 3

# Safety bounds
MAX_NAME_LENGTH = 128
MAX_DESCRIPTION_LENGTH = 1024
MAX_REGEX_LENGTH = 256
MAX_CONDITIONS_COUNT = 32
MAX_THRESHOLD_COUNT = 1_000_000
MAX_WINDOW_SECONDS = 86_400  # 24 hours
MAX_COOLDOWN_SECONDS = 604_800  # 7 days


class Condition(BaseModel):
    """Atomic condition predicate evaluating a single event field."""
    model_config = ConfigDict(extra="forbid")

    field: str
    operator: Operator
    value: Optional[Any] = None

    @field_validator("field")
    @classmethod
    def validate_field(cls, v: str) -> str:
        is_valid, normalized_or_err, suggestion = validate_field_name(v)
        if not is_valid:
            if suggestion:
                raise UnknownFieldError(rule_id=None, field=v, suggestion=suggestion)
            raise RuleValidationError(rule_id=None, message=normalized_or_err or f"Invalid field '{v}'", field=v)
        return normalized_or_err


class ConditionsBlock(BaseModel):
    """Structured condition tree supporting conjunction (all) and disjunction (any)."""
    model_config = ConfigDict(extra="forbid")

    all: Optional[List[Condition]] = None
    any: Optional[List[Condition]] = None

    @model_validator(mode="after")
    def validate_has_conditions(self) -> ConditionsBlock:
        all_conds = (self.all or []) + (self.any or [])
        if not all_conds:
            raise RuleValidationError(
                rule_id=None,
                message="Rule 'conditions' must define at least one condition under 'all' or 'any'",
            )
        if len(all_conds) > MAX_CONDITIONS_COUNT:
            raise RuleValidationError(
                rule_id=None,
                message=f"Rule exceeds maximum allowed condition count ({MAX_CONDITIONS_COUNT})",
            )
        return self


class ThresholdConfig(BaseModel):
    """Configuration for threshold-based sliding window rules."""
    model_config = ConfigDict(extra="forbid")

    count: int = Field(gt=0, le=MAX_THRESHOLD_COUNT)
    window_seconds: int = Field(gt=0, le=MAX_WINDOW_SECONDS)


class DetectionRule(BaseModel):
    """Complete declarative domain model for a LogIntel detection rule."""
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    description: str
    severity: Severity
    category: RuleCategory
    rule_type: RuleType
    enabled: bool = True
    conditions: ConditionsBlock
    threshold: Optional[ThresholdConfig] = None
    group_by: Optional[List[str]] = None
    cooldown_seconds: Optional[int] = None

    @field_validator("id")
    @classmethod
    def validate_rule_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise RuleValidationError(rule_id=v, message="Rule ID must not be empty or whitespace")
        if len(v) < MIN_RULE_ID_LENGTH or len(v) > MAX_RULE_ID_LENGTH:
            raise RuleValidationError(
                rule_id=v,
                message=f"Rule ID length ({len(v)}) must be between {MIN_RULE_ID_LENGTH} and {MAX_RULE_ID_LENGTH} characters",
            )
        if "/" in v or "\\" in v or ".." in v:
            raise RuleValidationError(
                rule_id=v,
                message="Rule ID contains forbidden path traversal characters ('/', '\\', '..')",
            )
        if not RULE_ID_PATTERN.match(v):
            raise RuleValidationError(
                rule_id=v,
                message=(
                    f"Rule ID '{v}' must match format 'category.rule_name' with lowercase alphanumerics "
                    "and underscores (e.g. 'auth.ssh_bruteforce')"
                ),
            )
        return v

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        stripped = v.strip() if isinstance(v, str) else ""
        if not stripped:
            raise RuleValidationError(rule_id=None, message="Rule 'name' must be a non-empty string")
        if len(stripped) > MAX_NAME_LENGTH:
            raise RuleValidationError(
                rule_id=None,
                message=f"Rule 'name' exceeds maximum length of {MAX_NAME_LENGTH} characters",
            )
        return stripped

    @field_validator("description")
    @classmethod
    def validate_description(cls, v: str) -> str:
        stripped = v.strip() if isinstance(v, str) else ""
        if not stripped:
            raise RuleValidationError(rule_id=None, message="Rule 'description' must be a non-empty string")
        if len(stripped) > MAX_DESCRIPTION_LENGTH:
            raise RuleValidationError(
                rule_id=None,
                message=f"Rule 'description' exceeds maximum length of {MAX_DESCRIPTION_LENGTH} characters",
            )
        return stripped

    @field_validator("cooldown_seconds")
    @classmethod
    def validate_cooldown(cls, v: Optional[int]) -> Optional[int]:
        if v is not None:
            if v <= 0 or v > MAX_COOLDOWN_SECONDS:
                raise RuleValidationError(
                    rule_id=None,
                    message=f"Rule 'cooldown_seconds' must be between 1 and {MAX_COOLDOWN_SECONDS} seconds",
                )
        return v

    @field_validator("group_by")
    @classmethod
    def validate_group_by(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is not None:
            normalized_list: List[str] = []
            for field in v:
                is_valid, norm_or_err, suggestion = validate_field_name(field)
                if not is_valid:
                    if suggestion:
                        raise UnknownFieldError(rule_id=None, field=field, suggestion=suggestion)
                    raise RuleValidationError(
                        rule_id=None,
                        message=f"group_by field '{field}' is not a valid canonical event field",
                        field=field,
                    )
                normalized_list.append(norm_or_err)
            return normalized_list
        return None

    @model_validator(mode="after")
    def validate_rule_type_consistency(self) -> DetectionRule:
        rule_id = self.id

        if self.rule_type == RuleType.ATOMIC:
            if self.threshold is not None:
                raise RuleValidationError(
                    rule_id=rule_id,
                    message="Rule type is ATOMIC but 'threshold' was provided. Threshold is only permitted for THRESHOLD rules.",
                )
            if self.group_by:
                raise RuleValidationError(
                    rule_id=rule_id,
                    message="Rule type is ATOMIC but 'group_by' was provided. Grouping is only permitted for THRESHOLD rules.",
                )

        elif self.rule_type == RuleType.THRESHOLD:
            if self.threshold is None:
                raise RuleValidationError(
                    rule_id=rule_id,
                    message="Rule type is THRESHOLD but 'threshold' configuration (count, window_seconds) is missing.",
                )
            if not self.group_by:
                raise RuleValidationError(
                    rule_id=rule_id,
                    message="Rule type is THRESHOLD but 'group_by' is missing or empty. Threshold rules require at least one grouping field.",
                )

        return self
