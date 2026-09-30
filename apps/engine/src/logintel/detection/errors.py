"""Detection rule error definitions."""

from typing import Optional, List


class DetectionError(Exception):
    """Base exception for all detection-related errors."""
    pass


class RuleParseError(DetectionError):
    """Raised when rule YAML cannot be parsed."""
    def __init__(self, message: str, details: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.details = details

    def __str__(self) -> str:
        if self.details:
            return f"{self.message}: {self.details}"
        return self.message


class RuleValidationError(DetectionError):
    """Raised when a detection rule fails schema or semantic validation."""
    def __init__(self, rule_id: Optional[str], message: str, field: Optional[str] = None):
        prefix = f"Rule '{rule_id}': " if rule_id else "Rule validation error: "
        field_info = f" (field: {field})" if field else ""
        full_message = f"{prefix}{message}{field_info}"
        super().__init__(full_message)
        self.rule_id = rule_id
        self.raw_message = message
        self.field = field


class DuplicateRuleError(DetectionError):
    """Raised when attempting to register a rule with an ID that already exists."""
    def __init__(self, rule_id: str):
        message = f"Duplicate rule ID '{rule_id}' already registered in rule registry"
        super().__init__(message)
        self.rule_id = rule_id


class UnknownFieldError(RuleValidationError):
    """Raised when a condition or group_by references an unknown canonical event field."""
    def __init__(self, rule_id: Optional[str], field: str, suggestion: Optional[str] = None):
        msg = f"Field '{field}' is not a valid canonical event field."
        if suggestion:
            msg += f" Did you mean '{suggestion}'?"
        super().__init__(rule_id=rule_id, message=msg, field=field)
        self.unknown_field = field
        self.suggestion = suggestion
