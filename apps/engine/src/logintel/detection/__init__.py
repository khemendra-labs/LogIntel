"""LogIntel Detection Core - Rule Specification, Schema, and Registry."""

from logintel.detection.errors import (
    DetectionError,
    DuplicateRuleError,
    RuleParseError,
    RuleValidationError,
    UnknownFieldError,
)
from logintel.detection.fields import (
    CANONICAL_FIELDS,
    FIELD_ALIASES,
    FieldType,
    get_field_type,
    normalize_field_name,
    validate_field_name,
)
from logintel.detection.loader import (
    load_default_rules,
    load_rule_from_dict,
    load_rule_from_file,
    load_rule_from_yaml,
    load_rules_from_dir,
    load_rules_from_yaml,
)
from logintel.detection.models import (
    Condition,
    ConditionsBlock,
    DetectionRule,
    Operator,
    RuleCategory,
    RuleType,
    ThresholdConfig,
)
from logintel.detection.registry import RuleRegistry, get_rule_registry
from logintel.detection.engine import DetectionEngine, MAX_EVENTS_PER_WINDOW
from logintel.detection.matcher import (
    evaluate_condition,
    evaluate_conditions_block,
    extract_field_value,
)
from logintel.detection.results import DetectionResult, EvidenceItem, EvidenceRole
from logintel.detection.replay import HistoricalReplayHarness, ReplayConfig, ReplayReport

__all__ = [
    # Errors
    "DetectionError",
    "RuleParseError",
    "RuleValidationError",
    "DuplicateRuleError",
    "UnknownFieldError",
    # Models
    "DetectionRule",
    "RuleCategory",
    "RuleType",
    "Operator",
    "Condition",
    "ConditionsBlock",
    "ThresholdConfig",
    # Fields
    "FieldType",
    "CANONICAL_FIELDS",
    "FIELD_ALIASES",
    "validate_field_name",
    "normalize_field_name",
    "get_field_type",
    # Loader
    "load_default_rules",
    "load_rule_from_dict",
    "load_rule_from_yaml",
    "load_rules_from_yaml",
    "load_rule_from_file",
    "load_rules_from_dir",
    # Registry
    "RuleRegistry",
    "get_rule_registry",
    # Validators
    "validate_rule",
    "validate_condition_semantics",
    # Results & Evidence
    "DetectionResult",
    "EvidenceItem",
    "EvidenceRole",
    # Matcher
    "extract_field_value",
    "evaluate_condition",
    "evaluate_conditions_block",
    # Engine
    "DetectionEngine",
    "MAX_EVENTS_PER_WINDOW",
    # Replay
    "HistoricalReplayHarness",
    "ReplayConfig",
    "ReplayReport",
]
