"""Safe YAML loader and parser for declarative detection rules."""

from pathlib import Path
from typing import Any, Dict, List, Union
import yaml
from pydantic import ValidationError

from logintel.detection.errors import RuleParseError, RuleValidationError
from logintel.detection.models import DetectionRule
from logintel.detection.validators import validate_rule


def load_rule_from_dict(data: Any, source_name: str = "<memory>") -> DetectionRule:
    """Validate and construct a DetectionRule from a Python dictionary."""
    if not isinstance(data, dict):
        raise RuleParseError(
            f"Failed to load rule from {source_name}",
            details="Root YAML document must be a mapping/dictionary",
        )

    rule_id = data.get("id") if isinstance(data.get("id"), str) else None

    try:
        rule = DetectionRule.model_validate(data)
    except ValidationError as e:
        # Extract first actionable error message from Pydantic
        first_err = e.errors()[0]
        loc = ".".join(str(p) for p in first_err.get("loc", []))
        msg = first_err.get("msg", "Validation failed")
        clean_msg = f"{msg} (location: {loc})" if loc else msg
        raise RuleValidationError(rule_id=rule_id, message=clean_msg, field=loc)

    # Perform deep semantic validation
    validate_rule(rule)
    return rule


def load_rule_from_yaml(yaml_str: str, source_name: str = "<string>") -> DetectionRule:
    """Safely parse a single detection rule from a YAML string."""
    if not isinstance(yaml_str, str) or not yaml_str.strip():
        raise RuleParseError(f"Failed to load rule from {source_name}: YAML content is empty")

    try:
        parsed = yaml.safe_load(yaml_str)
    except yaml.YAMLError as e:
        raise RuleParseError(f"Malformed YAML in {source_name}", details=str(e))

    return load_rule_from_dict(parsed, source_name=source_name)


def load_rules_from_yaml(yaml_str: str, source_name: str = "<string>") -> List[DetectionRule]:
    """Safely parse one or more detection rules from a YAML string (single doc or list)."""
    if not isinstance(yaml_str, str) or not yaml_str.strip():
        raise RuleParseError(f"Failed to load rules from {source_name}: YAML content is empty")

    try:
        # Support multi-document or single document
        docs = list(yaml.safe_load_all(yaml_str))
    except yaml.YAMLError as e:
        raise RuleParseError(f"Malformed YAML in {source_name}", details=str(e))

    rules: List[DetectionRule] = []
    for idx, doc in enumerate(docs):
        if doc is None:
            continue
        if isinstance(doc, list):
            for item_idx, item in enumerate(doc):
                rules.append(load_rule_from_dict(item, source_name=f"{source_name}[doc {idx}, item {item_idx}]"))
        elif isinstance(doc, dict):
            rules.append(load_rule_from_dict(doc, source_name=f"{source_name}[doc {idx}]"))
        else:
            raise RuleParseError(
                f"Failed to load rules from {source_name}",
                details=f"Document {idx} must be a dictionary or list of dictionaries, got '{type(doc).__name__}'",
            )

    return rules


def load_rule_from_file(path: Union[str, Path]) -> DetectionRule:
    """Load and validate a single rule from a file path."""
    p = Path(path)
    if not p.exists() or not p.is_file():
        raise RuleParseError(f"Rule file does not exist: {p}")

    try:
        content = p.read_text(encoding="utf-8")
    except Exception as e:
        raise RuleParseError(f"Could not read rule file '{p}'", details=str(e))

    return load_rule_from_yaml(content, source_name=str(p))


def load_rules_from_dir(dir_path: Union[str, Path], recursive: bool = True) -> List[DetectionRule]:
    """Load and validate all .yml and .yaml rule files within a directory."""
    d = Path(dir_path)
    if not d.exists() or not d.is_dir():
        raise RuleParseError(f"Rule directory does not exist: {d}")

    pattern = "**/*.y*ml" if recursive else "*.y*ml"
    files = sorted(d.glob(pattern))

    rules: List[DetectionRule] = []
    for f in files:
        if f.is_file():
            rules.append(load_rule_from_file(f))

    return rules


def load_default_rules() -> List[DetectionRule]:
    """Load all canonical detection rules from the configured rules directory."""
    from logintel.config import settings
    rules_dir = settings.rules_dir
    if rules_dir.exists() and rules_dir.is_dir():
        return load_rules_from_dir(rules_dir, recursive=True)
    return []
