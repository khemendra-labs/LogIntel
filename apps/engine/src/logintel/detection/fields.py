"""Canonical event field registry and validation for detection rules."""

import difflib
import re
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from logintel.models.events import EventType, Outcome, Severity


class FieldType(str, Enum):
    STRING = "STRING"
    INTEGER = "INTEGER"
    ENUM_EVENT_TYPE = "ENUM_EVENT_TYPE"
    ENUM_SEVERITY = "ENUM_SEVERITY"
    ENUM_OUTCOME = "ENUM_OUTCOME"
    LIST_STRING = "LIST_STRING"
    METADATA_VALUE = "METADATA_VALUE"


# Canonical top-level fields permitted in condition checks and grouping
CANONICAL_FIELDS: Dict[str, FieldType] = {
    "event_type": FieldType.ENUM_EVENT_TYPE,
    "severity": FieldType.ENUM_SEVERITY,
    "outcome": FieldType.ENUM_OUTCOME,
    "action": FieldType.STRING,
    "host": FieldType.STRING,
    "source": FieldType.STRING,
    "username": FieldType.STRING,
    "uid": FieldType.INTEGER,
    "session_id": FieldType.STRING,
    "terminal": FieldType.STRING,
    "process_name": FieldType.STRING,
    "process_pid": FieldType.INTEGER,
    "process_ppid": FieldType.INTEGER,
    "process_executable": FieldType.STRING,
    "process_command_line": FieldType.STRING,
    "src_ip": FieldType.STRING,
    "src_port": FieldType.INTEGER,
    "dst_ip": FieldType.STRING,
    "dst_port": FieldType.INTEGER,
    "protocol": FieldType.STRING,
    "summary": FieldType.STRING,
    "raw_message": FieldType.STRING,
    "parser": FieldType.STRING,
    "source_file": FieldType.STRING,
    "source_offset": FieldType.STRING,
    "iocs": FieldType.LIST_STRING,
}

# Standard aliases mapped to canonical names for author convenience
FIELD_ALIASES: Dict[str, str] = {
    "source_ip": "src_ip",
    "dest_ip": "dst_ip",
    "destination_ip": "dst_ip",
    "source_port": "src_port",
    "dest_port": "dst_port",
    "destination_port": "dst_port",
    "user": "username",
    "command": "process_command_line",
    "cmdline": "process_command_line",
    "executable": "process_executable",
    "pid": "process_pid",
    "ppid": "process_ppid",
    # Nested model aliases
    "actor.username": "username",
    "actor.uid": "uid",
    "actor.session_id": "session_id",
    "actor.terminal": "terminal",
    "process.name": "process_name",
    "process.pid": "process_pid",
    "process.ppid": "process_ppid",
    "process.executable": "process_executable",
    "process.command_line": "process_command_line",
    "network.src_ip": "src_ip",
    "network.src_port": "src_port",
    "network.dst_ip": "dst_ip",
    "network.dst_port": "dst_port",
    "network.protocol": "protocol",
}

# Strict pattern for safe nested metadata keys: alphanumeric and underscore only, 1-64 chars
SAFE_METADATA_KEY_REGEX = re.compile(r"^[a-zA-Z0-9_]{1,64}$")

# Dangerous attributes explicitly forbidden to prevent attribute injection
FORBIDDEN_ATTRIBUTES = {
    "__class__",
    "__dict__",
    "__doc__",
    "__globals__",
    "__init__",
    "__subclasses__",
    "globals",
    "locals",
    "mro",
    "eval",
    "exec",
    "import",
}


def normalize_field_name(field: str) -> str:
    """Normalize a field name using registered aliases.
    
    Returns the canonical field name if an alias exists, or the original string.
    """
    field_lower = field.strip()
    return FIELD_ALIASES.get(field_lower, field_lower)


def validate_field_name(field: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """Validate whether a field is a legitimate canonical event field.
    
    Returns:
        (is_valid, normalized_field_or_error, suggestion_if_invalid)
    """
    if not field or not isinstance(field, str):
        return False, "Field name must be a non-empty string", None

    norm = normalize_field_name(field)

    # 1. Direct canonical field check
    if norm in CANONICAL_FIELDS:
        return True, norm, None

    # 2. Nested metadata field check: metadata.<key>
    if norm.startswith("metadata."):
        sub_key = norm[len("metadata."):]
        if not sub_key:
            return False, "Nested metadata field must specify a key (e.g., 'metadata.target_user')", None
        if sub_key in FORBIDDEN_ATTRIBUTES or sub_key.startswith("__"):
            return False, f"Forbidden attribute access in nested field '{field}'", None
        if not SAFE_METADATA_KEY_REGEX.match(sub_key):
            return (
                False,
                f"Nested metadata key '{sub_key}' contains invalid characters. Must be 1-64 alphanumeric/underscore characters.",
                None,
            )
        return True, norm, None

    # 3. Check for invalid nested traversal (reject arbitrary object traversal)
    if "." in norm:
        prefix = norm.split(".")[0]
        if prefix in ("actor", "process", "network"):
            # Aliases didn't catch it, invalid subfield
            possibilities = [k for k in FIELD_ALIASES.keys() if k.startswith(f"{prefix}.")]
            matches = difflib.get_close_matches(norm, possibilities, n=1, cutoff=0.6)
            suggestion = matches[0] if matches else None
            return False, f"Unknown subfield in '{field}'.", suggestion
        else:
            return False, f"Arbitrary nested field path '{field}' is forbidden.", None

    # 4. Unknown field - provide close match suggestion
    all_known = list(CANONICAL_FIELDS.keys()) + list(FIELD_ALIASES.keys())
    matches = difflib.get_close_matches(field, all_known, n=1, cutoff=0.5)
    suggestion = matches[0] if matches else None
    return False, f"Unknown event field '{field}'.", suggestion


def get_field_type(normalized_field: str) -> FieldType:
    """Retrieve the expected type for a normalized field."""
    if normalized_field.startswith("metadata."):
        return FieldType.METADATA_VALUE
    return CANONICAL_FIELDS.get(normalized_field, FieldType.STRING)
