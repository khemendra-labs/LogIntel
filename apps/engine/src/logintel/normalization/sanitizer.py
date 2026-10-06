"""Sanitization, validation, and IOC extraction utilities for potentially hostile telemetry."""

from __future__ import annotations

import ipaddress
import re
from typing import List, Optional, Set

# Regex to detect ANSI escape sequences
ANSI_ESCAPE_PATTERN = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

# Regex to detect IPv4 addresses
IPV4_PATTERN = re.compile(
    r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

# Regex to detect valid IPv6 addresses
IPV6_PATTERN = re.compile(
    r"(?<![a-zA-Z0-9:])((?:[0-9a-fA-F]{1,4}:){1,7}(?:[0-9a-fA-F]{1,4}|:)|::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:)+(?::[0-9a-fA-F]{1,4})+|::1)(?![a-zA-Z0-9:])"
)

# Maximum allowed raw message length to prevent memory exhaustion / DoS
MAX_RAW_MESSAGE_LENGTH = 16384


def sanitize_message(text: str, max_length: int = MAX_RAW_MESSAGE_LENGTH) -> str:
    """Strip ANSI control characters, null bytes, and truncate excessive lengths."""
    if not text:
        return ""
    # Strip null bytes and control chars (preserve standard tabs/newlines)
    text = text.replace("\x00", "")
    # Remove terminal escape codes
    text = ANSI_ESCAPE_PATTERN.sub("", text)
    # Truncate if message exceeds maximum length
    if len(text) > max_length:
        text = text[:max_length] + " [TRUNCATED_EXCESSIVE_LENGTH]"
    return text.strip()


def validate_ip(ip_str: Optional[str]) -> Optional[str]:
    """Validate that a string is a legitimate IPv4 or IPv6 address. Return None if invalid."""
    if not ip_str:
        return None
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return str(ip)
    except ValueError:
        return None


def extract_iocs(text: str) -> List[str]:
    """Extract notable network and file indicators from a telemetry text snippet."""
    iocs: Set[str] = set()
    if not text:
        return []

    # Extract valid IPv4
    for match in IPV4_PATTERN.finditer(text):
        candidate = match.group(0)
        if validate_ip(candidate):
            iocs.add(candidate)

    # Extract valid IPv6
    for match in IPV6_PATTERN.finditer(text):
        candidate = match.group(0)
        valid = validate_ip(candidate)
        if valid and ":" in valid:
            iocs.add(valid)

    return sorted(list(iocs))


# Regex patterns for deterministic credential and secret masking
CREDENTIAL_KEY_VALUE_PATTERN = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[-_]?key|auth[-_]?token|access[-_]?token)\s*([=:])\s*([^\s'\"]+|'[^']*'|\"[^\"]*\")"
)
FLAG_CREDENTIAL_PATTERN = re.compile(
    r"(?i)(--(?:password|passwd|secret|token|api[-_]?key|auth[-_]?token|access[-_]?token))\s+([^\s'\"]+|'[^']*'|\"[^\"]*\")"
)
BEARER_TOKEN_PATTERN = re.compile(
    r"(?i)\b(bearer|basic)\s+([A-Za-z0-9_\-\.\+/=]{8,})"
)
SHORT_P_FLAG_PATTERN = re.compile(
    r"(?i)(\s-p\s*)([a-zA-Z!@#$%^&*()_+=\[\]{};:<>?~][^\s'\"]*|'[^']*'|\"[^\"]*\")"
)
CURL_U_FLAG_PATTERN = re.compile(
    r"(?i)(\s-u\s*)([^\s:]+):([^\s'\"]+|'[^']*'|\"[^\"]*\")"
)


def mask_credentials(cmd: str) -> str:
    """Deterministically mask credentials, passwords, and tokens in process command lines.

    Preserves raw command structure while concealing secret values.
    Avoids false positives such as port flags (-p 80, -p 443) or directory paths (mkdir -p /path).
    """
    if not cmd:
        return ""
    # Check if command is mkdir -p
    is_mkdir = bool(re.search(r"\bmkdir\b", cmd, re.IGNORECASE))

    # Mask key=value and key:value
    res = CREDENTIAL_KEY_VALUE_PATTERN.sub(r"\1\2[MASKED]", cmd)
    # Mask flag value
    res = FLAG_CREDENTIAL_PATTERN.sub(r"\1 [MASKED]", res)
    # Mask bearer / basic tokens
    res = BEARER_TOKEN_PATTERN.sub(r"\1 [MASKED]", res)
    # Mask -u user:pass
    res = CURL_U_FLAG_PATTERN.sub(r"\1\2:[MASKED]", res)
    # Mask -p <password> when not a directory flag or numeric port
    if not is_mkdir:
        res = SHORT_P_FLAG_PATTERN.sub(r"\1[MASKED]", res)
    return res

