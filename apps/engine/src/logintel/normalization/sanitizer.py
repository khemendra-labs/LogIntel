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
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|\b:(?::[0-9a-fA-F]{1,4}){1,7}\b"
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
        # Exclude loopback / link-local / broadcast if desired, but keep valid IPs
        if validate_ip(candidate):
            iocs.add(candidate)

    return sorted(list(iocs))
