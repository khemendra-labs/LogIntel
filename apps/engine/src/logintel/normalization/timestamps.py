"""Robust timestamp parsing for Linux telemetry formats."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional, Tuple

MONTH_MAP = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

# RFC 5424 ISO-8601 pattern: 2026-09-29T15:55:01.956604+05:30
ISO_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)

# RFC 3164 pattern: Sep 29 16:05:01 or Sep  9 16:05:01
RFC3164_PATTERN = re.compile(
    r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})"
)


def parse_syslog_header(line: str) -> Tuple[datetime, Optional[str], Optional[str], Optional[int], str]:
    """Parse common syslog prefixes.

    Returns:
        (timestamp, hostname, process_name, pid, remaining_message)
    """
    now = datetime.now(timezone.utc)
    ts = now
    host = None
    proc = None
    pid = None
    remainder = line.strip()

    # 1. Try ISO timestamp
    iso_match = ISO_PATTERN.match(remainder)
    if iso_match:
        ts_str = iso_match.group(1).replace(" ", "T")
        try:
            ts = datetime.fromisoformat(ts_str)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except ValueError:
            ts = now
        remainder = remainder[iso_match.end():].strip()
    else:
        # 2. Try RFC 3164 timestamp
        rfc_match = RFC3164_PATTERN.match(remainder)
        if rfc_match:
            mon_str, day_str, time_str = rfc_match.groups()
            month = MONTH_MAP.get(mon_str.lower(), now.month)
            day = int(day_str)
            hour, minute, second = [int(p) for p in time_str.split(":")]
            try:
                # If parsed month is ahead of current month by a lot, it might be last year
                year = now.year
                if month > now.month + 1:
                    year -= 1
                ts = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
            except ValueError:
                ts = now
            remainder = remainder[rfc_match.end():].strip()

    # 3. Extract hostname and process[pid]: if present
    # Example: "server01 CRON[5273]: pam_unix..."
    # or "server01 sudo: alice..."
    tokens = remainder.split(None, 2)
    if len(tokens) >= 2 and (":" in tokens[1] or tokens[1].endswith(":")):
        host = tokens[0]
        proc_token = tokens[1].rstrip(":")
        remainder = tokens[2] if len(tokens) > 2 else ""

        # Extract process and PID: e.g. CRON[5273] or sudo
        proc_match = re.match(r"^([^\[]+)(?:\[(\d+)\])?$", proc_token)
        if proc_match:
            proc = proc_match.group(1)
            pid = int(proc_match.group(2)) if proc_match.group(2) else None
        else:
            proc = proc_token
    elif len(tokens) >= 1 and (":" in tokens[0] or tokens[0].endswith(":")):
        proc_token = tokens[0].rstrip(":")
        remainder = remainder[len(tokens[0]):].strip()
        proc_match = re.match(r"^([^\[]+)(?:\[(\d+)\])?$", proc_token)
        if proc_match:
            proc = proc_match.group(1)
            pid = int(proc_match.group(2)) if proc_match.group(2) else None
        else:
            proc = proc_token

    return ts, host, proc, pid, remainder
