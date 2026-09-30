"""Parser for OpenSSH daemon authentication events."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Optional
from logintel.models import (
    Actor,
    CanonicalEvent,
    EventType,
    Network,
    Outcome,
    Process,
    RawRecord,
    Severity,
)
from logintel.normalization.sanitizer import extract_iocs, sanitize_message, validate_ip
from logintel.normalization.timestamps import parse_syslog_header
from logintel.parsers.base import BaseParser

# Regex patterns for SSH authentication
FAILED_PWD_RE = re.compile(
    r"Failed password for (?:invalid user )?([^\s]+) from ([^\s]+) port (\d+) ssh2"
)
ACCEPTED_PWD_RE = re.compile(
    r"Accepted (?:password|publickey) for ([^\s]+) from ([^\s]+) port (\d+) ssh2"
)
INVALID_USER_RE = re.compile(
    r"Invalid user ([^\s]+) from ([^\s]+) port (\d+)"
)
PREAUTH_CLOSED_RE = re.compile(
    r"Connection closed by authenticating user ([^\s]+) ([^\s]+) port (\d+)"
)


class SSHAuthParser(BaseParser):
    """Parser for OpenSSH authentication success and failure events."""

    @property
    def name(self) -> str:
        return "openssh_auth"

    def can_parse(self, record: RawRecord) -> bool:
        content = record.raw_content
        return "sshd" in content or (
            record.raw_attributes.get("SYSLOG_IDENTIFIER") == "sshd"
            or record.raw_attributes.get("_COMM") == "sshd"
        )

    def parse(self, record: RawRecord) -> Optional[CanonicalEvent]:
        raw_clean = sanitize_message(record.raw_content)
        ts, host, proc, pid, body = parse_syslog_header(raw_clean)
        
        # Prioritize parsed log header timestamp
        final_ts = ts or record.timestamp or datetime.now(timezone.utc)
        final_host = record.host or host or "unknown"
        final_proc = proc or "sshd"
        final_pid = pid or (int(record.raw_attributes["_PID"]) if "_PID" in record.raw_attributes else None)

        event_type = EventType.SYSTEM_GENERIC
        severity = Severity.INFORMATIONAL
        outcome = Outcome.UNKNOWN
        user: Optional[str] = None
        src_ip: Optional[str] = None
        src_port: Optional[int] = None
        summary = ""

        # Match failed password
        m = FAILED_PWD_RE.search(body)
        if m:
            user = m.group(1)
            src_ip = validate_ip(m.group(2))
            src_port = int(m.group(3))
            event_type = EventType.AUTH_LOGIN_FAILURE
            severity = Severity.ALERT
            outcome = Outcome.FAILURE
            summary = f"SSH authentication failure for user '{user}' from {src_ip or m.group(2)}"

        # Match accepted password/key
        if not summary:
            m = ACCEPTED_PWD_RE.search(body)
            if m:
                user = m.group(1)
                src_ip = validate_ip(m.group(2))
                src_port = int(m.group(3))
                event_type = EventType.AUTH_LOGIN_SUCCESS
                severity = Severity.NOTICE
                outcome = Outcome.SUCCESS
                summary = f"SSH authentication success for user '{user}' from {src_ip or m.group(2)}"

        # Match invalid user
        if not summary:
            m = INVALID_USER_RE.search(body)
            if m:
                user = m.group(1)
                src_ip = validate_ip(m.group(2))
                src_port = int(m.group(3))
                event_type = EventType.AUTH_LOGIN_FAILURE
                severity = Severity.ALERT
                outcome = Outcome.FAILURE
                summary = f"SSH login attempt for invalid user '{user}' from {src_ip or m.group(2)}"

        # Match preauth close
        if not summary:
            m = PREAUTH_CLOSED_RE.search(body)
            if m:
                user = m.group(1)
                src_ip = validate_ip(m.group(2))
                src_port = int(m.group(3))
                event_type = EventType.AUTH_LOGIN_FAILURE
                severity = Severity.WARNING
                outcome = Outcome.FAILURE
                summary = f"SSH connection closed during authentication for '{user}' from {src_ip or m.group(2)}"

        if not summary:
            # General SSHD message
            summary = f"SSH daemon activity: {body[:100]}"
            severity = Severity.INFORMATIONAL
            outcome = Outcome.UNKNOWN

        iocs = extract_iocs(raw_clean)
        if src_ip and src_ip not in iocs:
            iocs.append(src_ip)

        return CanonicalEvent(
            timestamp=final_ts,
            host=final_host,
            source=record.source,
            event_type=event_type,
            severity=severity,
            actor=Actor(username=user),
            process=Process(
                name=final_proc,
                pid=final_pid,
                executable="/usr/sbin/sshd",
            ),
            network=Network(
                src_ip=src_ip,
                src_port=src_port,
                dst_port=22,
                protocol="tcp",
            ),
            action="ssh_authenticate",
            outcome=outcome,
            summary=summary,
            raw_message=raw_clean,
            iocs=iocs,
            parser=self.name,
            source_file=record.source_file,
            source_offset=record.source_offset,
            metadata={"protocol": "ssh2"},
        )
