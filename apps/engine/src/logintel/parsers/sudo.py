"""Parser for sudo privilege elevation events."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Optional
from logintel.models import (
    Actor,
    CanonicalEvent,
    EventType,
    Outcome,
    Process,
    RawRecord,
    Severity,
)
from logintel.normalization.sanitizer import extract_iocs, sanitize_message
from logintel.normalization.timestamps import parse_syslog_header
from logintel.parsers.base import BaseParser

# Regex for standard sudo command execution (allows spaces in PWD)
SUDO_EXEC_RE = re.compile(
    r"^([^\s:]+)\s*:\s*(?:(?:a password is required|pam_unix|session|authentication failure).*)?TTY=([^\s;]+)\s*;\s*PWD=(.+?)\s*;\s*USER=([^\s;]+)\s*;\s*COMMAND=(.+)$"
)

SUDO_FAIL_RE = re.compile(
    r"^([^\s:]+)\s*:\s*(\d+ incorrect password attempts|user NOT in sudoers|authentication failure)",
    re.IGNORECASE,
)


class SudoParser(BaseParser):
    """Parser for sudo execution, password failures, and privilege elevation."""

    @property
    def name(self) -> str:
        return "sudo_privilege"

    def can_parse(self, record: RawRecord) -> bool:
        content = record.raw_content
        return "sudo" in content or (
            record.raw_attributes.get("SYSLOG_IDENTIFIER") == "sudo"
            or record.raw_attributes.get("_COMM") == "sudo"
        )

    def parse(self, record: RawRecord) -> Optional[CanonicalEvent]:
        raw_clean = sanitize_message(record.raw_content)
        ts, host, proc, pid, body = parse_syslog_header(raw_clean)

        final_ts = ts or record.timestamp or datetime.now(timezone.utc)
        final_host = record.host or host or "unknown"
        final_proc = proc or "sudo"
        final_pid = pid or (int(record.raw_attributes["_PID"]) if "_PID" in record.raw_attributes else None)

        user: Optional[str] = None
        target_user: Optional[str] = "root"
        terminal: Optional[str] = None
        command: Optional[str] = None
        pwd: Optional[str] = None
        
        event_type = EventType.SUDO_COMMAND
        severity = Severity.NOTICE
        outcome = Outcome.SUCCESS
        summary = ""

        # Check for failure / not in sudoers
        m_fail = SUDO_FAIL_RE.search(body)
        if m_fail:
            user = m_fail.group(1).strip()
            reason = m_fail.group(2).strip()
            event_type = EventType.PRIVILEGE_ELEVATION_FAILURE
            severity = Severity.ALERT if "incorrect" in reason.lower() else Severity.CRITICAL
            outcome = Outcome.FAILURE
            summary = f"Sudo privilege elevation failure for user '{user}': {reason}"

        # Check for command execution
        m_exec = SUDO_EXEC_RE.search(body)
        if m_exec:
            user = m_exec.group(1).strip()
            terminal = m_exec.group(2).strip()
            pwd = m_exec.group(3).strip()
            target_user = m_exec.group(4).strip()
            command = m_exec.group(5).strip()
            
            if "password is required" in body:
                event_type = EventType.PRIVILEGE_ELEVATION_ATTEMPT
                severity = Severity.WARNING
                outcome = Outcome.ATTEMPT
                summary = f"Sudo authentication required for '{user}' to run '{command}' as '{target_user}'"
            elif outcome != Outcome.FAILURE:
                event_type = EventType.SUDO_COMMAND
                severity = Severity.NOTICE
                outcome = Outcome.SUCCESS
                summary = f"User '{user}' executed privileged command '{command}' as '{target_user}'"

        if not summary:
            # Fallback for other sudo events (e.g. pam_unix session or auth)
            if "authentication failure" in body:
                event_type = EventType.PRIVILEGE_ELEVATION_FAILURE
                severity = Severity.ALERT
                outcome = Outcome.FAILURE
                summary = f"Sudo authentication failure: {body[:100]}"
            else:
                summary = f"Sudo activity: {body[:100]}"
                severity = Severity.INFORMATIONAL
                outcome = Outcome.SUCCESS

        metadata = {}
        if target_user:
            metadata["target_user"] = target_user
        if pwd:
            metadata["working_directory"] = pwd

        return CanonicalEvent(
            timestamp=final_ts,
            host=final_host,
            source=record.source,
            event_type=event_type,
            severity=severity,
            actor=Actor(
                username=user,
                terminal=terminal,
            ),
            process=Process(
                name=final_proc,
                pid=final_pid,
                executable="/usr/bin/sudo",
                command_line=command,
            ),
            action="sudo_command",
            outcome=outcome,
            summary=summary,
            raw_message=raw_clean,
            iocs=extract_iocs(raw_clean),
            parser=self.name,
            source_file=record.source_file,
            source_offset=record.source_offset,
            metadata=metadata,
        )
