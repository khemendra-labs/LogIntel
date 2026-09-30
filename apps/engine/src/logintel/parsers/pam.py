"""Parser for Linux PAM (Pluggable Authentication Modules) session events."""

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

PAM_OPEN_RE = re.compile(
    r"pam_unix\(([^:]+):session\):\s*session opened for user ([^\s(]+)(?:\(uid=(\d+)\))?(?:\s+by\s+([^\s(]+)(?:\(uid=(\d+)\))?)?"
)
PAM_CLOSE_RE = re.compile(
    r"pam_unix\(([^:]+):session\):\s*session closed for user ([^\s]+)"
)
PAM_AUTH_FAIL_RE = re.compile(
    r"pam_unix\(([^:]+):auth\):\s*authentication failure;\s*(.*)"
)


class PAMSessionParser(BaseParser):
    """Parser for PAM authentication and session lifecycle events."""

    @property
    def name(self) -> str:
        return "pam_session"

    def can_parse(self, record: RawRecord) -> bool:
        return "pam_unix" in record.raw_content

    def parse(self, record: RawRecord) -> Optional[CanonicalEvent]:
        raw_clean = sanitize_message(record.raw_content)
        ts, host, proc, pid, body = parse_syslog_header(raw_clean)

        final_ts = ts or record.timestamp or datetime.now(timezone.utc)
        final_host = record.host or host or "unknown"
        final_proc = proc or "pam"
        final_pid = pid or (int(record.raw_attributes["_PID"]) if "_PID" in record.raw_attributes else None)

        service = "system"
        user: Optional[str] = None
        uid: Optional[int] = None
        event_type = EventType.SYSTEM_GENERIC
        severity = Severity.INFORMATIONAL
        outcome = Outcome.SUCCESS
        summary = ""
        rhost: Optional[str] = None

        m_open = PAM_OPEN_RE.search(body)
        if m_open:
            service = m_open.group(1)
            user = m_open.group(2)
            uid = int(m_open.group(3)) if m_open.group(3) else None
            by_user = m_open.group(4)
            event_type = EventType.SESSION_OPEN
            severity = Severity.NOTICE if uid == 0 or user == "root" else Severity.INFORMATIONAL
            outcome = Outcome.SUCCESS
            by_str = f" by '{by_user}'" if by_user else ""
            summary = f"PAM session opened for user '{user}' (service: {service}){by_str}"

        if not summary:
            m_close = PAM_CLOSE_RE.search(body)
            if m_close:
                service = m_close.group(1)
                user = m_close.group(2)
                event_type = EventType.SESSION_CLOSE
                severity = Severity.INFORMATIONAL
                outcome = Outcome.SUCCESS
                summary = f"PAM session closed for user '{user}' (service: {service})"

        if not summary:
            m_fail = PAM_AUTH_FAIL_RE.search(body)
            if m_fail:
                service = m_fail.group(1)
                fail_details = m_fail.group(2)
                event_type = EventType.AUTH_LOGIN_FAILURE
                severity = Severity.ALERT
                outcome = Outcome.FAILURE

                # Extract rhost and ruser if present in detail string
                for pair in fail_details.split():
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        if k == "rhost":
                            rhost = validate_ip(v)
                        elif k in ("ruser", "logname", "user") and not user and v:
                            user = v

                summary = f"PAM authentication failure for user '{user or 'unknown'}' (service: {service})"

        if not summary:
            summary = f"PAM event: {body[:100]}"

        return CanonicalEvent(
            timestamp=final_ts,
            host=final_host,
            source=record.source,
            event_type=event_type,
            severity=severity,
            actor=Actor(
                username=user,
                uid=uid,
            ),
            process=Process(
                name=final_proc,
                pid=final_pid,
            ),
            network=Network(
                src_ip=rhost,
            ),
            action=f"pam_{service}",
            outcome=outcome,
            summary=summary,
            raw_message=raw_clean,
            iocs=extract_iocs(raw_clean),
            parser=self.name,
            source_file=record.source_file,
            source_offset=record.source_offset,
            metadata={"service": service},
        )
