"""Parser for Linux user and group administration events."""

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

USERADD_RE = re.compile(
    r"new user:\s*name=([^\s,]+),\s*UID=(\d+),\s*GID=(\d+)"
)
USERDEL_RE = re.compile(
    r"delete user\s*['\"]?([^'\"\s]+)['\"]?"
)
GROUPADD_RE = re.compile(
    r"new group:\s*name=([^\s,]+),\s*GID=(\d+)"
)


class UserManagementParser(BaseParser):
    """Parser for user and group creation, modification, and deletion."""

    @property
    def name(self) -> str:
        return "user_management"

    def can_parse(self, record: RawRecord) -> bool:
        content = record.raw_content
        return any(cmd in content for cmd in ("useradd", "userdel", "usermod", "groupadd", "groupdel"))

    def parse(self, record: RawRecord) -> Optional[CanonicalEvent]:
        raw_clean = sanitize_message(record.raw_content)
        ts, host, proc, pid, body = parse_syslog_header(raw_clean)

        final_ts = ts or record.timestamp or datetime.now(timezone.utc)
        final_host = record.host or host or "unknown"
        final_proc = proc or "user_admin"
        final_pid = pid or (int(record.raw_attributes["_PID"]) if "_PID" in record.raw_attributes else None)

        target_user: Optional[str] = None
        uid: Optional[int] = None
        event_type = EventType.SYSTEM_GENERIC
        severity = Severity.NOTICE
        outcome = Outcome.SUCCESS
        summary = ""

        m_add = USERADD_RE.search(body)
        if m_add:
            target_user = m_add.group(1)
            uid = int(m_add.group(2))
            event_type = EventType.USER_CREATE
            severity = Severity.WARNING if uid == 0 else Severity.NOTICE
            summary = f"New local user account created: '{target_user}' (UID: {uid})"

        if not summary:
            m_del = USERDEL_RE.search(body)
            if m_del:
                target_user = m_del.group(1)
                event_type = EventType.USER_DELETE
                severity = Severity.NOTICE
                summary = f"Local user account deleted: '{target_user}'"

        if not summary:
            m_grp = GROUPADD_RE.search(body)
            if m_grp:
                grp_name = m_grp.group(1)
                gid = int(m_grp.group(2))
                event_type = EventType.GROUP_MODIFY
                severity = Severity.NOTICE
                summary = f"New local group created: '{grp_name}' (GID: {gid})"

        if not summary:
            summary = f"User/group administration: {body[:100]}"

        return CanonicalEvent(
            timestamp=final_ts,
            host=final_host,
            source=record.source,
            event_type=event_type,
            severity=severity,
            actor=Actor(
                username=target_user,
                uid=uid,
            ),
            process=Process(
                name=final_proc,
                pid=final_pid,
            ),
            action="account_management",
            outcome=outcome,
            summary=summary,
            raw_message=raw_clean,
            iocs=extract_iocs(raw_clean),
            parser=self.name,
            source_file=record.source_file,
            source_offset=record.source_offset,
        )
