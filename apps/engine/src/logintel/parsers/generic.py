"""Fallback parser for generic syslog messages."""

from __future__ import annotations

from typing import Optional
from logintel.models import (
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


class GenericSyslogParser(BaseParser):
    """Fallback parser for generic Linux system messages."""

    @property
    def name(self) -> str:
        return "generic_syslog"

    def can_parse(self, record: RawRecord) -> bool:
        return True  # Fallback matches everything

    def parse(self, record: RawRecord) -> Optional[CanonicalEvent]:
        raw_clean = sanitize_message(record.raw_content)
        ts, host, proc, pid, body = parse_syslog_header(raw_clean)

        final_ts = record.timestamp or ts
        final_host = record.host or host or "unknown"
        final_proc = proc or record.raw_attributes.get("SYSLOG_IDENTIFIER") or "system"
        final_pid = pid or (int(record.raw_attributes["_PID"]) if "_PID" in record.raw_attributes else None)

        # Basic severity estimation based on content keywords
        lower_body = body.lower()
        severity = Severity.INFORMATIONAL
        if any(w in lower_body for w in ("critical", "emergency", "panic", "fatal")):
            severity = Severity.CRITICAL
        elif any(w in lower_body for w in ("error", "failed", "failure")):
            severity = Severity.ALERT
        elif any(w in lower_body for w in ("warn", "warning")):
            severity = Severity.WARNING
        elif any(w in lower_body for w in ("notice", "started", "stopped", "reloaded")):
            severity = Severity.NOTICE

        summary = body[:120] if body else f"{final_proc} activity"

        return CanonicalEvent(
            timestamp=final_ts,
            host=final_host,
            source=record.source,
            event_type=EventType.SYSTEM_GENERIC,
            severity=severity,
            process=Process(name=final_proc, pid=final_pid),
            outcome=Outcome.UNKNOWN,
            summary=summary,
            raw_message=raw_clean,
            iocs=extract_iocs(raw_clean),
            parser=self.name,
            source_file=record.source_file,
            source_offset=record.source_offset,
            metadata=record.raw_attributes,
        )
