"""Parser for systemd service lifecycle and unit state telemetry (M6.6).

Extracts and normalizes unit lifecycle transitions:
- Starting / Started (SERVICE_STARTING, SERVICE_STARTED)
- Stopping / Stopped (SERVICE_STOPPING, SERVICE_STOPPED)
- Failed (SERVICE_FAILED)
- Reloaded (SERVICE_RELOADED)
Works across both journald JSON attributes and syslog formatted stream lines.
"""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Optional

from logintel.models import (
    CanonicalEvent,
    EventType,
    Network,
    Outcome,
    Process,
    RawRecord,
    Severity,
)
from logintel.normalization.sanitizer import extract_iocs, sanitize_message
from logintel.normalization.timestamps import parse_syslog_header
from logintel.parsers.base import BaseParser

# Regex patterns for systemd lifecycle messages
STARTING_RE = re.compile(r"Starting\s+([^.]+?\.(?:service|socket|target|timer|mount|slice)|.+?)\.{3}", re.IGNORECASE)
STARTED_RE = re.compile(r"Started\s+([^.]+?\.(?:service|socket|target|timer|mount|slice)|.+?)\.", re.IGNORECASE)
STOPPING_RE = re.compile(r"Stopping\s+([^.]+?\.(?:service|socket|target|timer|mount|slice)|.+?)\.{3}", re.IGNORECASE)
STOPPED_RE = re.compile(r"Stopped\s+([^.]+?\.(?:service|socket|target|timer|mount|slice)|.+?)\.", re.IGNORECASE)
FAILED_START_RE = re.compile(r"Failed to start\s+([^.]+?\.(?:service|socket|target|timer|mount|slice)|.+?)\.", re.IGNORECASE)
FAILED_RESULT_RE = re.compile(r"([^\s:]+\.(?:service|socket|target|timer|mount|slice))\s+failed", re.IGNORECASE)
RELOADED_RE = re.compile(r"Reloaded\s+([^.]+?\.(?:service|socket|target|timer|mount|slice)|.+?)\.", re.IGNORECASE)
MAIN_PID_RE = re.compile(r"Main PID:\s*(\d+)", re.IGNORECASE)


class SystemdParser(BaseParser):
    """Parser for systemd unit lifecycle state transitions."""

    @property
    def name(self) -> str:
        return "systemd_lifecycle"

    def can_parse(self, record: RawRecord) -> bool:
        # Check explicit journald or systemd source type
        if record.source in ("journal", "systemd", "systemd-journald"):
            return True

        # Check structured journal attributes
        if record.raw_attributes.get("_SYSTEMD_UNIT") or record.raw_attributes.get("UNIT"):
            return True

        return False

    def parse(self, record: RawRecord) -> Optional[CanonicalEvent]:
        raw_clean = sanitize_message(record.raw_content)
        ts, host, proc, pid, body = parse_syslog_header(raw_clean)

        final_ts = ts or record.timestamp or datetime.now(timezone.utc)
        final_host = record.host or host or "unknown"
        final_proc = proc or "systemd"

        # Look for explicit systemd unit in raw attributes or message body
        unit_name = record.raw_attributes.get("_SYSTEMD_UNIT") or record.raw_attributes.get("UNIT")
        unit_action = "STATUS"
        event_type = EventType.SYSTEM_SERVICE_STATE
        severity = Severity.INFORMATIONAL
        outcome = Outcome.SUCCESS
        summary = ""
        description = None

        # Check lifecycle transitions
        m = FAILED_START_RE.search(body)
        if m:
            unit_action = "FAILED"
            event_type = EventType.SERVICE_FAILED
            severity = Severity.ALERT
            outcome = Outcome.FAILURE
            description = m.group(1).strip()
            summary = f"Systemd unit failed to start: '{description}'"
        else:
            m = FAILED_RESULT_RE.search(body)
            if m:
                unit_action = "FAILED"
                event_type = EventType.SERVICE_FAILED
                severity = Severity.ALERT
                outcome = Outcome.FAILURE
                description = m.group(1).strip()
                summary = f"Systemd unit failed: '{description}'"

        if not summary:
            m = STARTING_RE.search(body)
            if m:
                unit_action = "STARTING"
                event_type = EventType.SERVICE_STARTING
                severity = Severity.INFORMATIONAL
                outcome = Outcome.SUCCESS
                description = m.group(1).strip()
                summary = f"Systemd unit starting: '{description}'"

        if not summary:
            m = STARTED_RE.search(body)
            if m:
                unit_action = "STARTED"
                event_type = EventType.SERVICE_STARTED
                severity = Severity.NOTICE
                outcome = Outcome.SUCCESS
                description = m.group(1).strip()
                summary = f"Systemd unit started successfully: '{description}'"

        if not summary:
            m = STOPPING_RE.search(body)
            if m:
                unit_action = "STOPPING"
                event_type = EventType.SERVICE_STOPPING
                severity = Severity.INFORMATIONAL
                outcome = Outcome.SUCCESS
                description = m.group(1).strip()
                summary = f"Systemd unit stopping: '{description}'"

        if not summary:
            m = STOPPED_RE.search(body)
            if m:
                unit_action = "STOPPED"
                event_type = EventType.SERVICE_STOPPED
                severity = Severity.NOTICE
                outcome = Outcome.SUCCESS
                description = m.group(1).strip()
                summary = f"Systemd unit stopped: '{description}'"

        if not summary:
            m = RELOADED_RE.search(body)
            if m:
                unit_action = "RELOADED"
                event_type = EventType.SERVICE_RELOADED
                severity = Severity.NOTICE
                outcome = Outcome.SUCCESS
                description = m.group(1).strip()
                summary = f"Systemd unit reloaded configuration: '{description}'"

        if not summary:
            # Fallback within systemd messages
            summary = f"Systemd service state: {body[:100]}"
            event_type = EventType.SYSTEM_SERVICE_STATE

        # Extract unit name if not already found
        if not unit_name and description:
            # If description looks like a unit (has dot extension), use it
            if "." in description and any(description.endswith(ext) for ext in (".service", ".socket", ".timer", ".target", ".mount", ".slice")):
                unit_name = description

        # Extract Main PID if mentioned
        main_pid: Optional[int] = None
        pid_m = MAIN_PID_RE.search(body)
        if pid_m:
            main_pid = int(pid_m.group(1))

        unit_type = unit_name.rsplit(".", 1)[-1] if unit_name and "." in unit_name else "service"

        iocs = extract_iocs(raw_clean)
        if unit_name and unit_name not in iocs:
            iocs.append(unit_name)

        metadata = dict(record.raw_attributes)
        metadata.update({
            "unit_name": unit_name,
            "unit_type": unit_type,
            "unit_action": unit_action,
            "description": description,
            "main_pid": main_pid,
            "epistemic_status": "OBSERVED",
        })

        return CanonicalEvent(
            timestamp=final_ts,
            host=final_host,
            source=record.source or "systemd",
            event_type=event_type,
            severity=severity,
            process=Process(name="systemd", pid=pid or 1),
            network=Network(),
            action=f"UNIT_{unit_action}",
            outcome=outcome,
            summary=summary,
            raw_message=raw_clean,
            iocs=sorted(list(set(iocs))),
            parser=self.name,
            source_file=record.source_file,
            source_offset=record.source_offset,
            metadata=metadata,
        )
