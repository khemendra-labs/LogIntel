"""Parser for Linux kernel telemetry (/var/log/kern.log and dmesg/journal)."""

from __future__ import annotations

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
from logintel.normalization.sanitizer import extract_iocs, sanitize_message, validate_ip
from logintel.normalization.timestamps import parse_syslog_header
from logintel.parsers.base import BaseParser

UFW_RE = re.compile(
    r"\[UFW BLOCK\]\s+.*SRC=([^\s]+)\s+DST=([^\s]+).*PROTO=([^\s]+)(?:.*SPT=(\d+))?(?:.*DPT=(\d+))?"
)
SEGFAULT_RE = re.compile(
    r"([^\s\[]+)\[(\d+)\]: segfault at ([^\s]+) ip ([^\s]+) sp ([^\s]+) error (\d+)"
)


class KernelParser(BaseParser):
    """Parser for Linux kernel events, firewall drops, and driver messages."""

    @property
    def name(self) -> str:
        return "linux_kernel"

    def can_parse(self, record: RawRecord) -> bool:
        return (
            record.source in ("kern.log", "kernel")
            or "kernel:" in record.raw_content
            or record.raw_attributes.get("_TRANSPORT") == "kernel"
        )

    def parse(self, record: RawRecord) -> Optional[CanonicalEvent]:
        raw_clean = sanitize_message(record.raw_content)
        ts, host, proc, pid, body = parse_syslog_header(raw_clean)

        final_ts = record.timestamp or ts
        final_host = record.host or host or "unknown"
        final_proc = proc or "kernel"

        event_type = EventType.KERNEL_MESSAGE
        severity = Severity.INFORMATIONAL
        outcome = Outcome.SUCCESS
        summary = ""

        src_ip: Optional[str] = None
        dst_ip: Optional[str] = None
        proto: Optional[str] = None
        src_port: Optional[int] = None
        dst_port: Optional[int] = None

        # UFW Block check
        m_ufw = UFW_RE.search(body)
        if m_ufw:
            src_ip = validate_ip(m_ufw.group(1))
            dst_ip = validate_ip(m_ufw.group(2))
            proto = m_ufw.group(3).lower()
            src_port = int(m_ufw.group(4)) if m_ufw.group(4) else None
            dst_port = int(m_ufw.group(5)) if m_ufw.group(5) else None
            event_type = EventType.KERNEL_MESSAGE
            severity = Severity.WARNING
            outcome = Outcome.FAILURE
            summary = f"UFW Firewall blocked inbound connection from {src_ip or m_ufw.group(1)} to {dst_ip or m_ufw.group(2)}:{dst_port or 'any'}"

        # Segfault check
        if not summary:
            m_seg = SEGFAULT_RE.search(body)
            if m_seg:
                seg_proc = m_seg.group(1)
                seg_pid = int(m_seg.group(2))
                addr = m_seg.group(3)
                event_type = EventType.KERNEL_MESSAGE
                severity = Severity.ALERT
                outcome = Outcome.FAILURE
                summary = f"Application crash: segfault in '{seg_proc}' (PID: {seg_pid}) at memory address {addr}"

        # Boot / Kernel start
        if not summary:
            if "Linux version" in body:
                event_type = EventType.SYSTEM_BOOT
                severity = Severity.NOTICE
                summary = "System kernel boot / initialization"
            else:
                clean_body = body.split("kernel:", 1)[-1].strip() if "kernel:" in body else body
                summary = f"Kernel: {clean_body[:100]}"

        return CanonicalEvent(
            timestamp=final_ts,
            host=final_host,
            source=record.source,
            event_type=event_type,
            severity=severity,
            process=Process(name=final_proc, pid=pid),
            network=Network(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=proto,
            ),
            action="kernel_log",
            outcome=outcome,
            summary=summary,
            raw_message=raw_clean,
            iocs=extract_iocs(raw_clean),
            parser=self.name,
            source_file=record.source_file,
            source_offset=record.source_offset,
        )
