"""Parser for Linux kernel telemetry (/var/log/kern.log and dmesg/journal)."""

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

        final_ts = ts or record.timestamp or datetime.now(timezone.utc)
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

        # AppArmor Denial check
        if 'apparmor="DENIED"' in body:
            event_type = EventType.SECURITY_ACCESS_DENIED
            severity = Severity.ALERT
            outcome = Outcome.FAILURE

            op_m = re.search(r'operation="([^"]+)"', body)
            prof_m = re.search(r'profile="([^"]+)"', body)
            name_m = re.search(r'name="([^"]+)"', body)
            comm_m = re.search(r'comm="([^"]+)"', body)
            pid_m = re.search(r'pid=(\d+)', body)

            op = op_m.group(1) if op_m else "access"
            prof = prof_m.group(1) if prof_m else "unknown"
            target_name = name_m.group(1) if name_m else "resource"
            if comm_m:
                final_proc = comm_m.group(1)
            if pid_m:
                pid = int(pid_m.group(1))

            summary = f"AppArmor security policy DENIED operation '{op}' for profile '{prof}' on target '{target_name}'"

        # UFW Block check
        if not summary:
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

        # Kernel Module Loading / Unloading & Security Anomalies
        if not summary:
            if "entered promiscuous mode" in body:
                m_promisc = re.search(r"device\s+([^\s]+)\s+entered promiscuous mode", body)
                dev = m_promisc.group(1) if m_promisc else "network"
                event_type = EventType.KERNEL_SECURITY_ANOMALY
                severity = Severity.ALERT
                outcome = Outcome.SUCCESS
                summary = f"Network interface '{dev}' entered promiscuous mode (possible packet sniffing)"
            elif "left promiscuous mode" in body:
                m_promisc = re.search(r"device\s+([^\s]+)\s+left promiscuous mode", body)
                dev = m_promisc.group(1) if m_promisc else "network"
                event_type = EventType.KERNEL_SECURITY_ANOMALY
                severity = Severity.NOTICE
                outcome = Outcome.SUCCESS
                summary = f"Network interface '{dev}' left promiscuous mode"
            elif "module verification failed" in body:
                event_type = EventType.KERNEL_SECURITY_ANOMALY
                severity = Severity.ALERT
                outcome = Outcome.FAILURE
                summary = "Kernel security anomaly: module signature verification failed (untrusted kernel module)"
            elif "out-of-tree module taints kernel" in body or "loading out-of-tree module" in body:
                event_type = EventType.KERNEL_MODULE_LOAD
                severity = Severity.ALERT
                outcome = Outcome.SUCCESS
                summary = "Kernel module loaded: out-of-tree module taints kernel"
            elif "unloading module" in body or "unloaded module" in body:
                m_mod = re.search(r"(?:unloading|unloaded)\s+module\s+([^\s,]+)", body, re.IGNORECASE)
                mod_name = m_mod.group(1) if m_mod else "unknown"
                event_type = EventType.KERNEL_MODULE_UNLOAD
                severity = Severity.NOTICE
                outcome = Outcome.SUCCESS
                summary = f"Kernel module unloaded: '{mod_name}'"
            elif "loading module" in body or "loaded module" in body:
                m_mod = re.search(r"(?:loading|loaded)\s+module\s+([^\s,]+)", body, re.IGNORECASE)
                mod_name = m_mod.group(1) if m_mod else "unknown"
                event_type = EventType.KERNEL_MODULE_LOAD
                severity = Severity.NOTICE
                outcome = Outcome.SUCCESS
                summary = f"Kernel module loaded: '{mod_name}'"

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
