"""Parser for container runtime and lifecycle telemetry (M6.7).

Normalizes container events from Docker/containerd logs, journald streams, and JSON event records:
- Container create, start, stop, die, kill, destroy.
- Privileged container start flags.
- Container escape and breakout attempts.
"""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Optional

from logintel.containers.models import ContainerRuntime
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

CONTAINER_ACTION_RE = re.compile(
    r"(?:container|Container)\s+([a-f0-9]{12,64}|[a-zA-Z0-9_\-\.]+)\s+(created|started|stopped|died|killed|destroyed|removed)",
    re.IGNORECASE,
)
CONTAINER_LOG_MSG_RE = re.compile(
    r'msg="container\s+(started|stopped|created|died|killed)"(?:\s+container=([a-f0-9]{12,64}))?(?:\s+image="([^"]+)")?',
    re.IGNORECASE,
)


class ContainerParser(BaseParser):
    """Parser for container runtime lifecycle and security logs."""

    @property
    def name(self) -> str:
        return "container_runtime"

    def can_parse(self, record: RawRecord) -> bool:
        if record.source in ("docker", "containerd", "podman", "container"):
            return True

        # Check structured journal attributes
        if record.raw_attributes.get("CONTAINER_ID") or record.raw_attributes.get("CONTAINER_NAME"):
            return True

        content = record.raw_content
        if "dockerd[" in content or "containerd[" in content or "podman[" in content:
            return True

        if CONTAINER_ACTION_RE.search(content) or CONTAINER_LOG_MSG_RE.search(content):
            return True

        return False

    def parse(self, record: RawRecord) -> Optional[CanonicalEvent]:
        raw_clean = sanitize_message(record.raw_content)
        ts, host, proc, pid, body = parse_syslog_header(raw_clean)

        final_ts = ts or record.timestamp or datetime.now(timezone.utc)
        final_host = record.host or host or "unknown"
        final_proc = proc or "dockerd"

        container_id: Optional[str] = record.raw_attributes.get("CONTAINER_ID")
        container_name: Optional[str] = record.raw_attributes.get("CONTAINER_NAME")
        image: str = record.raw_attributes.get("IMAGE_NAME") or "unknown"
        action = "STATUS"
        privileged = False

        m_log = CONTAINER_LOG_MSG_RE.search(body)
        if m_log:
            action = m_log.group(1).lower()
            if m_log.group(2):
                container_id = m_log.group(2)[:12]
            if m_log.group(3):
                image = m_log.group(3)
        else:
            m_act = CONTAINER_ACTION_RE.search(body)
            if m_act:
                target = m_act.group(1)
                if len(target) >= 12 and all(c in "0123456789abcdefABCDEF" for c in target[:12]):
                    container_id = target[:12]
                else:
                    container_name = target
                action = m_act.group(2).lower()

        if "privileged" in body.lower():
            privileged = True

        event_type = EventType.CONTAINER_LIFECYCLE_START
        severity = Severity.NOTICE
        outcome = Outcome.SUCCESS
        summary = ""

        if action == "created":
            event_type = EventType.CONTAINER_LIFECYCLE_CREATE
            severity = Severity.INFORMATIONAL
            summary = f"Container created: '{container_name or container_id or 'unknown'}' (image: {image})"
        elif action in ("started", "start"):
            event_type = EventType.CONTAINER_LIFECYCLE_START
            if privileged:
                severity = Severity.ALERT
                summary = f"PRIVILEGED container started: '{container_name or container_id or 'unknown'}' (image: {image})"
            else:
                severity = Severity.NOTICE
                summary = f"Container started: '{container_name or container_id or 'unknown'}' (image: {image})"
        elif action in ("stopped", "stop"):
            event_type = EventType.CONTAINER_LIFECYCLE_STOP
            severity = Severity.INFORMATIONAL
            summary = f"Container stopped: '{container_name or container_id or 'unknown'}'"
        elif action in ("died", "die"):
            event_type = EventType.CONTAINER_LIFECYCLE_DIE
            severity = Severity.WARNING
            outcome = Outcome.FAILURE
            summary = f"Container terminated: '{container_name or container_id or 'unknown'}'"
        elif action in ("killed", "kill"):
            event_type = EventType.CONTAINER_LIFECYCLE_KILL
            severity = Severity.WARNING
            summary = f"Container forcibly killed: '{container_name or container_id or 'unknown'}'"
        elif action in ("destroyed", "destroy", "removed", "remove"):
            event_type = EventType.CONTAINER_LIFECYCLE_DESTROY
            severity = Severity.NOTICE
            summary = f"Container destroyed: '{container_name or container_id or 'unknown'}'"
        elif "escape" in body.lower():
            event_type = EventType.CONTAINER_SECURITY_ESCAPE_ATTEMPT
            severity = Severity.ALERT
            outcome = Outcome.FAILURE
            summary = f"Container security anomaly: potential breakout attempt from '{container_name or container_id or 'unknown'}'"
        else:
            summary = f"Container event: {body[:100]}"

        iocs = extract_iocs(raw_clean)
        if container_id and container_id not in iocs:
            iocs.append(container_id)
        if container_name and container_name not in iocs:
            iocs.append(container_name)

        metadata = dict(record.raw_attributes)
        metadata.update({
            "container_id": container_id,
            "container_name": container_name,
            "container_action": action,
            "image": image,
            "privileged": privileged,
            "runtime": ContainerRuntime.DOCKER.value,
            "epistemic_status": "OBSERVED",
        })

        return CanonicalEvent(
            timestamp=final_ts,
            host=final_host,
            source=record.source or "container",
            event_type=event_type,
            severity=severity,
            process=Process(name=final_proc, pid=pid),
            network=Network(),
            action=f"CONTAINER_{action.upper()}",
            outcome=outcome,
            summary=summary,
            raw_message=raw_clean,
            iocs=sorted(list(set(iocs))),
            parser=self.name,
            source_file=record.source_file,
            source_offset=record.source_offset,
            metadata=metadata,
        )
