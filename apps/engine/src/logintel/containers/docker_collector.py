"""Docker Unix socket client and telemetry collector (M6.7).

Communicates with /var/run/docker.sock:
- Safe unprivileged probing with graceful fallback if socket is missing or restricted.
- Inspects container state, image, network, and privileged security capabilities.
- Emits structured CanonicalEvents for container lifecycle transitions.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from logintel.containers.models import (
    ContainerInfo,
    ContainerLifecycleEvent,
    ContainerRuntime,
    ContainerState,
)
from logintel.models import (
    CanonicalEvent,
    EventType,
    Network,
    Outcome,
    Process,
    Severity,
)
from logintel.normalization.sanitizer import extract_iocs


class UnixSocketHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection over a local Unix domain socket."""

    def __init__(self, socket_path: str, timeout: float = 3.0):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.socket_path)
        self.sock = sock


class DockerSocketCollector:
    """Interacts with Docker Engine via /var/run/docker.sock."""

    def __init__(self, socket_path: str = "/var/run/docker.sock") -> None:
        self.socket_path = socket_path

    def check_availability(self) -> Tuple[bool, Optional[str]]:
        """Verify whether the Docker socket exists and is readable/writable."""
        if not os.path.exists(self.socket_path):
            return False, f"Docker socket '{self.socket_path}' does not exist"

        try:
            conn = UnixSocketHTTPConnection(self.socket_path, timeout=2.0)
            conn.request("GET", "/_ping")
            res = conn.getresponse()
            if res.status == 200:
                conn.close()
                return True, None
            conn.close()
            return False, f"Docker socket returned HTTP {res.status}"
        except PermissionError:
            return False, f"Permission denied accessing '{self.socket_path}'. User must belong to 'docker' group."
        except Exception as exc:
            return False, f"Error connecting to Docker socket: {exc}"

    def list_containers(self, all_containers: bool = False) -> List[ContainerInfo]:
        """Fetch containers via GET /containers/json."""
        avail, reason = self.check_availability()
        if not avail:
            return []

        try:
            conn = UnixSocketHTTPConnection(self.socket_path, timeout=3.0)
            path = "/containers/json?all=1" if all_containers else "/containers/json"
            conn.request("GET", path)
            res = conn.getresponse()
            if res.status != 200:
                conn.close()
                return []

            data = json.loads(res.read().decode("utf-8"))
            conn.close()

            containers: List[ContainerInfo] = []
            for item in data:
                cid = item.get("Id", "")[:12]
                names = item.get("Names", [])
                cname = names[0].lstrip("/") if names else None
                image = item.get("Image", "unknown")
                state_str = item.get("State", "unknown").lower()

                try:
                    state = ContainerState(state_str)
                except ValueError:
                    state = ContainerState.UNKNOWN

                created_ts = item.get("Created")
                created_dt = (
                    datetime.fromtimestamp(created_ts, tz=timezone.utc)
                    if created_ts
                    else None
                )

                containers.append(
                    ContainerInfo(
                        container_id=cid,
                        container_name=cname,
                        image=image,
                        runtime=ContainerRuntime.DOCKER,
                        state=state,
                        created_at=created_dt,
                        epistemic_status="OBSERVED",
                    )
                )
            return containers
        except Exception:
            return []

    def inspect_container(self, container_id: str) -> Optional[ContainerInfo]:
        """Fetch detailed container configuration via GET /containers/{id}/json."""
        avail, _ = self.check_availability()
        if not avail:
            return None

        try:
            conn = UnixSocketHTTPConnection(self.socket_path, timeout=3.0)
            conn.request("GET", f"/containers/{container_id}/json")
            res = conn.getresponse()
            if res.status != 200:
                conn.close()
                return None

            data = json.loads(res.read().decode("utf-8"))
            conn.close()

            cid = data.get("Id", container_id)[:12]
            cname = data.get("Name", "").lstrip("/") or None
            config = data.get("Config", {})
            host_config = data.get("HostConfig", {})
            net_settings = data.get("NetworkSettings", {})
            state_data = data.get("State", {})

            image = config.get("Image", "unknown")
            is_privileged = bool(host_config.get("Privileged", False))
            ip_addr = net_settings.get("IPAddress") or None
            pid = state_data.get("Pid")
            pids = [pid] if pid and pid > 0 else []

            state_str = state_data.get("Status", "unknown").lower()
            try:
                state = ContainerState(state_str)
            except ValueError:
                state = ContainerState.UNKNOWN

            return ContainerInfo(
                container_id=cid,
                container_name=cname,
                image=image,
                runtime=ContainerRuntime.DOCKER,
                state=state,
                pids=pids,
                ip_address=ip_addr,
                privileged=is_privileged,
                epistemic_status="OBSERVED",
            )
        except Exception:
            return None

    def create_canonical_event(self, event: ContainerLifecycleEvent) -> CanonicalEvent:
        """Convert a container lifecycle or security event to a CanonicalEvent."""
        action_lower = event.action.lower()
        event_type = EventType.CONTAINER_LIFECYCLE_START
        severity = Severity.NOTICE
        outcome = Outcome.SUCCESS
        summary = ""

        if action_lower == "create":
            event_type = EventType.CONTAINER_LIFECYCLE_CREATE
            severity = Severity.INFORMATIONAL
            summary = f"Container created: '{event.container_name or event.container_id}' (image: {event.image})"
        elif action_lower in ("start", "started"):
            event_type = EventType.CONTAINER_LIFECYCLE_START
            if event.privileged:
                severity = Severity.ALERT
                summary = f"PRIVILEGED container started: '{event.container_name or event.container_id}' (image: {event.image})"
            else:
                severity = Severity.NOTICE
                summary = f"Container started: '{event.container_name or event.container_id}' (image: {event.image})"
        elif action_lower in ("stop", "stopped"):
            event_type = EventType.CONTAINER_LIFECYCLE_STOP
            severity = Severity.INFORMATIONAL
            summary = f"Container stopped: '{event.container_name or event.container_id}'"
        elif action_lower in ("die", "died"):
            event_type = EventType.CONTAINER_LIFECYCLE_DIE
            severity = Severity.WARNING
            outcome = Outcome.FAILURE
            summary = f"Container terminated: '{event.container_name or event.container_id}'"
        elif action_lower in ("kill", "killed"):
            event_type = EventType.CONTAINER_LIFECYCLE_KILL
            severity = Severity.WARNING
            summary = f"Container forcibly killed: '{event.container_name or event.container_id}'"
        elif action_lower in ("destroy", "destroyed", "remove", "removed"):
            event_type = EventType.CONTAINER_LIFECYCLE_DESTROY
            severity = Severity.NOTICE
            summary = f"Container destroyed: '{event.container_name or event.container_id}'"
        elif "escape" in action_lower:
            event_type = EventType.CONTAINER_SECURITY_ESCAPE_ATTEMPT
            severity = Severity.ALERT
            outcome = Outcome.FAILURE
            summary = f"Container security anomaly: potential breakout attempt from '{event.container_name or event.container_id}'"
        else:
            event_type = EventType.CONTAINER_LIFECYCLE_START
            severity = Severity.INFORMATIONAL
            summary = f"Container event {event.action}: '{event.container_name or event.container_id}'"

        iocs = extract_iocs(event.raw_message or summary)
        if event.container_id and event.container_id not in iocs:
            iocs.append(event.container_id)
        if event.container_name and event.container_name not in iocs:
            iocs.append(event.container_name)

        metadata: Dict[str, Any] = {
            "container_id": event.container_id,
            "container_name": event.container_name,
            "container_action": event.action,
            "image": event.image,
            "runtime": event.runtime.value,
            "privileged": event.privileged,
            "epistemic_status": "OBSERVED",
        }

        return CanonicalEvent(
            timestamp=event.timestamp,
            host="localhost",
            source="docker",
            event_type=event_type,
            severity=severity,
            process=Process(name="dockerd", pid=None),
            network=Network(),
            action=f"CONTAINER_{event.action.upper()}",
            outcome=outcome,
            summary=summary,
            raw_message=event.raw_message or summary,
            iocs=sorted(list(set(iocs))),
            parser="container_telemetry",
            metadata=metadata,
        )
