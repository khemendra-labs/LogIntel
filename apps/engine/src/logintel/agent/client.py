"""Bounded HTTPS/mTLS client for the LogIntel fleet intake API."""

from __future__ import annotations

import json
import ssl
from typing import Any, Dict, List
from urllib.request import Request, urlopen

from logintel.agent.config import AgentConfig
from logintel.agent.spool import JsonlSpool


class FleetClient:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.spool = JsonlSpool(config.spool_dir, config.max_spool_bytes)

    def _ssl_context(self) -> ssl.SSLContext | None:
        if not self.config.endpoint.startswith("https://"):
            return None
        context = ssl.create_default_context(cafile=str(self.config.ca_file) if self.config.ca_file else None)
        if self.config.client_cert_file:
            if not self.config.client_key_file:
                raise ValueError("client_key_file is required when client_cert_file is configured")
            context.load_cert_chain(str(self.config.client_cert_file), str(self.config.client_key_file))
        return context

    def queue(self, records: List[Dict[str, Any]]) -> None:
        if records:
            self.spool.enqueue(records)

    def flush_once(self) -> int:
        item = self.spool.peek()
        if item is None:
            return 0
        path, records = item
        payload = json.dumps({"host": self.config.host, "records": records}, separators=(",", ":")).encode("utf-8")
        request = Request(
            f"{self.config.endpoint}/api/v1/fleet/ingest",
            data=payload,
            method="POST",
            headers={"Content-Type": "application/json", "X-LogIntel-Agent-Token": self.config.token},
        )
        with urlopen(request, timeout=self.config.timeout_seconds, context=self._ssl_context()) as response:
            if not 200 <= response.status < 300:
                raise RuntimeError(f"Fleet intake returned HTTP {response.status}")
        self.spool.acknowledge(path)
        return len(records)
