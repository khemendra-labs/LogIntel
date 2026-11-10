"""Safe operational notifications for local LogIntel deployments.

Outbound delivery is deliberately disabled by default.  When enabled, only a
single configured webhook can receive a compact, sanitized event envelope. The
calling API path is never blocked by network I/O and the in-memory audit trail
is bounded so notification trouble cannot exhaust a workstation.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import ipaddress
import json
import logging
import os
from threading import Lock, Semaphore
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urlparse
from urllib.request import Request, build_opener, HTTPHandler, HTTPSHandler


logger = logging.getLogger("logintel.notifications")
MAX_RECENT_DELIVERIES = 200
MAX_PAYLOAD_BYTES = 64 * 1024
MAX_PENDING_DELIVERIES = 8


@dataclass(frozen=True)
class NotificationSettings:
    """Runtime notification settings; environment-only to avoid stored secrets."""

    enabled: bool = False
    sink: Literal["log", "webhook"] = "log"
    webhook_url: Optional[str] = None
    timeout_seconds: float = 3.0

    @classmethod
    def from_environment(cls) -> "NotificationSettings":
        enabled = os.environ.get("LOGINTEL_NOTIFICATIONS_ENABLED", "false").lower() in {"1", "true", "yes"}
        sink = os.environ.get("LOGINTEL_NOTIFICATION_SINK", "log").lower()
        return cls(
            enabled=enabled,
            sink="webhook" if sink == "webhook" else "log",
            webhook_url=os.environ.get("LOGINTEL_NOTIFICATION_WEBHOOK_URL") or None,
        )


@dataclass
class NotificationDelivery:
    delivery_id: int
    event_type: str
    resource_type: str
    resource_id: str
    timestamp: str
    status: str
    detail: Optional[str] = None


def _validate_webhook_url(url: str) -> str:
    """Permit HTTPS anywhere and HTTP only for local test/relay endpoints."""
    parsed = urlparse(url)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Webhook URL must be an absolute http(s) URL without credentials")
    if parsed.scheme == "http":
        hostname = parsed.hostname.lower()
        is_loopback = hostname == "localhost"
        if not is_loopback:
            try:
                is_loopback = ipaddress.ip_address(hostname).is_loopback
            except ValueError:
                is_loopback = False
        if not is_loopback:
            raise ValueError("HTTP webhooks are allowed only for localhost; use HTTPS for remote receivers")
    return url


class NotificationService:
    """A small, bounded notification dispatcher with observable local outcomes."""

    def __init__(self, settings: Optional[NotificationSettings] = None) -> None:
        self.settings = settings or NotificationSettings.from_environment()
        self._lock = Lock()
        self._recent: List[NotificationDelivery] = []
        self._next_id = 1
        self._pending = Semaphore(MAX_PENDING_DELIVERIES)
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="LogIntelNotify")

    def status(self) -> Dict[str, Any]:
        with self._lock:
            recent = [asdict(d) for d in self._recent[-20:]]
        return {
            "enabled": self.settings.enabled,
            "sink": self.settings.sink,
            "webhook_configured": bool(self.settings.webhook_url),
            "recent_deliveries": recent,
        }

    def publish(self, event_type: str, resource_type: str, resource_id: str, payload: Dict[str, Any]) -> None:
        """Queue an opt-in notification without blocking the caller."""
        if not self.settings.enabled:
            return
        delivery = self._create_delivery(event_type, resource_type, resource_id, "QUEUED")
        if self.settings.sink == "log":
            logger.info("Operational notification: %s", json.dumps(self._envelope(delivery, payload), sort_keys=True))
            self._set_delivery(delivery.delivery_id, "DELIVERED", "Logged locally")
            return
        if not self.settings.webhook_url:
            self._set_delivery(delivery.delivery_id, "FAILED", "Webhook sink configured without a URL")
            return
        try:
            url = _validate_webhook_url(self.settings.webhook_url)
        except ValueError as exc:
            self._set_delivery(delivery.delivery_id, "FAILED", str(exc))
            return
        if not self._pending.acquire(blocking=False):
            self._set_delivery(delivery.delivery_id, "DROPPED", "Notification queue is full")
            return
        self._executor.submit(self._deliver_webhook, delivery, payload, url)

    def _create_delivery(self, event_type: str, resource_type: str, resource_id: str, status: str) -> NotificationDelivery:
        with self._lock:
            delivery = NotificationDelivery(
                delivery_id=self._next_id,
                event_type=event_type[:128],
                resource_type=resource_type[:64],
                resource_id=str(resource_id)[:128],
                timestamp=datetime.now(timezone.utc).isoformat(),
                status=status,
            )
            self._next_id += 1
            self._recent.append(delivery)
            del self._recent[:-MAX_RECENT_DELIVERIES]
            return delivery

    def _set_delivery(self, delivery_id: int, status: str, detail: Optional[str] = None) -> None:
        with self._lock:
            for delivery in self._recent:
                if delivery.delivery_id == delivery_id:
                    delivery.status = status
                    delivery.detail = detail[:512] if detail else None
                    return

    @staticmethod
    def _envelope(delivery: NotificationDelivery, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "event_type": delivery.event_type,
            "resource_type": delivery.resource_type,
            "resource_id": delivery.resource_id,
            "timestamp": delivery.timestamp,
            "payload": payload,
        }

    def _deliver_webhook(self, delivery: NotificationDelivery, payload: Dict[str, Any], url: str) -> None:
        try:
            body = json.dumps(self._envelope(delivery, payload), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            if len(body) > MAX_PAYLOAD_BYTES:
                raise ValueError("Notification payload exceeds 64 KiB")
            request = Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": "LogIntel/0.1"}, method="POST")
            # No redirect handler: a receiver must be the explicitly configured endpoint.
            opener = build_opener(HTTPHandler(), HTTPSHandler())
            with opener.open(request, timeout=self.settings.timeout_seconds) as response:
                if not 200 <= response.status < 300:
                    raise RuntimeError(f"Webhook returned HTTP {response.status}")
            self._set_delivery(delivery.delivery_id, "DELIVERED")
        except Exception as exc:
            logger.warning("Notification delivery %s failed: %s", delivery.delivery_id, exc)
            self._set_delivery(delivery.delivery_id, "FAILED", str(exc))
        finally:
            self._pending.release()


notification_service = NotificationService()
