"""Safe operational notifications for local LogIntel deployments.

Outbound delivery is deliberately disabled by default. When enabled, configured
webhook and/or Telegram bot channels can receive security notifications. The
calling API path is never blocked by network I/O and the in-memory audit trail
is bounded so notification trouble cannot exhaust a workstation.
Telegram notifications are strictly gated to HIGH and CRITICAL severity events.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import html
import ipaddress
import json
import logging
import os
from threading import Lock, Semaphore
from typing import Any, Dict, List, Literal, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, build_opener, HTTPHandler, HTTPSHandler


logger = logging.getLogger("logintel.notifications")
MAX_RECENT_DELIVERIES = 200
MAX_PAYLOAD_BYTES = 64 * 1024
MAX_PENDING_DELIVERIES = 8

HIGH_CRITICAL_SEVERITIES = {"CRITICAL", "ALERT", "HIGH"}


def is_high_or_critical(severity: Any) -> bool:
    """Return True only if severity is strictly HIGH, ALERT, or CRITICAL."""
    sev = str(severity or "").upper().strip()
    return sev in HIGH_CRITICAL_SEVERITIES


def format_telegram_alert(payload: Dict[str, Any], delivery_id: int) -> str:
    """Format rich, readable HTML alert message containing all security event details."""
    severity = str(payload.get("severity") or "UNKNOWN").upper().strip()
    sev_emoji = "🚨" if severity == "CRITICAL" else "⚠️"

    rule_id = html.escape(str(payload.get("rule_id") or "unknown_rule"))
    rule_name = html.escape(str(payload.get("rule_name") or rule_id))
    rule_desc = html.escape(str(payload.get("rule_description") or "No description provided"))
    category = html.escape(str(payload.get("rule_category") or "GENERAL"))
    host = html.escape(str(payload.get("host") or "localhost"))
    status = html.escape(str(payload.get("status") or "OPEN"))
    alert_id = payload.get("alert_id") or "N/A"
    occurrence_count = payload.get("occurrence_count", 1)
    first_seen = html.escape(str(payload.get("first_seen") or "N/A"))
    last_seen = html.escape(str(payload.get("last_seen") or "N/A"))
    summary = html.escape(str(payload.get("summary") or "Security Alert Triggered"))

    lines = [
        f"{sev_emoji} <b>[Prahari Security Alert: {severity}]</b>",
        f"<b>Rule:</b> <code>{rule_id}</code> ({rule_name})",
        f"<b>Severity:</b> <b>{severity}</b> | <b>Category:</b> {category}",
        f"<b>Host:</b> <code>{host}</code>",
        f"<b>Alert ID:</b> #{alert_id} (Occurrences: {occurrence_count})",
        f"<b>Status:</b> {status} | <b>Timestamp:</b> <code>{last_seen}</code>",
        f"<b>Summary:</b> {summary}",
        "",
        "📋 <b>Rule Description:</b>",
        f"<i>{rule_desc}</i>",
    ]

    trigger_ev = payload.get("trigger_event")
    if trigger_ev and isinstance(trigger_ev, dict):
        lines.append("")
        lines.append("🔍 <b>Trigger Evidence Details:</b>")

        ev_id = trigger_ev.get("event_id")
        if ev_id:
            lines.append(f"• <b>Event ID:</b> <code>{html.escape(str(ev_id))}</code>")

        ev_type = trigger_ev.get("event_type")
        if ev_type:
            src_name = html.escape(str(trigger_ev.get("source") or ""))
            lines.append(f"• <b>Event Type:</b> <code>{html.escape(str(ev_type))}</code>" + (f" (Source: {src_name})" if src_name else ""))

        # Actor / User
        user = trigger_ev.get("user")
        uid = trigger_ev.get("uid")
        term = trigger_ev.get("terminal")
        if user or uid is not None:
            user_info = f"{user or 'unknown'} (UID: {uid if uid is not None else 'N/A'})"
            if term:
                user_info += f" on {term}"
            lines.append(f"• <b>Actor:</b> <code>{html.escape(user_info)}</code>")

        # Process context
        proc = trigger_ev.get("process_name")
        pid = trigger_ev.get("process_pid")
        ppid = trigger_ev.get("process_ppid")
        exe = trigger_ev.get("executable")
        cmd = trigger_ev.get("command_line")
        if proc or pid:
            proc_info = f"{proc or 'unknown'}[PID: {pid or 'N/A'}, PPID: {ppid or 'N/A'}]"
            lines.append(f"• <b>Process:</b> <code>{html.escape(proc_info)}</code>")
        if exe:
            lines.append(f"• <b>Executable:</b> <code>{html.escape(str(exe))}</code>")
        if cmd:
            cmd_escaped = html.escape(str(cmd)[:600])
            if len(str(cmd)) > 600:
                cmd_escaped += " ...[truncated]"
            lines.append(f"• <b>Command Line:</b>\n<pre>{cmd_escaped}</pre>")

        # Network
        src_ip = trigger_ev.get("src_ip")
        dst_ip = trigger_ev.get("dst_ip")
        src_port = trigger_ev.get("src_port")
        dst_port = trigger_ev.get("dst_port")
        proto = trigger_ev.get("protocol")
        if src_ip or dst_ip:
            net_src = f"{src_ip or '*'}:{src_port or '*'}"
            net_dst = f"{dst_ip or '*'}:{dst_port or '*'}"
            lines.append(f"• <b>Network:</b> <code>{html.escape(net_src)} ➔ {html.escape(net_dst)} ({html.escape(str(proto or 'TCP'))})</code>")

        # Action & Outcome
        action = trigger_ev.get("action")
        outcome = trigger_ev.get("outcome")
        if action or outcome:
            lines.append(f"• <b>Action/Outcome:</b> {html.escape(str(action or 'N/A'))} / <b>{html.escape(str(outcome or 'N/A'))}</b>")

        # Raw log message
        raw = trigger_ev.get("raw_message")
        if raw:
            raw_escaped = html.escape(str(raw)[:700])
            if len(str(raw)) > 700:
                raw_escaped += " ...[truncated]"
            lines.append("")
            lines.append(f"📄 <b>Raw Telemetry:</b>\n<pre>{raw_escaped}</pre>")

    msg = "\n".join(lines)
    if len(msg) > 4000:
        msg = msg[:3950] + "\n\n<i>[Message truncated due to Telegram size limit]</i>"
    return msg


@dataclass(frozen=True)
class NotificationSettings:
    """Runtime notification settings; environment-only or API-configurable."""

    enabled: bool = False
    sink: Literal["log", "webhook", "telegram", "all"] = "log"
    webhook_url: Optional[str] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    timeout_seconds: float = 5.0

    @classmethod
    def from_environment(cls) -> "NotificationSettings":
        telegram_token = os.environ.get("LOGINTEL_TELEGRAM_BOT_TOKEN") or os.environ.get("TELEGRAM_BOT_TOKEN") or None
        telegram_chat = os.environ.get("LOGINTEL_TELEGRAM_CHAT_ID") or os.environ.get("TELEGRAM_CHAT_ID") or None

        raw_enabled = os.environ.get("LOGINTEL_NOTIFICATIONS_ENABLED")
        if raw_enabled is not None:
            enabled = raw_enabled.lower() in {"1", "true", "yes"}
        else:
            enabled = bool(telegram_token and telegram_chat)

        raw_sink = os.environ.get("LOGINTEL_NOTIFICATION_SINK", "").lower()
        if raw_sink in {"webhook", "telegram", "all", "log"}:
            sink = raw_sink
        elif telegram_token and telegram_chat:
            sink = "telegram"
        else:
            sink = "log"

        return cls(
            enabled=enabled,
            sink=sink,
            webhook_url=os.environ.get("LOGINTEL_NOTIFICATION_WEBHOOK_URL") or None,
            telegram_bot_token=telegram_token,
            telegram_chat_id=telegram_chat,
            timeout_seconds=float(os.environ.get("LOGINTEL_NOTIFICATION_TIMEOUT", "5.0")),
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
    """A bounded notification dispatcher supporting Webhook and Telegram bot channels."""

    def __init__(self, settings: Optional[NotificationSettings] = None) -> None:
        self.settings = settings or NotificationSettings.from_environment()
        self._lock = Lock()
        self._recent: List[NotificationDelivery] = []
        self._next_id = 1
        self._pending = Semaphore(MAX_PENDING_DELIVERIES)
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="LogIntelNotify")

    def configure_telegram(self, bot_token: str, chat_id: str, enabled: bool = True) -> None:
        """Update Telegram bot credentials and enable delivery at runtime."""
        with self._lock:
            sink = "all" if self.settings.sink == "webhook" or self.settings.webhook_url else "telegram"
            self.settings = NotificationSettings(
                enabled=enabled,
                sink=sink,
                webhook_url=self.settings.webhook_url,
                telegram_bot_token=bot_token.strip(),
                telegram_chat_id=str(chat_id).strip(),
                timeout_seconds=self.settings.timeout_seconds,
            )

    def status(self) -> Dict[str, Any]:
        with self._lock:
            recent = [asdict(d) for d in self._recent[-20:]]
            chat_id = self.settings.telegram_chat_id
            masked_chat = f"{chat_id[:2]}***{chat_id[-2:]}" if chat_id and len(chat_id) > 4 else ("***" if chat_id else None)
        return {
            "enabled": self.settings.enabled,
            "sink": self.settings.sink,
            "webhook_configured": bool(self.settings.webhook_url),
            "telegram_configured": bool(self.settings.telegram_bot_token and self.settings.telegram_chat_id),
            "telegram_chat_id_masked": masked_chat,
            "telegram_min_severity": "HIGH/CRITICAL",
            "recent_deliveries": recent,
        }

    def publish(self, event_type: str, resource_type: str, resource_id: str, payload: Dict[str, Any]) -> None:
        """Queue an opt-in notification without blocking the caller."""
        if not self.settings.enabled:
            return

        delivery = self._create_delivery(event_type, resource_type, resource_id, "QUEUED")

        # 1. Log sink (if explicitly selected or fallback)
        if self.settings.sink == "log":
            logger.info("Operational notification: %s", json.dumps(self._envelope(delivery, payload), sort_keys=True))
            self._set_delivery(delivery.delivery_id, "DELIVERED", "Logged locally")
            return

        # 2. Webhook delivery
        if self.settings.sink in ("webhook", "all"):
            if not self.settings.webhook_url:
                self._set_delivery(delivery.delivery_id, "FAILED", "Webhook sink configured without a URL")
            else:
                try:
                    url = _validate_webhook_url(self.settings.webhook_url)
                    if self._pending.acquire(blocking=False):
                        self._executor.submit(self._deliver_webhook, delivery, payload, url)
                    else:
                        self._set_delivery(delivery.delivery_id, "DROPPED", "Notification queue is full")
                except ValueError as exc:
                    self._set_delivery(delivery.delivery_id, "FAILED", str(exc))

        # 3. Telegram delivery (strictly gated to HIGH and CRITICAL severities)
        if (self.settings.sink in ("telegram", "all") or bool(self.settings.telegram_bot_token and self.settings.telegram_chat_id)) and self.settings.telegram_bot_token and self.settings.telegram_chat_id:
            severity = str(payload.get("severity") or "").upper().strip()
            if not is_high_or_critical(severity):
                self._set_delivery(delivery.delivery_id, "FILTERED", f"Severity '{severity}' is below HIGH/CRITICAL threshold")
                return

            if self._pending.acquire(blocking=False):
                self._executor.submit(
                    self._deliver_telegram,
                    delivery,
                    payload,
                    self.settings.telegram_bot_token,
                    self.settings.telegram_chat_id,
                )
            else:
                self._set_delivery(delivery.delivery_id, "DROPPED", "Notification queue is full")

    def send_telegram_test(
        self,
        bot_token: Optional[str] = None,
        chat_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Dispatch a test alert to the Telegram bot to verify configuration."""
        token = bot_token or self.settings.telegram_bot_token
        target_chat = chat_id or self.settings.telegram_chat_id

        if not token or not target_chat:
            raise ValueError("Telegram Bot Token and Chat ID must be configured to run a test.")

        test_payload = {
            "alert_id": "TEST-001",
            "rule_id": "system.test_alert",
            "rule_name": "LogIntel Telegram Integration Verification",
            "rule_description": "Manual verification test to confirm active Telegram bot delivery for High/Critical security events.",
            "rule_category": "SYSTEM",
            "severity": "HIGH",
            "host": os.uname().nodename if hasattr(os, "uname") else "localhost",
            "status": "OPEN",
            "occurrence_count": 1,
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "summary": "Analyst Telegram Bot Integration is ACTIVE and Operational",
            "trigger_event": {
                "event_id": "evt-verify-001",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "TELEGRAM_VERIFICATION",
                "source": "notification_engine",
                "severity": "HIGH",
                "action": "CONFIG_TEST",
                "outcome": "SUCCESS",
                "summary": "Telegram delivery pipeline verified successfully",
                "user": "secops-analyst",
                "process_name": "logintel-engine",
                "command_line": "/usr/bin/logintel --daemon",
                "raw_message": "LogIntel Telegram notification dispatcher connected to Telegram Bot API.",
            },
        }

        delivery = self._create_delivery("alert.detected", "alert", "TEST-001", "TEST_DISPATCH")
        text = format_telegram_alert(test_payload, delivery.delivery_id)
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        body = json.dumps({
            "chat_id": target_chat,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }).encode("utf-8")

        request = Request(
            url,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "LogIntel/0.1"},
            method="POST",
        )
        opener = build_opener(HTTPSHandler())
        try:
            with opener.open(request, timeout=self.settings.timeout_seconds) as response:
                if not 200 <= response.status < 300:
                    raise RuntimeError(f"Telegram API responded with HTTP {response.status}")
                resp_body = response.read().decode("utf-8")
        except HTTPError as exc:
            err_desc = str(exc)
            try:
                raw_bytes = exc.read().decode("utf-8")
                parsed = json.loads(raw_bytes)
                err_desc = parsed.get("description", str(exc))
            except Exception:
                pass

            if "chat not found" in err_desc.lower():
                raise RuntimeError(
                    f"Telegram Error: Chat not found (chat_id: {target_chat}). "
                    "Make sure you have opened your bot in Telegram and pressed 'START' (or sent a message to it) first. "
                    "Note: chat_id must be your Telegram Numeric ID (not a phone number). You can use 'Auto-Detect Chat ID' to find it automatically."
                ) from exc
            elif "unauthorized" in err_desc.lower():
                raise RuntimeError(
                    "Telegram Error: Unauthorized. Please check your Bot Token."
                ) from exc
            else:
                raise RuntimeError(f"Telegram API Error: {err_desc}") from exc
        except Exception as exc:
            raise RuntimeError(f"Failed to deliver to Telegram: {exc}") from exc

        self._set_delivery(delivery.delivery_id, "DELIVERED", "Test message delivered to Telegram")
        return {"status": "ok", "message": "Test alert successfully sent to Telegram", "response": json.loads(resp_body)}

    def detect_telegram_chat_id(self, bot_token: Optional[str] = None) -> Dict[str, Any]:
        """Query getUpdates and getMe to auto-discover the bot username and any initiated chat IDs."""
        token = (bot_token or self.settings.telegram_bot_token or "").strip()
        if not token:
            raise ValueError("Telegram Bot Token is required to detect chat ID.")

        opener = build_opener(HTTPSHandler())

        # 1. Query getMe to get bot username
        bot_username = "your_bot"
        bot_name = "Prahari"
        try:
            req_me = Request(
                f"https://api.telegram.org/bot{token}/getMe",
                headers={"User-Agent": "Prahari/0.1"},
            )
            with opener.open(req_me, timeout=self.settings.timeout_seconds) as resp:
                data_me = json.loads(resp.read().decode("utf-8"))
                if data_me.get("ok"):
                    bot_username = data_me["result"].get("username", bot_username)
                    bot_name = data_me["result"].get("first_name", bot_name)
        except HTTPError as exc:
            raise RuntimeError("Telegram Bot Token is invalid or unauthorized. Please verify the token.") from exc
        except Exception as exc:
            raise RuntimeError(f"Unable to reach Telegram API: {exc}") from exc

        # 2. Query getUpdates
        try:
            req_up = Request(
                f"https://api.telegram.org/bot{token}/getUpdates?limit=20",
                headers={"User-Agent": "Prahari/0.1"},
            )
            with opener.open(req_up, timeout=self.settings.timeout_seconds) as resp:
                data_up = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            raise RuntimeError(f"Failed to fetch updates from Telegram: {exc}") from exc

        updates = data_up.get("result", [])
        for item in reversed(updates):
            msg = item.get("message") or item.get("channel_post") or item.get("my_chat_member")
            if msg:
                chat = msg.get("chat", {})
                chat_id = chat.get("id")
                chat_title = chat.get("title") or chat.get("username") or f"{chat.get('first_name', '')} {chat.get('last_name', '')}".strip()
                if chat_id is not None:
                    return {
                        "found": True,
                        "chat_id": str(chat_id),
                        "chat_title": chat_title or f"Chat {chat_id}",
                        "bot_username": bot_username,
                        "message": f"Successfully detected chat with '{chat_title}' (Chat ID: {chat_id})!",
                    }

        return {
            "found": False,
            "bot_username": bot_username,
            "bot_name": bot_name,
            "message": (
                f"No messages received yet by @{bot_username}. "
                f"Please open Telegram, search for @{bot_username} (or open https://t.me/{bot_username}), "
                f"and press START or send any message. Then click 'Auto-Detect Chat ID' again."
            ),
        }

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

    def _deliver_telegram(
        self,
        delivery: NotificationDelivery,
        payload: Dict[str, Any],
        bot_token: str,
        chat_id: str,
    ) -> None:
        try:
            severity = str(payload.get("severity") or "").upper().strip()
            if not is_high_or_critical(severity):
                self._set_delivery(delivery.delivery_id, "FILTERED", f"Severity '{severity}' below HIGH/CRITICAL threshold")
                return

            text = format_telegram_alert(payload, delivery.delivery_id)
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            body = json.dumps({
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            }).encode("utf-8")

            request = Request(
                url,
                data=body,
                headers={"Content-Type": "application/json", "User-Agent": "LogIntel/0.1"},
                method="POST",
            )
            opener = build_opener(HTTPSHandler())
            try:
                with opener.open(request, timeout=self.settings.timeout_seconds) as response:
                    if not 200 <= response.status < 300:
                        raise RuntimeError(f"Telegram API returned HTTP {response.status}")
                self._set_delivery(delivery.delivery_id, "DELIVERED", "Sent to Telegram bot")
            except HTTPError as exc:
                err_desc = str(exc)
                try:
                    raw_bytes = exc.read().decode("utf-8")
                    parsed = json.loads(raw_bytes)
                    err_desc = parsed.get("description", str(exc))
                except Exception:
                    pass
                raise RuntimeError(f"Telegram Error: {err_desc}") from exc
        except Exception as exc:
            logger.warning("Telegram delivery %s failed: %s", delivery.delivery_id, exc)
            self._set_delivery(delivery.delivery_id, "FAILED", str(exc))
        finally:
            self._pending.release()


notification_service = NotificationService()
