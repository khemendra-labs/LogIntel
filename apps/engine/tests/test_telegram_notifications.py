"""Tests for Telegram Bot Notification delivery and severity filtering."""

from datetime import datetime, timezone
import json
import os
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from logintel.notifications.service import (
    NotificationDelivery,
    NotificationService,
    NotificationSettings,
    format_telegram_alert,
    is_high_or_critical,
)
from logintel.api.app import create_app
from logintel.api.auth import get_current_token


def test_severity_filter_strictly_gates_high_and_critical():
    """Verify that only HIGH, ALERT, and CRITICAL severities pass the gate."""
    assert is_high_or_critical("CRITICAL") is True
    assert is_high_or_critical("critical") is True
    assert is_high_or_critical("ALERT") is True
    assert is_high_or_critical("HIGH") is True
    assert is_high_or_critical("high") is True

    # Low, informational, notice, warning must be rejected
    assert is_high_or_critical("WARNING") is False
    assert is_high_or_critical("MEDIUM") is False
    assert is_high_or_critical("LOW") is False
    assert is_high_or_critical("NOTICE") is False
    assert is_high_or_critical("INFORMATIONAL") is False
    assert is_high_or_critical("INFO") is False
    assert is_high_or_critical("DEBUG") is False
    assert is_high_or_critical("") is False
    assert is_high_or_critical(None) is False


def test_telegram_message_formatter_includes_all_granular_details():
    """Verify format_telegram_alert incorporates every forensic detail into valid HTML."""
    payload = {
        "alert_id": 42,
        "rule_id": "auth.ssh_bruteforce",
        "rule_name": "SSH Multi-Host Credential Stuffing",
        "rule_description": "Detected excessive failed authentication attempts indicating an automated attack.",
        "rule_category": "AUTHENTICATION",
        "severity": "CRITICAL",
        "host": "prod-bastion-01",
        "status": "OPEN",
        "occurrence_count": 5,
        "first_seen": "2026-11-13T12:00:00Z",
        "last_seen": "2026-11-13T12:05:00Z",
        "summary": "SSH login failure spike from suspicious IP",
        "trigger_event": {
            "event_id": "evt-ssh-999",
            "timestamp": "2026-11-13T12:05:00Z",
            "event_type": "AUTH_LOGIN",
            "source": "auth.log",
            "severity": "CRITICAL",
            "action": "SSH_AUTH",
            "outcome": "FAILURE",
            "user": "root",
            "uid": 0,
            "terminal": "ssh:notty",
            "process_name": "sshd",
            "process_pid": 1337,
            "process_ppid": 1,
            "executable": "/usr/sbin/sshd",
            "command_line": "sshd: root [net]",
            "src_ip": "198.51.100.23",
            "src_port": 54321,
            "dst_ip": "10.0.0.1",
            "dst_port": 22,
            "protocol": "TCP",
            "raw_message": "Failed password for root from 198.51.100.23 port 54321 ssh2",
        },
    }

    formatted = format_telegram_alert(payload, delivery_id=1)

    # Validate header and severity badge
    assert "🚨" in formatted
    assert "[Prahari Security Alert: CRITICAL]" in formatted

    # Validate rule details
    assert "auth.ssh_bruteforce" in formatted
    assert "SSH Multi-Host Credential Stuffing" in formatted
    assert "AUTHENTICATION" in formatted
    assert "Detected excessive failed authentication attempts" in formatted

    # Validate host, status, and IDs
    assert "prod-bastion-01" in formatted
    assert "#42" in formatted
    assert "Occurrences: 5" in formatted

    # Validate trigger event granular forensic context
    assert "evt-ssh-999" in formatted
    assert "AUTH_LOGIN" in formatted
    assert "root (UID: 0) on ssh:notty" in formatted
    assert "sshd[PID: 1337, PPID: 1]" in formatted
    assert "/usr/sbin/sshd" in formatted
    assert "sshd: root [net]" in formatted
    assert "198.51.100.23:54321 ➔ 10.0.0.1:22 (TCP)" in formatted
    assert "FAILURE" in formatted
    assert "Failed password for root" in formatted


def test_telegram_dispatches_critical_and_filters_low():
    """Verify that publish() sends CRITICAL alerts to Telegram and filters out lower severities."""
    service = NotificationService(
        NotificationSettings(
            enabled=True,
            sink="telegram",
            telegram_bot_token="123456:TEST_TOKEN",
            telegram_chat_id="987654321",
        )
    )

    # 1. Informational / Warning should be marked FILTERED and make no network requests
    with patch("logintel.notifications.service.build_opener") as mock_opener:
        service.publish(
            event_type="alert.detected",
            resource_type="alert",
            resource_id="1",
            payload={"severity": "WARNING", "rule_id": "test.warning", "summary": "Low priority warning"},
        )
        # Allow thread pool execution
        service._executor.shutdown(wait=True)
        # Reset executor for next step
        from concurrent.futures import ThreadPoolExecutor
        service._executor = ThreadPoolExecutor(max_workers=1)

        deliveries = service.status()["recent_deliveries"]
        assert len(deliveries) == 1
        assert deliveries[0]["status"] == "FILTERED"
        assert "below HIGH/CRITICAL threshold" in deliveries[0]["detail"]
        mock_opener.assert_not_called()

    # 2. CRITICAL alert must trigger Telegram HTTP POST
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_opener_instance = MagicMock()
    mock_opener_instance.open.return_value.__enter__.return_value = mock_resp

    with patch("logintel.notifications.service.build_opener", return_value=mock_opener_instance):
        service.publish(
            event_type="alert.detected",
            resource_type="alert",
            resource_id="2",
            payload={
                "alert_id": 100,
                "severity": "CRITICAL",
                "rule_id": "privilege.sudo_abuse",
                "rule_name": "Sudo Privilege Abuse",
                "host": "workstation-1",
                "summary": "Unauthorized sudo execution",
            },
        )
        service._executor.shutdown(wait=True)

        deliveries = service.status()["recent_deliveries"]
        assert len(deliveries) == 2
        assert deliveries[1]["status"] == "DELIVERED"
        assert deliveries[1]["detail"] == "Sent to Telegram bot"

        # Verify endpoint called
        mock_opener_instance.open.assert_called_once()
        req = mock_opener_instance.open.call_args[0][0]
        assert req.full_url == "https://api.telegram.org/bot123456:TEST_TOKEN/sendMessage"
        sent_json = json.loads(req.data.decode("utf-8"))
        assert sent_json["chat_id"] == "987654321"
        assert sent_json["parse_mode"] == "HTML"
        assert "CRITICAL" in sent_json["text"]
        assert "privilege.sudo_abuse" in sent_json["text"]


def test_telegram_api_configuration_endpoint():
    """Verify POST /api/v1/system/notifications/telegram updates runtime settings safely."""
    app = create_app()
    client = TestClient(app)
    token = get_current_token()
    headers = {"Authorization": f"Bearer {token}"}

    # Query initial status
    status_resp = client.get("/api/v1/system/notifications", headers=headers)
    assert status_resp.status_code == 200
    assert "telegram_configured" in status_resp.json()

    # Configure Telegram credentials
    config_resp = client.post(
        "/api/v1/system/notifications/telegram",
        headers=headers,
        json={
            "bot_token": "9876543210:ABCdefGHIjklMNOpqrsTUVwxyz",
            "chat_id": "-1001234567890",
            "enabled": True,
        },
    )
    assert config_resp.status_code == 200
    data = config_resp.json()
    assert data["status"] == "ok"
    assert data["telegram_configured"] is True
    assert "***" in data["chat_id_masked"]

    # Verify updated status masks chat ID and conceals token
    updated_status = client.get("/api/v1/system/notifications", headers=headers).json()
    assert updated_status["telegram_configured"] is True
    assert updated_status["telegram_chat_id_masked"] == "-1***90"
    assert "9876543210" not in json.dumps(updated_status)  # Token is NEVER leaked in API responses


def test_detect_telegram_chat_id_endpoint(monkeypatch):
    """Verify POST /api/v1/system/notifications/telegram/detect auto-discovers chat IDs."""
    from logintel.notifications import notification_service

    # Mock detection response
    monkeypatch.setattr(
        notification_service,
        "detect_telegram_chat_id",
        lambda bot_token=None: {
            "found": True,
            "chat_id": "8778793394",
            "chat_title": "SecOps Analyst",
            "bot_username": "prhari_bot",
            "message": "Successfully detected chat with 'SecOps Analyst' (Chat ID: 8778793394)!",
        },
    )

    from fastapi.testclient import TestClient
    from logintel.api.app import app
    from logintel.api.auth import get_current_token

    client = TestClient(app)
    headers = {"Authorization": f"Bearer {get_current_token()}"}

    resp = client.post(
        "/api/v1/system/notifications/telegram/detect",
        headers=headers,
        json={"bot_token": "9086466678:AAFrur7YIuGzSuF2Ez4OQDdgayINAYkGJwk"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["found"] is True
    assert data["chat_id"] == "8778793394"
    assert data["bot_username"] == "prhari_bot"
