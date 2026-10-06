"""Determinism test suite for Host Threat Correlation (Milestone M6.9)."""

import hashlib
import json
from datetime import datetime, timezone
import pytest

from logintel.correlation.host_threat import HostThreatCorrelator


def _create_synthetic_multi_stage_dataset():
    base_ts = datetime(2026, 10, 6, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        {
            "id": "ev-01",
            "host": "srv-finance-01",
            "timestamp": base_ts.isoformat(),
            "username": "attacker",
            "event_type": "AUTH_LOGIN_SUCCESS",
            "source": "auth",
            "summary": "Successful SSH login for attacker from 198.51.100.12",
        },
        {
            "id": "ev-02",
            "host": "srv-finance-01",
            "timestamp": "2026-10-06T10:02:00+00:00",
            "username": "attacker",
            "process_name": "sudo",
            "process_command_line": "sudo bash",
            "event_type": "SUDO_COMMAND",
            "source": "sudo",
            "summary": "Elevated root shell spawned via sudo",
        },
        {
            "id": "ev-03",
            "host": "srv-finance-01",
            "timestamp": "2026-10-06T10:04:00+00:00",
            "username": "root",
            "process_name": "miner",
            "process_executable": "/dev/shm/.miner",
            "event_type": "PROCESS_EXECUTION",
            "source": "auditd",
            "summary": "In-memory process executed from /dev/shm",
        },
        {
            "id": "ev-04",
            "host": "srv-finance-01",
            "timestamp": "2026-10-06T10:06:00+00:00",
            "username": "root",
            "process_name": "bash",
            "dst_ip": "198.51.100.200",
            "dst_port": 4444,
            "event_type": "NETWORK_SOCKET_CONNECTION",
            "source": "procfs",
            "summary": "Bash shell established reverse socket to 198.51.100.200:4444",
        },
        {
            "id": "ev-05",
            "host": "srv-finance-01",
            "timestamp": "2026-10-06T10:08:00+00:00",
            "username": "root",
            "event_type": "FILE_PERSISTENCE_DROP",
            "source": "inotify",
            "summary": "Cron task dropped: /etc/cron.d/persist",
            "metadata": {"target_path": "/etc/cron.d/persist"},
        },
    ]

    alerts = [
        {
            "id": 101,
            "rule_id": "sec.reverse_shell_socket",
            "title": "Interactive Shell Outbound Socket Connection",
            "severity": "CRITICAL",
            "host": "srv-finance-01",
            "timestamp": "2026-10-06T10:06:00+00:00",
        }
    ]

    return events, alerts


def test_host_threat_correlation_bit_for_bit_determinism():
    """Verify 10 repeated correlation runs generate bit-for-bit identical hashes and stage sequences."""
    events, alerts = _create_synthetic_multi_stage_dataset()
    correlator = HostThreatCorrelator()

    hashes = []
    scores = []
    scenarios = []

    for _ in range(10):
        assessment = correlator.correlate_host_telemetry(
            host="srv-finance-01",
            events=events,
            alerts=alerts,
            incident_id=50,
        )

        data = assessment.model_dump(mode="json")
        # Freeze assessed_at to evaluate payload determinism
        data["assessed_at"] = "2026-10-06T12:00:00Z"

        serialized = json.dumps(data, sort_keys=True)
        h = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

        hashes.append(h)
        scores.append(assessment.overall_threat_score)
        scenarios.append(assessment.primary_scenario)

    assert len(set(hashes)) == 1, f"Found divergent hashes: {set(hashes)}"
    assert len(set(scores)) == 1, "Threat score fluctuated across runs"
    assert len(set(scenarios)) == 1, "Scenario classification fluctuated across runs"
    assert scores[0] >= 80.0
    assert scenarios[0] == "Privilege Escalation & Persistence Establishment"
