"""Test suite for Real-World Host Validation & Adversary Emulation (Milestone M6.10)."""

from fastapi.testclient import TestClient
import pytest

from logintel.api.app import app
from logintel.api.auth import get_current_token
from logintel.validation.host_emulator import (
    EmulatedScenarioType,
    HostScenarioEmulator,
    LiveHostValidator,
)


@pytest.fixture
def auth_headers():
    token = get_current_token()
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client():
    return TestClient(app)


def test_live_host_validator_readiness():
    """Verify LiveHostValidator non-destructively inspects host interfaces."""
    validator = LiveHostValidator()
    readiness = validator.check_host_readiness()
    assert isinstance(readiness, dict)
    assert "audit_log" in readiness
    assert "proc_net_tcp" in readiness
    assert "cron_dir" in readiness
    assert "systemd_dir" in readiness


def test_host_scenario_emulator_events_generation():
    """Verify HostScenarioEmulator generates well-formed CanonicalEvents for all scenarios."""
    emulator = HostScenarioEmulator()
    for sc_type in EmulatedScenarioType:
        events = emulator.generate_scenario_events(scenario_type=sc_type, host="test-host-01")
        assert len(events) >= 3
        assert all(ev.host == "test-host-01" for ev in events)
        assert all(ev.id.startswith("e2e-") for ev in events)


def test_host_scenario_emulation_web_shell():
    """Verify Web Shell to Root Escalation & Cron Persistence scenario passes end-to-end."""
    emulator = HostScenarioEmulator()
    result = emulator.emulate_scenario(
        scenario_type=EmulatedScenarioType.WEB_SHELL_PRIV_ESC_CRON,
        host="test-host-ws",
    )
    assert result.passed is True
    assert result.events_generated == 5
    assert result.detections_triggered >= 2
    assert "sec.reverse_shell_socket" in result.rule_ids_triggered
    assert "sec.cron_persistence_tamper" in result.rule_ids_triggered
    assert result.overall_threat_score >= 80.0
    assert result.epistemic_confidence == 1.0


def test_host_scenario_emulation_container_escape():
    """Verify Container Breakout & Host C2 Channel scenario passes end-to-end."""
    emulator = HostScenarioEmulator()
    result = emulator.emulate_scenario(
        scenario_type=EmulatedScenarioType.CONTAINER_ESCAPE_C2,
        host="test-host-ce",
    )
    assert result.passed is True
    assert result.events_generated == 4
    assert result.detections_triggered >= 3
    assert "sec.container_escape_attempt" in result.rule_ids_triggered
    assert "sec.memory_execution" in result.rule_ids_triggered
    assert "sec.systemd_persistence_drop" in result.rule_ids_triggered
    assert result.overall_threat_score >= 90.0
    assert result.epistemic_confidence == 1.0


def test_host_scenario_emulation_mem_exec():
    """Verify In-Memory Stealth Execution & Backdoor Listener scenario passes end-to-end."""
    emulator = HostScenarioEmulator()
    result = emulator.emulate_scenario(
        scenario_type=EmulatedScenarioType.MEM_EXEC_BACKDOOR_LISTENER,
        host="test-host-me",
    )
    assert result.passed is True
    assert result.events_generated == 3
    assert result.detections_triggered >= 3
    assert "sec.kernel_module_tampering" in result.rule_ids_triggered
    assert "sec.suspicious_listening_socket" in result.rule_ids_triggered
    assert "sec.ssh_authorized_keys_tamper" in result.rule_ids_triggered
    assert result.overall_threat_score >= 70.0


def test_host_validation_suite_run():
    """Verify complete validation suite execution."""
    emulator = HostScenarioEmulator()
    report = emulator.run_full_validation_suite(host="test-suite-01")
    assert report.total_scenarios == 3
    assert report.passed_scenarios == 3
    assert report.overall_passed is True
    assert "Linux" in report.platform


def test_api_system_host_validation(client, auth_headers):
    """Verify GET /api/v1/system/host-validation returns report."""
    res = client.get("/api/v1/system/host-validation", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["total_scenarios"] == 3
    assert data["overall_passed"] is True
    assert len(data["scenario_results"]) == 3


def test_api_system_host_validation_emulate_endpoint(client, auth_headers):
    """Verify POST /api/v1/system/host-validation/emulate executes scenario."""
    payload = {
        "scenario_type": "web_shell_priv_esc_cron",
        "host": "api-host-01",
    }
    res = client.post("/api/v1/system/host-validation/emulate", json=payload, headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["scenario_type"] == "web_shell_priv_esc_cron"
    assert data["passed"] is True
    assert data["overall_threat_score"] >= 80.0


def test_api_system_host_validation_emulate_invalid_type(client, auth_headers):
    """Verify POST /api/v1/system/host-validation/emulate rejects invalid scenario type."""
    payload = {
        "scenario_type": "non_existent_exploit",
        "host": "api-host-01",
    }
    res = client.post("/api/v1/system/host-validation/emulate", json=payload, headers=auth_headers)
    assert res.status_code == 400
    assert "invalid scenario type" in res.json()["detail"].lower()
