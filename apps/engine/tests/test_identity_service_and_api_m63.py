"""Tests for M6.3 IdentityService, end-to-end provenance linking, and API endpoints."""

from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from logintel.api.app import app
from logintel.api.auth import get_current_token
from logintel.identity.service import IdentityService
from logintel.models import CanonicalEvent, EventType, Outcome
from logintel.storage.db import Database
from logintel.storage.events_repo import EventsRepository


@pytest.fixture
def identity_test_setup(tmp_path):
    """Create isolated test database and populated events for identity chain testing."""
    db_path = tmp_path / "test_identity.db"
    test_db = Database(db_path)
    test_db.initialize()
    repo = EventsRepository(test_db)
    service = IdentityService(repository=repo)

    t0 = datetime(2026, 10, 6, 8, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 6, 8, 5, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 6, 8, 10, 0, tzinfo=timezone.utc)

    # 1. SSH login event
    ev_ssh = CanonicalEvent(
        id="ev-login-001",
        timestamp=t0,
        host="srv-prod-01",
        source="auth.log",
        event_type=EventType.AUTH_LOGIN_SUCCESS,
        actor={"username": "analyst_bob", "session_id": "77", "terminal": "pts/2"},
        network={"src_ip": "10.10.10.25", "src_port": 51234},
        metadata={"auid": "1002", "ses": "77", "service": "ssh", "auth_method": "publickey"},
        summary="SSH authentication success for user 'analyst_bob' from 10.10.10.25",
        raw_message="Accepted publickey for analyst_bob from 10.10.10.25 port 51234 ssh2",
    )

    # 2. Sudo command elevation
    ev_sudo = CanonicalEvent(
        id="ev-sudo-002",
        timestamp=t1,
        host="srv-prod-01",
        source="auth.log",
        event_type=EventType.SUDO_COMMAND,
        actor={"username": "analyst_bob", "uid": 1002, "session_id": "77", "terminal": "pts/2"},
        process={"name": "sudo", "executable": "/usr/bin/sudo", "command_line": "sudo su -"},
        metadata={
            "target_user": "root",
            "source_user": "analyst_bob",
            "transition_type": "SUDO",
            "is_privilege_transition": True,
            "ses": "77",
            "auid": "1002",
        },
        summary="User 'analyst_bob' executed privileged command 'sudo su -' as 'root'",
        raw_message="sudo: analyst_bob : TTY=pts/2 ; USER=root ; COMMAND=/bin/su -",
    )

    # 3. Root execution of sensitive tool
    ev_root_exec = CanonicalEvent(
        id="ev-root-003",
        timestamp=t2,
        host="srv-prod-01",
        source="audit.log",
        event_type=EventType.PROCESS_EXECUTION,
        actor={"username": "root", "uid": 0, "session_id": "77", "terminal": "pts/2"},
        process={"name": "nmap", "pid": 9876, "executable": "/usr/bin/nmap", "command_line": "nmap -sS 192.168.1.0/24"},
        metadata={
            "auid": "1002",
            "ses": "77",
            "euid": 0,
            "uid": 0,
            "is_elevated": True,
            "target_user": "root",
        },
        summary="Process execution: 'nmap' (PID: 9876) executed by 'root' (AUID: 1002): nmap -sS 192.168.1.0/24",
        raw_message="type=SYSCALL pid=9876 uid=0 auid=1002 ses=77 exe=\"/usr/bin/nmap\"",
    )

    repo.insert_events([ev_ssh, ev_sudo, ev_root_exec])

    return {
        "service": service,
        "repo": repo,
        "test_db": test_db,
        "root_event_id": ev_root_exec.id,
        "session_id": "77",
    }


def test_identity_service_resolves_full_provenance(identity_test_setup):
    """Verify IdentityService links root execution back through sudo to original SSH login."""
    service = identity_test_setup["service"]
    root_id = identity_test_setup["root_event_id"]

    chain = service.get_identity_chain_for_event(root_id)
    assert chain is not None
    assert chain.effective_user == "root"
    assert chain.effective_uid == 0
    assert chain.login_user == "analyst_bob"
    assert chain.login_auid == "1002"
    assert chain.session_id == "77"
    assert chain.remote_ip == "10.10.10.25"
    assert chain.terminal == "pts/2"
    assert chain.epistemic_status == "OBSERVED"
    assert "analyst_bob" in chain.narrative
    assert "root" in chain.narrative
    assert "nmap" in chain.narrative


def test_identity_service_get_session_details(identity_test_setup):
    """Verify IdentityService aggregates full session lifecycle and execution history."""
    service = identity_test_setup["service"]
    sess_id = identity_test_setup["session_id"]

    details = service.get_session_details(sess_id)
    assert details is not None
    assert details["session_id"] == "77"
    assert details["host"] == "srv-prod-01"
    assert details["login_user"] == "analyst_bob"
    assert details["remote_ip"] == "10.10.10.25"
    assert len(details["processes"]) >= 1
    assert any(p["name"] == "nmap" for p in details["processes"])
    assert len(details["privilege_transitions"]) >= 1
    assert details["privilege_transitions"][0]["transition_type"] == "SUDO"


def test_api_identity_chain_and_session_endpoints(identity_test_setup, monkeypatch):
    """Verify FastAPI routes expose identity chain and session inspection."""
    import logintel.identity.service as id_svc_mod
    monkeypatch.setattr(id_svc_mod, "identity_service", identity_test_setup["service"])

    import logintel.api.routes as routes_mod
    monkeypatch.setattr(routes_mod, "events_repo", identity_test_setup["repo"])

    from logintel.storage.investigation_repo import InvestigationRepository
    test_inv_repo = InvestigationRepository(identity_test_setup["test_db"])
    import sys
    inv_mod = sys.modules.get("logintel.storage.investigation_repo")
    if inv_mod:
        monkeypatch.setattr(inv_mod, "investigation_repo", test_inv_repo)

    client = TestClient(app)
    token = get_current_token()
    headers = {"Authorization": f"Bearer {token}"}

    root_id = identity_test_setup["root_event_id"]
    sess_id = identity_test_setup["session_id"]

    # 1. Test identity chain endpoint
    res = client.get(f"/api/v1/investigations/events/{root_id}/identity-chain", headers=headers)
    assert res.status_code == 200
    chain_data = res.json()
    assert chain_data["effective_user"] == "root"
    assert chain_data["login_user"] == "analyst_bob"
    assert chain_data["login_auid"] == "1002"
    assert chain_data["session_id"] == "77"
    assert chain_data["epistemic_status"] == "OBSERVED"

    # 2. Test session details endpoint
    res_sess = client.get(f"/api/v1/investigations/sessions/{sess_id}", headers=headers)
    assert res_sess.status_code == 200
    sess_data = res_sess.json()
    assert sess_data["session_id"] == "77"
    assert sess_data["login_user"] == "analyst_bob"
    assert len(sess_data["processes"]) >= 1

    # 3. Test event inspection with enriched identity chain
    res_inspect = client.get(f"/api/v1/investigations/events/{root_id}/inspect", headers=headers)
    assert res_inspect.status_code == 200
    inspect_data = res_inspect.json()
    assert "identity_chain" in inspect_data
    assert inspect_data["identity_chain"]["login_user"] == "analyst_bob"
