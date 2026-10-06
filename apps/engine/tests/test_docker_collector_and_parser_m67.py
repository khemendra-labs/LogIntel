"""Unit tests for DockerSocketCollector and ContainerParser (Milestone M6.7)."""

import pytest
from logintel.containers.docker_collector import DockerSocketCollector
from logintel.containers.models import ContainerLifecycleEvent, ContainerRuntime
from logintel.models import EventType, Outcome, RawRecord, Severity
from logintel.parsers.container import ContainerParser


def test_docker_socket_collector_availability_check():
    """Verify DockerSocketCollector handles existing or unprivileged socket gracefully."""
    col = DockerSocketCollector()
    avail, reason = col.check_availability()
    # On this host, socket exists but user is unprivileged (group docker required)
    assert isinstance(avail, bool)
    if not avail:
        assert reason is not None
        assert "docker" in reason.lower() or "socket" in reason.lower()


def test_docker_socket_collector_canonical_event_creation():
    """Verify DockerSocketCollector creates structured CanonicalEvents from lifecycle events."""
    col = DockerSocketCollector()

    ev_start = ContainerLifecycleEvent(
        container_id="112233445566",
        container_name="web-svc",
        action="start",
        image="nginx:latest",
        privileged=False,
    )
    canon_start = col.create_canonical_event(ev_start)
    assert canon_start.event_type == EventType.CONTAINER_LIFECYCLE_START
    assert canon_start.severity == Severity.NOTICE
    assert "112233445566" in canon_start.iocs

    ev_priv = ContainerLifecycleEvent(
        container_id="998877665544",
        container_name="privileged-agent",
        action="start",
        image="danger:root",
        privileged=True,
    )
    canon_priv = col.create_canonical_event(ev_priv)
    assert canon_priv.event_type == EventType.CONTAINER_LIFECYCLE_START
    assert canon_priv.severity == Severity.ALERT
    assert "PRIVILEGED" in canon_priv.summary


def test_container_parser_started():
    """Verify ContainerParser handles standard container start logs."""
    parser = ContainerParser()
    rec = RawRecord(
        source="docker",
        raw_content="dockerd[1234]: Container 1a2b3c4d5e6f started",
    )
    assert parser.can_parse(rec)
    ev = parser.parse(rec)
    assert ev is not None
    assert ev.event_type == EventType.CONTAINER_LIFECYCLE_START
    assert ev.severity == Severity.NOTICE
    assert "1a2b3c4d5e6f" in ev.summary


def test_container_parser_privileged_started():
    """Verify ContainerParser flags privileged container start with Severity.ALERT."""
    parser = ContainerParser()
    rec = RawRecord(
        source="docker",
        raw_content="dockerd[1234]: Container 1a2b3c4d5e6f started in privileged mode",
    )
    ev = parser.parse(rec)
    assert ev is not None
    assert ev.event_type == EventType.CONTAINER_LIFECYCLE_START
    assert ev.severity == Severity.ALERT


def test_container_parser_died_and_killed():
    """Verify ContainerParser handles die and kill events."""
    parser = ContainerParser()
    r_die = RawRecord(source="docker", raw_content="dockerd[1234]: Container worker-node died")
    ev_die = parser.parse(r_die)
    assert ev_die.event_type == EventType.CONTAINER_LIFECYCLE_DIE
    assert ev_die.severity == Severity.WARNING
    assert ev_die.outcome == Outcome.FAILURE

    r_kill = RawRecord(source="docker", raw_content="dockerd[1234]: Container worker-node killed")
    ev_kill = parser.parse(r_kill)
    assert ev_kill.event_type == EventType.CONTAINER_LIFECYCLE_KILL
    assert ev_kill.severity == Severity.WARNING


def test_container_parser_breakout_escape_attempt():
    """Verify breakout/escape telemetry triggers CONTAINER_SECURITY_ESCAPE_ATTEMPT."""
    parser = ContainerParser()
    rec = RawRecord(
        source="docker",
        raw_content="dockerd[1234]: Container exploit-pod attempted namespace escape via procfs",
    )
    ev = parser.parse(rec)
    assert ev.event_type == EventType.CONTAINER_SECURITY_ESCAPE_ATTEMPT
    assert ev.severity == Severity.ALERT
    assert ev.outcome == Outcome.FAILURE
