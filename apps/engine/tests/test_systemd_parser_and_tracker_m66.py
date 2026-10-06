"""Unit tests for SystemdParser and SystemdUnitTracker (Milestone M6.6)."""

import pytest

from logintel.models import EventType, Outcome, RawRecord, Severity
from logintel.parsers.systemd import SystemdParser
from logintel.systemd.tracker import SystemdUnitTracker


def test_systemd_parser_started():
    """Verify parsing unit started message."""
    parser = SystemdParser()
    rec = RawRecord(
        source="systemd",
        raw_content="Oct 06 12:00:01 host systemd[1]: Started OpenBSD Secure Shell server.",
        raw_attributes={},
    )
    assert parser.can_parse(rec)
    ev = parser.parse(rec)
    assert ev is not None
    assert ev.event_type == EventType.SERVICE_STARTED
    assert ev.severity == Severity.NOTICE
    assert ev.outcome == Outcome.SUCCESS
    assert "OpenBSD Secure Shell server" in ev.summary
    assert ev.action == "UNIT_STARTED"


def test_systemd_parser_starting():
    """Verify parsing unit starting message."""
    parser = SystemdParser()
    rec = RawRecord(
        source="systemd",
        raw_content="Oct 06 12:00:00 host systemd[1]: Starting OpenBSD Secure Shell server...",
        raw_attributes={},
    )
    assert parser.can_parse(rec)
    ev = parser.parse(rec)
    assert ev is not None
    assert ev.event_type == EventType.SERVICE_STARTING
    assert ev.severity == Severity.INFORMATIONAL
    assert ev.action == "UNIT_STARTING"


def test_systemd_parser_stopping_and_stopped():
    """Verify parsing unit stopping and stopped messages."""
    parser = SystemdParser()
    rec_stop = RawRecord(
        source="systemd",
        raw_content="Oct 06 12:05:00 host systemd[1]: Stopping User Manager for UID 1000...",
    )
    ev_stop = parser.parse(rec_stop)
    assert ev_stop.event_type == EventType.SERVICE_STOPPING
    assert ev_stop.action == "UNIT_STOPPING"

    rec_stopped = RawRecord(
        source="systemd",
        raw_content="Oct 06 12:05:01 host systemd[1]: Stopped User Manager for UID 1000.",
    )
    ev_stopped = parser.parse(rec_stopped)
    assert ev_stopped.event_type == EventType.SERVICE_STOPPED
    assert ev_stopped.action == "UNIT_STOPPED"


def test_systemd_parser_failed():
    """Verify parsing unit failed to start message triggers Severity.ALERT."""
    parser = SystemdParser()
    rec = RawRecord(
        source="systemd",
        raw_content="Oct 06 12:10:00 host systemd[1]: Failed to start malicious.service.",
    )
    assert parser.can_parse(rec)
    ev = parser.parse(rec)
    assert ev is not None
    assert ev.event_type == EventType.SERVICE_FAILED
    assert ev.severity == Severity.ALERT
    assert ev.outcome == Outcome.FAILURE
    assert ev.action == "UNIT_FAILED"
    assert ev.metadata.get("unit_name") == "malicious.service"


def test_systemd_parser_reloaded():
    """Verify parsing unit reloaded message."""
    parser = SystemdParser()
    rec = RawRecord(
        source="syslog",
        raw_content="Oct 06 12:15:00 host systemd[1]: Reloaded nginx.service.",
    )
    ev = parser.parse(rec)
    assert ev is not None
    assert ev.event_type == EventType.SERVICE_RELOADED
    assert ev.action == "UNIT_RELOADED"


def test_systemd_parser_journald_attributes():
    """Verify parser extracts unit from journald structured attributes."""
    parser = SystemdParser()
    rec = RawRecord(
        source="journal",
        raw_content="Started apache2.service.",
        raw_attributes={"_SYSTEMD_UNIT": "apache2.service", "UNIT": "apache2.service"},
    )
    assert parser.can_parse(rec)
    ev = parser.parse(rec)
    assert ev is not None
    assert ev.metadata.get("unit_name") == "apache2.service"


def test_systemd_unit_tracker_live_or_fallback():
    """Verify tracker availability and unit query functionality."""
    tracker = SystemdUnitTracker()
    avail, err = tracker.check_availability()
    # On this Linux host, systemctl is available
    if avail:
        units = tracker.list_units(unit_type="service")
        assert isinstance(units, list)
        assert len(units) > 0
