"""Unit tests for Enhanced Kernel & Security Telemetry (Milestone M6.6)."""

import pytest

from logintel.models import EventType, Outcome, RawRecord, Severity
from logintel.parsers.kernel import KernelParser


def test_kernel_module_loaded():
    """Verify parsing standard kernel module load."""
    parser = KernelParser()
    rec = RawRecord(
        source="kern.log",
        raw_content="Oct 06 12:00:00 host kernel: [  123.456] loading module wireguard",
    )
    assert parser.can_parse(rec)
    ev = parser.parse(rec)
    assert ev is not None
    assert ev.event_type == EventType.KERNEL_MODULE_LOAD
    assert ev.severity == Severity.NOTICE
    assert "wireguard" in ev.summary


def test_kernel_module_loaded_out_of_tree_taints():
    """Verify out-of-tree module load raises Severity.ALERT."""
    parser = KernelParser()
    rec = RawRecord(
        source="kern.log",
        raw_content="Oct 06 12:01:00 host kernel: module: loading out-of-tree module taints kernel.",
    )
    assert parser.can_parse(rec)
    ev = parser.parse(rec)
    assert ev is not None
    assert ev.event_type == EventType.KERNEL_MODULE_LOAD
    assert ev.severity == Severity.ALERT
    assert "out-of-tree" in ev.summary


def test_kernel_module_unloaded():
    """Verify parsing kernel module unload."""
    parser = KernelParser()
    rec = RawRecord(
        source="kern.log",
        raw_content="Oct 06 12:02:00 host kernel: [  125.789] unloading module wireguard",
    )
    ev = parser.parse(rec)
    assert ev is not None
    assert ev.event_type == EventType.KERNEL_MODULE_UNLOAD
    assert ev.severity == Severity.NOTICE


def test_kernel_module_signature_verification_failure():
    """Verify module verification failure raises KERNEL_SECURITY_ANOMALY with Severity.ALERT."""
    parser = KernelParser()
    rec = RawRecord(
        source="kern.log",
        raw_content="Oct 06 12:03:00 host kernel: PKCS#7 signature not signed with a trusted key; module verification failed: signature and/or required key missing",
    )
    ev = parser.parse(rec)
    assert ev is not None
    assert ev.event_type == EventType.KERNEL_SECURITY_ANOMALY
    assert ev.severity == Severity.ALERT
    assert ev.outcome == Outcome.FAILURE


def test_kernel_promiscuous_mode_entered_and_left():
    """Verify network promiscuous mode entered raises ALERT and left raises NOTICE."""
    parser = KernelParser()
    rec_enter = RawRecord(
        source="kern.log",
        raw_content="Oct 06 12:04:00 host kernel: device eth0 entered promiscuous mode",
    )
    ev_enter = parser.parse(rec_enter)
    assert ev_enter.event_type == EventType.KERNEL_SECURITY_ANOMALY
    assert ev_enter.severity == Severity.ALERT
    assert "eth0" in ev_enter.summary

    rec_left = RawRecord(
        source="kern.log",
        raw_content="Oct 06 12:05:00 host kernel: device eth0 left promiscuous mode",
    )
    ev_left = parser.parse(rec_left)
    assert ev_left.event_type == EventType.KERNEL_SECURITY_ANOMALY
    assert ev_left.severity == Severity.NOTICE
