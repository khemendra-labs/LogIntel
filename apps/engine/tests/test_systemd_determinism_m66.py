"""Determinism Certification Test Suite for Systemd & Kernel Telemetry (Milestone M6.6).

Verifies that 10 consecutive evaluations of parsing systemd lifecycle and kernel telemetry
batches produce 100% bit-for-bit identical results and digests.
"""

import hashlib
import json
import pytest

from logintel.models import RawRecord
from logintel.parsers.kernel import KernelParser
from logintel.parsers.systemd import SystemdParser


def test_systemd_and_kernel_determinism():
    """Verify bit-for-bit determinism across 10 repetitions."""
    sys_parser = SystemdParser()
    kern_parser = KernelParser()

    records = [
        RawRecord(source="syslog", raw_content="Oct 06 12:00:01 host systemd[1]: Starting OpenBSD Secure Shell server..."),
        RawRecord(source="syslog", raw_content="Oct 06 12:00:02 host systemd[1]: Started OpenBSD Secure Shell server."),
        RawRecord(source="syslog", raw_content="Oct 06 12:05:00 host systemd[1]: Failed to start malicious.service."),
        RawRecord(source="syslog", raw_content="Oct 06 12:10:00 host systemd[1]: Reloaded nginx.service."),
        RawRecord(source="kern.log", raw_content="Oct 06 12:15:00 host kernel: loading out-of-tree module taints kernel."),
        RawRecord(source="kern.log", raw_content="Oct 06 12:20:00 host kernel: device eth0 entered promiscuous mode"),
    ]

    run_hashes = []

    for iteration in range(10):
        events_data = []
        for r in records:
            if sys_parser.can_parse(r):
                ev = sys_parser.parse(r)
            elif kern_parser.can_parse(r):
                ev = kern_parser.parse(r)
            else:
                continue

            events_data.append({
                "type": ev.event_type.value,
                "severity": ev.severity.value,
                "action": ev.action,
                "summary": ev.summary,
                "fp": ev.compute_fingerprint(),
                "iocs": sorted(ev.iocs),
            })

        serialized = json.dumps(events_data, sort_keys=True)
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        run_hashes.append(digest)

    # Certification: All 10 repetitions produced the exact same hash
    assert len(set(run_hashes)) == 1, f"Determinism failure: observed multiple hashes: {set(run_hashes)}"
