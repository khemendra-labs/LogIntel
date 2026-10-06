"""Determinism Certification Test Suite for Container & Namespace Telemetry (Milestone M6.7).

Verifies that 10 consecutive evaluations of parsing container lifecycle and security records
produce 100% bit-for-bit identical results and digests.
"""

import hashlib
import json
import pytest

from logintel.models import RawRecord
from logintel.parsers.container import ContainerParser


def test_container_telemetry_determinism():
    """Verify bit-for-bit determinism across 10 repetitions."""
    parser = ContainerParser()

    records = [
        RawRecord(source="docker", raw_content="dockerd[1]: Container 111122223333 created"),
        RawRecord(source="docker", raw_content="dockerd[1]: Container 111122223333 started"),
        RawRecord(source="docker", raw_content="dockerd[1]: Container 111122223333 started in privileged mode"),
        RawRecord(source="docker", raw_content="dockerd[1]: Container 111122223333 stopped"),
        RawRecord(source="docker", raw_content="dockerd[1]: Container 111122223333 died"),
        RawRecord(source="docker", raw_content="dockerd[1]: Container 111122223333 killed"),
        RawRecord(source="docker", raw_content="dockerd[1]: Container 111122223333 attempted escape from namespace"),
    ]

    run_hashes = []

    for iteration in range(10):
        events_data = []
        for r in records:
            if parser.can_parse(r):
                ev = parser.parse(r)
                if ev:
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

    assert len(set(run_hashes)) == 1, f"Determinism failure: observed multiple hashes: {set(run_hashes)}"
