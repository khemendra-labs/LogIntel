"""Determinism certification test suite for Milestone M6.2: Linux Process & Execution Telemetry."""

from datetime import datetime, timezone
import hashlib
import json
import pytest

from logintel.collectors.audit import AuditLogCollector
from logintel.correlation.ancestry import ProcessAncestryResolver
from logintel.models import CanonicalEvent, EventType, RawRecord
from logintel.parsers.audit import AuditParser


def test_audit_synthesis_determinism_10_runs():
    """Verify 10 repeated parses on multi-record audit input yield identical SHA-256 fingerprints."""
    raw = (
        'type=SYSCALL msg=audit(1791255901.300:699): arch=c000003e syscall=1 success=yes exit=1 '
        'items=0 ppid=1572 pid=75899 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 '
        'tty=(none) ses=12 comm="cron" exe="/usr/sbin/cron" subj=unconfined key=(null)\n'
        'type=PROCTITLE msg=audit(1791255901.300:699): proctitle=2F7573722F7362696E2F43524F4E002D66002D50'
    )
    rec = RawRecord(
        source="audit.log",
        raw_content=raw,
        host="Khemendra-labs",
        source_file="/var/log/audit/audit.log",
        source_offset="12345",
    )
    parser = AuditParser()

    fingerprints = set()
    semantic_hashes = set()

    for i in range(10):
        event = parser.parse(rec)
        assert event is not None
        fp = event.compute_fingerprint()
        fingerprints.add(fp)

        # Compute semantic payload hash
        semantic_payload = json.dumps(
            {
                "event_type": event.event_type.value,
                "process_name": event.process.name,
                "process_pid": event.process.pid,
                "process_ppid": event.process.ppid,
                "process_cmdline": event.process.command_line,
                "username": event.actor.username,
                "uid": event.actor.uid,
                "session_id": event.actor.session_id,
                "summary": event.summary,
                "metadata": event.metadata,
            },
            sort_keys=True,
        )
        h = hashlib.sha256(semantic_payload.encode("utf-8")).hexdigest()
        semantic_hashes.add(h)

    assert len(fingerprints) == 1, "Event fingerprint must be 100% deterministic across 10 runs"
    assert len(semantic_hashes) == 1, "Semantic payload hash must be 100% deterministic across 10 runs"


def test_ancestry_determinism_10_runs():
    """Verify 10 repeated ancestry resolutions on identical input yield identical trees."""
    t0 = datetime(2026, 10, 6, 8, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 6, 8, 0, 1, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 6, 8, 0, 2, tzinfo=timezone.utc)

    e1 = CanonicalEvent(timestamp=t0, host="h1", source="audit.log", event_type=EventType.PROCESS_EXECUTION, process={"name": "init", "pid": 1, "ppid": None}, summary="init", raw_message="init")
    e2 = CanonicalEvent(timestamp=t1, host="h1", source="audit.log", event_type=EventType.PROCESS_EXECUTION, process={"name": "bash", "pid": 100, "ppid": 1}, summary="bash", raw_message="bash")
    e3 = CanonicalEvent(timestamp=t2, host="h1", source="audit.log", event_type=EventType.PROCESS_EXECUTION, process={"name": "grep", "pid": 200, "ppid": 100}, summary="grep", raw_message="grep")

    events = [e1, e2, e3]
    trees = set()

    for i in range(10):
        chain = ProcessAncestryResolver.resolve_ancestry_from_events(e3, events)
        rendered = chain.format_tree()
        trees.add(rendered)

    assert len(trees) == 1, "Process ancestry tree representation must be strictly deterministic"
