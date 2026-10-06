"""Integration test proving the complete end-to-end audit process evidence chain for M6.2."""

from datetime import datetime, timezone
import json
import sqlite3
import pytest

from logintel.collectors.audit import AuditLogCollector
from logintel.correlation.ancestry import ProcessAncestryResolver
from logintel.models import CanonicalEvent, EventType, Outcome, RawRecord, Severity
from logintel.parsers.audit import AuditParser
from logintel.storage.events_repo import EventsRepository


def test_m62_end_to_end_evidence_chain(tmp_path):
    """Verify complete evidence chain from raw audit record to SQLite, ancestry, and investigation evidence."""
    db_file = tmp_path / "forensic_test.db"
    conn = sqlite3.connect(str(db_file))
    conn.execute(
        """
        CREATE TABLE events (
            id TEXT PRIMARY KEY,
            event_fingerprint TEXT UNIQUE,
            timestamp TEXT NOT NULL,
            ingested_at TEXT NOT NULL,
            host TEXT NOT NULL,
            source TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            username TEXT,
            uid INTEGER,
            session_id TEXT,
            terminal TEXT,
            process_name TEXT,
            process_pid INTEGER,
            process_ppid INTEGER,
            process_executable TEXT,
            process_command_line TEXT,
            src_ip TEXT,
            src_port INTEGER,
            dst_ip TEXT,
            dst_port INTEGER,
            protocol TEXT,
            action TEXT,
            outcome TEXT NOT NULL,
            summary TEXT NOT NULL,
            raw_message TEXT NOT NULL,
            iocs_json TEXT NOT NULL DEFAULT '[]',
            parser TEXT NOT NULL,
            source_file TEXT,
            source_offset TEXT,
            metadata_json TEXT NOT NULL DEFAULT '{}'
        );
        """
    )
    conn.commit()
    conn.close()

    # Step 1: Raw Audit Records (Simulating parent bash spawning nmap)
    audit_parent_raw = (
        'type=SYSCALL msg=audit(1620000000.100:101): arch=c000003e syscall=59 success=yes exit=0 '
        'ppid=1 pid=5000 auid=1000 uid=1000 gid=1000 euid=1000 ses=3 comm="bash" exe="/bin/bash" tty=pts0\n'
        'type=EXECVE msg=audit(1620000000.100:101): argc=1 a0="/bin/bash"'
    )
    audit_child_raw = (
        'type=SYSCALL msg=audit(1620000000.200:102): arch=c000003e syscall=59 success=yes exit=0 '
        'ppid=5000 pid=5001 auid=1000 uid=1000 gid=1000 euid=1000 ses=3 comm="nmap" exe="/usr/bin/nmap" tty=pts0\n'
        'type=EXECVE msg=audit(1620000000.200:102): argc=4 a0="nmap" a1="-sS" a2="--password=secret123" a3="192.168.1.1"'
    )

    # Step 2: Ingestion & Normalization via AuditParser
    parser = AuditParser()
    rec_parent = RawRecord(source="audit.log", raw_content=audit_parent_raw, host="Ubuntu-TestHost", source_offset="0")
    rec_child = RawRecord(source="audit.log", raw_content=audit_child_raw, host="Ubuntu-TestHost", source_offset="200")

    ev_parent = parser.parse(rec_parent)
    ev_child = parser.parse(rec_child)

    assert ev_parent is not None
    assert ev_child is not None

    # Step 3: Fingerprinting & Credential Masking Verification
    fp_parent = ev_parent.compute_fingerprint()
    fp_child = ev_child.compute_fingerprint()
    assert len(fp_parent) == 64 and len(fp_child) == 64
    assert "[MASKED]" in ev_child.process.command_line
    assert "secret123" not in ev_child.process.command_line
    assert "secret123" in ev_child.raw_message  # Raw evidence preserved intact

    # Step 4: Storage in SQLite
    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()
    for ev in [ev_parent, ev_child]:
        row = ev.to_db_row()
        cols = ", ".join(row.keys())
        placeholders = ", ".join(f":{k}" for k in row.keys())
        cur.execute(f"INSERT OR IGNORE INTO events ({cols}) VALUES ({placeholders})", row)
    conn.commit()

    count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert count == 2

    # Step 5: Process Ancestry Graph Synthesis
    chain = ProcessAncestryResolver.resolve_ancestry_from_events(ev_child, [ev_parent, ev_child])
    assert chain.target_pid == 5001
    assert len(chain.chain) == 2
    assert chain.chain[0].pid == 5001
    assert chain.chain[0].name == "nmap"
    assert chain.chain[1].pid == 5000
    assert chain.chain[1].name == "bash"
    assert chain.chain[1].relationship_to_child == "SPAWNED"
    assert chain.chain[1].confidence == "DIRECT"
    assert chain.chain[1].epistemic_status == "OBSERVED"

    # Step 6: Investigation Evidence Citation
    evidence_tag = f"[proc:{ev_child.host}:{ev_child.process.pid}:{ev_child.id}]"
    assert "Ubuntu-TestHost:5001" in evidence_tag
    conn.close()
