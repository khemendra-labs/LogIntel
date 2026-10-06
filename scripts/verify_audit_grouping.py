#!/usr/bin/env python3
"""Forensic verification script for M6.2 multi-record audit grouping and raw evidence preservation (C03)."""

import os
import sys
import tempfile
from datetime import datetime, timezone

# Add engine src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../apps/engine/src")))

from logintel.collectors.audit import AuditLogCollector
from logintel.parsers.audit import AuditParser
from logintel.models import CanonicalEvent, EventType, RawRecord


def run_grouping_verification():
    print("=== M6.2 Multi-Record Audit Grouping & Raw Preservation Verification (C03) ===")

    with tempfile.TemporaryDirectory() as tmp_dir:
        # Case 1: Multi-record group with SYSCALL, EXECVE, CWD, PATH, PROCTITLE
        fixture_path = os.path.join(tmp_dir, "multi_record.log")
        with open(fixture_path, "w") as f:
            f.write(
                'type=SYSCALL msg=audit(1727700000.100:101): arch=c000003e syscall=59 success=yes exit=0 pid=1234 ppid=1000 auid=1000 uid=0 gid=0 exe="/usr/bin/cat"\n'
                'type=EXECVE msg=audit(1727700000.100:101): argc=2 a0="cat" a1="/etc/hosts"\n'
                'type=CWD msg=audit(1727700000.100:101): cwd="/home/user"\n'
                'type=PATH msg=audit(1727700000.100:101): item=0 name="/usr/bin/cat" nametype=NORMAL\n'
                'type=PROCTITLE msg=audit(1727700000.100:101): proctitle=636174002F6574632F686F737473\n'
                # Case 2: Same timestamp, different serial
                'type=SYSCALL msg=audit(1727700000.100:102): arch=c000003e syscall=59 success=yes exit=0 pid=1235 ppid=1000 exe="/bin/ls"\n'
                'type=EXECVE msg=audit(1727700000.100:102): argc=1 a0="ls"\n'
                # Case 3: Adjacent single-record non-syscall event
                'type=USER_START msg=audit(1727700000.200:103): pid=5000 uid=0 auid=1000 ses=5 msg=\'op=PAM:session_open acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/1 res=success\'\n'
            )

        collector = AuditLogCollector(file_path=fixture_path)
        records = list(collector.collect_historical())

        assert len(records) == 3, f"Expected 3 distinct records, got {len(records)}"

        # Verify Record 1 (Grouped SYSCALL + EXECVE + CWD + PATH + PROCTITLE)
        rec1 = records[0]
        lines1 = rec1.raw_content.splitlines()
        assert len(lines1) == 5, f"Expected 5 grouped lines, got {len(lines1)}"
        assert rec1.raw_attributes["audit_id"] == "1727700000.100:101"
        assert rec1.raw_attributes["contributing_records_count"] == 5
        print("  ✓ Case 1: 5 contributing records grouped under same audit_id (1727700000.100:101)")

        parser = AuditParser()
        ev1 = parser.parse(rec1)
        assert ev1 is not None
        assert ev1.event_type == EventType.PROCESS_EXECUTION
        assert ev1.process.pid == 1234
        assert ev1.process.ppid == 1000
        assert ev1.process.command_line == "cat /etc/hosts"
        assert ev1.raw_message == rec1.raw_content
        print("  ✓ Case 1 parsing: CanonicalEvent extracted, raw_message preserved verbatim (5 lines)")

        # Verify Record 2 (Same timestamp, different serial)
        rec2 = records[1]
        lines2 = rec2.raw_content.splitlines()
        assert len(lines2) == 2, f"Expected 2 lines for rec2, got {len(lines2)}"
        assert rec2.raw_attributes["audit_id"] == "1727700000.100:102"
        print("  ✓ Case 2: Same timestamp with different serial (102 vs 101) segregated cleanly")

        ev2 = parser.parse(rec2)
        assert ev2.process.pid == 1235
        assert ev2.process.command_line == "ls"
        print("  ✓ Case 2 parsing: CanonicalEvent separated with distinct PID 1235")

        # Verify Record 3 (Adjacent session event)
        rec3 = records[2]
        assert rec3.raw_attributes["audit_id"] == "1727700000.200:103"
        ev3 = parser.parse(rec3)
        assert ev3.event_type == EventType.AUDIT_SESSION_START
        print("  ✓ Case 3: Adjacent session event segregated with audit_id 1727700000.200:103")

    print("\nALL MULTI-RECORD AUDIT GROUPING AND RAW PRESERVATION CHECKS PASSED.")


if __name__ == "__main__":
    run_grouping_verification()
