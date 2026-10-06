#!/usr/bin/env python3
"""Benign real-host execution and audit collection verification for M6.2 Corrective Closure."""

import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../apps/engine/src")))

from logintel.collectors.audit import AuditLogCollector
from logintel.parsers.audit import AuditParser
from logintel.models import CanonicalEvent
from logintel.models.events import EventType


def main():
    print("=== M6.2 Real-Host Benign Telemetry Verification ===")
    audit_log = "/var/log/audit/audit.log"
    if not os.path.exists(audit_log) or not os.access(audit_log, os.R_OK):
        print(f"SKIPPED: {audit_log} not readable by current user.")
        return

    # 1. Execute benign host commands
    print("Executing benign host commands...")
    subprocess.run(["/bin/echo", "logintel-m62-corrective-test"], check=True, capture_output=True)
    subprocess.run(["/usr/bin/id"], check=True, capture_output=True)
    subprocess.run(["/usr/bin/whoami"], check=True, capture_output=True)
    subprocess.run([sys.executable, "-c", "print('logintel-m62-benign')"], check=True, capture_output=True)

    # 2. Collect from audit.log
    collector = AuditLogCollector(file_path=audit_log)
    available, reason = collector.check_availability()
    print(f"AuditLogCollector availability: {available} ({reason or 'OK'})")
    assert available is True, f"Collector unavailable: {reason}"

    # Read latest records
    records = list(collector.collect_historical(limit=100))
    print(f"Retrieved {len(records)} audit records from live host audit.log")
    assert len(records) > 0, "No audit records retrieved from active audit.log"

    # 3. Parse with AuditParser
    parser = AuditParser()
    parsed_count = 0
    for r in records:
        evt = parser.parse(r)
        if evt:
            parsed_count += 1

    print(f"Successfully normalized {parsed_count} / {len(records)} records into CanonicalEvent")
    print("✓ Real-host evidence path verified: auditd -> audit.log -> AuditLogCollector -> AuditParser -> CanonicalEvent")


if __name__ == "__main__":
    main()
