"""High-volume synthetic benchmark for Milestone M6.3: Advanced Identity & Session Continuity."""

import gc
import json
import os
import resource
import sqlite3
import tempfile
import time
from datetime import datetime, timedelta, timezone
from typing import List

from logintel.identity.models import IdentityContinuityChain
from logintel.identity.resolver import SessionContinuityResolver
from logintel.models import CanonicalEvent, EventType, Severity


def generate_synthetic_identity_events(count: int) -> List[CanonicalEvent]:
    """Generate realistic synthetic session and process execution events."""
    events: List[CanonicalEvent] = []
    base_ts = datetime(2026, 10, 6, 8, 0, 0, tzinfo=timezone.utc)

    # 10 sessions, each having login -> sudo -> executions
    num_sessions = max(1, count // 10)

    for s in range(num_sessions):
        sess_id = str(100 + s)
        user = f"analyst_{s % 20}"
        auid = str(1000 + (s % 20))
        remote_ip = f"192.168.1.{10 + (s % 100)}"

        # Login event
        ev_login = CanonicalEvent(
            id=f"bench-login-{s}",
            timestamp=base_ts + timedelta(seconds=s * 10),
            host="BenchmarkHost",
            source="auth.log",
            event_type=EventType.AUTH_LOGIN_SUCCESS,
            actor={"username": user, "session_id": sess_id, "terminal": f"pts/{s % 10}"},
            network={"src_ip": remote_ip, "src_port": 50000 + s},
            metadata={"auid": auid, "ses": sess_id, "service": "ssh"},
            summary=f"SSH login for {user}",
            raw_message=f"Accepted publickey for {user} from {remote_ip}",
        )
        events.append(ev_login)

        # Sudo elevation
        ev_sudo = CanonicalEvent(
            id=f"bench-sudo-{s}",
            timestamp=base_ts + timedelta(seconds=s * 10 + 2),
            host="BenchmarkHost",
            source="auth.log",
            event_type=EventType.SUDO_COMMAND,
            actor={"username": user, "session_id": sess_id, "terminal": f"pts/{s % 10}"},
            process={"name": "sudo", "command_line": "sudo -i"},
            metadata={
                "source_user": user,
                "target_user": "root",
                "transition_type": "SUDO",
                "is_privilege_transition": True,
                "ses": sess_id,
                "auid": auid,
            },
            summary=f"sudo -i by {user}",
            raw_message=f"sudo: {user} : COMMAND=/bin/bash",
        )
        events.append(ev_sudo)

        # Executions under root
        for k in range(8):
            ev_exec = CanonicalEvent(
                id=f"bench-exec-{s}-{k}",
                timestamp=base_ts + timedelta(seconds=s * 10 + 3 + k),
                host="BenchmarkHost",
                source="audit.log",
                event_type=EventType.PROCESS_EXECUTION,
                actor={"username": "root", "uid": 0, "session_id": sess_id, "terminal": f"pts/{s % 10}"},
                process={"name": f"cmd_{k}", "pid": 5000 + s * 10 + k, "command_line": f"cmd_{k} --opt"},
                metadata={"auid": auid, "ses": sess_id, "uid": 0, "euid": 0, "is_elevated": True},
                summary=f"cmd_{k} executed by root",
                raw_message=f"SYSCALL cmd_{k}",
            )
            events.append(ev_exec)
            if len(events) >= count:
                break
        if len(events) >= count:
            break

    return events[:count]


def run_identity_benchmark(count: int = 1000):
    """Run performance and memory benchmark for M6.3 identity resolution."""
    print(f"\n========================================================")
    print(f" LOGINTEL M6.3 IDENTITY & SESSION CONTINUITY BENCHMARK ")
    print(f" Synthetic events count: {count}")
    print(f"========================================================")

    gc.collect()
    mem_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    events = generate_synthetic_identity_events(count)
    resolver = SessionContinuityResolver()

    # Ingestion phase
    t0 = time.perf_counter()
    for ev in events:
        if ev.event_type in (EventType.AUTH_LOGIN_SUCCESS, EventType.AUDIT_SESSION_START, EventType.SESSION_OPEN):
            resolver.register_session_start(ev)
        elif ev.event_type in (EventType.AUTH_LOGOUT, EventType.AUDIT_SESSION_END, EventType.SESSION_CLOSE):
            resolver.register_session_end(ev)
    t1 = time.perf_counter()

    ingest_duration = t1 - t0
    ingest_throughput = count / ingest_duration if ingest_duration > 0 else float("inf")

    # Resolution phase: resolve identity continuity for all execution events
    exec_events = [e for e in events if e.event_type == EventType.PROCESS_EXECUTION]
    t2 = time.perf_counter()
    chains: List[IdentityContinuityChain] = []
    for ev in exec_events:
        c = resolver.resolve_identity_continuity(ev, all_events=events)
        chains.append(c)
    t3 = time.perf_counter()

    resolve_duration = t3 - t2
    resolve_throughput = len(exec_events) / resolve_duration if resolve_duration > 0 else float("inf")
    avg_latency_ms = (resolve_duration / len(exec_events) * 1000) if exec_events else 0.0

    gc.collect()
    mem_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    mem_delta_kb = mem_after - mem_before

    print(f" Ingestion Throughput: {ingest_throughput:.2f} eps ({ingest_duration*1000:.2f} ms total)")
    print(f" Provenance Resolution Throughput: {resolve_throughput:.2f} eps ({resolve_duration*1000:.2f} ms total)")
    print(f" Average Resolution Latency: {avg_latency_ms:.4f} ms / event")
    print(f" Memory Delta: {mem_delta_kb} KB")
    print(f" Resolved Chains Count: {len(chains)}")
    print(f" Observed Confidence Rate: {sum(1 for c in chains if c.epistemic_status == 'OBSERVED') / len(chains) * 100:.1f}%")
    print(f"========================================================\n")

    assert ingest_throughput >= 5000, "Ingestion throughput must exceed 5,000 eps"
    assert resolve_throughput >= 2000, "Resolution throughput must exceed 2,000 eps"
    assert avg_latency_ms < 1.0, "Average latency must be under 1ms"


if __name__ == "__main__":
    run_identity_benchmark(1000)
