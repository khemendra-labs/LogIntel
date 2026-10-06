"""Performance and memory benchmark for Host Threat Correlation (Milestone M6.9)."""

import resource
import time
from datetime import datetime, timezone
from logintel.correlation.host_threat import HostThreatCorrelator


def run_benchmark():
    correlator = HostThreatCorrelator()
    rusage_before = resource.getrusage(resource.RUSAGE_SELF)
    mem_before_kb = rusage_before.ru_maxrss

    n_events = 2000
    events = []
    base_ts = datetime.now(timezone.utc)

    event_types = [
        "AUTH_LOGIN_SUCCESS",
        "PROCESS_EXECUTION",
        "SUDO_COMMAND",
        "FILE_PERSISTENCE_DROP",
        "NETWORK_SOCKET_CONNECTION",
        "CONTAINER_SECURITY_ESCAPE_ATTEMPT",
    ]

    for i in range(n_events):
        ev_type = event_types[i % len(event_types)]
        events.append({
            "id": f"bench-ev-{i}",
            "host": "benchmark-host-01",
            "timestamp": base_ts.isoformat(),
            "username": f"user_{i % 10}",
            "process_name": "bash" if i % 4 == 0 else f"proc_{i % 20}",
            "process_executable": f"/tmp/tool_{i}" if i % 5 == 0 else f"/usr/bin/proc_{i % 20}",
            "process_command_line": "bash -i" if i % 4 == 0 else f"cmd_{i}",
            "dst_ip": f"198.51.100.{i % 254 + 1}",
            "dst_port": 4444 if i % 10 == 0 else 80,
            "event_type": ev_type,
            "summary": f"Benchmark event {i} type {ev_type}",
            "metadata": {
                "target_path": f"/etc/cron.d/job_{i % 10}",
                "container_id": f"cont_{i % 5}",
            },
        })

    alerts = [
        {
            "id": 1,
            "rule_id": "sec.reverse_shell_socket",
            "title": "Interactive Shell Outbound Socket",
            "severity": "CRITICAL",
            "host": "benchmark-host-01",
            "timestamp": base_ts.isoformat(),
        },
        {
            "id": 2,
            "rule_id": "sec.cron_persistence_tamper",
            "title": "Cron Persistence Modification",
            "severity": "WARNING",
            "host": "benchmark-host-01",
            "timestamp": base_ts.isoformat(),
        },
    ]

    t0 = time.perf_counter()
    assessment = correlator.correlate_host_telemetry(
        host="benchmark-host-01",
        events=events,
        alerts=alerts,
        incident_id=999,
    )
    elapsed = time.perf_counter() - t0

    rusage_after = resource.getrusage(resource.RUSAGE_SELF)
    mem_after_kb = rusage_after.ru_maxrss
    rss_delta_kb = mem_after_kb - mem_before_kb
    throughput = n_events / elapsed if elapsed > 0 else float("inf")

    print(f"=== M6.9 HOST THREAT CORRELATION BENCHMARK ===")
    print(f"Events processed: {n_events}")
    print(f"Alerts correlated: {len(alerts)}")
    print(f"Attack sequences detected: {len(assessment.attack_sequences)}")
    print(f"MITRE tactics observed: {len(assessment.mitre_tactics_observed)}")
    print(f"MITRE techniques observed: {len(assessment.mitre_techniques_observed)}")
    print(f"Overall threat score: {assessment.overall_threat_score:.1f}")
    print(f"Overall severity: {assessment.overall_severity.value}")
    print(f"Primary scenario: {assessment.primary_scenario}")
    print(f"Host graph nodes: {assessment.node_count}")
    print(f"Host graph edges: {assessment.edge_count}")
    print(f"Total time: {elapsed * 1000:.2f} ms")
    print(f"Throughput: {throughput:.2f} events/sec")
    print(f"RSS Memory Delta: {rss_delta_kb:.2f} KB")

    assert throughput > 5000, f"Expected >5,000 eps, got {throughput:.2f}"
    print("M6.9 Benchmark Passed Successfully!")


if __name__ == "__main__":
    run_benchmark()
