"""Command-line interface for running deterministic historical detection replays."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime

from logintel.detection.replay import HistoricalReplayHarness, ReplayConfig
from logintel.storage.db import db


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="LogIntel Historical Detection Replay & Regression Harness",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--rule-id", action="append", help="Filter by specific rule ID(s)")
    parser.add_argument("--category", help="Filter rules by category (AUTH, PRIVILEGE, PROCESS, ACCOUNT, NETWORK)")
    parser.add_argument("--host", help="Filter events by host")
    parser.add_argument("--max-events", type=int, default=10000, help="Maximum events to evaluate")
    parser.add_argument("--batch-size", type=int, default=1000, help="Database streaming batch size")
    parser.add_argument("--dry-run", action="store_true", default=True, help="Evaluate in-memory without polluting operational tables")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")

    args = parser.parse_args(argv)

    db.initialize()
    harness = HistoricalReplayHarness()

    cfg = ReplayConfig(
        rule_ids=args.rule_id,
        category=args.category,
        host=args.host,
        max_events=args.max_events,
        batch_size=args.batch_size,
        dry_run=args.dry_run,
    )

    report = harness.replay_from_database(config=cfg)

    if args.format == "json":
        print(report.model_dump_json(indent=2))
        return 0

    print("=" * 70)
    print("LOGINTEL HISTORICAL DETECTION REPLAY REPORT")
    print("=" * 70)
    print(f"Events Evaluated:       {report.total_events_evaluated}")
    print(f"Active Rules:           {report.rules_evaluated_count}")
    print(f"Execution Duration:     {report.duration_seconds}s")
    print(f"Throughput:             {report.events_per_second:.1f} events/sec")
    print(f"Total Detections:       {report.total_detections_count}")
    print(f"Simulated Alerts:       {report.simulated_alerts_count}")
    print(f"Dry Run Mode:           {report.dry_run}")
    print("-" * 70)
    print("Detections By Rule:")
    if report.detections_by_rule:
        for rule_id, count in sorted(report.detections_by_rule.items()):
            print(f"  - {rule_id:<35} : {count:>5} hit(s)")
    else:
        print("  (None)")
    print("-" * 70)
    print("Simulated Consolidated Alerts:")
    if report.simulated_alerts:
        for alert in report.simulated_alerts:
            print(f"  [{alert.severity:<8}] {alert.rule_id:<30} on {alert.host:<12} (x{alert.occurrence_count} hits)")
    else:
        print("  (None)")
    print("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())
