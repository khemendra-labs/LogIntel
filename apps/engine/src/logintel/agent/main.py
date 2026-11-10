"""`logintel-agent` command: secure enrollment, queueing, and delivery."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

from logintel.agent.client import FleetClient
from logintel.agent.config import AgentConfig, default_config_path
from logintel.agent.collectors import AgentCollectors


def main() -> None:
    parser = argparse.ArgumentParser(description="LogIntel remote Linux collector agent")
    parser.add_argument("--config", type=Path, default=default_config_path())
    commands = parser.add_subparsers(dest="command", required=True)
    enroll = commands.add_parser("enroll", help="write an owner-only agent configuration")
    enroll.add_argument("--endpoint", required=True)
    enroll.add_argument("--token", required=True)
    enroll.add_argument("--host")
    enroll.add_argument("--spool-dir", type=Path)
    enroll.add_argument("--ca-file", type=Path)
    enroll.add_argument("--client-cert-file", type=Path)
    enroll.add_argument("--client-key-file", type=Path)
    queue = commands.add_parser("queue", help="queue JSONL raw records from standard input")
    commands.add_parser("flush", help="upload one queued batch")
    commands.add_parser("status", help="show spool usage without secrets")
    run = commands.add_parser("run", help="collect native Linux telemetry and upload continuously")
    run.add_argument("--once", action="store_true", help="perform one collection/upload cycle")
    args = parser.parse_args()

    if args.command == "enroll":
        config = AgentConfig(endpoint=args.endpoint, token=args.token, **{key: value for key, value in {
            "host": args.host, "spool_dir": args.spool_dir, "ca_file": args.ca_file,
            "client_cert_file": args.client_cert_file, "client_key_file": args.client_key_file,
        }.items() if value is not None})
        print(f"Wrote secure agent configuration: {config.write(args.config)}")
        return

    config = AgentConfig.load(args.config)
    client = FleetClient(config)
    if args.command == "queue":
        records = [json.loads(line) for line in sys.stdin if line.strip()]
        for start in range(0, len(records), config.batch_size):
            client.queue(records[start:start + config.batch_size])
        print(json.dumps({"queued_records": len(records), "spool_bytes": client.spool.bytes_used()}))
    elif args.command == "flush":
        print(json.dumps({"uploaded_records": client.flush_once(), "spool_bytes": client.spool.bytes_used()}))
    elif args.command == "run":
        collectors = AgentCollectors(config)
        while True:
            # Flush backlog first to preserve event order during an outage.
            try:
                while client.flush_once():
                    pass
            except Exception as exc:
                print(f"upload deferred: {exc}", file=sys.stderr)
            try:
                records = collectors.collect_once()
                for start in range(0, len(records), config.batch_size):
                    client.queue(records[start:start + config.batch_size])
            except Exception as exc:
                print(f"collection deferred: {exc}", file=sys.stderr)
            if args.once:
                break
            time.sleep(config.poll_interval_seconds)
    else:
        print(json.dumps({"host": config.host, "endpoint": config.endpoint, "spool_bytes": client.spool.bytes_used()}))


if __name__ == "__main__":
    main()
