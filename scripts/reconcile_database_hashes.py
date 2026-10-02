#!/usr/bin/env python3
"""
LogIntel M5.1 Forensic Database Content-Hash Reconciliation Tool

Computes canonical record-content hashes (SHA-256) across all 8 core tables:
- events
- alerts
- detections
- incidents
- incident_entities
- incident_relationships
- investigation_notes
- investigation_notes_audit

Validates baseline vs post-test states ensuring:
- added = 0
- removed = 0
- changed = 0
- unchanged = baseline count
- 100% preservation of IDs, event_fingerprints, content_hashes, and raw forensic fields.
"""

import sys
import json
import sqlite3
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Tuple

TABLE_CONFIGS = [
    {
        "name": "events",
        "stable_id_cols": ["id"],
        "extra_preserved_cols": ["event_fingerprint", "raw_message", "timestamp", "source", "parser", "source_file", "source_offset"],
        "order_by": "id ASC"
    },
    {
        "name": "alerts",
        "stable_id_cols": ["id"],
        "extra_preserved_cols": ["dedup_key", "rule_id"],
        "order_by": "id ASC"
    },
    {
        "name": "detections",
        "stable_id_cols": ["id"],
        "extra_preserved_cols": ["rule_id", "timestamp"],
        "order_by": "id ASC"
    },
    {
        "name": "incidents",
        "stable_id_cols": ["id"],
        "extra_preserved_cols": ["incident_key", "created_at"],
        "order_by": "id ASC"
    },
    {
        "name": "incident_entities",
        "stable_id_cols": ["id"],
        "extra_preserved_cols": ["incident_id", "entity_key", "entity_type"],
        "order_by": "id ASC"
    },
    {
        "name": "incident_relationships",
        "stable_id_cols": ["id"],
        "extra_preserved_cols": ["incident_id", "source_entity_key", "target_entity_key", "relationship_type"],
        "order_by": "id ASC"
    },
    {
        "name": "investigation_notes",
        "stable_id_cols": ["id"],
        "extra_preserved_cols": ["incident_id", "created_at"],
        "order_by": "id ASC"
    },
    {
        "name": "investigation_notes_audit",
        "stable_id_cols": ["id"],
        "extra_preserved_cols": ["note_id", "incident_id", "action"],
        "order_by": "id ASC"
    }
]

def hash_record(record_dict: Dict[str, Any]) -> str:
    """
    Deterministic canonical JSON record hashing.
    Preserves exact NULL vs empty string, integer types, UTF-8 strings.
    """
    canonical_bytes = json.dumps(
        record_dict,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()

def extract_manifest(db_path: Path) -> Dict[str, Any]:
    """
    Extracts census and content hashes from SQLite database for all 8 tables.
    """
    if not db_path.exists():
        raise FileNotFoundError(f"Database not found: {db_path}")

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    manifest = {
        "metadata": {
            "db_path": str(db_path),
            "algorithm": "SHA-256 canonical JSON",
            "table_counts": {}
        },
        "tables": {}
    }

    for config in TABLE_CONFIGS:
        table_name = config["name"]
        order_by = config["order_by"]
        stable_id_cols = config["stable_id_cols"]
        extra_cols = config.get("extra_preserved_cols", [])

        cursor.execute(f"SELECT * FROM {table_name} ORDER BY {order_by}")
        rows = cursor.fetchall()
        manifest["metadata"]["table_counts"][table_name] = len(rows)

        table_records = []
        for row in rows:
            row_dict = dict(row)
            content_hash = hash_record(row_dict)
            stable_id = str(row_dict[stable_id_cols[0]])

            entry = {
                "id": stable_id,
                "content_hash": content_hash
            }
            for col in extra_cols:
                entry[col] = row_dict.get(col)

            table_records.append(entry)

        manifest["tables"][table_name] = table_records

    conn.close()
    return manifest

def reconcile_manifests(baseline: Dict[str, Any], post_test: Dict[str, Any]) -> Dict[str, Any]:
    """
    Reconciles baseline manifest vs post-test manifest.
    Calculates added, removed, changed, unchanged per table.
    """
    results = {
        "summary": {},
        "events_preservation": {},
        "all_passed": True
    }

    for config in TABLE_CONFIGS:
        table_name = config["name"]
        base_records = {r["id"]: r for r in baseline["tables"].get(table_name, [])}
        post_records = {r["id"]: r for r in post_test["tables"].get(table_name, [])}

        base_ids = set(base_records.keys())
        post_ids = set(post_records.keys())

        added_ids = sorted(list(post_ids - base_ids))
        removed_ids = sorted(list(base_ids - post_ids))
        common_ids = base_ids & post_ids

        changed_ids = []
        unchanged_ids = []

        for rec_id in common_ids:
            if base_records[rec_id]["content_hash"] == post_records[rec_id]["content_hash"]:
                unchanged_ids.append(rec_id)
            else:
                changed_ids.append(rec_id)

        passed = (len(added_ids) == 0 and len(removed_ids) == 0 and len(changed_ids) == 0)
        if not passed:
            results["all_passed"] = False

        results["summary"][table_name] = {
            "baseline_count": len(base_ids),
            "post_test_count": len(post_ids),
            "added": len(added_ids),
            "removed": len(removed_ids),
            "changed": len(changed_ids),
            "unchanged": len(unchanged_ids),
            "added_ids": added_ids[:10],
            "removed_ids": removed_ids[:10],
            "changed_ids": changed_ids[:10],
            "passed": passed
        }

    # Detailed event-specific checks
    base_events = {r["id"]: r for r in baseline["tables"].get("events", [])}
    post_events = {r["id"]: r for r in post_test["tables"].get("events", [])}

    event_ids_unchanged = 0
    fingerprints_unchanged = 0
    hashes_unchanged = 0
    raw_messages_unchanged = 0
    timestamps_unchanged = 0
    sources_unchanged = 0
    provenance_unchanged = 0

    for eid, b_rec in base_events.items():
        if eid in post_events:
            event_ids_unchanged += 1
            p_rec = post_events[eid]
            if b_rec.get("event_fingerprint") == p_rec.get("event_fingerprint"):
                fingerprints_unchanged += 1
            if b_rec.get("content_hash") == p_rec.get("content_hash"):
                hashes_unchanged += 1
            if b_rec.get("raw_message") == p_rec.get("raw_message"):
                raw_messages_unchanged += 1
            if b_rec.get("timestamp") == p_rec.get("timestamp"):
                timestamps_unchanged += 1
            if b_rec.get("source") == p_rec.get("source"):
                sources_unchanged += 1
            if (b_rec.get("parser") == p_rec.get("parser") and
                b_rec.get("source_file") == p_rec.get("source_file") and
                b_rec.get("source_offset") == p_rec.get("source_offset")):
                provenance_unchanged += 1

    total_events = len(base_events)
    events_passed = (
        event_ids_unchanged == total_events and
        fingerprints_unchanged == total_events and
        hashes_unchanged == total_events and
        raw_messages_unchanged == total_events and
        timestamps_unchanged == total_events and
        sources_unchanged == total_events and
        provenance_unchanged == total_events
    )

    if not events_passed:
        results["all_passed"] = False

    results["events_preservation"] = {
        "total_baseline_events": total_events,
        "event_ids_unchanged": event_ids_unchanged,
        "fingerprints_unchanged": fingerprints_unchanged,
        "content_hashes_unchanged": hashes_unchanged,
        "raw_messages_unchanged": raw_messages_unchanged,
        "timestamps_unchanged": timestamps_unchanged,
        "sources_unchanged": sources_unchanged,
        "provenance_unchanged": provenance_unchanged,
        "events_passed": events_passed
    }

    return results

def check_db_integrity(db_path: Path) -> Dict[str, Any]:
    """Runs PRAGMA integrity_check, foreign_key_check, user_version and migration count."""
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    cursor.execute("PRAGMA integrity_check")
    integrity = [r[0] for r in cursor.fetchall()]

    cursor.execute("PRAGMA foreign_key_check")
    fk_check = cursor.fetchall()

    cursor.execute("PRAGMA user_version")
    user_version = cursor.fetchone()[0]

    cursor.execute("SELECT max(version), count(*) FROM schema_migrations")
    max_version, migration_count = cursor.fetchone()

    cursor.execute("SELECT version, name FROM schema_migrations ORDER BY version ASC")
    migrations = cursor.fetchall()

    conn.close()

    is_healthy = (
        integrity == ["ok"] and
        len(fk_check) == 0 and
        max_version == 5 and
        migration_count == 5 and
        all(m[0] != 6 for m in migrations)
    )

    return {
        "integrity_check": integrity,
        "foreign_key_check": fk_check,
        "user_version": user_version,
        "schema_version": max_version,
        "migration_count": migration_count,
        "migrations": migrations,
        "migration_6_absent": (migration_count == 5 and all(m[0] != 6 for m in migrations)),
        "is_healthy": is_healthy
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: reconcile_database_hashes.py [generate-baseline|reconcile|verify-integrity] [args...]")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "generate-baseline":
        db_path = Path(sys.argv[2])
        out_path = Path(sys.argv[3])
        print(f"Extracting baseline manifest from {db_path}...")
        manifest = extract_manifest(db_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)
        print(f"Wrote baseline manifest to {out_path} ({len(manifest['tables']['events'])} events).")

    elif cmd == "reconcile":
        base_manifest_path = Path(sys.argv[2])
        post_db_path = Path(sys.argv[3])
        post_manifest_path = Path(sys.argv[4])

        print(f"Reading baseline manifest: {base_manifest_path}...")
        with open(base_manifest_path, "r", encoding="utf-8") as f:
            baseline = json.load(f)

        print(f"Extracting post-test manifest from {post_db_path}...")
        post_test = extract_manifest(post_db_path)
        with open(post_manifest_path, "w", encoding="utf-8") as f:
            json.dump(post_test, f, indent=2, ensure_ascii=False)
        print(f"Wrote post-test manifest to {post_manifest_path}.")

        print("Reconciling content hashes...")
        results = reconcile_manifests(baseline, post_test)
        print("\nReconciliation Summary Table:")
        print(f"{'Table':<28} | {'Baseline':<10} | {'Added':<7} | {'Removed':<7} | {'Changed':<7} | {'Unchanged':<10} | Status")
        print("-" * 88)
        for tbl, s in results["summary"].items():
            status = "PASS" if s["passed"] else "FAIL"
            print(f"{tbl:<28} | {s['baseline_count']:<10} | {s['added']:<7} | {s['removed']:<7} | {s['changed']:<7} | {s['unchanged']:<10} | {status}")

        print("\nEvents Specific Preservation:")
        for k, v in results["events_preservation"].items():
            print(f"  {k}: {v}")

        integrity = check_db_integrity(post_db_path)
        print("\nPost-Test DB Integrity Check:")
        print(f"  PRAGMA integrity_check: {integrity['integrity_check']}")
        print(f"  PRAGMA foreign_key_check: {integrity['foreign_key_check']}")
        print(f"  PRAGMA user_version: {integrity['user_version']}")
        print(f"  Migration count: {integrity['migration_count']}")
        print(f"  Migration 6 absent: {integrity['migration_6_absent']}")
        print(f"  Overall healthy: {integrity['is_healthy']}")

        if not results["all_passed"] or not integrity["is_healthy"]:
            print("\nVERIFICATION FAILED")
            sys.exit(1)
        else:
            print("\nVERIFICATION PASSED — ZERO MUTATION DETECTED")

    elif cmd == "verify-integrity":
        db_path = Path(sys.argv[2])
        integrity = check_db_integrity(db_path)
        print(json.dumps(integrity, indent=2))
