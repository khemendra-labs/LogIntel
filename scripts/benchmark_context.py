#!/usr/bin/env python3
"""Benchmark InvestigationContext assembly and serialization across 4 workloads."""

import time
import tempfile
import json
from pathlib import Path

from logintel.storage.db import Database
from logintel.ai.context.assembler import InvestigationContextAssembler
from logintel.ai.context.serializer import ContextSerializer
from logintel.ai.context.budget import ContextBudget


def run_benchmarks():
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "bench.db")
        db.initialize()
        with db.connection() as conn:
            cur = conn.cursor()
            cur.execute("INSERT INTO hosts (id, hostname, first_seen, last_seen) VALUES ('h1', 'host-1', '2026-09-30T00:00:00Z', '2026-09-30T23:59:59Z')")
            cur.execute("INSERT INTO detection_rules (id, name, description, severity, category, rule_type, definition_yaml) VALUES ('rule.1', 'Rule 1', 'Desc', 'WARNING', 'Test', 'pattern', 'yaml')")

            # 1. Small: Incident 10 (1 alert, 1 event, 2 entities, 1 rel, 1 note)
            cur.execute("INSERT INTO incidents (id, incident_key, title, summary, severity, status, primary_host, primary_user, first_seen, last_seen, alert_count, event_count) VALUES (10, 'INC-SMALL', 'Small Workload', 'Summary', 'INFORMATIONAL', 'OPEN', 'host-1', 'user1', '2026-09-30T10:00:00Z', '2026-09-30T10:05:00Z', 1, 1)")
            cur.execute("INSERT INTO alerts (id, rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count) VALUES (10, 'rule.1', 'dedup-10', 'Alert 10', 'Desc', 'INFORMATIONAL', 'OPEN', 'host-1', '2026-09-30T10:00:00Z', '2026-09-30T10:05:00Z', 1)")
            cur.execute("INSERT INTO incident_alerts (incident_id, alert_id) VALUES (10, 10)")
            cur.execute("INSERT INTO detections (id, alert_id, rule_id, timestamp, host, summary, evidence_count) VALUES (10, 10, 'rule.1', '2026-09-30T10:00:00Z', 'host-1', 'Det 10', 1)")
            cur.execute("INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint) VALUES ('evt-s-1', '2026-09-30T10:00:00Z', '2026-09-30T10:00:01Z', 'host-1', 'syslog', 'auth', 'INFORMATIONAL', 'login', 'success', 'Sum', 'Raw message for small event', 'parser', 'fp-s-1')")
            cur.execute("INSERT INTO detection_evidence (detection_id, event_id, role) VALUES (10, 'evt-s-1', 'primary')")
            cur.execute("INSERT INTO incident_entities (incident_id, entity_key, entity_type, display_name, metadata_json) VALUES (10, 'ip:10.0.0.1', 'IP', '10.0.0.1', '{}')")
            cur.execute("INSERT INTO incident_entities (incident_id, entity_key, entity_type, display_name, metadata_json) VALUES (10, 'user:user1', 'USER', 'user1', '{}')")
            cur.execute("INSERT INTO incident_relationships (id, incident_id, source_entity_key, target_entity_key, relationship_type, confidence, evidence_event_ids_json) VALUES (10, 10, 'ip:10.0.0.1', 'user:user1', 'AUTHENTICATED_TO', 'STRONG', '[\"evt-s-1\"]')")
            cur.execute("INSERT INTO investigation_notes (id, incident_id, author, content, created_at, target_type, is_deleted) VALUES (10, 10, 'Analyst', 'Small Note', '2026-09-30T10:01:00Z', 'incident', 0)")

            # 2. Medium: Incident 20 (3 alerts, 6 events, 6 entities, 4 rels, 2 notes)
            cur.execute("INSERT INTO incidents (id, incident_key, title, summary, severity, status, primary_host, primary_user, first_seen, last_seen, alert_count, event_count) VALUES (20, 'INC-MEDIUM', 'Medium Workload', 'Summary', 'NOTICE', 'OPEN', 'host-1', 'user2', '2026-09-30T10:00:00Z', '2026-09-30T10:15:00Z', 3, 6)")
            for a in range(21, 24):
                cur.execute(f"INSERT INTO alerts (id, rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count) VALUES ({a}, 'rule.1', 'dedup-{a}', 'Alert {a}', 'Desc', 'NOTICE', 'OPEN', 'host-1', '2026-09-30T10:00:00Z', '2026-09-30T10:15:00Z', 1)")
                cur.execute(f"INSERT INTO incident_alerts (incident_id, alert_id) VALUES (20, {a})")
                cur.execute(f"INSERT INTO detections (id, alert_id, rule_id, timestamp, host, summary, evidence_count) VALUES ({a}, {a}, 'rule.1', '2026-09-30T10:00:00Z', 'host-1', 'Det {a}', 2)")
                e1, e2 = f"evt-m-{a}-1", f"evt-m-{a}-2"
                cur.execute(f"INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint) VALUES ('{e1}', '2026-09-30T10:00:00Z', '2026-09-30T10:00:01Z', 'host-1', 'syslog', 'auth', 'NOTICE', 'login', 'failure', 'Sum {e1}', 'Raw log {e1}', 'parser', 'fp-{e1}')")
                cur.execute(f"INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint) VALUES ('{e2}', '2026-09-30T10:01:00Z', '2026-09-30T10:01:01Z', 'host-1', 'syslog', 'auth', 'NOTICE', 'login', 'success', 'Sum {e2}', 'Raw log {e2}', 'parser', 'fp-{e2}')")
                cur.execute(f"INSERT INTO detection_evidence (detection_id, event_id, role) VALUES ({a}, '{e1}', 'primary')")
                cur.execute(f"INSERT INTO detection_evidence (detection_id, event_id, role) VALUES ({a}, '{e2}', 'secondary')")
            for ent in range(1, 7):
                cur.execute(f"INSERT INTO incident_entities (incident_id, entity_key, entity_type, display_name, metadata_json) VALUES (20, 'ent:med:{ent}', 'HOST', 'host-{ent}', '{{}}')")
            for rel in range(1, 5):
                cur.execute(f"INSERT INTO incident_relationships (id, incident_id, source_entity_key, target_entity_key, relationship_type, confidence, evidence_event_ids_json) VALUES ({rel+20}, 20, 'ent:med:{rel}', 'ent:med:{rel+1}', 'CONNECTED_TO', 'STRONG', '[\"evt-m-21-1\"]')")
            cur.execute("INSERT INTO investigation_notes (id, incident_id, author, content, created_at, target_type, is_deleted) VALUES (21, 20, 'Analyst', 'Med Note 1', '2026-09-30T10:05:00Z', 'incident', 0)")
            cur.execute("INSERT INTO investigation_notes (id, incident_id, author, content, created_at, target_type, is_deleted) VALUES (22, 20, 'Analyst', 'Med Note 2', '2026-09-30T10:10:00Z', 'incident', 0)")

            # 3. Large: Incident 30 (10 alerts, 20 events, 20 entities, 10 rels, 5 notes)
            cur.execute("INSERT INTO incidents (id, incident_key, title, summary, severity, status, primary_host, primary_user, first_seen, last_seen, alert_count, event_count) VALUES (30, 'INC-LARGE', 'Large Workload', 'Summary', 'WARNING', 'OPEN', 'host-1', 'root', '2026-09-30T10:00:00Z', '2026-09-30T11:00:00Z', 10, 20)")
            for a in range(31, 41):
                cur.execute(f"INSERT INTO alerts (id, rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count) VALUES ({a}, 'rule.1', 'dedup-{a}', 'Alert {a}', 'Desc', 'WARNING', 'OPEN', 'host-1', '2026-09-30T10:00:00Z', '2026-09-30T11:00:00Z', 1)")
                cur.execute(f"INSERT INTO incident_alerts (incident_id, alert_id) VALUES (30, {a})")
                cur.execute(f"INSERT INTO detections (id, alert_id, rule_id, timestamp, host, summary, evidence_count) VALUES ({a}, {a}, 'rule.1', '2026-09-30T10:00:00Z', 'host-1', 'Det {a}', 2)")
                e1, e2 = f"evt-l-{a}-1", f"evt-l-{a}-2"
                cur.execute(f"INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint) VALUES ('{e1}', '2026-09-30T10:00:00Z', '2026-09-30T10:00:01Z', 'host-1', 'syslog', 'auth', 'WARNING', 'login', 'failure', 'Sum {e1}', 'Raw {e1}', 'parser', 'fp-{e1}')")
                cur.execute(f"INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint) VALUES ('{e2}', '2026-09-30T10:01:00Z', '2026-09-30T10:01:01Z', 'host-1', 'syslog', 'auth', 'WARNING', 'login', 'success', 'Sum {e2}', 'Raw {e2}', 'parser', 'fp-{e2}')")
                cur.execute(f"INSERT INTO detection_evidence (detection_id, event_id, role) VALUES ({a}, '{e1}', 'primary')")
                cur.execute(f"INSERT INTO detection_evidence (detection_id, event_id, role) VALUES ({a}, '{e2}', 'secondary')")
            for ent in range(1, 21):
                cur.execute(f"INSERT INTO incident_entities (incident_id, entity_key, entity_type, display_name, metadata_json) VALUES (30, 'ent:lrg:{ent}', 'HOST', 'host-{ent}', '{{}}')")
            for rel in range(1, 11):
                cur.execute(f"INSERT INTO incident_relationships (id, incident_id, source_entity_key, target_entity_key, relationship_type, confidence, evidence_event_ids_json) VALUES ({rel+40}, 30, 'ent:lrg:{rel}', 'ent:lrg:{rel+1}', 'CONNECTED_TO', 'STRONG', '[\"evt-l-31-1\"]')")
            for n in range(1, 6):
                cur.execute(f"INSERT INTO investigation_notes (id, incident_id, author, content, created_at, target_type, is_deleted) VALUES ({n+30}, 30, 'Analyst', 'Lrg Note {n}', '2026-09-30T10:{n:02d}:00Z', 'incident', 0)")

            # 4. Synthetic Large: Incident 50 (25 alerts, 50 supporting events, 50 entities, 25 rels, 10 notes)
            cur.execute("INSERT INTO incidents (id, incident_key, title, summary, severity, status, primary_host, primary_user, first_seen, last_seen, alert_count, event_count) VALUES (50, 'INC-SYNTHETIC-LARGE', 'Synthetic Large Workload', 'Summary', 'CRITICAL', 'OPEN', 'host-1', 'root', '2026-09-30T10:00:00Z', '2026-09-30T12:00:00Z', 25, 50)")
            for a in range(51, 76):
                cur.execute(f"INSERT INTO alerts (id, rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count) VALUES ({a}, 'rule.1', 'dedup-{a}', 'Alert {a}', 'Desc', 'CRITICAL', 'OPEN', 'host-1', '2026-09-30T10:00:00Z', '2026-09-30T12:00:00Z', 1)")
                cur.execute(f"INSERT INTO incident_alerts (incident_id, alert_id) VALUES (50, {a})")
                cur.execute(f"INSERT INTO detections (id, alert_id, rule_id, timestamp, host, summary, evidence_count) VALUES ({a}, {a}, 'rule.1', '2026-09-30T10:00:00Z', 'host-1', 'Det {a}', 2)")
                e1, e2 = f"evt-syn-{a}-1", f"evt-syn-{a}-2"
                cur.execute(f"INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint) VALUES ('{e1}', '2026-09-30T10:00:00Z', '2026-09-30T10:00:01Z', 'host-1', 'syslog', 'auth', 'CRITICAL', 'login', 'failure', 'Sum {e1}', 'Raw message telemetry content payload {e1}', 'parser', 'fp-{e1}')")
                cur.execute(f"INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint) VALUES ('{e2}', '2026-09-30T10:01:00Z', '2026-09-30T10:01:01Z', 'host-1', 'syslog', 'auth', 'CRITICAL', 'login', 'success', 'Sum {e2}', 'Raw message telemetry content payload {e2}', 'parser', 'fp-{e2}')")
                cur.execute(f"INSERT INTO detection_evidence (detection_id, event_id, role) VALUES ({a}, '{e1}', 'primary')")
                cur.execute(f"INSERT INTO detection_evidence (detection_id, event_id, role) VALUES ({a}, '{e2}', 'secondary')")
            for ent in range(1, 51):
                cur.execute(f"INSERT INTO incident_entities (incident_id, entity_key, entity_type, display_name, metadata_json) VALUES (50, 'ent:syn:{ent}', 'HOST', 'host-{ent}', '{{}}')")
            for rel in range(1, 26):
                cur.execute(f"INSERT INTO incident_relationships (id, incident_id, source_entity_key, target_entity_key, relationship_type, confidence, evidence_event_ids_json) VALUES ({rel+80}, 50, 'ent:syn:{rel}', 'ent:syn:{rel+1}', 'CONNECTED_TO', 'STRONG', '[\"evt-syn-51-1\"]')")
            for n in range(1, 11):
                cur.execute(f"INSERT INTO investigation_notes (id, incident_id, author, content, created_at, target_type, is_deleted) VALUES ({n+60}, 50, 'Analyst', 'Syn Note {n}', '2026-09-30T10:{n:02d}:00Z', 'incident', 0)")

            conn.commit()

        assembler = InvestigationContextAssembler(database=db)
        budget = ContextBudget(max_supporting_events=100, max_contextual_events=50, max_entities=100, max_alerts=50, max_relationships=50)

        workloads = [
            ("Small", 10),
            ("Medium", 20),
            ("Large", 30),
            ("Synthetic Large", 50)
        ]

        results = []
        for name, inc_id in workloads:
            # Warmup
            assembler.assemble(incident_id=inc_id, budget=budget, generated_at="2026-10-01T12:00:00Z")

            asm_times = []
            json_times = []
            xml_times = []
            tot_times = []
            for _ in range(10):
                t0 = time.perf_counter()
                ctx = assembler.assemble(incident_id=inc_id, budget=budget, generated_at="2026-10-01T12:00:00Z")
                t1 = time.perf_counter()
                j_str = ContextSerializer.serialize_json(ctx)
                t2 = time.perf_counter()
                x_str = ContextSerializer.serialize_xml_envelope(ctx)
                t3 = time.perf_counter()
                asm_times.append((t1 - t0) * 1000)
                json_times.append((t2 - t1) * 1000)
                xml_times.append((t3 - t2) * 1000)
                tot_times.append((t3 - t0) * 1000)

            results.append({
                "workload": name,
                "incident_id": inc_id,
                "supporting_events": len(ctx.supporting_events),
                "contextual_events": len(ctx.contextual_events),
                "alerts": len(ctx.alerts),
                "entities": len(ctx.entities),
                "relationships": len(ctx.relationships),
                "attack_path_steps": len(ctx.attack_path_steps),
                "mitre_mappings": len(ctx.mitre_mappings),
                "notes": len(ctx.analyst_notes),
                "json_size_bytes": len(j_str.encode("utf-8")),
                "xml_size_bytes": len(x_str.encode("utf-8")),
                "assembly_latency_ms": round(sum(asm_times) / len(asm_times), 3),
                "json_serialization_latency_ms": round(sum(json_times) / len(json_times), 3),
                "xml_serialization_latency_ms": round(sum(xml_times) / len(xml_times), 3),
                "total_pipeline_latency_ms": round(sum(tot_times) / len(tot_times), 3),
            })

        print(json.dumps(results, indent=2))

if __name__ == "__main__":
    run_benchmarks()
