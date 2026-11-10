"""Regression coverage for production-oriented ingestion foundations."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient

from logintel.api.routes import router
from logintel.config import settings
from logintel.detection.engine import DetectionEngine
from logintel.detection.models import DetectionRule
from logintel.detection.registry import RuleRegistry
from logintel.detection.results import DetectionResult
from logintel.ingestion.engine import IngestionEngine
from logintel.models import CanonicalEvent, RawRecord
from logintel.models.events import EventType, Outcome, Severity
from logintel.storage.events_repo import EventsRepository
from logintel.storage.db import Database
from logintel.storage.maintenance import RetentionService
from logintel.notifications.service import NotificationService, NotificationSettings
from logintel.agent.config import AgentConfig
from logintel.agent.spool import JsonlSpool
from logintel.agent.collectors import AgentCollectors


def _event() -> CanonicalEvent:
    now = datetime.now(timezone.utc)
    return CanonicalEvent(
        id="live-detection-event",
        timestamp=now,
        ingested_at=now,
        host="node-1",
        source="test",
        event_type=EventType.AUTH_LOGIN_FAILURE,
        severity=Severity.WARNING,
        outcome=Outcome.FAILURE,
        summary="failed login",
        raw_message="failed login",
    )


def test_newly_inserted_events_are_detected_once(tmp_path, monkeypatch):
    database = Database(tmp_path / "events.db")
    database.initialize()
    repo = EventsRepository(database)

    class FixedParser:
        def parse_record(self, _: RawRecord):
            return _event(), True

    class CapturingAlerts:
        def __init__(self):
            self.count = 0

        def record_detection(self, result, rule):
            self.count += 1

    class OneMatchEngine:
        def __init__(self):
            self.registry = RuleRegistry()
            self.rule = DetectionRule.model_validate({
                "id": "test.live", "name": "Live", "description": "test",
                "severity": "WARNING", "category": "AUTH", "rule_type": "ATOMIC",
                "conditions": {"all": [{"field": "event_type", "operator": "equals", "value": "AUTH_LOGIN_FAILURE"}]},
            })
            self.registry.register(self.rule)

        def evaluate_batch(self, events):
            return [DetectionResult(rule_id="test.live", timestamp=events[0].timestamp, host="node-1", summary="match", evidence_event_ids=[events[0].id])]

    alerts = CapturingAlerts()
    engine = IngestionEngine(repo=repo, registry=FixedParser(), detection_engine=OneMatchEngine(), alerts_repository=alerts)
    engine.collectors.clear()
    record = RawRecord(source="test", raw_content="line", host="node-1")

    assert engine.ingest_records([record]) == 1
    assert engine.ingest_records([record]) == 0
    assert alerts.count == 1
    database.close()


def test_remote_ingestion_is_opt_in_and_bounded(monkeypatch):
    import logintel.api.routes as routes

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    payload = {"host": "agent-01", "records": [{"source": "auth.log", "raw_content": "test"}]}
    monkeypatch.setattr(settings.remote_ingest, "enabled", False)
    assert client.post("/api/v1/fleet/ingest", json=payload).status_code == 404

    monkeypatch.setattr(settings.remote_ingest, "enabled", True)
    monkeypatch.setattr(settings.remote_ingest, "agent_token", "agent-test-token")
    received = []
    monkeypatch.setattr(routes.ingestion_engine, "ingest_records", lambda records: received.append(records) or len(records))
    response = client.post("/api/v1/fleet/ingest", json=payload, headers={"X-LogIntel-Agent-Token": "agent-test-token"})
    assert response.status_code == 200
    assert received[0][0].host == "agent-01"
    assert received[0][0].source == "remote:auth.log"


def test_retention_preserves_detection_evidence(tmp_path):
    database = Database(tmp_path / "retention.db")
    database.initialize()
    with database.connection() as conn:
        conn.execute("INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint) VALUES ('old-free', '2020-01-01T00:00:00+00:00', '2020-01-01T00:00:00+00:00', 'host', 'test', 'UNKNOWN', 'WARNING', 'x', 'UNKNOWN', 'free', 'free', 'test', 'old-free')")
        conn.execute("INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint) VALUES ('old-evidence', '2020-01-01T00:00:00+00:00', '2020-01-01T00:00:00+00:00', 'host', 'test', 'UNKNOWN', 'WARNING', 'x', 'UNKNOWN', 'evidence', 'evidence', 'test', 'old-evidence')")
        conn.execute("INSERT INTO detection_rules (id, name, description, severity, category, rule_type, definition_yaml) VALUES ('r', 'r', 'r', 'WARNING', 'AUTH', 'ATOMIC', '{}')")
        conn.execute("INSERT INTO alerts (rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count) VALUES ('r', 'r:1', 'r', 'r', 'WARNING', 'OPEN', 'host', '2020-01-01T00:00:00+00:00', '2020-01-01T00:00:00+00:00', 1)")
        conn.execute("INSERT INTO detections (alert_id, rule_id, timestamp, host, summary) VALUES (1, 'r', '2020-01-01T00:00:00+00:00', 'host', 'r')")
        conn.execute("INSERT INTO detection_evidence (detection_id, event_id, role) VALUES (1, 'old-evidence', 'TRIGGER')")
        conn.commit()
    result = RetentionService(database).run(retention_days=1, dry_run=False)
    assert result["deleted_events"] == 1
    with database.connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM events WHERE id = 'old-free'").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM events WHERE id = 'old-evidence'").fetchone()[0] == 1
    database.close()


def test_notifications_are_opt_in_and_bounded():
    disabled = NotificationService(NotificationSettings(enabled=False))
    disabled.publish("alert.detected", "alert", "1", {"host": "node"})
    assert disabled.status()["recent_deliveries"] == []

    local = NotificationService(NotificationSettings(enabled=True, sink="log"))
    local.publish("alert.detected", "alert", "1", {"host": "node"})
    assert local.status()["recent_deliveries"][-1]["status"] == "DELIVERED"


def test_agent_config_is_owner_only_and_spool_is_fifo(tmp_path):
    config_path = tmp_path / "agent.json"
    config = AgentConfig(
        endpoint="https://fleet.example.test",
        token="x" * 32,
        host="node-1",
        spool_dir=tmp_path / "spool",
    )
    config.write(config_path)
    assert config_path.stat().st_mode & 0o777 == 0o600
    assert AgentConfig.load(config_path).host == "node-1"
    spool = JsonlSpool(config.spool_dir, max_bytes=1024 * 1024)
    first = spool.enqueue([{"source": "auth.log", "raw_content": "one"}])
    current = spool.peek()
    assert current is not None
    assert current[0] == first
    assert current[1][0]["raw_content"] == "one"
    spool.acknowledge(first)
    assert spool.peek() is None


def test_agent_native_file_collection_persists_offsets_and_handles_rotation(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text("first\n", encoding="utf-8")
    config = AgentConfig(
        endpoint="https://fleet.example.test", token="x" * 32, host="node-1",
        spool_dir=tmp_path / "spool", journald_enabled=False, log_paths={"auth.log": log_file},
    )
    collector = AgentCollectors(config)
    assert [item["raw_content"] for item in collector.collect_once()] == ["first"]
    assert collector.collect_once() == []
    with log_file.open("a", encoding="utf-8") as handle:
        handle.write("second\n")
    assert [item["raw_content"] for item in collector.collect_once()] == ["second"]
    log_file.write_text("rotated\n", encoding="utf-8")
    assert [item["raw_content"] for item in collector.collect_once()] == ["rotated"]
    with log_file.open("a", encoding="utf-8") as handle:
        handle.write("x" * 200 + "\nshort\n")
    config.max_record_bytes = 64
    assert [item["raw_content"] for item in collector.collect_once()] == ["short"]
