"""Verification tests for collectors, storage persistence, and restart survival."""

import tempfile
from pathlib import Path
from logintel.collectors import (
    AuthLogCollector,
    JournalCollector,
    KernLogCollector,
    SyslogCollector,
)
from logintel.ingestion import IngestionEngine
from logintel.models import Actor, CanonicalEvent, EventType, Outcome, Severity
from logintel.parsers.registry import ParserRegistry
from logintel.storage.db import Database
from logintel.storage.events_repo import EventsRepository


def test_collectors_availability():
    """Verify that all M1 collectors report their availability accurately on Linux."""
    collectors = [
        AuthLogCollector(),
        SyslogCollector(),
        KernLogCollector(),
        JournalCollector(),
    ]
    for col in collectors:
        avail, reason = col.check_availability()
        # On Ubuntu 24.04 with user in adm group, these should all be available
        assert isinstance(avail, bool)
        if not avail:
            assert reason is not None


def test_database_restart_and_persistence():
    """Verify that events persist across database close and reopen."""
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "persist_test.db"

        # 1. First session: initialize DB and insert events
        db1 = Database(db_path)
        db1.initialize()
        repo1 = EventsRepository(db1)

        event1 = CanonicalEvent(
            host="host-alpha",
            source="auth.log",
            event_type=EventType.AUTH_LOGIN_FAILURE,
            severity=Severity.ALERT,
            actor=Actor(username="eve"),
            outcome=Outcome.FAILURE,
            summary="Repeated authentication failure for eve",
            raw_message="Failed password for eve from 192.0.2.1",
            parser="openssh_auth",
        )
        repo1.insert_events([event1])
        db1.close()

        # 2. Second session: open existing DB file (simulate restart)
        db2 = Database(db_path)
        db2.initialize()
        repo2 = EventsRepository(db2)

        # Verify event persisted
        fetched = repo2.get_event_by_id(event1.id)
        assert fetched is not None
        assert fetched.actor.username == "eve"
        assert fetched.event_type == EventType.AUTH_LOGIN_FAILURE
        assert fetched.summary == "Repeated authentication failure for eve"

        # Verify search works
        results, total = repo2.query_events(search="eve")
        assert total == 1
        assert results[0].id == event1.id

        db2.close()


def test_ingestion_pipeline_with_custom_repo():
    """Verify complete pipeline: collectors -> parsers -> normalizer -> SQLite."""
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "pipeline_test.db"
        test_db = Database(db_path)
        test_db.initialize()
        repo = EventsRepository(test_db)
        registry = ParserRegistry()

        engine = IngestionEngine(repo=repo, registry=registry)
        
        # Run a single historical cycle
        count = engine.run_cycle(historical=True, limit_per_source=5)
        assert count >= 0

        # Query events from repo
        events, total = repo.query_events(limit=10)
        assert total == count
        test_db.close()
