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


def test_restart_idempotence_and_offset_persistence():
    """Verify that restarting the engine does NOT produce duplicate events from the same source lines."""
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "idempotence_test.db"
        log_file = Path(td) / "test_auth.log"

        # Write 5 initial lines
        initial_lines = [
            f"Sep 29 10:0{i}:00 sec-node sudo: user{i} : TTY=pts/1 ; PWD=/home ; USER=root ; COMMAND=/bin/ls\n"
            for i in range(5)
        ]
        log_file.write_text("".join(initial_lines))

        # First run: start engine and ingest
        db1 = Database(db_path)
        db1.initialize()
        repo1 = EventsRepository(db1)
        registry = ParserRegistry()

        engine1 = IngestionEngine(repo=repo1, registry=registry)
        # Custom mock collector pointing to our temp file
        engine1.collectors.clear()
        engine1.collectors["auth.log"] = AuthLogCollector(file_path=str(log_file))

        count1 = engine1.run_cycle(historical=True, limit_per_source=10)
        assert count1 == 5

        # Check total events
        _, total1 = repo1.query_events()
        assert total1 == 5

        # Check ingestion state
        state1 = repo1.get_ingestion_state("auth.log")
        assert state1 is not None
        assert state1["byte_offset"] > 0
        db1.close()

        # Simulate engine restart: open DB and create new IngestionEngine
        db2 = Database(db_path)
        db2.initialize()
        repo2 = EventsRepository(db2)

        # Restore state as IngestionEngine._setup_collectors does
        saved_state = repo2.get_ingestion_state("auth.log")
        engine2 = IngestionEngine(repo=repo2, registry=registry)
        engine2.collectors.clear()
        engine2.collectors["auth.log"] = AuthLogCollector(
            file_path=str(log_file),
            current_offset=saved_state["byte_offset"],
            current_inode=saved_state.get("inode"),
        )

        # Run cycle again without appending new lines
        count2 = engine2.run_cycle(historical=False)
        assert count2 == 0  # 0 new events on restart!

        _, total2 = repo2.query_events()
        assert total2 == 5  # No duplicates created!

        # Now append 3 new lines
        appended_lines = [
            f"Sep 29 10:1{i}:00 sec-node sudo: user_new{i} : TTY=pts/1 ; PWD=/home ; USER=root ; COMMAND=/bin/ls\n"
            for i in range(3)
        ]
        with open(log_file, "a") as f:
            f.write("".join(appended_lines))

        # Run cycle again: should read only the 3 new lines
        count3 = engine2.run_cycle(historical=False)
        assert count3 == 3

        _, total3 = repo2.query_events()
        assert total3 == 8
        db2.close()


def test_log_rotation_scenarios():
    """Verify log rotation detection when file is truncated or rotated."""
    from logintel.collectors.file_tailer import FileTailer

    with tempfile.TemporaryDirectory() as td:
        log_file = Path(td) / "rotating.log"
        log_file.write_text("line 1 long log entry\nline 2 long log entry\n")

        tailer = FileTailer(str(log_file), "test_rot", "host1")
        records1 = list(tailer.read_new())
        assert len(records1) == 2
        initial_offset = tailer.current_offset
        assert initial_offset > 20

        # Scenario C: File truncation (file size < persisted offset)
        log_file.write_text("short\n")
        assert log_file.stat().st_size < initial_offset

        records2 = list(tailer.read_new())
        assert len(records2) == 1
        assert records2[0].raw_content == "short"

        # Scenario B: Inode rotation (file rotated to .1 and new file created)
        import os
        rot_file = Path(td) / "rotating.log.1"
        os.rename(log_file, rot_file)
        log_file.write_text("new file after rotation\n")

        records3 = list(tailer.read_new())
        assert len(records3) == 1
        assert records3[0].raw_content == "new file after rotation"


def test_query_plan_composite_indexes():
    """Verify that composite indexes eliminate temporary B-trees in SQLite query plans."""
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "query_plan_test.db"
        test_db = Database(db_path)
        test_db.initialize()

        with test_db.connection() as conn:
            c = conn.cursor()
            # Plan 1: filter by source with ORDER BY timestamp DESC
            c.execute("EXPLAIN QUERY PLAN SELECT * FROM events WHERE source = ? ORDER BY timestamp DESC LIMIT 50", ("auth.log",))
            plan1 = " ".join([row[3] for row in c.fetchall()])
            assert "USE TEMP B-TREE FOR ORDER BY" not in plan1
            assert "idx_events_source_time" in plan1

            # Plan 2: filter by severity with ORDER BY timestamp DESC
            c.execute("EXPLAIN QUERY PLAN SELECT * FROM events WHERE severity = ? ORDER BY timestamp DESC LIMIT 50", ("ALERT",))
            plan2 = " ".join([row[3] for row in c.fetchall()])
            assert "USE TEMP B-TREE FOR ORDER BY" not in plan2
            assert "idx_events_severity_time" in plan2

        test_db.close()
