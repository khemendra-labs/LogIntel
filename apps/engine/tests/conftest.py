"""Global test configuration and session-wide fixtures for LogIntel engine tests.

Guarantees:
1. Live host telemetry ingestion (syslog, auth.log, journald) is NEVER started during automated test runs.
2. Ingestion worker threads are deactivated so host events do not mutate the authoritative database.
"""

import pytest
from logintel.ingestion.engine import ingestion_engine


@pytest.fixture(autouse=True, scope="session")
def disable_live_telemetry_ingestion():
    """Session-wide autouse fixture preventing live telemetry ingestion during tests."""
    original_start = ingestion_engine.start
    original_stop = ingestion_engine.stop
    ingestion_engine.start = lambda: None
    ingestion_engine.stop = lambda: None
    yield
    ingestion_engine.start = original_start
    ingestion_engine.stop = original_stop
