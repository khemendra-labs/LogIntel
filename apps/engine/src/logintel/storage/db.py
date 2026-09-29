"""SQLite database management for LogIntel."""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Optional
from logintel.config import settings
from logintel.logging import get_logger
from logintel.storage.migrations import apply_migrations

logger = get_logger("storage.db")


class Database:
    """Thread-safe SQLite database manager with WAL mode and automatic migration."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or settings.db_path
        self._local = threading.local()
        self._initialized = False
        self._lock = threading.Lock()

    def _get_connection(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(
                str(self.db_path),
                timeout=30.0,
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            # Enable WAL mode and optimized pragmas
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA busy_timeout = 10000;")
            self._local.conn = conn
        return self._local.conn

    def initialize(self) -> None:
        """Run migrations and verify database connectivity."""
        with self._lock:
            if not self._initialized:
                logger.info("Initializing database at %s", self.db_path)
                with self.connection() as conn:
                    apply_migrations(conn)
                self._initialized = True
                logger.info("Database initialized successfully with WAL mode.")

    @contextmanager
    def connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Provide a connection context."""
        conn = self._get_connection()
        try:
            yield conn
        except Exception:
            conn.rollback()
            raise

    def close(self) -> None:
        """Close current thread connection."""
        if hasattr(self._local, "conn") and self._local.conn is not None:
            try:
                self._local.conn.close()
            except Exception:
                pass
            self._local.conn = None


# Global database instance
db = Database()
