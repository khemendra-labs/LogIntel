"""Bounded, evidence-preserving SQLite maintenance operations."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from logintel.config import settings
from logintel.storage.db import Database, db as default_db


class RetentionService:
    """Plans and executes conservative event retention in bounded transactions."""

    def __init__(self, database: Optional[Database] = None) -> None:
        self.database = database or default_db

    def plan(self, retention_days: Optional[int] = None) -> Dict[str, Any]:
        days = retention_days or settings.retention.event_retention_days
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        sql = """
            SELECT COUNT(*) FROM events e
            WHERE e.timestamp < ?
              AND NOT EXISTS (SELECT 1 FROM detection_evidence de WHERE de.event_id = e.id)
        """
        with self.database.connection() as conn:
            eligible = conn.execute(sql, (cutoff,)).fetchone()[0]
            protected = conn.execute(
                "SELECT COUNT(*) FROM events e WHERE e.timestamp < ? AND EXISTS "
                "(SELECT 1 FROM detection_evidence de WHERE de.event_id = e.id)", (cutoff,)
            ).fetchone()[0]
        return {"cutoff": cutoff, "retention_days": days, "eligible_events": eligible, "protected_evidence_events": protected}

    def run(self, retention_days: Optional[int] = None, dry_run: bool = True) -> Dict[str, Any]:
        plan = self.plan(retention_days)
        if dry_run:
            return {**plan, "dry_run": True, "deleted_events": 0}
        limit = settings.retention.max_delete_batch
        with self.database.connection() as conn:
            cur = conn.execute(
                """DELETE FROM events WHERE id IN (
                    SELECT e.id FROM events e
                    WHERE e.timestamp < ?
                      AND NOT EXISTS (SELECT 1 FROM detection_evidence de WHERE de.event_id = e.id)
                    ORDER BY e.timestamp ASC LIMIT ?
                )""",
                (plan["cutoff"], limit),
            )
            deleted = cur.rowcount
            conn.commit()
            # Passive checkpoint avoids blocking concurrent investigative reads.
            checkpoint = conn.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
        return {**plan, "dry_run": False, "deleted_events": deleted, "batch_limit": limit, "checkpoint": list(checkpoint) if checkpoint else []}


retention_service = RetentionService()
