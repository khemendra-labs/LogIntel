"""Repository for canonical event persistence, querying, and aggregated statistics."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple
from logintel.logging import get_logger
from logintel.models import CanonicalEvent
from logintel.storage.db import Database, db

logger = get_logger("storage.events_repo")


class EventsRepository:
    """Manages storage and retrieval of CanonicalEvents in SQLite."""

    def __init__(self, database: Optional[Database] = None):
        self.db = database or db

    def insert_events(self, events: List[CanonicalEvent]) -> int:
        """Batch insert canonical events into the database. Returns number of inserted events."""
        if not events:
            return 0

        rows = [e.to_db_row() for e in events]
        sql = """
        INSERT OR IGNORE INTO events (
            id, timestamp, ingested_at, host, source, event_type, severity,
            username, uid, session_id, terminal,
            process_name, process_pid, process_ppid, process_executable, process_command_line,
            src_ip, src_port, dst_ip, dst_port, protocol,
            action, outcome, summary, raw_message, iocs_json,
            parser, source_file, source_offset, metadata_json,
            event_fingerprint
        ) VALUES (
            :id, :timestamp, :ingested_at, :host, :source, :event_type, :severity,
            :username, :uid, :session_id, :terminal,
            :process_name, :process_pid, :process_ppid, :process_executable, :process_command_line,
            :src_ip, :src_port, :dst_ip, :dst_port, :protocol,
            :action, :outcome, :summary, :raw_message, :iocs_json,
            :parser, :source_file, :source_offset, :metadata_json,
            :event_fingerprint
        )
        """
        with self.db.connection() as conn:
            before = conn.total_changes
            cursor = conn.cursor()
            cursor.executemany(sql, rows)
            conn.commit()
            return conn.total_changes - before

    def get_event_by_id(self, event_id: str) -> Optional[CanonicalEvent]:
        """Fetch a single canonical event by its UUID."""
        sql = "SELECT * FROM events WHERE id = ?"
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (event_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return CanonicalEvent.from_db_row(dict(row))

    def query_events(
        self,
        limit: int = 50,
        offset: int = 0,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        source: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        username: Optional[str] = None,
        ip: Optional[str] = None,
        outcome: Optional[str] = None,
        search: Optional[str] = None,
        sort_order: str = "DESC",
    ) -> Tuple[List[CanonicalEvent], int]:
        """Query canonical events with pagination, parameter filtering, and total count."""
        where_clauses: List[str] = []
        params: List[Any] = []

        if start_time:
            where_clauses.append("timestamp >= ?")
            params.append(start_time.isoformat())

        if end_time:
            where_clauses.append("timestamp <= ?")
            params.append(end_time.isoformat())

        if source:
            where_clauses.append("source = ?")
            params.append(source)

        if event_type:
            where_clauses.append("event_type = ?")
            params.append(event_type)

        if severity:
            where_clauses.append("severity = ?")
            params.append(severity)

        if username:
            where_clauses.append("username = ?")
            params.append(username)

        if ip:
            where_clauses.append("(src_ip = ? OR dst_ip = ?)")
            params.extend([ip, ip])

        if outcome:
            where_clauses.append("outcome = ?")
            params.append(outcome)

        if search:
            search_param = f"%{search}%"
            where_clauses.append(
                "(summary LIKE ? OR raw_message LIKE ? OR process_name LIKE ? OR username LIKE ?)"
            )
            params.extend([search_param, search_param, search_param, search_param])

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        order_direction = "ASC" if sort_order.upper() == "ASC" else "DESC"

        count_sql = f"SELECT COUNT(*) FROM events {where_sql}"
        data_sql = f"""
            SELECT * FROM events
            {where_sql}
            ORDER BY timestamp {order_direction}
            LIMIT ? OFFSET ?
        """

        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(count_sql, params)
            total_count = cursor.fetchone()[0]

            data_params = list(params) + [limit, offset]
            cursor.execute(data_sql, data_params)
            rows = cursor.fetchall()
            events = [CanonicalEvent.from_db_row(dict(r)) for r in rows]

            return events, total_count

    def get_event_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """Aggregate event counts, severity breakdowns, sources, and hourly timeline."""
        since_time = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

        with self.db.connection() as conn:
            cursor = conn.cursor()

            # Total events count
            cursor.execute("SELECT COUNT(*) FROM events")
            total_events = cursor.fetchone()[0]

            # Events in window
            cursor.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ?", (since_time,))
            window_events = cursor.fetchone()[0]

            # By severity
            cursor.execute(
                "SELECT severity, COUNT(*) FROM events WHERE timestamp >= ? GROUP BY severity",
                (since_time,),
            )
            by_severity = {row[0]: row[1] for row in cursor.fetchall()}

            # By event type (top 10)
            cursor.execute(
                "SELECT event_type, COUNT(*) as cnt FROM events WHERE timestamp >= ? GROUP BY event_type ORDER BY cnt DESC LIMIT 10",
                (since_time,),
            )
            by_type = {row[0]: row[1] for row in cursor.fetchall()}

            # By source
            cursor.execute(
                "SELECT source, COUNT(*) FROM events WHERE timestamp >= ? GROUP BY source",
                (since_time,),
            )
            by_source = {row[0]: row[1] for row in cursor.fetchall()}

            # Hourly timeline
            cursor.execute(
                """
                SELECT strftime('%Y-%m-%dT%H:00:00Z', timestamp) as hour_bucket, COUNT(*)
                FROM events
                WHERE timestamp >= ?
                GROUP BY hour_bucket
                ORDER BY hour_bucket ASC
                """,
                (since_time,),
            )
            timeline = [{"bucket": row[0], "count": row[1]} for row in cursor.fetchall()]

            # Recent security-relevant events (failures, warnings, alerts)
            cursor.execute(
                """
                SELECT * FROM events
                WHERE severity IN ('WARNING', 'ALERT', 'CRITICAL') OR outcome = 'FAILURE'
                ORDER BY timestamp DESC
                LIMIT 10
                """
            )
            recent_alerts = [CanonicalEvent.from_db_row(dict(r)).model_dump(mode="json") for r in cursor.fetchall()]

            return {
                "total_events": total_events,
                "window_hours": hours,
                "window_events": window_events,
                "by_severity": by_severity,
                "by_type": by_type,
                "by_source": by_source,
                "timeline": timeline,
                "recent_alerts": recent_alerts,
            }

    def get_ingestion_state(self, source_name: str) -> Optional[Dict[str, Any]]:
        """Fetch current ingestion state record for a source."""
        sql = "SELECT * FROM ingestion_state WHERE source_name = ?"
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (source_name,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def update_ingestion_state(
        self,
        source_name: str,
        cursor: Optional[str] = None,
        byte_offset: int = 0,
        inode: Optional[int] = None,
        records_delta: int = 0,
        error_count_delta: int = 0,
        last_error: Optional[str] = None,
    ) -> None:
        """Upsert current cursor, offset, inode, and metrics for a telemetry source."""
        now_iso = datetime.now(timezone.utc).isoformat()
        sql = """
        INSERT INTO ingestion_state (
            source_name, cursor, byte_offset, inode, last_run_at, total_records_ingested, error_count, last_error
        ) VALUES (
            :source_name, :cursor, :byte_offset, :inode, :now, :records_delta, :error_count_delta, :last_error
        )
        ON CONFLICT(source_name) DO UPDATE SET
            cursor = coalesce(:cursor, ingestion_state.cursor),
            byte_offset = :byte_offset,
            inode = coalesce(:inode, ingestion_state.inode),
            last_run_at = :now,
            total_records_ingested = ingestion_state.total_records_ingested + :records_delta,
            error_count = ingestion_state.error_count + :error_count_delta,
            last_error = coalesce(:last_error, ingestion_state.last_error)
        """
        with self.db.connection() as conn:
            conn.cursor().execute(
                sql,
                {
                    "source_name": source_name,
                    "cursor": cursor,
                    "byte_offset": byte_offset,
                    "inode": inode,
                    "now": now_iso,
                    "records_delta": records_delta,
                    "error_count_delta": error_count_delta,
                    "last_error": last_error,
                },
            )
            conn.commit()

    def get_all_ingestion_states(self) -> List[Dict[str, Any]]:
        """Fetch ingestion state for all tracked sources."""
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ingestion_state ORDER BY source_name ASC")
            return [dict(r) for r in cursor.fetchall()]

    def upsert_host(
        self,
        hostname: str,
        os_name: Optional[str] = None,
        os_version: Optional[str] = None,
    ) -> None:
        """Ensure host entry exists and is updated with last_seen."""
        import hashlib
        host_id = hashlib.sha256(hostname.encode("utf-8")).hexdigest()[:16]
        now_iso = datetime.now(timezone.utc).isoformat()
        sql = """
        INSERT INTO hosts (id, hostname, os_name, os_version, first_seen, last_seen)
        VALUES (:id, :hostname, :os_name, :os_version, :now, :now)
        ON CONFLICT(hostname) DO UPDATE SET
            last_seen = :now,
            os_name = coalesce(:os_name, hosts.os_name),
            os_version = coalesce(:os_version, hosts.os_version)
        """
        with self.db.connection() as conn:
            conn.cursor().execute(
                sql,
                {
                    "id": host_id,
                    "hostname": hostname,
                    "os_name": os_name,
                    "os_version": os_version,
                    "now": now_iso,
                },
            )
            conn.commit()

    def upsert_source(
        self,
        name: str,
        source_type: str,
        path: Optional[str] = None,
        enabled: bool = True,
    ) -> None:
        """Ensure source metadata entry exists and is kept in sync."""
        import hashlib
        source_id = hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]
        now_iso = datetime.now(timezone.utc).isoformat()
        sql = """
        INSERT INTO sources (id, name, source_type, path, enabled, created_at, updated_at)
        VALUES (:id, :name, :source_type, :path, :enabled, :now, :now)
        ON CONFLICT(name) DO UPDATE SET
            source_type = :source_type,
            path = :path,
            enabled = :enabled,
            updated_at = :now
        """
        with self.db.connection() as conn:
            conn.cursor().execute(
                sql,
                {
                    "id": source_id,
                    "name": name,
                    "source_type": source_type,
                    "path": path,
                    "enabled": 1 if enabled else 0,
                    "now": now_iso,
                },
            )
            conn.commit()

    def get_all_hosts(self) -> List[Dict[str, Any]]:
        """Fetch all recorded host entities."""
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM hosts ORDER BY hostname ASC")
            return [dict(r) for r in cursor.fetchall()]

    def get_all_sources(self) -> List[Dict[str, Any]]:
        """Fetch all configured source entities."""
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sources ORDER BY name ASC")
            return [dict(r) for r in cursor.fetchall()]


events_repo = EventsRepository()
