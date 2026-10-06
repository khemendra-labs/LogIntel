"""Collector for Linux audit log (/var/log/audit/audit.log).

Tails audit.log with offset tracking, log rotation detection, and deterministic
multi-record event correlation by audit message identifier (msg=audit(ts:seq)).
"""

from __future__ import annotations

import re
from typing import Generator, List, Optional, Tuple

from logintel.collectors.base import Collector
from logintel.collectors.file_tailer import FileTailer
from logintel.config import settings
from logintel.logging import get_logger
from logintel.models import RawRecord

logger = get_logger("collectors.audit")

AUDIT_MSG_ID_RE = re.compile(r"\bmsg=audit\(([^)]+)\)")
MAX_GROUPED_AUDIT_LINES = 32


class AuditLogCollector(Collector):
    """Monitors /var/log/audit/audit.log for process execution, syscalls, and session events."""

    def __init__(
        self,
        file_path: Optional[str] = None,
        current_offset: int = 0,
        current_inode: Optional[int] = None,
    ):
        super().__init__(name="audit.log", source_type="file")
        path = file_path or settings.collectors.audit_log_path
        self.tailer = FileTailer(
            file_path=path,
            source_name="audit.log",
            host=settings.host_name,
            current_offset=current_offset,
            current_inode=current_inode,
        )
        self._pending_batch: List[RawRecord] = []
        self._pending_audit_id: Optional[str] = None

    def check_availability(self) -> Tuple[bool, Optional[str]]:
        avail, reason = self.tailer.check_availability()
        if not avail:
            return (
                False,
                f"Audit telemetry unavailable: {reason} Ensure the user belongs to the 'adm' group (sudo usermod -aG adm $USER).",
            )
        return True, None

    @staticmethod
    def _extract_audit_id(line: str) -> Optional[str]:
        m = AUDIT_MSG_ID_RE.search(line)
        return m.group(1) if m else None

    def _merge_records(self, batch: List[RawRecord], audit_id: Optional[str]) -> RawRecord:
        """Merge multiple single-line audit records belonging to the same event."""
        primary = batch[0]
        merged_content = "\n".join(r.raw_content for r in batch)
        merged_offsets = [r.source_offset for r in batch if r.source_offset is not None]

        return RawRecord(
            source=self.name,
            raw_content=merged_content,
            timestamp=primary.timestamp,
            host=primary.host,
            source_file=primary.source_file,
            source_offset=primary.source_offset,
            raw_attributes={
                "audit_id": audit_id,
                "contributing_offsets": merged_offsets,
                "contributing_records_count": len(batch),
            },
        )

    def collect_historical(self, limit: int = 2000) -> Generator[RawRecord, None, None]:
        """Read historical audit entries and group related records by audit_id."""
        batch: List[RawRecord] = []
        current_id: Optional[str] = None

        for rec in self.tailer.read_historical(max_records=limit):
            audit_id = self._extract_audit_id(rec.raw_content)

            if audit_id and audit_id == current_id and len(batch) < MAX_GROUPED_AUDIT_LINES:
                batch.append(rec)
            else:
                if batch:
                    self.total_records += 1
                    yield self._merge_records(batch, current_id)
                    batch = []
                if audit_id:
                    current_id = audit_id
                    batch = [rec]
                else:
                    self.total_records += 1
                    yield rec

        if batch:
            self.total_records += 1
            yield self._merge_records(batch, current_id)

    def collect_new(self) -> Generator[RawRecord, None, None]:
        """Read newly appended records and group by audit_id across collection cycles."""
        for rec in self.tailer.read_new():
            audit_id = self._extract_audit_id(rec.raw_content)

            if audit_id and audit_id == self._pending_audit_id and len(self._pending_batch) < MAX_GROUPED_AUDIT_LINES:
                self._pending_batch.append(rec)
            else:
                if self._pending_batch:
                    self.total_records += 1
                    yield self._merge_records(self._pending_batch, self._pending_audit_id)
                    self._pending_batch = []

                if audit_id:
                    self._pending_audit_id = audit_id
                    self._pending_batch = [rec]
                else:
                    self.total_records += 1
                    yield rec

        # Flush pending batch at the end of cycle
        if self._pending_batch:
            self.total_records += 1
            yield self._merge_records(self._pending_batch, self._pending_audit_id)
            self._pending_batch = []
            self._pending_audit_id = None
