"""Collector for Linux authentication log (/var/log/auth.log)."""

from __future__ import annotations

from typing import Generator, Optional, Tuple
from logintel.collectors.base import Collector
from logintel.collectors.file_tailer import FileTailer
from logintel.config import settings
from logintel.models import RawRecord


class AuthLogCollector(Collector):
    """Monitors /var/log/auth.log for authentication and privilege events."""

    def __init__(
        self,
        file_path: Optional[str] = None,
        current_offset: int = 0,
        current_inode: Optional[int] = None,
    ):
        super().__init__(name="auth.log", source_type="file")
        path = file_path or settings.collectors.auth_log_path
        self.tailer = FileTailer(
            file_path=path,
            source_name="auth.log",
            host=settings.host_name,
            current_offset=current_offset,
            current_inode=current_inode,
        )

    def check_availability(self) -> Tuple[bool, Optional[str]]:
        return self.tailer.check_availability()

    def collect_historical(self, limit: int = 2000) -> Generator[RawRecord, None, None]:
        for rec in self.tailer.read_historical(max_records=limit):
            self.total_records += 1
            yield rec

    def collect_new(self) -> Generator[RawRecord, None, None]:
        for rec in self.tailer.read_new():
            self.total_records += 1
            yield rec
