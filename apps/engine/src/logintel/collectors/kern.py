"""Collector for Linux kernel log (/var/log/kern.log)."""

from __future__ import annotations

from typing import Generator, Optional, Tuple
from logintel.collectors.base import Collector
from logintel.collectors.file_tailer import FileTailer
from logintel.config import settings
from logintel.models import RawRecord


class KernLogCollector(Collector):
    """Monitors /var/log/kern.log for kernel messages, driver events, and hardware alerts."""

    def __init__(self, file_path: Optional[str] = None):
        super().__init__(name="kern.log", source_type="file")
        path = file_path or settings.collectors.kern_log_path
        self.tailer = FileTailer(
            file_path=path,
            source_name="kern.log",
            host=settings.host_name,
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
