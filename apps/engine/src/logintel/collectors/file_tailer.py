"""File tailer utility with rotation awareness, offset tracking, and error handling."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Optional, Tuple
from logintel.logging import get_logger
from logintel.models import RawRecord

logger = get_logger("collectors.file_tailer")


class FileTailer:
    """Reads logs from a file with offset tracking and rotation detection."""

    def __init__(
        self,
        file_path: str,
        source_name: str,
        host: str,
        current_offset: int = 0,
        current_inode: Optional[int] = None,
    ):
        self.file_path = Path(file_path)
        self.source_name = source_name
        self.host = host
        self.current_offset = current_offset
        self.current_inode = current_inode

    def check_availability(self) -> Tuple[bool, Optional[str]]:
        """Verify file existence and read permissions."""
        if not self.file_path.exists():
            return False, f"File {self.file_path} does not exist."
        if not os.access(self.file_path, os.R_OK):
            return (
                False,
                f"Permission denied reading {self.file_path}. Ensure the user belongs to the 'adm' group (sudo usermod -aG adm $USER).",
            )
        return True, None

    def _get_file_stat(self) -> Optional[os.stat_result]:
        try:
            return self.file_path.stat()
        except (OSError, PermissionError) as exc:
            logger.debug("Stat error on %s: %s", self.file_path, exc)
            return None

    def read_historical(self, max_records: int = 2000) -> Generator[RawRecord, None, None]:
        """Read recent historical entries from the file up to max_records."""
        available, reason = self.check_availability()
        if not available:
            logger.warning("Cannot read historical records from %s: %s", self.file_path, reason)
            return

        # If offset is already persisted from a previous run, do not re-read historical lines
        if self.current_offset > 0:
            logger.info(
                "Persisted offset %d detected for %s; skipping historical reload and resuming incrementally.",
                self.current_offset,
                self.file_path,
            )
            yield from self.read_new()
            return

        stat = self._get_file_stat()
        if not stat:
            return
        self.current_inode = stat.st_ino
        file_size = stat.st_size

        try:
            with open(self.file_path, "r", encoding="utf-8", errors="replace") as f:
                # If file is very large, seek to roughly estimate last records
                estimated_bytes_per_line = 150
                bytes_to_read = max_records * estimated_bytes_per_line
                if file_size > bytes_to_read:
                    f.seek(file_size - bytes_to_read)
                    # Discard partial line
                    f.readline()
                else:
                    f.seek(0)

                while True:
                    line_start_offset = f.tell()
                    line = f.readline()
                    if not line:
                        break
                    self.current_offset = f.tell()
                    cleaned = line.rstrip("\r\n")
                    if cleaned:
                        yield RawRecord(
                            source=self.source_name,
                            raw_content=cleaned,
                            timestamp=None,
                            host=self.host,
                            source_file=str(self.file_path),
                            source_offset=str(line_start_offset),
                        )
        except Exception as exc:
            logger.error("Error reading historical records from %s: %s", self.file_path, exc)

    def read_new(self) -> Generator[RawRecord, None, None]:
        """Read new appended lines since last offset. Detect log rotation."""
        available, reason = self.check_availability()
        if not available:
            return

        stat = self._get_file_stat()
        if not stat:
            return

        # Check for log rotation: inode change or file truncation
        if self.current_inode is not None and (
            stat.st_ino != self.current_inode or stat.st_size < self.current_offset
        ):
            logger.info("Log rotation detected for %s. Resetting offset to 0.", self.file_path)
            self.current_offset = 0
            self.current_inode = stat.st_ino

        if stat.st_size <= self.current_offset:
            # No new data
            return

        self.current_inode = stat.st_ino

        try:
            with open(self.file_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self.current_offset)
                while True:
                    line_start_offset = f.tell()
                    line = f.readline()
                    if not line:
                        break
                    self.current_offset = f.tell()
                    cleaned = line.rstrip("\r\n")
                    if cleaned:
                        yield RawRecord(
                            source=self.source_name,
                            raw_content=cleaned,
                            timestamp=None,
                            host=self.host,
                            source_file=str(self.file_path),
                            source_offset=str(line_start_offset),
                        )
        except Exception as exc:
            logger.error("Error reading new lines from %s: %s", self.file_path, exc)
