"""Collector for systemd journal telemetry via journalctl JSON output."""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Generator, Optional, Tuple
from logintel.collectors.base import Collector
from logintel.config import settings
from logintel.logging import get_logger
from logintel.models import RawRecord

logger = get_logger("collectors.journal")


class JournalCollector(Collector):
    """Collects systemd journal telemetry using cursor tracking."""

    def __init__(self, cursor: Optional[str] = None):
        super().__init__(name="journald", source_type="journal")
        self.cursor: Optional[str] = cursor
        self._journalctl_bin: Optional[str] = shutil.which("journalctl")

    def check_availability(self) -> Tuple[bool, Optional[str]]:
        if not self._journalctl_bin:
            return False, "journalctl command not found in PATH."

        try:
            res = subprocess.run(
                [self._journalctl_bin, "-n", "1", "--quiet"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=3,
            )
            if res.returncode != 0:
                return (
                    False,
                    f"journalctl exited with code {res.returncode}: {res.stderr.strip() or 'Permission denied'}. User must belong to 'systemd-journal' or 'adm' group.",
                )
            return True, None
        except Exception as exc:
            return False, f"Error executing journalctl: {exc}"

    def collect_historical(self, limit: int = 1000) -> Generator[RawRecord, None, None]:
        available, reason = self.check_availability()
        if not available:
            logger.warning("Journal telemetry unavailable: %s", reason)
            return

        # If a persisted cursor exists from previous runs, resume incrementally instead of re-reading history
        if self.cursor:
            logger.info("Restored persisted journald cursor %s; continuing incremental collection.", self.cursor)
            yield from self.collect_new()
            return

        cmd = [self._journalctl_bin, "-o", "json", "-n", str(limit)]
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, stderr = proc.communicate(timeout=15)
            if proc.returncode != 0:
                logger.error("journalctl failed: %s", stderr.strip())
                return

            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    cursor = data.get("__CURSOR")
                    if cursor:
                        self.cursor = cursor

                    # Extract timestamp from __REALTIME_TIMESTAMP (microseconds)
                    rt_ts = data.get("__REALTIME_TIMESTAMP")
                    dt = None
                    if rt_ts:
                        try:
                            dt = datetime.fromtimestamp(int(rt_ts) / 1_000_000, tz=timezone.utc)
                        except Exception:
                            dt = datetime.now(timezone.utc)
                    else:
                        dt = datetime.now(timezone.utc)

                    msg = data.get("MESSAGE", "")
                    if isinstance(msg, list):
                        # Some journald messages can be byte arrays
                        msg = bytes(msg).decode("utf-8", errors="replace")

                    self.total_records += 1
                    yield RawRecord(
                        source="journald",
                        raw_content=msg,
                        timestamp=dt,
                        host=data.get("_HOSTNAME") or settings.host_name,
                        source_file="journald",
                        source_offset=cursor,
                        raw_attributes=data,
                    )
                except Exception as exc:
                    logger.debug("Failed parsing journal JSON record: %s", exc)
        except Exception as exc:
            logger.error("Error executing journalctl historical query: %s", exc)

    def collect_new(self) -> Generator[RawRecord, None, None]:
        available, reason = self.check_availability()
        if not available:
            return

        cmd = [self._journalctl_bin, "-o", "json"]
        if self.cursor:
            cmd.extend(["--after-cursor", self.cursor])
        else:
            cmd.extend(["-n", "50"])

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, stderr = proc.communicate(timeout=10)
            if proc.returncode != 0:
                if self.cursor:
                    logger.warning(
                        "journalctl with cursor '%s' failed (code %d): %s. Cursor may be vacuumed or invalid. Recovering from current tail.",
                        self.cursor,
                        proc.returncode,
                        stderr.strip(),
                    )
                    self.cursor = None
                    recovery_proc = subprocess.run(
                        [self._journalctl_bin, "-o", "json", "-n", "10"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=5,
                    )
                    if recovery_proc.returncode == 0:
                        stdout = recovery_proc.stdout
                    else:
                        return
                else:
                    logger.error("journalctl failed: %s", stderr.strip())
                    return

            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    cursor = data.get("__CURSOR")
                    if cursor:
                        self.cursor = cursor

                    rt_ts = data.get("__REALTIME_TIMESTAMP")
                    dt = None
                    if rt_ts:
                        try:
                            dt = datetime.fromtimestamp(int(rt_ts) / 1_000_000, tz=timezone.utc)
                        except Exception:
                            dt = datetime.now(timezone.utc)
                    else:
                        dt = datetime.now(timezone.utc)

                    msg = data.get("MESSAGE", "")
                    if isinstance(msg, list):
                        msg = bytes(msg).decode("utf-8", errors="replace")

                    self.total_records += 1
                    yield RawRecord(
                        source="journald",
                        raw_content=msg,
                        timestamp=dt,
                        host=data.get("_HOSTNAME") or settings.host_name,
                        source_file="journald",
                        source_offset=cursor,
                        raw_attributes=data,
                    )
                except Exception as exc:
                    logger.debug("Error processing incremental journal entry: %s", exc)
        except Exception as exc:
            logger.error("Error running incremental journalctl: %s", exc)
