"""Process-to-socket inode correlation resolver (M6.4).

Scans /proc/<pid>/fd/ to associate kernel socket inodes with active host processes:
- Extracts PID, process name (comm), executable path (exe), and command line.
- Sanitizes credentials in command line via mask_credentials.
- Handles unprivileged permissions gracefully (e.g. EACCES on root processes).
- Assigns epistemic status: OBSERVED when inode is found, UNKNOWN when missing.
"""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import re
import time
from typing import Dict, NamedTuple, Optional

from logintel.network.models import SocketEntry
from logintel.normalization.sanitizer import mask_credentials

SOCKET_LINK_RE = re.compile(r"^socket:\[(\d+)\]$")


class ProcessSocketInfo(NamedTuple):
    pid: int
    name: str
    executable: Optional[str]
    command_line: Optional[str]
    user: Optional[str]


class SocketProcessResolver:
    """Correlates socket inodes to host processes by scanning /proc/<pid>/fd/."""

    def __init__(self, proc_path: str = "/proc", cache_ttl_sec: float = 2.0) -> None:
        self.proc_path = Path(proc_path)
        self.cache_ttl_sec = cache_ttl_sec
        self._cache: Dict[int, ProcessSocketInfo] = {}
        self._last_scan_time: float = 0.0

    def refresh_cache(self, force: bool = False) -> Dict[int, ProcessSocketInfo]:
        """Scan /proc for socket file descriptors and update the inode-to-process map."""
        now = time.time()
        if not force and (now - self._last_scan_time) < self.cache_ttl_sec:
            return self._cache

        new_map: Dict[int, ProcessSocketInfo] = {}

        if not self.proc_path.exists():
            self._cache = {}
            self._last_scan_time = now
            return self._cache

        try:
            pid_dirs = [d for d in os.listdir(self.proc_path) if d.isdigit()]
        except (OSError, PermissionError):
            return self._cache

        for pid_str in pid_dirs:
            try:
                pid = int(pid_str)
                fd_dir = self.proc_path / pid_str / "fd"
                if not fd_dir.is_dir():
                    continue

                # Read process metadata lazily if we find a socket
                proc_info: Optional[ProcessSocketInfo] = None

                try:
                    fd_entries = os.listdir(fd_dir)
                except (OSError, PermissionError):
                    # Permission denied on processes owned by another user (e.g. root)
                    continue

                for fd_name in fd_entries:
                    fd_path = fd_dir / fd_name
                    try:
                        target = os.readlink(fd_path)
                    except (OSError, PermissionError):
                        continue

                    m = SOCKET_LINK_RE.match(target)
                    if m:
                        inode = int(m.group(1))
                        if proc_info is None:
                            proc_info = self._read_proc_info(pid)
                        new_map[inode] = proc_info

            except (ValueError, OSError):
                continue

        self._cache = new_map
        self._last_scan_time = now
        return self._cache

    def _read_proc_info(self, pid: int) -> ProcessSocketInfo:
        """Extract process name, executable, and sanitized command line for a PID."""
        pid_dir = self.proc_path / str(pid)

        # Process name from /proc/<pid>/comm
        name = "unknown"
        comm_file = pid_dir / "comm"
        try:
            if comm_file.exists():
                name = comm_file.read_text(encoding="utf-8", errors="replace").strip()
        except (OSError, PermissionError):
            pass

        # Executable path from /proc/<pid>/exe symlink
        executable: Optional[str] = None
        exe_path = pid_dir / "exe"
        try:
            if exe_path.exists():
                executable = os.readlink(exe_path)
        except (OSError, PermissionError):
            pass

        # Command line from /proc/<pid>/cmdline
        command_line: Optional[str] = None
        cmd_file = pid_dir / "cmdline"
        try:
            if cmd_file.exists():
                raw_cmd = cmd_file.read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
                if raw_cmd:
                    command_line = mask_credentials(raw_cmd)
        except (OSError, PermissionError):
            pass

        # Username / UID from /proc/<pid>/status
        user: Optional[str] = None
        status_file = pid_dir / "status"
        try:
            if status_file.exists():
                for line in status_file.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.startswith("Uid:"):
                        parts = line.split()
                        if len(parts) > 1:
                            user = f"uid:{parts[1]}"
                        break
        except (OSError, PermissionError):
            pass

        return ProcessSocketInfo(
            pid=pid,
            name=name,
            executable=executable,
            command_line=command_line,
            user=user,
        )

    def resolve_entry(self, entry: SocketEntry) -> SocketEntry:
        """Enrich a SocketEntry with process context matching its inode."""
        if entry.inode <= 0:
            entry.epistemic_status = "UNKNOWN"
            return entry

        cache = self.refresh_cache()
        info = cache.get(entry.inode)

        if info:
            entry.pid = info.pid
            entry.process_name = info.name
            entry.process_executable = info.executable
            entry.process_cmdline = info.command_line
            entry.process_user = info.user
            entry.epistemic_status = "OBSERVED"
        else:
            entry.epistemic_status = "UNKNOWN"

        return entry

    def resolve_entries(self, entries: list[SocketEntry]) -> list[SocketEntry]:
        """Enrich a batch of SocketEntry records."""
        self.refresh_cache()
        for e in entries:
            self.resolve_entry(e)
        return entries
