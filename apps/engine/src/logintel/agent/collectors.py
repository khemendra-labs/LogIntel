"""Low-overhead native Linux telemetry collection for the remote agent."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
from typing import Any, Dict, List

from logintel.agent.config import AgentConfig


class AgentCollectors:
    """Collect appended file lines and bounded journal entries with durable cursors."""

    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.state_path = config.spool_dir / "collector-state.json"
        self.state = self._load_state()

    def _load_state(self) -> Dict[str, Any]:
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"files": {}, "journal_cursor": None}

    def _save_state(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.state_path.with_suffix(".tmp")
        temp.write_text(json.dumps(self.state, separators=(",", ":")), encoding="utf-8")
        temp.chmod(0o600)
        temp.replace(self.state_path)

    def collect_once(self) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        for source, path in self.config.log_paths.items():
            records.extend(self._collect_file(source, path))
        if self.config.journald_enabled:
            records.extend(self._collect_journal())
        self._save_state()
        return records

    def _collect_file(self, source: str, path: Path) -> List[Dict[str, Any]]:
        try:
            stat = path.stat()
        except OSError:
            return []
        saved = self.state["files"].get(source, {})
        offset = int(saved.get("offset", 0))
        if saved.get("inode") != stat.st_ino or stat.st_size < offset:
            offset = 0
        records: List[Dict[str, Any]] = []
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(offset)
                while True:
                    line = handle.readline(self.config.max_record_bytes + 1)
                    if not line:
                        break
                    if len(line.encode("utf-8", errors="replace")) > self.config.max_record_bytes:
                        # Drain the remainder in fixed-size chunks. Oversized
                        # lines are intentionally skipped: sending a truncated
                        # security record creates misleading forensic evidence.
                        while line and not line.endswith("\n"):
                            line = handle.readline(64 * 1024)
                        offset = handle.tell()
                        continue
                    content = line.rstrip("\r\n")
                    if content:
                        records.append({"source": source, "raw_content": content, "source_file": str(path), "source_offset": str(offset)})
                    offset = handle.tell()
        except OSError:
            return records
        self.state["files"][source] = {"inode": stat.st_ino, "offset": offset}
        return records

    def _collect_journal(self) -> List[Dict[str, Any]]:
        command = ["journalctl", "--no-pager", "-o", "json"]
        cursor = self.state.get("journal_cursor")
        if cursor:
            command.extend(["--after-cursor", cursor])
        else:
            command.extend(["-n", str(self.config.journal_max_records)])
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
        except OSError:
            return []
        if result.returncode != 0:
            self.state["journal_cursor"] = None
            return []
        records: List[Dict[str, Any]] = []
        for line in result.stdout.splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            self.state["journal_cursor"] = entry.get("__CURSOR", self.state.get("journal_cursor"))
            message = entry.get("MESSAGE", "")
            if isinstance(message, list):
                message = bytes(message).decode("utf-8", errors="replace")
            if message:
                records.append({"source": "journald", "raw_content": str(message), "source_file": "journald", "source_offset": self.state.get("journal_cursor")})
                if len(records) >= self.config.journal_max_records:
                    break
        return records
