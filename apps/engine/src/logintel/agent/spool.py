"""Crash-safe bounded JSONL spool for remote collector batches."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List
import uuid


class JsonlSpool:
    def __init__(self, directory: Path, max_bytes: int) -> None:
        self.directory = directory
        self.max_bytes = max_bytes
        self.directory.mkdir(parents=True, exist_ok=True)
        self.directory.chmod(0o700)

    def _files(self) -> List[Path]:
        return sorted(self.directory.glob("*.jsonl"), key=lambda item: item.name)

    def bytes_used(self) -> int:
        return sum(item.stat().st_size for item in self._files())

    def enqueue(self, records: List[Dict[str, Any]]) -> Path:
        payload = "".join(json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n" for record in records)
        encoded = payload.encode("utf-8")
        if len(encoded) > self.max_bytes or self.bytes_used() + len(encoded) > self.max_bytes:
            raise RuntimeError("Agent spool capacity reached; telemetry is retained at source until capacity is available")
        target = self.directory / f"{uuid.uuid4().hex}.jsonl"
        temporary = target.with_suffix(".tmp")
        temporary.write_bytes(encoded)
        temporary.chmod(0o600)
        temporary.replace(target)
        return target

    def peek(self) -> tuple[Path, List[Dict[str, Any]]] | None:
        files = self._files()
        if not files:
            return None
        path = files[0]
        return path, [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]

    def acknowledge(self, path: Path) -> None:
        path.unlink(missing_ok=True)
