"""Raw telemetry record emitted by collectors before parsing and normalization."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass
class RawRecord:
    """Represents an unparsed, raw record obtained by a telemetry collector."""
    source: str
    raw_content: str
    timestamp: Optional[datetime] = None
    host: Optional[str] = None
    source_file: Optional[str] = None
    source_offset: Optional[str] = None
    raw_attributes: Dict[str, Any] = field(default_factory=dict)
