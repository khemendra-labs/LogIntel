"""Base collector abstraction for Linux telemetry sources."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Generator, Optional, Tuple
from logintel.models import RawRecord


class Collector(ABC):
    """Abstract base class for all Linux telemetry collectors."""

    def __init__(self, name: str, source_type: str):
        self.name = name
        self.source_type = source_type
        self.last_collected_at = None
        self.error_count = 0
        self.last_error: Optional[str] = None
        self.total_records = 0

    @abstractmethod
    def check_availability(self) -> Tuple[bool, Optional[str]]:
        """Check whether the telemetry source exists and is readable.

        Returns:
            Tuple of (is_available, error_message_or_permission_hint)
        """
        pass

    @abstractmethod
    def collect_historical(self, limit: int = 2000) -> Generator[RawRecord, None, None]:
        """Collect historical records up to limit, or from last saved offset/cursor."""
        pass

    @abstractmethod
    def collect_new(self) -> Generator[RawRecord, None, None]:
        """Collect new incremental records since last offset/cursor."""
        pass

    def get_health(self) -> Dict[str, Any]:
        """Return diagnostic health status for this collector."""
        available, reason = self.check_availability()
        return {
            "name": self.name,
            "source_type": self.source_type,
            "available": available,
            "error_reason": reason,
            "error_count": self.error_count,
            "last_error": self.last_error,
            "total_records": self.total_records,
            "last_collected_at": self.last_collected_at.isoformat() if self.last_collected_at else None,
        }
