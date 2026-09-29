"""Base parser protocol for security telemetry parsing."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional
from logintel.models import CanonicalEvent, RawRecord


class BaseParser(ABC):
    """Abstract interface for log parsers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this parser."""
        pass

    @abstractmethod
    def can_parse(self, record: RawRecord) -> bool:
        """Quickly test whether this parser applies to the given raw record."""
        pass

    @abstractmethod
    def parse(self, record: RawRecord) -> Optional[CanonicalEvent]:
        """Parse raw record into a structured CanonicalEvent."""
        pass
