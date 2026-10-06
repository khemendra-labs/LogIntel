"""Parser registry managing detection and execution of parsers."""

from __future__ import annotations

from typing import List, Optional, Tuple
from logintel.logging import get_logger
from logintel.models import CanonicalEvent, RawRecord
from logintel.parsers.audit import AuditParser
from logintel.parsers.base import BaseParser
from logintel.parsers.container import ContainerParser
from logintel.parsers.generic import GenericSyslogParser
from logintel.parsers.kernel import KernelParser
from logintel.parsers.pam import PAMSessionParser
from logintel.parsers.ssh import SSHAuthParser
from logintel.parsers.sudo import SudoParser
from logintel.parsers.systemd import SystemdParser
from logintel.parsers.user_mgmt import UserManagementParser

logger = get_logger("parsers.registry")


class ParserRegistry:
    """Manages ordered parser evaluation for incoming raw records."""

    def __init__(self):
        self._parsers: List[BaseParser] = []
        self._fallback_parser = GenericSyslogParser()
        self._load_default_parsers()

    def _load_default_parsers(self) -> None:
        # Specialized parsers registered in order of specificity
        self.register_parser(AuditParser())
        self.register_parser(SSHAuthParser())
        self.register_parser(SudoParser())
        self.register_parser(PAMSessionParser())
        self.register_parser(UserManagementParser())
        self.register_parser(KernelParser())
        self.register_parser(SystemdParser())
        self.register_parser(ContainerParser())

    def register_parser(self, parser: BaseParser) -> None:
        """Register a new parser."""
        self._parsers.append(parser)
        logger.debug("Registered parser: %s", parser.name)

    def parse_record(self, record: RawRecord) -> Tuple[CanonicalEvent, bool]:
        """Attempt parsing with specialized parsers; fallback to generic syslog if none match.

        Returns:
            Tuple of (canonical_event, is_specialized_parsed)
        """
        for parser in self._parsers:
            try:
                if parser.can_parse(record):
                    event = parser.parse(record)
                    if event:
                        return event, True
            except Exception as exc:
                logger.warning("Parser %s failed on record: %s", parser.name, exc)

        # Fallback
        fallback_event = self._fallback_parser.parse(record)
        return fallback_event or CanonicalEvent(
            host=record.host or "unknown",
            source=record.source,
            summary=record.raw_content[:80],
            raw_message=record.raw_content,
            source_file=record.source_file,
            source_offset=record.source_offset,
        ), False


# Global singleton registry
parser_registry = ParserRegistry()
