"""Filesystem persistence and high-value integrity telemetry collector (M6.5).

Monitors Linux High-Value Targets (cron drops, systemd service drops, SSH keys,
privilege files like /etc/passwd, /etc/sudoers, and dynamic linker configs):
- Detects FILE_PERSISTENCE_DROP when new persistence hooks are installed.
- Detects FILE_PERSISTENCE_REMOVE when persistence hooks are removed.
- Detects FILE_INTEGRITY_MODIFY when sensitive file content hashes change.
- Detects FILE_METADATA_MODIFY when file permissions or ownership change.
- Preserves raw evidence in raw_message with deterministic SHA-256 fingerprints.
- Clamps memory and file sizes (10 MB limit per file, 2,000 files per scan).
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Dict, Generator, List, Optional

from logintel.collectors.base import Collector
from logintel.filesystem.models import (
    DEFAULT_HVT_TARGETS,
    FileState,
    FileTransition,
    FileTransitionType,
    HVTTarget,
    TargetCategory,
)
from logintel.filesystem.scanner import FileIntegrityScanner
from logintel.models import (
    Actor,
    CanonicalEvent,
    EventType,
    Network,
    Outcome,
    Process,
    RawRecord,
    Severity,
)


class FilesystemPersistenceCollector(Collector):
    """Monitors filesystem persistence vectors and high-value target integrity."""

    def __init__(
        self,
        name: str = "filesystem_collector",
        source_type: str = "filesystem_hvt",
        targets: Optional[List[HVTTarget]] = None,
        max_hash_size_bytes: int = 10 * 1024 * 1024,
    ) -> None:
        super().__init__(name=name, source_type=source_type)
        self.scanner = FileIntegrityScanner(
            targets=targets or DEFAULT_HVT_TARGETS,
            max_hash_size_bytes=max_hash_size_bytes,
        )
        self.host = "localhost"

        # Previous state cache: path -> FileState
        self._tracked_states: Dict[str, FileState] = {}
        self._transitions_log: List[FileTransition] = []
        self._is_initial_snapshot: bool = True

    def check_availability(self) -> tuple[bool, Optional[str]]:
        """Verify that filesystem scanner can inspect at least one target path."""
        for target in self.scanner.targets:
            state = self.scanner.scan_path(target.path, target.category)
            if state is not None:
                return True, None
        return False, "None of the configured High-Value Target paths could be read"

    def get_tracked_states(self) -> Dict[str, FileState]:
        """Return the current map of tracked file states."""
        return dict(self._tracked_states)

    def get_transitions(self) -> List[FileTransition]:
        """Return recorded state transitions."""
        return list(self._transitions_log)

    def collect(self) -> List[RawRecord]:
        """Poll filesystem targets and produce raw records for transitions."""
        events = self.collect_events()
        records: List[RawRecord] = []
        for ev in events:
            rec = RawRecord(
                source="filesystem_hvt",
                raw_content=ev.raw_message,
                host=ev.host,
                timestamp=ev.timestamp,
                source_file=ev.source_file,
                source_offset=str(ev.source_offset or "0"),
            )
            records.append(rec)
        return records

    def collect_historical(self, limit: int = 2000) -> Generator[RawRecord, None, None]:
        """Collect baseline file state records."""
        records = self.collect()
        for r in records[:limit]:
            yield r

    def collect_new(self) -> Generator[RawRecord, None, None]:
        """Collect incremental transition records."""
        records = self.collect()
        for r in records:
            yield r

    def collect_events(self) -> List[CanonicalEvent]:
        """Scan HVT paths, compare with previous states, and emit canonical events."""
        current_states = self.scanner.scan_all()
        events: List[CanonicalEvent] = []

        if self._is_initial_snapshot:
            # First poll: establish baseline for all discovered files
            for path, state in current_states.items():
                ev = self._create_baseline_event(state)
                events.append(ev)
            self._tracked_states = current_states
            self._is_initial_snapshot = False
            return events

        # 1. Detect newly created files
        for path, curr in current_states.items():
            if path not in self._tracked_states:
                ev, trans = self._handle_created_file(curr)
                events.append(ev)
                self._transitions_log.append(trans)

        # 2. Detect modified files or metadata changes
        for path, curr in current_states.items():
            if path in self._tracked_states:
                prev = self._tracked_states[path]
                # Content modification (skip for directories whose mtime/size change on child file creation)
                if not curr.is_dir and (
                    curr.sha256_hash != prev.sha256_hash
                    or curr.size_bytes != prev.size_bytes
                    or curr.mtime != prev.mtime
                ):
                    ev, trans = self._handle_modified_file(prev, curr)
                    events.append(ev)
                    self._transitions_log.append(trans)
                # Metadata / permission modification
                elif curr.mode_octal != prev.mode_octal or curr.uid != prev.uid or curr.gid != prev.gid:
                    ev, trans = self._handle_metadata_change(prev, curr)
                    events.append(ev)
                    self._transitions_log.append(trans)

        # 3. Detect deleted files
        for path, prev in self._tracked_states.items():
            if path not in current_states:
                ev, trans = self._handle_deleted_file(prev)
                events.append(ev)
                self._transitions_log.append(trans)

        self._tracked_states = current_states
        return events

    def _create_baseline_event(self, state: FileState) -> CanonicalEvent:
        """Create baseline observation event on startup."""
        now = datetime.now(timezone.utc)
        summary = f"Baseline file integrity recorded for '{state.path}' in {state.category.value} (SHA256: {state.sha256_hash or 'unreadable'})"
        raw_msg = (
            f"path={state.path} category={state.category.value} action=BASELINE inode={state.inode} "
            f"mode={state.mode_octal} uid={state.uid} size={state.size_bytes} sha256={state.sha256_hash or 'none'}"
        )
        fp = hashlib.sha256(raw_msg.encode("utf-8")).hexdigest()
        event_id = f"fs-base-{state.inode or 0}-{fp[:12]}"

        iocs = [state.path]
        if state.sha256_hash:
            iocs.append(state.sha256_hash)

        return CanonicalEvent(
            id=event_id,
            timestamp=now,
            ingested_at=now,
            host=self.host,
            source="filesystem_hvt",
            event_type=EventType.FILE_INTEGRITY_MODIFY,
            severity=Severity.INFORMATIONAL,
            actor=Actor(uid=state.uid),
            process=Process(),
            network=Network(),
            action="FILE_BASELINE",
            outcome=Outcome.SUCCESS,
            summary=summary,
            raw_message=raw_msg,
            iocs=iocs,
            parser="filesystem_scanner",
            source_file=state.path,
            source_offset=str(state.size_bytes or 0),
            event_fingerprint=fp,
            metadata={
                "category": state.category.value,
                "inode": state.inode,
                "mode": state.mode_octal,
                "uid": state.uid,
                "gid": state.gid,
                "size_bytes": state.size_bytes,
                "sha256": state.sha256_hash,
                "is_symlink": state.is_symlink,
                "symlink_target": state.symlink_target,
                "is_baseline": True,
                "epistemic_status": state.epistemic_status,
            },
        )

    def _handle_created_file(self, state: FileState) -> tuple[CanonicalEvent, FileTransition]:
        """Generate event when a new file appears in an HVT directory."""
        now = datetime.now(timezone.utc)
        is_persistence = state.category in (
            TargetCategory.PERSISTENCE_CRON,
            TargetCategory.PERSISTENCE_SYSTEMD,
            TargetCategory.PERSISTENCE_SSH,
            TargetCategory.PERSISTENCE_SHELL,
        )

        event_type = EventType.FILE_PERSISTENCE_DROP if is_persistence else EventType.FILE_INTEGRITY_MODIFY
        severity = Severity.ALERT if is_persistence else Severity.WARNING
        summary = f"New persistence file dropped in {state.category.value}: '{state.path}' (SHA256: {state.sha256_hash or 'unreadable'})"
        raw_msg = (
            f"path={state.path} category={state.category.value} action=CREATE inode={state.inode} "
            f"mode={state.mode_octal} uid={state.uid} size={state.size_bytes} sha256={state.sha256_hash or 'none'}"
        )
        fp = hashlib.sha256(raw_msg.encode("utf-8")).hexdigest()
        event_id = f"fs-drop-{state.inode or 0}-{fp[:12]}"

        iocs = [state.path]
        if state.sha256_hash:
            iocs.append(state.sha256_hash)

        ev = CanonicalEvent(
            id=event_id,
            timestamp=now,
            ingested_at=now,
            host=self.host,
            source="filesystem_hvt",
            event_type=event_type,
            severity=severity,
            actor=Actor(uid=state.uid),
            process=Process(),
            network=Network(),
            action="FILE_CREATE",
            outcome=Outcome.SUCCESS,
            summary=summary,
            raw_message=raw_msg,
            iocs=iocs,
            parser="filesystem_scanner",
            source_file=state.path,
            source_offset=str(state.size_bytes or 0),
            event_fingerprint=fp,
            metadata={
                "category": state.category.value,
                "inode": state.inode,
                "mode": state.mode_octal,
                "uid": state.uid,
                "gid": state.gid,
                "size_bytes": state.size_bytes,
                "sha256": state.sha256_hash,
                "is_symlink": state.is_symlink,
                "symlink_target": state.symlink_target,
                "is_baseline": False,
                "epistemic_status": state.epistemic_status,
            },
        )
        trans = FileTransition(
            path=state.path,
            category=state.category,
            transition_type=FileTransitionType.CREATED,
            previous_state=None,
            current_state=state,
            timestamp=now,
            details=summary,
        )
        return ev, trans

    def _handle_modified_file(self, prev: FileState, curr: FileState) -> tuple[CanonicalEvent, FileTransition]:
        """Generate event when a tracked file content or size changes."""
        now = datetime.now(timezone.utc)
        is_critical = curr.category in (
            TargetCategory.ACCOUNT_PRIVILEGE,
            TargetCategory.DYNAMIC_LINKER,
        )

        severity = Severity.CRITICAL if is_critical else Severity.ALERT
        summary = (
            f"File integrity modified in {curr.category.value}: '{curr.path}' "
            f"(Previous SHA256: {prev.sha256_hash or 'none'}, New SHA256: {curr.sha256_hash or 'unreadable'})"
        )
        raw_msg = (
            f"path={curr.path} category={curr.category.value} action=MODIFY inode={curr.inode} "
            f"mode={curr.mode_octal} uid={curr.uid} old_sha256={prev.sha256_hash or 'none'} new_sha256={curr.sha256_hash or 'none'}"
        )
        fp = hashlib.sha256(raw_msg.encode("utf-8")).hexdigest()
        event_id = f"fs-mod-{curr.inode or 0}-{fp[:12]}"

        iocs = [curr.path]
        if curr.sha256_hash:
            iocs.append(curr.sha256_hash)
        if prev.sha256_hash:
            iocs.append(prev.sha256_hash)

        ev = CanonicalEvent(
            id=event_id,
            timestamp=now,
            ingested_at=now,
            host=self.host,
            source="filesystem_hvt",
            event_type=EventType.FILE_INTEGRITY_MODIFY,
            severity=severity,
            actor=Actor(uid=curr.uid),
            process=Process(),
            network=Network(),
            action="FILE_MODIFY",
            outcome=Outcome.SUCCESS,
            summary=summary,
            raw_message=raw_msg,
            iocs=sorted(list(set(iocs))),
            parser="filesystem_scanner",
            source_file=curr.path,
            source_offset=str(curr.size_bytes or 0),
            event_fingerprint=fp,
            metadata={
                "category": curr.category.value,
                "inode": curr.inode,
                "mode": curr.mode_octal,
                "uid": curr.uid,
                "gid": curr.gid,
                "old_size_bytes": prev.size_bytes,
                "new_size_bytes": curr.size_bytes,
                "old_sha256": prev.sha256_hash,
                "new_sha256": curr.sha256_hash,
                "epistemic_status": curr.epistemic_status,
            },
        )
        trans = FileTransition(
            path=curr.path,
            category=curr.category,
            transition_type=FileTransitionType.MODIFIED,
            previous_state=prev,
            current_state=curr,
            timestamp=now,
            details=summary,
        )
        return ev, trans

    def _handle_metadata_change(self, prev: FileState, curr: FileState) -> tuple[CanonicalEvent, FileTransition]:
        """Generate event when file permissions or ownership change."""
        now = datetime.now(timezone.utc)
        summary = (
            f"File permissions or ownership modified on '{curr.path}': "
            f"{prev.mode_octal} (UID:{prev.uid}) -> {curr.mode_octal} (UID:{curr.uid})"
        )
        raw_msg = (
            f"path={curr.path} category={curr.category.value} action=METADATA inode={curr.inode} "
            f"old_mode={prev.mode_octal} new_mode={curr.mode_octal} old_uid={prev.uid} new_uid={curr.uid}"
        )
        fp = hashlib.sha256(raw_msg.encode("utf-8")).hexdigest()
        event_id = f"fs-meta-{curr.inode or 0}-{fp[:12]}"

        ev = CanonicalEvent(
            id=event_id,
            timestamp=now,
            ingested_at=now,
            host=self.host,
            source="filesystem_hvt",
            event_type=EventType.FILE_METADATA_MODIFY,
            severity=Severity.WARNING,
            actor=Actor(uid=curr.uid),
            process=Process(),
            network=Network(),
            action="METADATA_MODIFY",
            outcome=Outcome.SUCCESS,
            summary=summary,
            raw_message=raw_msg,
            iocs=[curr.path],
            parser="filesystem_scanner",
            source_file=curr.path,
            source_offset=str(curr.size_bytes or 0),
            event_fingerprint=fp,
            metadata={
                "category": curr.category.value,
                "inode": curr.inode,
                "old_mode": prev.mode_octal,
                "new_mode": curr.mode_octal,
                "old_uid": prev.uid,
                "new_uid": curr.uid,
                "sha256": curr.sha256_hash,
                "epistemic_status": curr.epistemic_status,
            },
        )
        trans = FileTransition(
            path=curr.path,
            category=curr.category,
            transition_type=FileTransitionType.METADATA_CHANGED,
            previous_state=prev,
            current_state=curr,
            timestamp=now,
            details=summary,
        )
        return ev, trans

    def _handle_deleted_file(self, prev: FileState) -> tuple[CanonicalEvent, FileTransition]:
        """Generate event when a monitored file is deleted."""
        now = datetime.now(timezone.utc)
        is_persistence = prev.category in (
            TargetCategory.PERSISTENCE_CRON,
            TargetCategory.PERSISTENCE_SYSTEMD,
            TargetCategory.PERSISTENCE_SSH,
            TargetCategory.PERSISTENCE_SHELL,
        )
        event_type = EventType.FILE_PERSISTENCE_REMOVE if is_persistence else EventType.FILE_INTEGRITY_MODIFY
        summary = f"Monitored file removed from {prev.category.value}: '{prev.path}'"
        raw_msg = f"path={prev.path} category={prev.category.value} action=DELETE inode={prev.inode} old_sha256={prev.sha256_hash or 'none'}"
        fp = hashlib.sha256(raw_msg.encode("utf-8")).hexdigest()
        event_id = f"fs-del-{prev.inode or 0}-{fp[:12]}"

        ev = CanonicalEvent(
            id=event_id,
            timestamp=now,
            ingested_at=now,
            host=self.host,
            source="filesystem_hvt",
            event_type=event_type,
            severity=Severity.NOTICE,
            actor=Actor(uid=prev.uid),
            process=Process(),
            network=Network(),
            action="FILE_DELETE",
            outcome=Outcome.SUCCESS,
            summary=summary,
            raw_message=raw_msg,
            iocs=[prev.path],
            parser="filesystem_scanner",
            source_file=prev.path,
            event_fingerprint=fp,
            metadata={
                "category": prev.category.value,
                "inode": prev.inode,
                "old_sha256": prev.sha256_hash,
                "epistemic_status": "OBSERVED",
            },
        )
        trans = FileTransition(
            path=prev.path,
            category=prev.category,
            transition_type=FileTransitionType.DELETED,
            previous_state=prev,
            current_state=None,
            timestamp=now,
            details=summary,
        )
        return ev, trans
