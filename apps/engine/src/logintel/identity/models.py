"""Identity, session lifecycle, and privilege transition models for LogIntel (M6.3).

Provides forensic representations for:
- Audit identity (auid/loginuid) vs real identity (uid) vs effective identity (euid).
- Session continuity tokens and lifecycle states.
- Privilege elevation transitions (sudo, su, setuid, polkit).
- Epistemic certainty tracking (OBSERVED, INFERRED, UNKNOWN).
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field, model_validator


UNSET_AUID_VALUES = {"4294967295", "-1", "unset", "none", "(none)", "4294967295L"}


class SessionState(str, Enum):
    """Lifecycle states of an interactive or service session."""
    ACTIVE = "ACTIVE"
    CLOSED = "CLOSED"
    EXPIRED = "EXPIRED"
    UNKNOWN = "UNKNOWN"


class PrivilegeTransitionType(str, Enum):
    """Mechanism of privilege escalation or user identity transition."""
    SUDO = "SUDO"
    SU = "SU"
    SETUID = "SETUID"
    POLKIT = "POLKIT"
    DIRECT_ROOT_LOGIN = "DIRECT_ROOT_LOGIN"
    AUTHENTICATION_FAILURE = "AUTHENTICATION_FAILURE"
    UNKNOWN = "UNKNOWN"


class AuditIdentity(BaseModel):
    """Multi-tier identity representation capturing Linux audit and PAM semantics."""
    auid: Optional[str] = None
    uid: Optional[int] = None
    euid: Optional[int] = None
    suid: Optional[int] = None
    fsuid: Optional[int] = None
    username: Optional[str] = None
    login_username: Optional[str] = None
    is_unset_auid: bool = False
    is_elevated: bool = False

    @model_validator(mode="after")
    def _validate_auid_unset(self) -> "AuditIdentity":
        if self.auid is None or str(self.auid).lower() in UNSET_AUID_VALUES or str(self.auid) == "4294967295":
            object.__setattr__(self, "is_unset_auid", True)
        return self

    @classmethod
    def from_audit_kvs(cls, kvs: Dict[str, str], username: Optional[str] = None) -> "AuditIdentity":
        """Construct an AuditIdentity from raw audit key-values."""
        auid_raw = kvs.get("auid")
        uid_raw = kvs.get("uid")
        euid_raw = kvs.get("euid")
        suid_raw = kvs.get("suid")
        fsuid_raw = kvs.get("fsuid")

        auid_str = str(auid_raw) if auid_raw is not None else None
        is_unset = (
            auid_str is None
            or auid_str.lower() in UNSET_AUID_VALUES
            or auid_str == "4294967295"
        )

        def _to_int(val: Optional[str]) -> Optional[int]:
            if val is None:
                return None
            try:
                return int(val)
            except ValueError:
                return None

        uid_int = _to_int(uid_raw)
        euid_int = _to_int(euid_raw)
        suid_int = _to_int(suid_raw)
        fsuid_int = _to_int(fsuid_raw)

        # Elevation detected if effective UID is root (0) while real UID != 0,
        # or if EUID differs from UID.
        is_elevated = (euid_int == 0 and uid_int is not None and uid_int != 0) or (
            euid_int is not None and uid_int is not None and euid_int != uid_int
        )

        return cls(
            auid=None if is_unset else auid_str,
            uid=uid_int,
            euid=euid_int,
            suid=suid_int,
            fsuid=fsuid_int,
            username=username,
            login_username=None,  # Resolved via SessionContinuityResolver
            is_unset_auid=is_unset,
            is_elevated=is_elevated,
        )

    @property
    def has_interactive_auid(self) -> bool:
        """True if the AUID represents a genuine human login, False if unset or missing."""
        return not self.is_unset_auid and bool(self.auid)

    @property
    def is_daemon_or_system(self) -> bool:
        """True if process executed outside an interactive session context."""
        return self.is_unset_auid or not self.auid


class SessionRecord(BaseModel):
    """Tracks a single host login session from inception to termination."""
    session_id: str
    host: str
    auid: Optional[str] = None
    login_user: Optional[str] = None
    terminal: Optional[str] = None
    remote_ip: Optional[str] = None
    service: Optional[str] = None
    start_time: datetime
    end_time: Optional[datetime] = None
    state: SessionState = SessionState.ACTIVE
    start_event_id: Optional[str] = None
    end_event_id: Optional[str] = None
    process_pids: Set[int] = Field(default_factory=set)

    @property
    def is_active(self) -> bool:
        return self.state == SessionState.ACTIVE


class PrivilegeTransition(BaseModel):
    """Represents an observed or inferred privilege transition."""
    transition_type: PrivilegeTransitionType
    host: str
    source_user: Optional[str] = None
    target_user: Optional[str] = None
    source_uid: Optional[int] = None
    target_uid: Optional[int] = None
    auid: Optional[str] = None
    session_id: Optional[str] = None
    terminal: Optional[str] = None
    command: Optional[str] = None
    timestamp: datetime
    event_id: Optional[str] = None
    outcome: str = "SUCCESS"  # SUCCESS, FAILURE, ATTEMPT
    epistemic_status: str = "OBSERVED"  # OBSERVED, INFERRED, UNKNOWN


class IdentityContinuityChain(BaseModel):
    """Traces identity provenance for a high-privilege action back to original login."""
    target_process_name: Optional[str] = None
    target_pid: Optional[int] = None
    effective_user: str = "root"
    effective_uid: int = 0
    login_user: Optional[str] = None
    login_auid: Optional[str] = None
    session_id: Optional[str] = None
    terminal: Optional[str] = None
    remote_ip: Optional[str] = None
    privilege_transitions: List[PrivilegeTransition] = Field(default_factory=list)
    epistemic_status: str = "OBSERVED"
    narrative: str = ""
