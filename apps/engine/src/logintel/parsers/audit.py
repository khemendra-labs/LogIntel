"""Parser for Linux audit telemetry (/var/log/audit/audit.log).

Processes SYSCALL, EXECVE, PROCTITLE, USER_START, and USER_END audit records
into CanonicalEvent instances with deterministic credential masking and
forensic raw evidence preservation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple

from logintel.logging import get_logger
from logintel.models import (
    Actor,
    CanonicalEvent,
    EventType,
    Outcome,
    Process,
    RawRecord,
    Severity,
)
from logintel.normalization.sanitizer import (
    extract_iocs,
    mask_credentials,
    sanitize_message,
)
from logintel.parsers.base import BaseParser

logger = get_logger("parsers.audit")

# Resource bounds to prevent resource exhaustion / DoS from hostile telemetry
MAX_AUDIT_LINE_LENGTH = 16384
MAX_EXECVE_ARGC = 1024
MAX_COMMAND_LINE_LENGTH = 8192
MAX_PROCTITLE_LENGTH = 4096
MAX_METADATA_ENTRIES = 128

# Regex patterns for auditd line parsing
AUDIT_MSG_RE = re.compile(r"\bmsg=audit\((\d+(?:\.\d+)?):(\d+)\)")
AUDIT_TYPE_RE = re.compile(r"\btype=([A-Z0-9_]+)")
KEY_VAL_RE = re.compile(r"([a-zA-Z0-9_-]+)=(?:\"([^\"]*)\"|\'([^\']*)\'|([^\s]+))")


def decode_audit_hex(val: str, max_len: int = MAX_COMMAND_LINE_LENGTH, is_quoted: bool = False) -> str:
    """Decode a hex-encoded audit string or unquote if standard string.

    Auditd encodes arguments containing spaces, quotes, or non-printable chars
    as pure hexadecimal byte sequences without delimiters. Quoted strings are
    plain text and should not be hex-decoded.
    """
    if not val:
        return ""
    val = val.strip()

    # Quoted values in auditd are already decoded plain text
    if is_quoted or (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
        clean = val[1:-1] if (val.startswith('"') or val.startswith("'")) else val
        if len(clean) > max_len:
            return clean[:max_len] + " [TRUNCATED]"
        return clean

    # Check if purely hexadecimal with even length
    if len(val) >= 2 and len(val) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", val):
        try:
            raw_bytes = bytes.fromhex(val)
            decoded = raw_bytes.decode("utf-8", errors="replace")
            # Replace null byte terminators or delimiters with spaces
            decoded = decoded.replace("\x00", " ").strip()
            if len(decoded) > max_len:
                return decoded[:max_len] + " [TRUNCATED]"
            return decoded
        except Exception:
            pass

    if len(val) > max_len:
        return val[:max_len] + " [TRUNCATED]"
    return val


def parse_audit_line_kvs(line: str) -> Tuple[Optional[str], Optional[float], Optional[str], Dict[str, str], Set[str]]:
    """Extract record_type, timestamp, sequence_id, key-value mapping, and set of quoted keys from an audit line."""
    if len(line) > MAX_AUDIT_LINE_LENGTH:
        line = line[:MAX_AUDIT_LINE_LENGTH]

    record_type: Optional[str] = None
    m_type = AUDIT_TYPE_RE.search(line)
    if m_type:
        record_type = m_type.group(1)

    epoch_sec: Optional[float] = None
    seq_id: Optional[str] = None
    m_msg = AUDIT_MSG_RE.search(line)
    if m_msg:
        try:
            epoch_sec = float(m_msg.group(1))
            seq_id = m_msg.group(2)
        except ValueError:
            pass

    kvs: Dict[str, str] = {}
    quoted_keys: Set[str] = set()
    for m in KEY_VAL_RE.finditer(line):
        k = m.group(1)
        is_q = (m.group(2) is not None or m.group(3) is not None)
        v = m.group(2) if m.group(2) is not None else (m.group(3) if m.group(3) is not None else m.group(4))
        kvs[k] = v or ""
        if is_q:
            quoted_keys.add(k)

    # If line has embedded msg='op=... ...', parse nested key-values
    nested_msg = kvs.get("msg")
    if nested_msg and ("op=" in nested_msg or "acct=" in nested_msg):
        for m in KEY_VAL_RE.finditer(nested_msg):
            k = m.group(1)
            is_q = (m.group(2) is not None or m.group(3) is not None)
            v = m.group(2) if m.group(2) is not None else (m.group(3) if m.group(3) is not None else m.group(4))
            if k not in kvs:
                kvs[k] = v or ""
                if is_q:
                    quoted_keys.add(k)

    return record_type, epoch_sec, seq_id, kvs, quoted_keys


class AuditParser(BaseParser):
    """Parser for Linux kernel and daemon audit events."""

    @property
    def name(self) -> str:
        return "linux_audit"

    def can_parse(self, record: RawRecord) -> bool:
        content = record.raw_content
        return (
            record.source in ("audit.log", "auditd", "audit")
            or ("type=" in content and "msg=audit(" in content)
        )

    def parse(self, record: RawRecord) -> Optional[CanonicalEvent]:
        raw_clean = sanitize_message(record.raw_content)
        lines = [line.strip() for line in raw_clean.splitlines() if line.strip()]
        if not lines:
            return None

        primary_ts: Optional[datetime] = record.timestamp
        primary_seq: Optional[str] = None
        records_by_type: Dict[str, Dict[str, str]] = {}
        quoted_by_type: Dict[str, Set[str]] = {}
        all_record_types: List[str] = []

        for line in lines:
            rtype, epoch, seq, kvs, qkeys = parse_audit_line_kvs(line)
            if epoch and not primary_ts:
                try:
                    primary_ts = datetime.fromtimestamp(epoch, tz=timezone.utc)
                except Exception:
                    primary_ts = datetime.now(timezone.utc)
            if seq and not primary_seq:
                primary_seq = seq
            if rtype:
                all_record_types.append(rtype)
                # Store or merge into records_by_type
                if rtype in records_by_type:
                    records_by_type[rtype].update(kvs)
                    quoted_by_type[rtype].update(qkeys)
                else:
                    records_by_type[rtype] = kvs
                    quoted_by_type[rtype] = set(qkeys)

        final_ts = primary_ts or datetime.now(timezone.utc)
        host = record.host or "unknown"

        # Check for Session Lifecycle events (USER_START, USER_END)
        if "USER_START" in records_by_type or "USER_END" in records_by_type:
            return self._parse_session_event(
                record=record,
                records=records_by_type,
                timestamp=final_ts,
                host=host,
                seq_id=primary_seq,
                all_types=all_record_types,
            )

        # Check for Process Execution events (EXECVE, SYSCALL, PROCTITLE)
        if "EXECVE" in records_by_type or "PROCTITLE" in records_by_type or "SYSCALL" in records_by_type:
            return self._parse_execution_event(
                record=record,
                records=records_by_type,
                timestamp=final_ts,
                host=host,
                seq_id=primary_seq,
                all_types=all_record_types,
                quoted_keys=quoted_by_type.get("EXECVE"),
            )

        # Fallback for generic / unclassified audit events (SERVICE_START, LOGIN, etc.)
        return self._parse_generic_audit_event(
            record=record,
            records=records_by_type,
            timestamp=final_ts,
            host=host,
            seq_id=primary_seq,
            all_types=all_record_types,
        )

    def _parse_session_event(
        self,
        record: RawRecord,
        records: Dict[str, Dict[str, str]],
        timestamp: datetime,
        host: str,
        seq_id: Optional[str],
        all_types: List[str],
    ) -> CanonicalEvent:
        is_start = "USER_START" in records
        session_kvs = records.get("USER_START") or records.get("USER_END") or {}

        acct = session_kvs.get("acct") or session_kvs.get("UID") or session_kvs.get("AUID") or "unknown"
        pid_raw = session_kvs.get("pid")
        pid = int(pid_raw) if pid_raw and pid_raw.isdigit() else None
        
        uid_raw = session_kvs.get("uid")
        uid = int(uid_raw) if uid_raw and uid_raw.isdigit() else None

        auid_raw = session_kvs.get("auid")
        auid = auid_raw if auid_raw and auid_raw not in ("4294967295", "-1", "unset") else None

        ses_raw = session_kvs.get("ses")
        ses = ses_raw if ses_raw and ses_raw not in ("4294967295", "-1", "unset") else None

        exe = session_kvs.get("exe")
        proc_name = Path(exe).name if exe else (session_kvs.get("comm") or "pam")
        terminal = session_kvs.get("terminal")
        if terminal in ("?", "(none)"):
            terminal = None

        res = session_kvs.get("res", "").lower()
        outcome = Outcome.SUCCESS if res == "success" else (Outcome.FAILURE if res == "failed" else Outcome.UNKNOWN)
        severity = Severity.INFORMATIONAL if outcome == Outcome.SUCCESS else Severity.WARNING
        event_type = EventType.AUDIT_SESSION_START if is_start else EventType.AUDIT_SESSION_END

        action_word = "opened" if is_start else "closed"
        summary = f"Audit PAM session {action_word} for user '{acct}' (PID: {pid or 'unknown'}, AUID: {auid or 'unset'}, session: {ses or 'unset'})"

        is_elevated_session = bool(
            acct == "root"
            and auid is not None
            and auid not in ("0", "4294967295", "-1", "unset")
        )

        metadata: Dict[str, Any] = {
            "audit_sequence": seq_id,
            "record_types": all_types,
            "auid": auid,
            "ses": ses,
            "audit_session": ses,
            "op": session_kvs.get("op"),
            "grantors": session_kvs.get("grantors"),
            "terminal": terminal,
            "exe": exe,
            "is_elevated_session": is_elevated_session,
        }
        if is_elevated_session:
            metadata["is_privilege_transition"] = True
            metadata["transition_type"] = "PAM_ELEVATION"
            metadata["target_user"] = "root"

        return CanonicalEvent(
            timestamp=timestamp,
            host=host,
            source=record.source,
            event_type=event_type,
            severity=severity,
            actor=Actor(
                username=acct,
                uid=uid,
                session_id=ses,
                terminal=terminal,
            ),
            process=Process(
                name=proc_name,
                pid=pid,
                executable=exe,
            ),
            action=session_kvs.get("op", f"session_{action_word}"),
            outcome=outcome,
            summary=summary,
            raw_message=record.raw_content,
            parser=self.name,
            source_file=record.source_file,
            source_offset=record.source_offset,
            metadata=metadata,
        )

    def _parse_execution_event(
        self,
        record: RawRecord,
        records: Dict[str, Dict[str, str]],
        timestamp: datetime,
        host: str,
        seq_id: Optional[str],
        all_types: List[str],
        quoted_keys: Optional[Set[str]] = None,
    ) -> CanonicalEvent:
        syscall_kvs = records.get("SYSCALL", {})
        execve_kvs = records.get("EXECVE", {})
        proctitle_kvs = records.get("PROCTITLE", {})
        qkeys = quoted_keys or set()

        # Process Identifiers
        pid_raw = syscall_kvs.get("pid") or execve_kvs.get("pid")
        pid = int(pid_raw) if pid_raw and pid_raw.isdigit() else None

        ppid_raw = syscall_kvs.get("ppid")
        ppid = int(ppid_raw) if ppid_raw and ppid_raw.isdigit() and int(ppid_raw) > 0 else None

        comm = syscall_kvs.get("comm")
        exe = syscall_kvs.get("exe")
        proc_name = comm or (Path(exe).name if exe else "unknown")

        # Identity Identifiers
        username = (
            syscall_kvs.get("UID")
            or syscall_kvs.get("AUID")
            or syscall_kvs.get("username")
            or "unknown"
        )
        uid_raw = syscall_kvs.get("uid")
        uid = int(uid_raw) if uid_raw and uid_raw.isdigit() else None

        euid_raw = syscall_kvs.get("euid")
        euid = int(euid_raw) if euid_raw and euid_raw.isdigit() else None

        auid_raw = syscall_kvs.get("auid")
        auid = auid_raw if auid_raw and auid_raw not in ("4294967295", "-1", "unset") else None

        ses_raw = syscall_kvs.get("ses")
        ses = ses_raw if ses_raw and ses_raw not in ("4294967295", "-1", "unset") else None

        tty = syscall_kvs.get("tty")
        if tty in ("(none)", "?"):
            tty = None

        # Reconstruct Command Line
        execve_cmdline: Optional[str] = None
        raw_execve_args: List[str] = []
        if execve_kvs:
            # Gather arguments a0, a1, ...
            arg_items: List[Tuple[int, str]] = []
            for k, v in execve_kvs.items():
                if k.startswith("a") and k[1:].isdigit():
                    idx = int(k[1:])
                    if idx < MAX_EXECVE_ARGC:
                        decoded_arg = decode_audit_hex(v, is_quoted=(k in qkeys))
                        arg_items.append((idx, decoded_arg))

            arg_items.sort(key=lambda x: x[0])
            raw_execve_args = [item[1] for item in arg_items]
            if raw_execve_args:
                execve_cmdline = " ".join(raw_execve_args)
                if len(execve_cmdline) > MAX_COMMAND_LINE_LENGTH:
                    execve_cmdline = execve_cmdline[:MAX_COMMAND_LINE_LENGTH] + " [TRUNCATED]"

        # Reconstruct PROCTITLE if available
        proctitle_cmdline: Optional[str] = None
        if proctitle_kvs and "proctitle" in proctitle_kvs:
            raw_pt = proctitle_kvs["proctitle"]
            proctitle_cmdline = decode_audit_hex(raw_pt, max_len=MAX_PROCTITLE_LENGTH)

        # Decide canonical command line
        final_raw_cmd: str
        cmd_source: str
        if execve_cmdline:
            final_raw_cmd = execve_cmdline
            cmd_source = "EXECVE"
        elif proctitle_cmdline:
            final_raw_cmd = proctitle_cmdline
            cmd_source = "PROCTITLE"
        elif exe:
            final_raw_cmd = exe
            cmd_source = "EXE"
        else:
            final_raw_cmd = comm or "unknown"
            cmd_source = "COMM"

        # Bound final command line length
        if len(final_raw_cmd) > MAX_COMMAND_LINE_LENGTH:
            final_raw_cmd = final_raw_cmd[:MAX_COMMAND_LINE_LENGTH] + " [TRUNCATED]"

        # Apply deterministic credential masking for canonical and display representations
        masked_cmdline = mask_credentials(final_raw_cmd)
        masked_execve_args = [mask_credentials(arg) for arg in raw_execve_args]
        masked_proctitle = mask_credentials(proctitle_cmdline) if proctitle_cmdline else None

        # Determine Outcome
        success_str = syscall_kvs.get("success", "").lower()
        exit_code_raw = syscall_kvs.get("exit")
        exit_code = int(exit_code_raw) if exit_code_raw and (exit_code_raw.isdigit() or exit_code_raw.startswith("-")) else None

        if success_str == "yes" or (exit_code is not None and exit_code >= 0):
            outcome = Outcome.SUCCESS
        elif success_str == "no" or (exit_code is not None and exit_code < 0):
            outcome = Outcome.FAILURE
        else:
            outcome = Outcome.UNKNOWN

        severity = Severity.NOTICE if outcome == Outcome.SUCCESS else Severity.WARNING

        summary = (
            f"Process execution: '{proc_name}' (PID: {pid or 'unknown'}, PPID: {ppid or 'unknown'}) "
            f"executed by '{username}' (AUID: {auid or 'unset'}): {masked_cmdline}"
        )

        # Check for privilege transition in execution
        is_elevated_exec = bool(
            (euid == 0 and uid is not None and uid != 0)
            or (euid is not None and uid is not None and euid != uid)
        )
        transition_type: Optional[str] = None
        if is_elevated_exec:
            if proc_name == "sudo" or "sudo" in (exe or ""):
                transition_type = "SUDO"
            elif proc_name == "su" or "su" in (exe or ""):
                transition_type = "SU"
            elif proc_name == "pkexec" or "pkexec" in (exe or ""):
                transition_type = "POLKIT"
            else:
                transition_type = "SETUID"

        metadata: Dict[str, Any] = {
            "audit_sequence": seq_id,
            "record_types": all_types,
            "cmdline_source": cmd_source,
            "auid": auid,
            "uid": uid,
            "euid": euid,
            "suid": syscall_kvs.get("suid"),
            "fsuid": syscall_kvs.get("fsuid"),
            "ses": ses,
            "session_id": ses,
            "syscall": syscall_kvs.get("syscall"),
            "arch": syscall_kvs.get("arch"),
            "exit_code": exit_code,
            "execve_args": masked_execve_args,
            "proctitle": masked_proctitle,
            "is_elevated": is_elevated_exec,
            "transition_type": transition_type,
        }
        if is_elevated_exec:
            metadata["is_privilege_transition"] = True
            metadata["target_user"] = "root" if euid == 0 else str(euid)

        # Check for discrepancy between EXECVE and PROCTITLE
        if execve_cmdline and proctitle_cmdline and execve_cmdline != proctitle_cmdline:
            metadata["cmdline_discrepancy"] = True

        return CanonicalEvent(
            timestamp=timestamp,
            host=host,
            source=record.source,
            event_type=EventType.PROCESS_EXECUTION,
            severity=severity,
            actor=Actor(
                username=username,
                uid=uid,
                session_id=ses,
                terminal=tty,
            ),
            process=Process(
                name=proc_name,
                pid=pid,
                ppid=ppid,
                executable=exe,
                command_line=masked_cmdline,
            ),
            action="execve",
            outcome=outcome,
            summary=summary,
            raw_message=record.raw_content,
            iocs=extract_iocs(final_raw_cmd),
            parser=self.name,
            source_file=record.source_file,
            source_offset=record.source_offset,
            metadata=metadata,
        )

    def _parse_generic_audit_event(
        self,
        record: RawRecord,
        records: Dict[str, Dict[str, str]],
        timestamp: datetime,
        host: str,
        seq_id: Optional[str],
        all_types: List[str],
    ) -> CanonicalEvent:
        first_type = all_types[0] if all_types else "AUDIT_GENERIC"
        kvs = records.get(first_type, {})

        comm = kvs.get("comm")
        exe = kvs.get("exe")
        proc_name = comm or (Path(exe).name if exe else "auditd")
        pid_raw = kvs.get("pid")
        pid = int(pid_raw) if pid_raw and pid_raw.isdigit() else None

        username = kvs.get("UID") or kvs.get("AUID") or kvs.get("acct") or "system"

        res = kvs.get("res", "").lower()
        outcome = Outcome.SUCCESS if res in ("1", "success") else (Outcome.FAILURE if res in ("0", "failed") else Outcome.UNKNOWN)

        summary = f"Audit {first_type} event recorded for '{proc_name}' (PID: {pid or 'unknown'}, user: '{username}')"

        metadata: Dict[str, Any] = {
            "audit_sequence": seq_id,
            "record_types": all_types,
            "primary_type": first_type,
        }

        return CanonicalEvent(
            timestamp=timestamp,
            host=host,
            source=record.source,
            event_type=EventType.SYSTEM_GENERIC,
            severity=Severity.INFORMATIONAL,
            actor=Actor(
                username=username,
                session_id=kvs.get("ses"),
            ),
            process=Process(
                name=proc_name,
                pid=pid,
                executable=exe,
            ),
            action=first_type.lower(),
            outcome=outcome,
            summary=summary,
            raw_message=record.raw_content,
            parser=self.name,
            source_file=record.source_file,
            source_offset=record.source_offset,
            metadata=metadata,
        )
