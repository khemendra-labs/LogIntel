"""Shared forensic scope, host canonicalization, and UTC datetime utilities.

Provides deterministic, timezone-aware ISO-8601 parsing and bound intersection
as well as exact host-catalog alias resolution shared across timeline and
multi-host services.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Set, Tuple

from logintel.storage.db import Database


UNKNOWN_HOST_TOKENS = frozenset({"", "unknown", "unknown-host", "none", "null"})


def normalize_host_identifier(val: Optional[str]) -> Optional[str]:
    """Normalize a host identifier/hostname for exact case-insensitive comparison."""
    if not val:
        return None
    norm = str(val).strip().lower()
    if norm in UNKNOWN_HOST_TOKENS:
        return None
    return norm


def parse_iso_datetime(ts_str: Optional[str]) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp string into a timezone-aware UTC datetime.

    Naive datetimes are treated as UTC. Returns None for missing or malformed inputs.
    """
    if ts_str is None:
        return None
    raw = str(ts_str).strip()
    if not raw:
        return None
    try:
        if raw.endswith(("Z", "z")):
            raw = raw[:-1] + "+00:00"
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def normalize_iso_utc(ts_str: Optional[str]) -> Optional[str]:
    """Normalize a valid ISO-8601 timestamp into canonical UTC ISO format ending in Z."""
    dt = parse_iso_datetime(ts_str)
    if dt is None:
        return None
    return dt.isoformat().replace("+00:00", "Z")


def has_inverted_range(start_str: Optional[str], end_str: Optional[str]) -> bool:
    """Return True if either bound is malformed or start > end chronologically."""
    start_dt: Optional[datetime] = None
    end_dt: Optional[datetime] = None
    if start_str is not None and str(start_str).strip():
        start_dt = parse_iso_datetime(start_str)
        if start_dt is None:
            return True
    if end_str is not None and str(end_str).strip():
        end_dt = parse_iso_datetime(end_str)
        if end_dt is None:
            return True
    if start_dt is not None and end_dt is not None and start_dt > end_dt:
        return True
    return False


def intersect_time_bounds(
    scope_start: Optional[str],
    scope_end: Optional[str],
    query_start: Optional[str],
    query_end: Optional[str],
) -> Tuple[Optional[datetime], Optional[datetime], bool]:
    """Intersect case-scope time bounds with query time bounds.

    Returns (eff_start_dt, eff_end_dt, is_empty_window).
    Fails closed (is_empty_window=True) when any provided bound is malformed
    or when any bound pair or their intersection is inverted (start > end).
    """
    parsed: List[Optional[datetime]] = []
    for raw in (scope_start, scope_end, query_start, query_end):
        if raw is not None and str(raw).strip():
            dt = parse_iso_datetime(raw)
            if dt is None:
                return None, None, True
            parsed.append(dt)
        else:
            parsed.append(None)

    s_start, s_end, q_start, q_end = parsed
    if s_start and s_end and s_start > s_end:
        return None, None, True
    if q_start and q_end and q_start > q_end:
        return None, None, True

    starts = [dt for dt in (s_start, q_start) if dt is not None]
    ends = [dt for dt in (s_end, q_end) if dt is not None]
    eff_start = max(starts) if starts else None
    eff_end = min(ends) if ends else None

    if eff_start and eff_end and eff_start > eff_end:
        return eff_start, eff_end, True
    return eff_start, eff_end, False


def is_timestamp_in_bounds(
    ts_str: Optional[str],
    start_dt: Optional[datetime],
    end_dt: Optional[datetime],
) -> bool:
    """Check whether ts_str falls inclusively within [start_dt, end_dt].

    When either bound is set, missing or unparseable timestamps fail closed (False).
    """
    if start_dt is None and end_dt is None:
        return True
    dt = parse_iso_datetime(ts_str)
    if dt is None:
        return False
    if start_dt is not None and dt < start_dt:
        return False
    if end_dt is not None and dt > end_dt:
        return False
    return True


def is_interval_overlapping_bounds(
    item_start: Optional[str],
    item_end: Optional[str],
    bound_start_dt: Optional[datetime],
    bound_end_dt: Optional[datetime],
) -> bool:
    """Check whether interval [item_start, item_end] overlaps [bound_start_dt, bound_end_dt].

    Fails closed when bounds are set and both interval endpoints are missing/unparseable.
    """
    if bound_start_dt is None and bound_end_dt is None:
        return True

    s_raw_present = item_start is not None and bool(str(item_start).strip())
    e_raw_present = item_end is not None and bool(str(item_end).strip())

    s_dt = parse_iso_datetime(item_start) if s_raw_present else None
    e_dt = parse_iso_datetime(item_end) if e_raw_present else None

    # Reject explicitly malformed endpoint strings when bounds are active
    if s_raw_present and s_dt is None:
        return False
    if e_raw_present and e_dt is None:
        return False

    if s_dt is None and e_dt is None:
        return False
    eff_s = s_dt if s_dt is not None else e_dt
    eff_e = e_dt if e_dt is not None else s_dt
    assert eff_s is not None and eff_e is not None
    if eff_s > eff_e:
        eff_s, eff_e = eff_e, eff_s

    if bound_start_dt is not None and eff_e < bound_start_dt:
        return False
    if bound_end_dt is not None and eff_s > bound_end_dt:
        return False
    return True


@dataclass(frozen=True)
class HostCatalogEntry:
    """Authoritative host record loaded from logintel.db:hosts."""

    host_id: str
    hostname: str
    os_name: Optional[str] = None
    os_version: Optional[str] = None


class HostCatalogIndex:
    """Exact case-insensitive host alias resolver backed by logintel.db:hosts."""

    def __init__(self, entries: Iterable[HostCatalogEntry] = ()) -> None:
        self.by_alias: Dict[str, HostCatalogEntry] = {}
        for entry in entries:
            h_id = (entry.host_id or "").strip()
            h_name = (entry.hostname or "").strip()
            if h_id:
                self.by_alias[h_id.lower()] = entry
            if h_name:
                self.by_alias[h_name.lower()] = entry

    @classmethod
    def from_db(cls, db: Optional[Database]) -> "HostCatalogIndex":
        """Load hosts catalog safely from forensic DB (returns empty index on missing/closed DB)."""
        if db is None:
            return cls()
        entries: List[HostCatalogEntry] = []
        try:
            with db.connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT id, hostname, os_name, os_version FROM hosts")
                for row in cur.fetchall():
                    entries.append(
                        HostCatalogEntry(
                            host_id=str(row["id"] or ""),
                            hostname=str(row["hostname"] or ""),
                            os_name=row["os_name"],
                            os_version=row["os_version"],
                        )
                    )
        except Exception:
            pass
        return cls(entries)

    def resolve(self, host_ref: Optional[str]) -> Optional[HostCatalogEntry]:
        """Resolve a host_id or hostname to its authoritative catalog entry."""
        norm = normalize_host_identifier(host_ref)
        if norm is None:
            return None
        return self.by_alias.get(norm)

    def resolve_canonical_id(self, host_ref: str) -> str:
        """Return canonical host_id if in catalog, else normalized original string."""
        entry = self.resolve(host_ref)
        if entry is not None and entry.host_id:
            return entry.host_id
        return str(host_ref).strip()

    def resolve_aliases(self, host_ref: Optional[str]) -> Set[str]:
        """Return all exact lowercase aliases for host_ref (never substring/prefix matching)."""
        norm = normalize_host_identifier(host_ref)
        if norm is None:
            return set()
        aliases: Set[str] = {norm}
        entry = self.by_alias.get(norm)
        if entry is not None:
            if entry.host_id:
                aliases.add(entry.host_id.strip().lower())
            if entry.hostname:
                aliases.add(entry.hostname.strip().lower())
        return aliases

    def expand_scope_targets(self, scope_targets: Iterable[str]) -> Set[str]:
        """Expand scope target hosts into all exact lowercase canonical IDs and hostnames."""
        expanded: Set[str] = set()
        for target in scope_targets:
            expanded.update(self.resolve_aliases(target))
        return expanded

    def matches_scope(
        self,
        host_ref: Optional[str],
        scope_targets: Iterable[str],
        expanded_targets: Optional[Set[str]] = None,
    ) -> bool:
        """Exact alias-aware scope check without prefix or substring collisions."""
        host_aliases = self.resolve_aliases(host_ref)
        if not host_aliases:
            return False
        target_aliases = (
            expanded_targets
            if expanded_targets is not None
            else self.expand_scope_targets(scope_targets)
        )
        if not target_aliases:
            return False
        return bool(host_aliases & target_aliases)

