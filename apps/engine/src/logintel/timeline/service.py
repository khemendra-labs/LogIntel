"""Deterministic Unified Investigation Timeline & Interactive Replay Service (M7.2).

Constructs unified, multi-layer timelines across M1-M6 telemetry sources,
enforces strict case isolation, provides deterministic ordering, manages transient
replay sessions, supports analyst bookmarks without schema mutations, and guarantees
identical cryptographic export repeatability.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from logintel.ai.domain.case import ALLOWED_CASE_TRANSITIONS, CaseStatus, InvestigationCase, ResolutionStatus
from logintel.logging import get_logger
from logintel.storage.case_repo import CaseRepository, case_repo as default_case_repo
from logintel.storage.db import Database, db as default_forensic_db
from logintel.storage.scope_utils import (
    HostCatalogIndex,
    intersect_time_bounds,
    is_interval_overlapping_bounds,
    is_timestamp_in_bounds,
    parse_iso_datetime,
)
from logintel.timeline.models import (
    CollectionStatus,
    EpistemicStatus,
    InvestigationTimelineItem,
    TimelineContextResponse,
    TimelineFilterParams,
    TimelineQueryResponse,
    TimelineReplayFrame,
    TimelineReplaySession,
    TimelineSourceLayer,
    TimestampPrecision,
)

logger = get_logger("timeline.service")

# Priority order for deterministic tie-breaking on identical timestamps
LAYER_PRIORITY: Dict[TimelineSourceLayer, int] = {
    TimelineSourceLayer.AUTH: 10,
    TimelineSourceLayer.KERNEL: 15,
    TimelineSourceLayer.PROCESS: 20,
    TimelineSourceLayer.NETWORK: 30,
    TimelineSourceLayer.FILESYSTEM: 40,
    TimelineSourceLayer.SYSTEMD: 50,
    TimelineSourceLayer.CONTAINER: 60,
    TimelineSourceLayer.ALERT: 70,
    TimelineSourceLayer.DETECTION: 75,
    TimelineSourceLayer.INCIDENT: 80,
    TimelineSourceLayer.CORRELATION: 90,
    TimelineSourceLayer.ANALYST_NOTE: 100,
}

CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")


class UnifiedTimelineService:
    """Service providing unified timeline projections, interactive replay sessions, and bookmarks."""

    def __init__(
        self,
        forensic_db: Optional[Database] = None,
        case_repository: Optional[CaseRepository] = None,
    ) -> None:
        self.db = forensic_db or default_forensic_db
        self.case_repo = case_repository or default_case_repo

    def _sanitize(self, text: Optional[str], max_len: int = 500) -> str:
        """Strip control characters and clamp length."""
        if not text:
            return ""
        clean = CONTROL_CHAR_RE.sub("", str(text))
        return clean[:max_len].strip()

    def _detect_precision(self, ts_str: str) -> TimestampPrecision:
        """Detect timestamp precision from string format."""
        if not ts_str:
            return TimestampPrecision.UNKNOWN
        if "." in ts_str:
            return TimestampPrecision.MILLISECOND
        return TimestampPrecision.SECOND

    def _classify_layer(self, source: str, event_type: str) -> TimelineSourceLayer:
        """Deterministically map event source and type to telemetry layer."""
        s = (source or "").lower()
        et = (event_type or "").lower()

        if any(k in et for k in ("socket", "connect", "net", "bind", "accept", "dns")):
            return TimelineSourceLayer.NETWORK
        if any(k in et for k in ("process", "exec", "fork", "command", "ancestry")) or "audit" in s:
            return TimelineSourceLayer.PROCESS
        if any(k in et for k in ("file", "hvt", "inode", "write", "unlink", "chmod")):
            return TimelineSourceLayer.FILESYSTEM
        if any(k in et for k in ("systemd", "unit", "service")):
            return TimelineSourceLayer.SYSTEMD
        if any(k in et for k in ("container", "docker", "namespace")):
            return TimelineSourceLayer.CONTAINER
        if any(k in et for k in ("auth", "login", "ssh", "sudo", "pam", "user_mgmt")):
            return TimelineSourceLayer.AUTH
        if "kernel" in s or "kernel" in et:
            return TimelineSourceLayer.KERNEL
        return TimelineSourceLayer.AUTH

    def _timeline_sort_key(self, item: InvestigationTimelineItem) -> Tuple[datetime, str, int, str, str]:
        """Strict deterministic multi-key ordering using UTC-normalized timestamp first."""
        dt = parse_iso_datetime(item.timestamp) or datetime.max.replace(tzinfo=timezone.utc)
        ts = item.timestamp or ""
        prio = LAYER_PRIORITY.get(item.layer, 999)
        src_id = item.source_id or ""
        t_id = item.timeline_id or ""
        return (dt, ts, prio, src_id, t_id)

    def _item_matches_time_bounds(
        self,
        item: InvestigationTimelineItem,
        start_dt: Optional[datetime],
        end_dt: Optional[datetime],
    ) -> bool:
        """Check whether a timeline item matches UTC time bounds (interval semantics for alerts)."""
        if start_dt is None and end_dt is None:
            return True
        if item.layer == TimelineSourceLayer.ALERT and isinstance(item.metadata, dict):
            last_seen = item.metadata.get("last_seen")
            if last_seen:
                return is_interval_overlapping_bounds(item.timestamp, str(last_seen), start_dt, end_dt)
        return is_timestamp_in_bounds(item.timestamp, start_dt, end_dt)

    def _load_bookmarks(self, case_id: int, case: Optional[InvestigationCase] = None) -> Dict[str, str]:
        """Load analyst bookmarks for a case from case_evidence_references without schema changes."""
        if case is None:
            case = self.case_repo.get_case(case_id)
        if not case:
            return {}
        bookmarks: Dict[str, str] = {}
        for ref in case.evidence_references:
            if ref.source_type == "timeline" or ref.citation_tag.startswith("[bookmark:"):
                # source_id stores timeline_id
                bookmarks[ref.source_id] = ref.analyst_annotation or ""
        return bookmarks

    MAX_INCIDENT_EVENTS = 1000

    def build_raw_timeline_items(self, case_id: int) -> List[InvestigationTimelineItem]:
        """Aggregate, project, and deterministically sort all timeline items for a case."""
        items, _ = self._build_raw_timeline_items_with_meta(case_id)
        return items

    def _build_raw_timeline_items_with_meta(
        self,
        case_id: int,
        host_filter: Optional[str] = None,
        time_start: Optional[str] = None,
        time_end: Optional[str] = None,
        host_catalog: Optional[HostCatalogIndex] = None,
    ) -> Tuple[List[InvestigationTimelineItem], bool]:
        """Aggregate, project, and sort timeline items, returning (items, is_truncated)."""
        case = self.case_repo.get_case(case_id)
        if not case:
            raise ValueError(f"Investigation case {case_id} not found")

        catalog = host_catalog or HostCatalogIndex.from_db(self.db)
        target_hosts = getattr(case.scope, "target_hosts", []) or []
        scope_time_start = getattr(case.scope, "time_start", None) if case.scope else None
        scope_time_end = getattr(case.scope, "time_end", None) if case.scope else None

        eff_start_dt, eff_end_dt, is_empty_window = intersect_time_bounds(
            scope_time_start,
            scope_time_end,
            time_start,
            time_end,
        )
        if is_empty_window:
            return [], False

        allowed_host_aliases: Optional[Set[str]] = None
        if target_hosts:
            allowed_host_aliases = catalog.expand_scope_targets(target_hosts)
        if host_filter is not None and host_filter.strip():
            filter_aliases = catalog.resolve_aliases(host_filter)
            if not filter_aliases:
                return [], False
            if allowed_host_aliases is not None:
                allowed_host_aliases = allowed_host_aliases & filter_aliases
            else:
                allowed_host_aliases = filter_aliases
        if (target_hosts or (host_filter and host_filter.strip())) and not allowed_host_aliases:
            return [], False

        db_truncated = False

        bookmarks = self._load_bookmarks(case_id, case=case)
        items: List[InvestigationTimelineItem] = []
        items_by_id: Dict[str, InvestigationTimelineItem] = {}
        seen_ids: Set[str] = set()

        # 1. Authoritative Case Evidence References (events, alerts, detections)
        for ref in case.evidence_references:
            if ref.source_type == "timeline" or ref.citation_tag.startswith("[bookmark:"):
                continue  # Skip bookmark references from raw evidence items
            
            rec = ref.resolved_record or {}
            if not isinstance(rec, dict):
                rec = {}
            if not rec and ref.analyst_annotation:
                try:
                    parsed = json.loads(ref.analyst_annotation) if isinstance(ref.analyst_annotation, str) else ref.analyst_annotation
                    if isinstance(parsed, dict):
                        rec = parsed
                except Exception:
                    pass
            has_active_bounds = eff_start_dt is not None or eff_end_dt is not None
            rec_ts = rec.get("timestamp") or rec.get("first_seen") or rec.get("created_at")
            if rec_ts:
                ts = rec_ts
            elif has_active_bounds and ref.source_type in ("event", "alert", "detection"):
                ts = None
            else:
                ts = ref.created_at
            host = rec.get("host") or (target_hosts[0] if target_hosts else "unknown-host")
            source = rec.get("source") or ref.source_type
            ev_type = rec.get("event_type") or rec.get("action") or ref.source_type.upper()

            def _coerce_ep(val: Any, fallback: EpistemicStatus = EpistemicStatus.UNKNOWN) -> EpistemicStatus:
                if val is None:
                    return fallback
                raw = str(getattr(val, "value", val)).strip().upper()
                if not raw:
                    return fallback
                try:
                    return EpistemicStatus(raw)
                except Exception:
                    return fallback

            def _min_ep(vals: List[EpistemicStatus]) -> EpistemicStatus:
                rank = {
                    EpistemicStatus.UNKNOWN: 0,
                    EpistemicStatus.INFERRED: 1,
                    EpistemicStatus.OBSERVED: 2,
                }
                return min(vals, key=lambda s: rank.get(s, 0))

            ref_ep = _coerce_ep(getattr(ref, "epistemic_status", None), EpistemicStatus.UNKNOWN)
            ep_parts = [ref_ep]
            if "epistemic_status" in rec and rec.get("epistemic_status") is not None:
                ep_parts.append(_coerce_ep(rec.get("epistemic_status"), EpistemicStatus.UNKNOWN))
            epistemic = _min_ep(ep_parts)
            is_auth_rec = rec.get("is_authoritative") is not False
            if epistemic == EpistemicStatus.OBSERVED and not is_auth_rec:
                epistemic = EpistemicStatus.INFERRED

            if ref.source_type == "alert":
                layer = TimelineSourceLayer.ALERT
                pfx = "alt"
            elif ref.source_type == "detection":
                layer = TimelineSourceLayer.DETECTION
                pfx = "det"
            elif ref.source_type == "event":
                layer = self._classify_layer(source, ev_type)
                pfx = "ev"
            elif ref.source_type == "audit":
                layer = TimelineSourceLayer.ANALYST_NOTE
                pfx = "aud"
            else:
                layer = self._classify_layer(source, ev_type)
                pfx = ref.source_type.lower().replace("_", "-")[:8]

            entities = []
            if rec.get("username"):
                entities.append(f"user:{rec['username']}")
            if rec.get("src_ip"):
                entities.append(f"ip:{rec['src_ip']}")
            if rec.get("dest_ip"):
                entities.append(f"ip:{rec['dest_ip']}")
            if rec.get("process"):
                entities.append(f"process:{rec['process']}")
            if rec.get("path"):
                entities.append(f"file:{rec['path']}")

            ts_str = str(ts) if ts else ""
            cand_id = f"tl-{pfx}-{ref.source_id}"
            if cand_id in items_by_id:
                existing = items_by_id[cand_id]
                # If truly equivalent record (same host, timestamp, and source domain), merge evidence refs conservatively
                if existing.host_id == str(host) and existing.timestamp == ts_str and existing.source_id == str(ref.source_id):
                    tag = ref.citation_tag or f"[{ref.source_type}:{ref.source_id}]"
                    if tag not in existing.evidence_refs:
                        existing.evidence_refs.append(tag)
                    existing.epistemic_status = _min_ep([existing.epistemic_status, epistemic])
                    continue
                else:
                    # Distinct record sharing a bare ID: disambiguate with host
                    h_clean = str(host).lower().replace(".", "-").replace(":", "-")
                    cand_id = f"tl-{pfx}-{h_clean}-{ref.source_id}"
                    if cand_id in items_by_id:
                        cand_id = f"tl-{pfx}-{h_clean}-{ref.source_id}-{ref.reference_id}"

            t_id = cand_id
            seen_ids.add(t_id)

            summary = rec.get("summary") or rec.get("raw_message") or rec.get("description") or f"Forensic {ref.source_type}"
            provenance_label = (
                f"Authoritative forensic reference ({ref.source_type}:{ref.source_id})"
                if epistemic == EpistemicStatus.OBSERVED
                else f"Non-authoritative forensic reference ({ref.source_type}:{ref.source_id}, status={epistemic.value})"
            )

            is_bm = t_id in bookmarks
            item = InvestigationTimelineItem(
                timeline_id=t_id,
                case_id=case_id,
                timestamp=ts_str,
                timestamp_precision=self._detect_precision(ts_str),
                host_id=str(host),
                layer=layer,
                event_type=str(ev_type),
                source_type=str(source),
                source_id=str(ref.source_id),
                title=self._sanitize(rec.get("title") or f"{layer.value}: {ev_type}", 120),
                display_summary=self._sanitize(summary, 300),
                entity_refs=sorted(list(set(entities))),
                relationship_refs=[],
                detection_refs=[str(ref.source_id)] if ref.source_type == "detection" else [],
                incident_refs=[case.incident_id] if case.incident_id else [],
                evidence_refs=[ref.citation_tag or f"[{ref.source_type}:{ref.source_id}]"],
                epistemic_status=epistemic,
                collection_status=CollectionStatus.SOURCE_AVAILABLE,
                provenance=provenance_label,
                is_bookmarked=is_bm,
                bookmark_notes=bookmarks.get(t_id),
                metadata=rec,
            )
            items_by_id[t_id] = item
            items.append(item)

        # 2. Scope-Linked Canonical Telemetry Events from logintel.db
        if self.db and case.incident_id:
            with self.db.connection() as conn:
                # Retrieve incident alerts
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT a.id, a.rule_id, a.severity, a.status, a.first_seen, a.last_seen, a.host, a.title, a.description
                    FROM incident_alerts ia
                    JOIN alerts a ON ia.alert_id = a.id
                    WHERE ia.incident_id = ?
                    """,
                    (case.incident_id,),
                )
                alerts_rows = cur.fetchall()
                for a in alerts_rows:
                    a_host = str(a["host"] or "unknown-host")
                    if allowed_host_aliases is not None:
                        if not (catalog.resolve_aliases(a_host) & allowed_host_aliases):
                            continue
                    if not is_interval_overlapping_bounds(
                        a["first_seen"],
                        a["last_seen"] or a["first_seen"],
                        eff_start_dt,
                        eff_end_dt,
                    ):
                        continue
                    cand_id = f"tl-alt-{a['id']}"
                    if cand_id in items_by_id:
                        existing = items_by_id[cand_id]
                        if existing.host_id == a_host and existing.source_id == str(a["id"]):
                            # Equivalent record already present from case evidence references
                            tag = f"[alert:{a['id']}]"
                            if tag not in existing.evidence_refs:
                                existing.evidence_refs.append(tag)
                            continue
                        else:
                            h_clean = a_host.lower().replace(".", "-").replace(":", "-")
                            cand_id = f"tl-alt-{h_clean}-{a['id']}"

                    t_id = cand_id
                    seen_ids.add(t_id)
                    alt_item = InvestigationTimelineItem(
                        timeline_id=t_id,
                        case_id=case_id,
                        timestamp=str(a["first_seen"]),
                        timestamp_precision=self._detect_precision(str(a["first_seen"])),
                        host_id=a_host,
                        layer=TimelineSourceLayer.ALERT,
                        event_type="ALERT_TRIGGERED",
                        source_type="rule_engine",
                        source_id=str(a["id"]),
                        title=self._sanitize(a["title"] or f"Alert {a['rule_id']}", 120),
                        display_summary=self._sanitize(a["description"] or "Security alert", 300),
                        entity_refs=[],
                        relationship_refs=[],
                        detection_refs=[str(a["rule_id"])],
                        incident_refs=[case.incident_id],
                        evidence_refs=[f"[alert:{a['id']}]"],
                        epistemic_status=EpistemicStatus.OBSERVED,
                        collection_status=CollectionStatus.SOURCE_AVAILABLE,
                        provenance=f"Alert engine (rule: {a['rule_id']})",
                        is_bookmarked=t_id in bookmarks,
                        bookmark_notes=bookmarks.get(t_id),
                        metadata={
                            "severity": a["severity"],
                            "status": a["status"],
                            "last_seen": a["last_seen"],
                        },
                    )
                    items_by_id[t_id] = alt_item
                    items.append(alt_item)

                # Retrieve scoped incident canonical events before ORDER BY/LIMIT so out-of-scope rows never displace in-scope rows
                max_ev = self.MAX_INCIDENT_EVENTS
                ev_where = ["ia.incident_id = ?"]
                ev_params: List[Any] = [case.incident_id]
                if allowed_host_aliases is not None:
                    sorted_aliases = sorted(allowed_host_aliases)
                    host_ph = ",".join("?" for _ in sorted_aliases)
                    ev_where.append(f"LOWER(e.host) IN ({host_ph})")
                    ev_params.extend(sorted_aliases)
                if eff_start_dt is not None:
                    ev_where.append("unixepoch(e.timestamp, 'subsec') >= ?")
                    ev_params.append(eff_start_dt.timestamp())
                if eff_end_dt is not None:
                    ev_where.append("unixepoch(e.timestamp, 'subsec') <= ?")
                    ev_params.append(eff_end_dt.timestamp())

                ev_sql = f"""
                    SELECT DISTINCT e.id, e.timestamp, e.source, e.event_type, e.severity, e.host, e.username, e.src_ip, e.dst_ip, e.action, e.raw_message
                    FROM detections d
                    JOIN detection_evidence de ON de.detection_id = d.id
                    JOIN incident_alerts ia ON d.alert_id = ia.alert_id
                    JOIN events e ON de.event_id = e.id
                    WHERE {' AND '.join(ev_where)}
                    ORDER BY COALESCE(unixepoch(e.timestamp, 'subsec'), 9e99) ASC, e.id ASC
                    LIMIT ?
                """
                cur.execute(ev_sql, tuple(ev_params + [max_ev + 1]))
                ev_rows = cur.fetchall()
                if len(ev_rows) > max_ev:
                    db_truncated = True
                    ev_rows = ev_rows[:max_ev]
                for ev in ev_rows:
                    ev_host = str(ev["host"] or "unknown-host")
                    cand_id = f"tl-ev-{ev['id']}"
                    if cand_id in items_by_id:
                        existing = items_by_id[cand_id]
                        if existing.host_id == ev_host and existing.source_id == str(ev["id"]):
                            tag = f"[event:{ev['id']}]"
                            if tag not in existing.evidence_refs:
                                existing.evidence_refs.append(tag)
                            continue
                        else:
                            h_clean = ev_host.lower().replace(".", "-").replace(":", "-")
                            cand_id = f"tl-ev-{h_clean}-{ev['id']}"

                    t_id = cand_id
                    seen_ids.add(t_id)

                    layer = self._classify_layer(ev["source"], ev["event_type"])
                    entities = []
                    if ev["username"]:
                        entities.append(f"user:{ev['username']}")
                    if ev["src_ip"]:
                        entities.append(f"ip:{ev['src_ip']}")
                    if ev["dst_ip"]:
                        entities.append(f"ip:{ev['dst_ip']}")

                    ev_item = InvestigationTimelineItem(
                        timeline_id=t_id,
                        case_id=case_id,
                        timestamp=str(ev["timestamp"]),
                        timestamp_precision=self._detect_precision(str(ev["timestamp"])),
                        host_id=ev_host,
                        layer=layer,
                        event_type=str(ev["event_type"] or "telemetry"),
                        source_type=str(ev["source"]),
                        source_id=str(ev["id"]),
                        title=self._sanitize(f"{layer.value}: {ev['action'] or ev['event_type']}", 120),
                        display_summary=self._sanitize(ev["raw_message"] or "Authoritative event", 300),
                        entity_refs=sorted(list(set(entities))),
                        relationship_refs=[],
                        detection_refs=[],
                        incident_refs=[case.incident_id],
                        evidence_refs=[f"[event:{ev['id']}]"],
                        epistemic_status=EpistemicStatus.OBSERVED,
                        collection_status=CollectionStatus.SOURCE_AVAILABLE,
                        provenance=f"Authoritative {ev['source']} log (id: {ev['id']})",
                        is_bookmarked=t_id in bookmarks,
                        bookmark_notes=bookmarks.get(t_id),
                        metadata={"severity": ev["severity"]},
                    )
                    items_by_id[t_id] = ev_item
                    items.append(ev_item)

        # 3. Case Audit Log Milestones
        for a in case.audit_history:
            aud_host = target_hosts[0] if target_hosts else "analyst-workstation"
            cand_id = f"tl-aud-{a.audit_id or a.timestamp}"
            if cand_id in items_by_id:
                cand_id = f"tl-aud-{a.audit_id}-{a.timestamp}"

            t_id = cand_id
            seen_ids.add(t_id)
            aud_item = InvestigationTimelineItem(
                timeline_id=t_id,
                case_id=case_id,
                timestamp=a.timestamp,
                timestamp_precision=self._detect_precision(a.timestamp),
                host_id=aud_host,
                layer=TimelineSourceLayer.ANALYST_NOTE,
                event_type=f"AUDIT_{a.action}",
                source_type="audit_trail",
                source_id=str(a.audit_id or a.timestamp),
                title=self._sanitize(f"Analyst Action: {a.action}", 120),
                display_summary=self._sanitize(f"Analyst '{a.actor}' performed {a.action}. {a.reason or ''}", 300),
                entity_refs=[f"user:{a.actor}"],
                relationship_refs=[],
                detection_refs=[],
                incident_refs=[case.incident_id] if case.incident_id else [],
                evidence_refs=[],
                epistemic_status=EpistemicStatus.OBSERVED,
                collection_status=CollectionStatus.SOURCE_AVAILABLE,
                provenance=f"Immutable case audit trail (actor: {a.actor})",
                is_bookmarked=t_id in bookmarks,
                bookmark_notes=bookmarks.get(t_id),
                metadata={"actor": a.actor, "action": a.action},
            )
            items_by_id[t_id] = aud_item
            items.append(aud_item)

        # Strict deterministic multi-key sorting
        items.sort(key=self._timeline_sort_key)
        return items, db_truncated

    def query_timeline(
        self,
        case_id: int,
        params: TimelineFilterParams,
    ) -> TimelineQueryResponse:
        """Filter, paginate, and return timeline items under case scope."""
        case = self.case_repo.get_case(case_id, resolve_evidence=False)
        scope_time_start: Optional[str] = getattr(case.scope, "time_start", None) if case and case.scope else None
        scope_time_end: Optional[str] = getattr(case.scope, "time_end", None) if case and case.scope else None
        target_hosts: List[str] = getattr(case.scope, "target_hosts", []) or [] if case and case.scope else []

        host_catalog = HostCatalogIndex.from_db(self.db)
        scope_start_dt, scope_end_dt, scope_is_empty = intersect_time_bounds(
            scope_time_start,
            scope_time_end,
            None,
            None,
        )
        eff_start_dt, eff_end_dt, is_empty_window = intersect_time_bounds(
            scope_time_start,
            scope_time_end,
            params.time_start,
            params.time_end,
        )
        if scope_is_empty or is_empty_window:
            limit = min(max(params.limit, 1), 500)
            offset = max(params.offset, 0)
            return TimelineQueryResponse(
                items=[],
                total=0,
                limit=limit,
                offset=offset,
                epistemic_breakdown={},
                layer_breakdown={},
                is_truncated=False,
            )

        all_items, db_truncated = self._build_raw_timeline_items_with_meta(
            case_id,
            host_filter=params.host,
            time_start=params.time_start,
            time_end=params.time_end,
            host_catalog=host_catalog,
        )

        # Enforce case-scope bounds using UTC datetimes and exact host-catalog aliases
        target_expanded = host_catalog.expand_scope_targets(target_hosts) if target_hosts else set()
        scoped_items = [
            i for i in all_items
            if self._item_matches_time_bounds(i, scope_start_dt, scope_end_dt)
            and (
                not target_hosts
                or host_catalog.matches_scope(i.host_id, target_hosts, expanded_targets=target_expanded)
            )
        ]

        # Enforce intersected UTC time bounds and query host aliases
        filtered = [
            i for i in scoped_items
            if self._item_matches_time_bounds(i, eff_start_dt, eff_end_dt)
        ]

        if params.host:
            query_host_aliases = host_catalog.resolve_aliases(params.host)
            if not query_host_aliases:
                filtered = []
            else:
                filtered = [
                    i for i in filtered
                    if bool(host_catalog.resolve_aliases(i.host_id) & query_host_aliases)
                ]
        if params.layer:
            layer_q = params.layer.strip().upper()
            filtered = [i for i in filtered if i.layer.value == layer_q]
        if params.event_type:
            et_q = params.event_type.strip().lower()
            filtered = [i for i in filtered if et_q in i.event_type.lower()]
        if params.source:
            src_q = params.source.strip().lower()
            filtered = [i for i in filtered if src_q in i.source_type.lower()]
        if params.entity:
            ent_q = params.entity.strip().lower()
            filtered = [i for i in filtered if any(ent_q in e.lower() for e in i.entity_refs)]
        if params.epistemic_status:
            filtered = [i for i in filtered if i.epistemic_status == params.epistemic_status]
        if params.collection_status:
            filtered = [i for i in filtered if i.collection_status == params.collection_status]
        if params.bookmarked_only:
            filtered = [i for i in filtered if i.is_bookmarked]
        if params.search:
            search_q = params.search.strip().lower()[:200]
            filtered = [
                i
                for i in filtered
                if search_q in i.title.lower()
                or search_q in i.display_summary.lower()
                or any(search_q in e.lower() for e in i.entity_refs)
            ]

        total = len(filtered)
        limit = min(max(params.limit, 1), 500)
        offset = max(params.offset, 0)
        page = filtered[offset : offset + limit]

        # Metric breakdowns over case-scoped items
        epistemic_counts: Dict[str, int] = {}
        layer_counts: Dict[str, int] = {}
        for item in scoped_items:
            epistemic_counts[item.epistemic_status.value] = epistemic_counts.get(item.epistemic_status.value, 0) + 1
            layer_counts[item.layer.value] = layer_counts.get(item.layer.value, 0) + 1

        return TimelineQueryResponse(
            items=page,
            total=total,
            limit=limit,
            offset=offset,
            epistemic_breakdown=epistemic_counts,
            layer_breakdown=layer_counts,
            is_truncated=db_truncated,
        )

    def get_replay_session(
        self,
        case_id: int,
        params: Optional[TimelineFilterParams] = None,
    ) -> TimelineReplaySession:
        """Construct full deterministic replay session with frame index and Merkle fingerprint."""
        filter_p = params or TimelineFilterParams(limit=500)
        filter_p.limit = 500  # Expand to maximum bound for replay
        query_res = self.query_timeline(case_id, filter_p)
        items = query_res.items

        # Build index lookups and frames
        entity_index: Dict[str, List[str]] = {}
        host_index: Dict[str, List[str]] = {}
        evidence_index: Dict[str, str] = {}
        frames: List[TimelineReplayFrame] = []
        cumulative_counts: Dict[str, int] = {}

        fingerprint_lines: List[str] = []

        start_time = items[0].timestamp if items else None
        end_time = items[-1].timestamp if items else None
        time_span = 0.0

        if start_time and end_time:
            dt1 = parse_iso_datetime(start_time)
            dt2 = parse_iso_datetime(end_time)
            if dt1 is not None and dt2 is not None:
                time_span = max((dt2 - dt1).total_seconds(), 0.0)

        for idx, it in enumerate(items):
            cumulative_counts[it.layer.value] = cumulative_counts.get(it.layer.value, 0) + 1
            
            # Index entities
            for ent in it.entity_refs:
                entity_index.setdefault(ent, []).append(it.timeline_id)
            
            # Index host
            host_index.setdefault(it.host_id, []).append(it.timeline_id)

            # Index evidence
            for ev in it.evidence_refs:
                evidence_index[ev] = it.timeline_id

            is_ev = bool(it.evidence_refs or it.layer in (TimelineSourceLayer.ALERT, TimelineSourceLayer.DETECTION))

            frames.append(
                TimelineReplayFrame(
                    frame_index=idx,
                    timeline_id=it.timeline_id,
                    timestamp=it.timestamp,
                    title=it.title,
                    layer=it.layer,
                    epistemic_status=it.epistemic_status,
                    active_entities=it.entity_refs,
                    active_hosts=[it.host_id],
                    is_evidence=is_ev,
                    cumulative_counts=dict(cumulative_counts),
                )
            )

            fingerprint_lines.append(f"{idx}:{it.timeline_id}:{it.timestamp}:{it.layer.value}")

        # Deterministic SHA-256 fingerprint
        fp_data = "\n".join(fingerprint_lines).encode("utf-8")
        provenance_fingerprint = f"sha256:{hashlib.sha256(fp_data).hexdigest()}"

        return TimelineReplaySession(
            case_id=case_id,
            total_items=len(items),
            start_time=start_time,
            end_time=end_time,
            time_span_seconds=time_span,
            items=items,
            frames=frames,
            entity_index=entity_index,
            host_index=host_index,
            evidence_index=evidence_index,
            epistemic_breakdown=query_res.epistemic_breakdown,
            layer_breakdown=query_res.layer_breakdown,
            is_truncated=bool(query_res.is_truncated or (query_res.total > len(items))),
            provenance_fingerprint=provenance_fingerprint,
        )

    def get_timeline_context(self, case_id: int, timeline_id: str) -> TimelineContextResponse:
        """Retrieve synchronized context linking timeline item to graph, evidence, and raw source."""
        all_items = self.build_raw_timeline_items(case_id)
        target = next((i for i in all_items if i.timeline_id == timeline_id), None)
        if not target:
            raise ValueError(f"Timeline item '{timeline_id}' not found in case {case_id}")

        related_graph_nodes = list(target.entity_refs)
        if target.host_id and f"host:{target.host_id}" not in related_graph_nodes:
            related_graph_nodes.append(f"host:{target.host_id}")

        return TimelineContextResponse(
            item=target,
            related_graph_nodes=sorted(related_graph_nodes),
            related_evidence=target.evidence_refs,
            source_record=target.metadata,
        )

    def bookmark_item(
        self,
        case_id: int,
        timeline_id: str,
        analyst_note: Optional[str] = None,
        actor: str = "SecAnalyst-1",
    ) -> Dict[str, Any]:
        """Record analyst bookmark reference in cases.db without mutating forensic telemetry."""
        case = self.case_repo.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")

        ref_id = f"bm-{timeline_id.replace('tl-', '')}"
        note = self._sanitize(analyst_note or "Bookmarked by analyst", 500)

        # Associate in case_evidence_references
        ref = self.case_repo.add_evidence_reference(
            case_id=case_id,
            source_type="timeline",
            source_id=timeline_id,
            role="SUPPORTING",
            epistemic_status="OBSERVED",
            citation_tag=f"[bookmark:{timeline_id}]",
            analyst_annotation=note,
            actor=actor,
        )

        # Record in case_audit_log
        self.case_repo.append_audit_log(
            case_id=case_id,
            actor=actor,
            action="ADD_BOOKMARK",
            previous_value=None,
            new_value=timeline_id,
            reason=note,
        )

        return {
            "status": "BOOKMARKED",
            "case_id": case_id,
            "timeline_id": timeline_id,
            "reference_id": ref.reference_id if hasattr(ref, "reference_id") else ref_id,
            "analyst_note": note,
        }

    def remove_bookmark(
        self,
        case_id: int,
        timeline_id: str,
        actor: str = "SecAnalyst-1",
    ) -> Dict[str, Any]:
        """Remove analyst bookmark reference in cases.db."""
        case = self.case_repo.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")

        # Find matching reference
        for ref in case.evidence_references:
            if ref.source_id == timeline_id and (ref.source_type == "timeline" or ref.citation_tag.startswith("[bookmark:")):
                self.case_repo.remove_evidence_reference(case_id, ref.reference_id, actor=actor)
                self.case_repo.append_audit_log(
                    case_id=case_id,
                    actor=actor,
                    action="REMOVE_BOOKMARK",
                    previous_value=timeline_id,
                    new_value=None,
                    reason="Bookmark removed by analyst",
                )
                return {"status": "REMOVED", "case_id": case_id, "timeline_id": timeline_id}

        return {"status": "NOT_FOUND", "case_id": case_id, "timeline_id": timeline_id}

    def export_timeline(
        self,
        case_id: int,
        export_format: str = "json",
        params: Optional[TimelineFilterParams] = None,
    ) -> Tuple[str, str]:
        """Export case timeline deterministically in JSON or CSV format with completeness metadata."""
        filter_p = (params or TimelineFilterParams(limit=500)).model_copy(update={"limit": 500})
        res = self.query_timeline(case_id, filter_p)
        items = res.items
        export_truncated = bool(res.is_truncated or (res.total > len(items)))
        completeness_status = "PARTIAL" if export_truncated else "COMPLETE"
        truncation_notice = (
            f"Partial export: exported {len(items)} of {res.total} matching scoped items (export cap={filter_p.limit}, backend_capped={res.is_truncated})."
            if export_truncated
            else None
        )

        if export_format.lower() == "csv":
            output = io.StringIO()
            writer = csv.writer(output, lineterminator="\n")
            writer.writerow([
                "timeline_id",
                "timestamp",
                "precision",
                "host",
                "layer",
                "event_type",
                "source",
                "source_id",
                "title",
                "summary",
                "epistemic_status",
                "collection_status",
                "entities",
                "evidence_refs",
                "provenance",
                "is_bookmarked",
            ])
            for it in items:
                writer.writerow([
                    it.timeline_id,
                    it.timestamp,
                    it.timestamp_precision.value,
                    it.host_id,
                    it.layer.value,
                    it.event_type,
                    it.source_type,
                    it.source_id,
                    it.title,
                    it.display_summary,
                    it.epistemic_status.value,
                    it.collection_status.value,
                    ";".join(it.entity_refs),
                    ";".join(it.evidence_refs),
                    it.provenance,
                    "YES" if it.is_bookmarked else "NO",
                ])
            output.write(
                f"# completeness_status={completeness_status};exported_items={len(items)};total_matching={res.total};is_truncated={str(export_truncated).lower()}\n"
            )
            return output.getvalue(), "text/csv"

        # Canonical deterministic JSON export
        export_dict = {
            "case_id": case_id,
            "export_timestamp": "DETERMINISTIC_EXPORT",
            "total_items": len(items),
            "total_matching": res.total,
            "is_truncated": export_truncated,
            "completeness_status": completeness_status,
            "truncation_notice": truncation_notice,
            "epistemic_breakdown": res.epistemic_breakdown,
            "layer_breakdown": res.layer_breakdown,
            "items": [it.model_dump(mode="json") for it in items],
        }
        json_str = json.dumps(export_dict, indent=2, sort_keys=True, ensure_ascii=False)
        return json_str, "application/json"


# Default singleton instance
timeline_service = UnifiedTimelineService()
