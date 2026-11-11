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

    def _timeline_sort_key(self, item: InvestigationTimelineItem) -> Tuple[str, int, str, str]:
        """Strict deterministic multi-key ordering: (timestamp, layer_priority, source_id, timeline_id)."""
        ts = item.timestamp or ""
        prio = LAYER_PRIORITY.get(item.layer, 999)
        src_id = item.source_id or ""
        t_id = item.timeline_id or ""
        return (ts, prio, src_id, t_id)

    def _load_bookmarks(self, case_id: int) -> Dict[str, str]:
        """Load analyst bookmarks for a case from case_evidence_references without schema changes."""
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

    def _build_raw_timeline_items_with_meta(self, case_id: int) -> Tuple[List[InvestigationTimelineItem], bool]:
        """Aggregate, project, and sort timeline items, returning (items, is_truncated)."""
        case = self.case_repo.get_case(case_id)
        if not case:
            raise ValueError(f"Investigation case {case_id} not found")

        db_truncated = False

        bookmarks = self._load_bookmarks(case_id)
        target_hosts = getattr(case.scope, "target_hosts", []) or []
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
            ts = rec.get("timestamp") or rec.get("first_seen") or rec.get("created_at") or ref.created_at
            host = rec.get("host") or (target_hosts[0] if target_hosts else "unknown-host")
            source = rec.get("source") or ref.source_type
            ev_type = rec.get("event_type") or rec.get("action") or ref.source_type.upper()

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

            cand_id = f"tl-{pfx}-{ref.source_id}"
            if cand_id in items_by_id:
                existing = items_by_id[cand_id]
                # If truly equivalent record (same host, timestamp, and source domain), merge evidence refs
                if existing.host_id == str(host) and existing.timestamp == str(ts) and existing.source_id == str(ref.source_id):
                    tag = ref.citation_tag or f"[{ref.source_type}:{ref.source_id}]"
                    if tag not in existing.evidence_refs:
                        existing.evidence_refs.append(tag)
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
            epistemic = EpistemicStatus.OBSERVED
            if ref.epistemic_status:
                try:
                    epistemic = EpistemicStatus(ref.epistemic_status)
                except Exception:
                    epistemic = EpistemicStatus.OBSERVED

            is_bm = t_id in bookmarks
            item = InvestigationTimelineItem(
                timeline_id=t_id,
                case_id=case_id,
                timestamp=str(ts),
                timestamp_precision=self._detect_precision(str(ts)),
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
                provenance=f"Authoritative forensic reference ({ref.source_type}:{ref.source_id})",
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
                    SELECT a.id, a.rule_id, a.severity, a.status, a.first_seen, a.host, a.title, a.description
                    FROM incident_alerts ia
                    JOIN alerts a ON ia.alert_id = a.id
                    WHERE ia.incident_id = ?
                    """,
                    (case.incident_id,),
                )
                alerts_rows = cur.fetchall()
                for a in alerts_rows:
                    a_host = str(a["host"] or "unknown-host")
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
                        metadata={"severity": a["severity"], "status": a["status"]},
                    )
                    items_by_id[t_id] = alt_item
                    items.append(alt_item)

                # Retrieve incident canonical events deterministically; fetch +1 to detect cap truncation accurately
                max_ev = self.MAX_INCIDENT_EVENTS
                cur.execute(
                    f"""
                    SELECT DISTINCT e.id, e.timestamp, e.source, e.event_type, e.severity, e.host, e.username, e.src_ip, e.dst_ip, e.action, e.raw_message
                    FROM detections d
                    JOIN detection_evidence de ON de.detection_id = d.id
                    JOIN incident_alerts ia ON d.alert_id = ia.alert_id
                    JOIN events e ON de.event_id = e.id
                    WHERE ia.incident_id = ?
                    ORDER BY e.timestamp ASC, e.id ASC
                    LIMIT ?
                    """,
                    (case.incident_id, max_ev + 1),
                )
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
        all_items, db_truncated = self._build_raw_timeline_items_with_meta(case_id)

        case = self.case_repo.get_case(case_id, resolve_evidence=False)
        scope_time_start: Optional[str] = getattr(case.scope, "time_start", None) if case and case.scope else None
        scope_time_end: Optional[str] = getattr(case.scope, "time_end", None) if case and case.scope else None
        target_hosts: List[str] = getattr(case.scope, "target_hosts", []) or [] if case and case.scope else []

        # Enforce case-scope bounds first so out-of-scope items never leak into results or breakdowns
        scoped_items = all_items
        if scope_time_start:
            scoped_items = [i for i in scoped_items if i.timestamp >= scope_time_start]
        if scope_time_end:
            scoped_items = [i for i in scoped_items if i.timestamp <= scope_time_end]
        if target_hosts:
            target_norm = {h.strip().lower() for h in target_hosts if h.strip()}
            scoped_items = [i for i in scoped_items if i.host_id.strip().lower() in target_norm]

        # Enforce intersection of case temporal bounds and query parameters
        eff_start = params.time_start
        if scope_time_start:
            if eff_start is None or scope_time_start > eff_start:
                eff_start = scope_time_start

        eff_end = params.time_end
        if scope_time_end:
            if eff_end is None or scope_time_end < eff_end:
                eff_end = scope_time_end

        # Query filter pass
        filtered = scoped_items
        if eff_start:
            filtered = [i for i in filtered if i.timestamp >= eff_start]
        if eff_end:
            filtered = [i for i in filtered if i.timestamp <= eff_end]

        # Exact canonical host filtering (no substring matching)
        if params.host:
            host_q = params.host.strip().lower()
            filtered = [i for i in filtered if i.host_id.strip().lower() == host_q]
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
            try:
                dt1 = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
                dt2 = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
                time_span = max((dt2 - dt1).total_seconds(), 0.0)
            except Exception:
                pass

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
        """Export case timeline deterministically in JSON or CSV format."""
        filter_p = params or TimelineFilterParams(limit=500)
        filter_p.limit = 500
        res = self.query_timeline(case_id, filter_p)
        items = res.items

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
            return output.getvalue(), "text/csv"

        # Canonical deterministic JSON export
        export_dict = {
            "case_id": case_id,
            "export_timestamp": "DETERMINISTIC_EXPORT",
            "total_items": len(items),
            "epistemic_breakdown": res.epistemic_breakdown,
            "layer_breakdown": res.layer_breakdown,
            "items": [it.model_dump(mode="json") for it in items],
        }
        json_str = json.dumps(export_dict, indent=2, sort_keys=True, ensure_ascii=False)
        return json_str, "application/json"


# Default singleton instance
timeline_service = UnifiedTimelineService()
