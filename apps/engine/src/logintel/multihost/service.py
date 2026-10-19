"""Multi-Host Investigation Service for Milestone 7.12.

Assembles case-scoped multi-host dossiers, validates host scope against authoritative
evidence, computes lateral movement traces, detects host identity discrepancies,
and exposes host-specific timeline projections while strictly preserving forensic invariants.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from logintel.ai.domain.case import InvestigationCase, ResolutionStatus
from logintel.ai.domain.investigation_temporal import EntityContinuity, MultiHostTrace
from logintel.ai.temporal.reconstruction_engine import TemporalReconstructionEngine
from logintel.logging import get_logger
from logintel.multihost.models import (
    CaseHostSummary,
    CaseMultiHostDossier,
    ComparativeTimelineResponse,
    HostDiscrepancy,
    HostEpistemicStatus,
    HostTimelineLane,
    HostTimelineResponse,
    HostVisibilityGap,
    MultiHostExportResponse,
)
from logintel.storage.case_repo import CaseRepository, case_repo as default_case_repo
from logintel.storage.db import Database, db as default_forensic_db
from logintel.timeline.models import TimelineFilterParams
from logintel.timeline.service import UnifiedTimelineService

logger = get_logger("multihost.service")


class MultiHostInvestigationService:
    """Service providing case-scoped multi-host dossier synthesis, timeline slicing, and trace tracking."""

    def __init__(
        self,
        case_repository: Optional[CaseRepository] = None,
        forensic_database: Optional[Database] = None,
        reconstruction_engine: Optional[TemporalReconstructionEngine] = None,
        timeline_service: Optional[UnifiedTimelineService] = None,
    ) -> None:
        self.case_repo = case_repository or default_case_repo
        self.forensic_db = forensic_database or default_forensic_db
        self.engine = reconstruction_engine or TemporalReconstructionEngine()
        self.timeline_svc = timeline_service or UnifiedTimelineService(
            forensic_db=self.forensic_db,
            case_repository=self.case_repo,
        )

    def _compute_hash(self, payload: Any) -> str:
        """Compute deterministic SHA-256 fingerprint."""
        raw = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
        return f"sha256:{hashlib.sha256(raw).hexdigest()}"

    def _normalize_host_str(self, host: Optional[str]) -> Optional[str]:
        """Strip control characters and whitespace from host string."""
        if not host:
            return None
        cleaned = re.sub(r"[\x00-\x1f\x7f]", "", str(host).strip())
        return cleaned if cleaned else None

    def _load_host_catalog(self) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
        """Load authoritative host catalog from read-only logintel.db:hosts table."""
        by_id: Dict[str, Dict[str, Any]] = {}
        by_hostname: Dict[str, Dict[str, Any]] = {}

        if not self.forensic_db:
            return by_id, by_hostname

        try:
            with self.forensic_db.connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT id, hostname, os_name, os_version, first_seen, last_seen FROM hosts"
                )
                rows = cur.fetchall()
                for row in rows:
                    item = dict(row)
                    if item.get("id"):
                        by_id[item["id"].strip().lower()] = item
                    if item.get("hostname"):
                        by_hostname[item["hostname"].strip().lower()] = item
        except Exception as e:
            logger.warning("Could not read host catalog from logintel.db:hosts: %s", e)

        return by_id, by_hostname

    def get_case_dossier(self, case_id: int) -> CaseMultiHostDossier:
        """Assemble a complete, deterministic, case-scoped multi-host dossier."""
        case = self.case_repo.get_case(case_id, resolve_evidence=True)
        if not case:
            raise ValueError(f"Investigation case {case_id} not found")

        now_iso = datetime.now(timezone.utc).isoformat()
        target_hosts: List[str] = getattr(case.scope, "target_hosts", []) or []
        is_scope_unspecified: bool = len(target_hosts) == 0

        catalog_by_id, catalog_by_hostname = self._load_host_catalog()

        # Data structures per host identifier
        # We index by canonical host identifier (or raw string)
        host_ident_map: Dict[str, str] = {}  # raw_key.lower() -> canonical_key
        host_raw_labels: Dict[str, str] = {}  # canonical_key -> display_name
        host_event_counts: Dict[str, int] = {}
        host_alert_counts: Dict[str, int] = {}
        host_first_seen: Dict[str, Optional[str]] = {}
        host_last_seen: Dict[str, Optional[str]] = {}
        host_evidence_tags: Dict[str, Set[str]] = {}
        host_discrepancies: Dict[str, List[HostDiscrepancy]] = {}
        host_gaps: Dict[str, List[HostVisibilityGap]] = {}

        def register_host(raw_host: str) -> str:
            norm = self._normalize_host_str(raw_host)
            if not norm:
                return "unknown-host"
            low = norm.lower()

            # Check if it matches existing registered key
            if low in host_ident_map:
                return host_ident_map[low]

            # Check if it matches catalog by ID or hostname
            if low in catalog_by_id:
                cat = catalog_by_id[low]
                can_id = cat["id"]
                can_host = cat["hostname"]
                host_ident_map[low] = can_id
                host_ident_map[can_host.lower()] = can_id
                host_raw_labels[can_id] = can_host
                return can_id

            if low in catalog_by_hostname:
                cat = catalog_by_hostname[low]
                can_id = cat["id"]
                can_host = cat["hostname"]
                host_ident_map[low] = can_id
                host_ident_map[can_id.lower()] = can_id
                host_raw_labels[can_id] = can_host
                return can_id

            # Uncataloged host
            host_ident_map[low] = norm
            host_raw_labels[norm] = norm
            return norm

        scope_time_start: Optional[str] = getattr(case.scope, "time_start", None)
        scope_time_end: Optional[str] = getattr(case.scope, "time_end", None)

        def _parse_ts_utc(ts: Optional[str]) -> Optional[datetime]:
            if not ts:
                return None
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except Exception:
                return None

        scope_start_dt = _parse_ts_utc(scope_time_start)
        scope_end_dt = _parse_ts_utc(scope_time_end)

        def _is_in_scope_time(ts: Optional[str]) -> bool:
            if not ts:
                return True
            dt = _parse_ts_utc(ts)
            if dt is None:
                clean_ts = ts.replace("Z", "+00:00")
                if scope_time_start and clean_ts < scope_time_start.replace("Z", "+00:00"):
                    return False
                if scope_time_end and clean_ts > scope_time_end.replace("Z", "+00:00"):
                    return False
                return True
            if scope_start_dt and dt < scope_start_dt:
                return False
            if scope_end_dt and dt > scope_end_dt:
                return False
            return True

        def update_timestamps(key: str, ts: Optional[str]) -> None:
            if not ts:
                return
            clean_ts = ts.replace("Z", "+00:00")
            if not _is_in_scope_time(clean_ts):
                return
            cur_first = host_first_seen.get(key)
            if cur_first is None or clean_ts < cur_first:
                host_first_seen[key] = clean_ts
            cur_last = host_last_seen.get(key)
            if cur_last is None or clean_ts > cur_last:
                host_last_seen[key] = clean_ts

        counted_event_ids: Dict[str, Set[str]] = {}
        counted_alert_ids: Dict[str, Set[str]] = {}

        # 1. Inspect explicit target_hosts from case scope
        for th in target_hosts:
            key = register_host(th)
            # Ensure initialized
            host_event_counts.setdefault(key, 0)
            host_alert_counts.setdefault(key, 0)
            host_evidence_tags.setdefault(key, set())
            host_discrepancies.setdefault(key, [])
            host_gaps.setdefault(key, [])

        # 2. Extract hosts from case evidence references
        for ref in case.evidence_references:
            rec = ref.resolved_record or {}
            if not rec and ref.analyst_annotation:
                try:
                    rec = json.loads(ref.analyst_annotation)
                except Exception:
                    pass
            ref_host = rec.get("host") or rec.get("hostname")
            if ref_host:
                key = register_host(ref_host)
                host_evidence_tags.setdefault(key, set()).add(ref.citation_tag or f"[{ref.source_type}:{ref.source_id}]")
                ts = rec.get("timestamp") or rec.get("first_seen") or rec.get("created_at") or ref.created_at
                
                # Enforce temporal scope boundaries for evidence references
                if not _is_in_scope_time(ts):
                    continue

                update_timestamps(key, ts)
                if ref.source_type == "alert":
                    alert_id = str(rec.get("id") or ref.source_id)
                    counted_alerts = counted_alert_ids.setdefault(key, set())
                    if alert_id not in counted_alerts:
                        counted_alerts.add(alert_id)
                        host_alert_counts[key] = host_alert_counts.get(key, 0) + 1
                elif ref.source_type == "event":
                    ev_id = str(rec.get("id") or ref.source_id)
                    counted_events = counted_event_ids.setdefault(key, set())
                    if ev_id not in counted_events:
                        counted_events.add(ev_id)
                        host_event_counts[key] = host_event_counts.get(key, 0) + 1

        # 3. Read incident alerts from logintel.db
        if self.forensic_db and case.incident_id:
            try:
                with self.forensic_db.connection() as conn:
                    cur = conn.cursor()
                    cur.execute(
                        """
                        SELECT a.id, a.rule_id, a.severity, a.status, a.first_seen, a.last_seen, a.host
                        FROM incident_alerts ia
                        JOIN alerts a ON ia.alert_id = a.id
                        WHERE ia.incident_id = ?
                        """,
                        (case.incident_id,),
                    )
                    for row in cur.fetchall():
                        a_host = row["host"]
                        if a_host:
                            key = register_host(a_host)
                            a_first = row["first_seen"]
                            a_last = row["last_seen"]
                            if (scope_start_dt or scope_end_dt) and not (_is_in_scope_time(a_first) or _is_in_scope_time(a_last)):
                                continue
                            alert_id = str(row["id"])
                            counted_alerts = counted_alert_ids.setdefault(key, set())
                            if alert_id not in counted_alerts:
                                counted_alerts.add(alert_id)
                                host_alert_counts[key] = host_alert_counts.get(key, 0) + 1
                            update_timestamps(key, a_first)
                            update_timestamps(key, a_last)
                            host_evidence_tags.setdefault(key, set()).add(f"[alert:{row['id']}]")
            except Exception as e:
                logger.warning("Error reading incident alerts for case %d: %s", case_id, e)

        # 4. Read canonical telemetry events linked to incident or participating hosts from logintel.db
        all_canonical_keys = list(set(host_ident_map.values()))
        if self.forensic_db and all_canonical_keys:
            try:
                with self.forensic_db.connection() as conn:
                    cur = conn.cursor()
                    for ckey in all_canonical_keys:
                        # Find matching query terms for this host
                        display_name = host_raw_labels.get(ckey, ckey)
                        query = """
                            SELECT id, timestamp, host, event_type, source
                            FROM events
                            WHERE (host = ? OR host = ?)
                        """
                        params: List[Any] = [ckey, display_name]
                        if scope_time_start:
                            query += " AND timestamp >= ?"
                            params.append(scope_time_start)
                        if scope_time_end:
                            query += " AND timestamp <= ?"
                            params.append(scope_time_end)
                        query += " LIMIT 500"

                        cur.execute(query, tuple(params))
                        ev_rows = cur.fetchall()
                        counted_events = counted_event_ids.setdefault(ckey, set())
                        for ev in ev_rows:
                            ev_id = str(ev["id"])
                            if ev_id not in counted_events:
                                counted_events.add(ev_id)
                                host_event_counts[ckey] = host_event_counts.get(ckey, 0) + 1
                                update_timestamps(ckey, ev["timestamp"])
            except Exception as e:
                logger.warning("Error reading canonical events for case %d: %s", case_id, e)

        # 5. Build lateral movement traces and entity continuities using TemporalReconstructionEngine
        evidence_items = self.engine._harvest_case_evidence(case)
        if not evidence_items:
            for ref in case.evidence_references:
                rec = ref.resolved_record or {}
                if not rec and ref.analyst_annotation:
                    try:
                        rec = json.loads(ref.analyst_annotation)
                    except Exception:
                        pass
                if rec and (rec.get("host") or rec.get("hostname")):
                    item = dict(rec)
                    item["_citation_tag"] = ref.citation_tag
                    item["_source_type"] = ref.source_type
                    item["_source_id"] = str(ref.source_id)
                    item["_ref_id"] = ref.reference_id
                    item["_hash"] = self._compute_hash(rec)
                    ts = rec.get("timestamp") or rec.get("first_seen") or rec.get("created_at") or ref.created_at
                    item["timestamp"] = str(ts) if ts else None
                    if "host" not in item and "hostname" in item:
                        item["host"] = item["hostname"]
                    evidence_items.append(item)
            evidence_items.sort(key=lambda it: (it.get("timestamp") or "9999-99-99T99:99:99Z", str(it.get("_source_id", ""))))

        episodes = self.engine.build_temporal_episodes(case, evidence_items)
        transitions = self.engine.detect_transitions(case, evidence_items, episodes)
        lateral_traces = self.engine.reconstruct_multi_host_traces(case, transitions, evidence_items)
        entity_continuity = self.engine.detect_entity_continuity(case, evidence_items)

        # Inbound and outbound lateral hop counts
        inbound_hops: Dict[str, int] = {}
        outbound_hops: Dict[str, int] = {}
        for tr in lateral_traces:
            src_key = register_host(tr.source_host)
            dst_key = register_host(tr.target_host)
            outbound_hops[src_key] = outbound_hops.get(src_key, 0) + 1
            inbound_hops[dst_key] = inbound_hops.get(dst_key, 0) + 1

        # 6. Synthesize CaseHostSummary for every distinct canonical host
        participating_hosts: List[CaseHostSummary] = []
        overall_gaps: List[HostVisibilityGap] = []
        distinct_keys = sorted(list(set(host_ident_map.values())), key=lambda k: k.lower())

        target_hosts_norm = {h.lower() for h in target_hosts}

        for ckey in distinct_keys:
            display_name = host_raw_labels.get(ckey, ckey)
            cat_entry = catalog_by_id.get(ckey.lower()) or catalog_by_hostname.get(display_name.lower())

            os_name: Optional[str] = None
            os_version: Optional[str] = None
            host_id: str = ckey
            hostname: str = display_name
            gaps: List[HostVisibilityGap] = list(host_gaps.get(ckey, []))
            discrepancies: List[HostDiscrepancy] = list(host_discrepancies.get(ckey, []))

            if cat_entry:
                host_id = cat_entry["id"]
                hostname = cat_entry["hostname"]
                os_name = cat_entry.get("os_name")
                os_version = cat_entry.get("os_version")
                # Update catalog timestamps if observed are empty
                if not host_first_seen.get(ckey):
                    host_first_seen[ckey] = cat_entry.get("first_seen")
                if not host_last_seen.get(ckey):
                    host_last_seen[ckey] = cat_entry.get("last_seen")
                
                # Check for hostname discrepancy if display name differed
                if display_name.lower() != hostname.lower() and display_name.lower() != host_id.lower():
                    discrepancies.append(
                        HostDiscrepancy(
                            field="hostname",
                            catalog_value=hostname,
                            telemetry_value=display_name,
                            sources=["logintel.db:hosts", "telemetry"],
                            description=f"Host referenced as '{display_name}' in telemetry matches catalog hostname '{hostname}'",
                        )
                    )
            else:
                # Missing from authoritative host catalog
                gap = HostVisibilityGap(
                    gap_type="MISSING_HOST_CATALOG_ENTRY",
                    host_identifier=ckey,
                    description=f"Host '{ckey}' observed in telemetry is absent from authoritative host catalog (logintel.db:hosts)",
                    remedy_suggestion="Register host in inventory catalog or verify telemetry source attribution",
                )
                gaps.append(gap)
                overall_gaps.append(gap)

            ev_cnt = host_event_counts.get(ckey, 0)
            al_cnt = host_alert_counts.get(ckey, 0)
            is_in_target = (ckey.lower() in target_hosts_norm) or (display_name.lower() in target_hosts_norm)

            # Check if target host has zero telemetry
            if is_in_target and ev_cnt == 0 and al_cnt == 0:
                gap = HostVisibilityGap(
                    gap_type="TARGET_HOST_TELEMETRY_ABSENT",
                    host_identifier=ckey,
                    description=f"Host '{ckey}' explicitly included in investigation scope but zero events or alerts were observed",
                    remedy_suggestion="Verify agent telemetry ingestion, host network connectivity, and log collection pipelines",
                )
                gaps.append(gap)
                overall_gaps.append(gap)
                epistemic_status = HostEpistemicStatus.UNKNOWN
            else:
                epistemic_status = HostEpistemicStatus.OBSERVED

            participating_hosts.append(
                CaseHostSummary(
                    host_id=host_id,
                    hostname=hostname,
                    os_name=os_name,
                    os_version=os_version,
                    is_in_target_scope=is_in_target,
                    first_seen=host_first_seen.get(ckey),
                    last_seen=host_last_seen.get(ckey),
                    event_count=ev_cnt,
                    alert_count=al_cnt,
                    inbound_lateral_hops=inbound_hops.get(ckey, 0),
                    outbound_lateral_hops=outbound_hops.get(ckey, 0),
                    evidence_references=sorted(list(host_evidence_tags.get(ckey, set()))),
                    telemetry_gaps=sorted(gaps, key=lambda g: (g.gap_type, g.host_identifier)),
                    discrepancies=sorted(discrepancies, key=lambda d: (d.field, d.description)),
                    host_graph_available=(ev_cnt > 0 or cat_entry is not None),
                    epistemic_status=epistemic_status,
                )
            )

        # 7. Deterministic sorting
        participating_hosts.sort(key=lambda h: (h.host_id.lower(), h.hostname.lower()))
        lateral_traces.sort(key=lambda tr: (tr.start_time, tr.trace_id))
        entity_continuity.sort(key=lambda c: (c.continuity_type.value, c.entity_key))
        overall_gaps.sort(key=lambda g: (g.gap_type, g.host_identifier))

        # 8. Forensic Completeness Limitations
        limitations: List[str] = [
            "Authoritative telemetry database logintel.db is strictly read-only; investigation mutations are confined to cases.db.",
            "Epistemic boundaries strictly enforced: absent telemetry does not constitute proof that an event did not occur.",
        ]
        if is_scope_unspecified:
            limitations.append(
                "Case host scope is unspecified; participating hosts were dynamically derived from case evidence, alerts, and telemetry."
            )
        else:
            limitations.append(
                f"Investigation scope explicitly bounded to {len(target_hosts)} target host(s)."
            )

        missing_cat_count = sum(1 for h in participating_hosts if any(g.gap_type == "MISSING_HOST_CATALOG_ENTRY" for g in h.telemetry_gaps))
        if missing_cat_count > 0:
            limitations.append(
                f"Telemetry includes {missing_cat_count} participating host(s) lacking authoritative registration in logintel.db:hosts catalog."
            )

        absent_telemetry_count = sum(1 for h in participating_hosts if h.epistemic_status == HostEpistemicStatus.UNKNOWN)
        if absent_telemetry_count > 0:
            limitations.append(
                f"Case includes {absent_telemetry_count} scoped host(s) with zero observed telemetry events or alerts."
            )

        scoped_count = sum(1 for h in participating_hosts if h.is_in_target_scope)
        total_hops = sum(tr.hop_count for tr in lateral_traces)

        # 9. Compute Provenance Fingerprint
        prov_payload = {
            "case_id": case_id,
            "incident_id": case.incident_id,
            "scope_target_hosts": sorted(target_hosts),
            "participating_hosts": [h.host_id for h in participating_hosts],
            "lateral_traces": [t.trace_id for t in lateral_traces],
            "entity_continuities": [c.continuity_id for c in entity_continuity],
            "total_hosts_count": len(participating_hosts),
            "cross_host_hops_count": total_hops,
        }
        prov_hash = self._compute_hash(prov_payload)

        return CaseMultiHostDossier(
            case_id=case_id,
            incident_id=case.incident_id,
            scope_target_hosts=target_hosts,
            is_scope_unspecified=is_scope_unspecified,
            participating_hosts=participating_hosts,
            lateral_traces=lateral_traces,
            entity_continuity=entity_continuity,
            total_hosts_count=len(participating_hosts),
            scoped_hosts_count=scoped_count,
            cross_host_hops_count=total_hops,
            overall_visibility_gaps=overall_gaps,
            completeness_limitations=limitations,
            generated_at=now_iso,
            provenance_hash=prov_hash,
        )

    def get_host_timeline(
        self,
        case_id: int,
        host_id: str,
        limit: int = 100,
        offset: int = 0,
        time_start: Optional[str] = None,
        time_end: Optional[str] = None,
    ) -> HostTimelineResponse:
        """Retrieve host-scoped unified timeline projection within authorized case bounds."""
        case = self.case_repo.get_case(case_id, resolve_evidence=True)
        if not case:
            raise ValueError(f"Investigation case {case_id} not found")

        host_norm = self._normalize_host_str(host_id)
        if not host_norm:
            raise ValueError("Host identifier cannot be empty")

        # Authorize host against case scope and evidence
        dossier = self.get_case_dossier(case_id)
        matched_host: Optional[CaseHostSummary] = None
        for h in dossier.participating_hosts:
            if h.host_id.lower() == host_norm.lower() or h.hostname.lower() == host_norm.lower():
                matched_host = h
                break

        if not matched_host:
            raise ValueError(
                f"Host '{host_id}' not found or not associated with Case {case_id}"
            )

        # Query unified timeline service with host filter
        params = TimelineFilterParams(
            host=matched_host.host_id,
            limit=limit,
            offset=offset,
            time_start=time_start,
            time_end=time_end,
        )
        t_res = self.timeline_svc.query_timeline(case_id, params)

        return HostTimelineResponse(
            case_id=case_id,
            host_id=matched_host.host_id,
            hostname=matched_host.hostname,
            items=t_res.items,
            total=t_res.total,
            limit=t_res.limit,
            offset=t_res.offset,
            first_seen=matched_host.first_seen,
            last_seen=matched_host.last_seen,
            epistemic_breakdown=t_res.epistemic_breakdown,
            layer_breakdown=t_res.layer_breakdown,
        )

    def get_lateral_traces(self, case_id: int) -> List[MultiHostTrace]:
        """Retrieve reconstructed lateral movement traces for a case."""
        dossier = self.get_case_dossier(case_id)
        return dossier.lateral_traces

    def get_continuity(self, case_id: int) -> List[EntityContinuity]:
        """Retrieve cross-host entity continuity records for a case (M7.12.3)."""
        dossier = self.get_case_dossier(case_id)
        return dossier.entity_continuity

    def get_comparative_timeline(
        self,
        case_id: int,
        host_ids: List[str],
        time_start: Optional[str] = None,
        time_end: Optional[str] = None,
        limit_per_lane: int = 50,
    ) -> ComparativeTimelineResponse:
        """Assemble synchronized parallel timeline lanes across multiple participating hosts (M7.12.4)."""
        case = self.case_repo.get_case(case_id, resolve_evidence=False)
        if not case:
            raise ValueError(f"Investigation case {case_id} not found")

        # Normalize and deduplicate requested host IDs
        clean_hosts: List[str] = []
        seen = set()
        for h in host_ids:
            norm = self._normalize_host_str(h)
            if norm and norm.lower() not in seen:
                seen.add(norm.lower())
                clean_hosts.append(norm)

        if not clean_hosts:
            return ComparativeTimelineResponse(
                case_id=case_id,
                time_start=time_start,
                time_end=time_end,
                lanes=[],
                total_events=0,
            )

        lanes: List[HostTimelineLane] = []
        all_timestamps: List[str] = []
        total_events = 0

        for hid in clean_hosts:
            try:
                tl = self.get_host_timeline(
                    case_id=case_id,
                    host_id=hid,
                    limit=limit_per_lane,
                    offset=0,
                    time_start=time_start,
                    time_end=time_end,
                )
                lane = HostTimelineLane(
                    host_id=tl.host_id,
                    hostname=tl.hostname,
                    items=tl.items,
                    total=tl.total,
                    first_seen=tl.first_seen,
                    last_seen=tl.last_seen,
                )
                lanes.append(lane)
                total_events += tl.total
                for it in tl.items:
                    if it.timestamp:
                        all_timestamps.append(it.timestamp)
            except ValueError:
                # Host not associated with case or unobserved
                continue

        # Sort lanes deterministically by host_id
        lanes.sort(key=lambda l: l.host_id.lower())

        min_time = min(all_timestamps) if all_timestamps else time_start
        max_time = max(all_timestamps) if all_timestamps else time_end

        return ComparativeTimelineResponse(
            case_id=case_id,
            time_start=time_start,
            time_end=time_end,
            lanes=lanes,
            total_events=total_events,
            aligned_min_time=min_time,
            aligned_max_time=max_time,
        )

    def export_dossier(self, case_id: int, format: str = "json") -> MultiHostExportResponse:
        """Export case multi-host dossier as structured JSON or forensic Markdown (M7.12.5)."""
        dossier = self.get_case_dossier(case_id)
        fmt = format.lower().strip()
        if fmt not in ("json", "markdown"):
            raise ValueError(f"Unsupported export format '{format}'. Supported formats: 'json', 'markdown'.")

        if fmt == "json":
            content = dossier.model_dump_json(indent=2)
            filename = f"case_{case_id}_multihost_dossier.json"
        else:
            # Generate structured markdown report
            lines: List[str] = [
                f"# Multi-Host Investigation Report — Case #{case_id}",
                "",
                f"**Generated:** {dossier.generated_at}  ",
                f"**Provenance Fingerprint:** `{dossier.provenance_hash}`  ",
                f"**Scope Mode:** {'Dynamic (All Evidence Hosts)' if dossier.is_scope_unspecified else f'Explicit Target Scope ({dossier.scoped_hosts_count} hosts)'}  ",
                "",
                "## 1. Executive Summary",
                "",
                f"- **Total Participating Hosts:** {dossier.total_hosts_count}",
                f"- **Reconstructed Lateral Hops:** {dossier.cross_host_hops_count}",
                f"- **Cross-Host Correlated Entities:** {len(dossier.entity_continuity)}",
                f"- **Identified Visibility Gaps:** {len(dossier.overall_visibility_gaps)}",
                "",
                "## 2. Participating Host Catalog & Epistemic Status",
                "",
                "| Host ID | Hostname | OS | Status | Events | Alerts | Inbound Hops | Outbound Hops | Gaps |",
                "|---|---|---|---|---|---|---|---|---|",
            ]
            def _escape_md_cell(val: Any) -> str:
                if val is None:
                    return ""
                s = getattr(val, "value", str(val))
                return str(s).replace("|", "\\|").replace("\r\n", " ").replace("\n", " ").strip()

            for h in dossier.participating_hosts:
                os_str = f"{h.os_name or ''} {h.os_version or ''}".strip() or "Unknown"
                gaps_str = f"{len(h.telemetry_gaps)} gaps" if h.telemetry_gaps else "None"
                status_str = getattr(h.epistemic_status, "value", str(h.epistemic_status))
                lines.append(
                    f"| `{_escape_md_cell(h.host_id)}` | {_escape_md_cell(h.hostname)} | {_escape_md_cell(os_str)} | **{_escape_md_cell(status_str)}** | {h.event_count} | {h.alert_count} | {h.inbound_lateral_hops} | {h.outbound_lateral_hops} | {_escape_md_cell(gaps_str)} |"
                )

            lines.extend([
                "",
                "## 3. Reconstructed Lateral Movement Traces",
                "",
            ])
            if not dossier.lateral_traces:
                lines.append("*No cross-host lateral movement traces identified from evidence.*")
            else:
                lines.append("| Trace ID | Source Host | Target Host | Actor | Hop Count | Status | Time Window |")
                lines.append("|---|---|---|---|---|---|---|")
                for t in dossier.lateral_traces:
                    status_str = getattr(t.epistemic_status, "value", str(t.epistemic_status))
                    lines.append(
                        f"| `{_escape_md_cell(t.trace_id)}` | `{_escape_md_cell(t.source_host)}` | `{_escape_md_cell(t.target_host)}` | `{_escape_md_cell(t.actor)}` | {t.hop_count} | {_escape_md_cell(status_str)} | {_escape_md_cell(t.start_time)} → {_escape_md_cell(t.end_time)} |"
                    )

            lines.extend([
                "",
                "## 4. Cross-Host Entity Continuity",
                "",
            ])
            if not dossier.entity_continuity:
                lines.append("*No cross-host entity continuities identified.*")
            else:
                lines.append("| Continuity ID | Type | Entity Key | Occurrences | Participating Hosts | Description |")
                lines.append("|---|---|---|---|---|---|")
                for c in dossier.entity_continuity:
                    hosts_str = ", ".join(f"`{_escape_md_cell(h)}`" for h in c.participating_hosts)
                    c_type_str = getattr(c.continuity_type, "value", str(c.continuity_type))
                    lines.append(
                        f"| `{_escape_md_cell(c.continuity_id)}` | {_escape_md_cell(c_type_str)} | `{_escape_md_cell(c.entity_key)}` | {c.occurrences_count} | {hosts_str} | {_escape_md_cell(c.description)} |"
                    )

            lines.extend([
                "",
                "## 5. Visibility Boundaries & Completeness Limitations",
                "",
            ])
            for lim in dossier.completeness_limitations:
                lines.append(f"- {lim}")

            if dossier.overall_visibility_gaps:
                lines.extend([
                    "",
                    "### Telemetry Collection Gaps",
                    "",
                ])
                for g in dossier.overall_visibility_gaps:
                    remedy = f" (Remedy: {g.remedy_suggestion})" if g.remedy_suggestion else ""
                    lines.append(f"- **[{g.gap_type}]** Host `{g.host_identifier}`: {g.description}{remedy}")

            lines.extend([
                "",
                "---",
                f"*Report compiled deterministically by LogIntel Multi-Host Investigation Engine (M7.12).* Root Digest: `{dossier.provenance_hash}`",
                "",
            ])
            content = "\n".join(lines)
            filename = f"case_{case_id}_multihost_report.md"

        return MultiHostExportResponse(
            case_id=case_id,
            format=fmt,
            filename=filename,
            content=content,
            root_digest=dossier.provenance_hash,
        )


multihost_service = MultiHostInvestigationService()

