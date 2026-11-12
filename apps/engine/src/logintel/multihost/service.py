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
from logintel.storage.scope_utils import (
    HostCatalogIndex,
    intersect_time_bounds,
    is_interval_overlapping_bounds,
    is_timestamp_in_bounds,
    normalize_host_identifier,
    normalize_iso_utc,
    parse_iso_datetime,
)
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

        target_hosts_norm: Set[str] = set()
        if not is_scope_unspecified:
            for th in target_hosts:
                th_norm = self._normalize_host_str(th)
                if th_norm:
                    th_low = th_norm.lower()
                    target_hosts_norm.add(th_low)
                    cat = catalog_by_id.get(th_low) or catalog_by_hostname.get(th_low)
                    if cat:
                        target_hosts_norm.add(cat["id"].lower())
                        target_hosts_norm.add(cat["hostname"].lower())

        host_catalog = HostCatalogIndex.from_db(self.forensic_db)
        target_hosts_expanded = host_catalog.expand_scope_targets(target_hosts)

        def _is_host_in_scope(raw_host: Optional[str]) -> bool:
            if not raw_host:
                return False
            if is_scope_unspecified:
                return True
            return host_catalog.matches_scope(
                raw_host,
                target_hosts,
                expanded_targets=target_hosts_expanded,
            )

        scope_time_start: Optional[str] = getattr(case.scope, "time_start", None)
        scope_time_end: Optional[str] = getattr(case.scope, "time_end", None)
        scope_start_dt, scope_end_dt, scope_is_empty = intersect_time_bounds(
            scope_time_start,
            scope_time_end,
            None,
            None,
        )

        def _is_in_scope_time(ts: Optional[str]) -> bool:
            if scope_is_empty:
                return False
            return is_timestamp_in_bounds(ts, scope_start_dt, scope_end_dt)

        def _alert_overlaps_scope(first_seen: Optional[str], last_seen: Optional[str]) -> bool:
            if scope_is_empty:
                return False
            return is_interval_overlapping_bounds(
                first_seen,
                last_seen,
                scope_start_dt,
                scope_end_dt,
            )

        def update_timestamps(key: str, ts: Optional[str], clamp: bool = False) -> None:
            dt = parse_iso_datetime(ts)
            if dt is None or scope_is_empty:
                return
            if clamp:
                if scope_start_dt is not None and dt < scope_start_dt:
                    dt = scope_start_dt
                if scope_end_dt is not None and dt > scope_end_dt:
                    dt = scope_end_dt
            else:
                if not is_timestamp_in_bounds(ts, scope_start_dt, scope_end_dt):
                    return

            canonical_iso = dt.isoformat()
            cur_first_dt = parse_iso_datetime(host_first_seen.get(key))
            if cur_first_dt is None or dt < cur_first_dt:
                host_first_seen[key] = canonical_iso
            cur_last_dt = parse_iso_datetime(host_last_seen.get(key))
            if cur_last_dt is None or dt > cur_last_dt:
                host_last_seen[key] = canonical_iso

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
            if not isinstance(rec, dict):
                rec = {}
            if not rec and ref.analyst_annotation:
                try:
                    parsed = json.loads(ref.analyst_annotation) if isinstance(ref.analyst_annotation, str) else ref.analyst_annotation
                    if isinstance(parsed, dict):
                        rec = parsed
                except Exception:
                    pass
            ref_host = rec.get("host") or rec.get("hostname")
            if ref_host and _is_host_in_scope(ref_host):
                key = register_host(ref_host)
                host_evidence_tags.setdefault(key, set()).add(ref.citation_tag or f"[{ref.source_type}:{ref.source_id}]")
                
                # Enforce temporal scope boundaries for evidence references
                if ref.source_type == "alert":
                    a_first = rec.get("first_seen") or rec.get("timestamp") or rec.get("created_at") or ref.created_at
                    a_last = rec.get("last_seen") or a_first
                    if not _alert_overlaps_scope(a_first, a_last):
                        continue
                    update_timestamps(key, a_first, clamp=True)
                    update_timestamps(key, a_last, clamp=True)
                    alert_id = str(rec.get("id") or ref.source_id)
                    counted_alerts = counted_alert_ids.setdefault(key, set())
                    if alert_id not in counted_alerts:
                        counted_alerts.add(alert_id)
                        host_alert_counts[key] = host_alert_counts.get(key, 0) + 1
                else:
                    ts = rec.get("timestamp") or rec.get("first_seen") or rec.get("created_at") or ref.created_at
                    if not _is_in_scope_time(ts):
                        continue
                    update_timestamps(key, ts, clamp=False)
                    if ref.source_type == "event":
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
                        if a_host and _is_host_in_scope(a_host):
                            key = register_host(a_host)
                            a_first = row["first_seen"]
                            a_last = row["last_seen"]
                            if not _alert_overlaps_scope(a_first, a_last):
                                continue
                            alert_id = str(row["id"])
                            counted_alerts = counted_alert_ids.setdefault(key, set())
                            if alert_id not in counted_alerts:
                                counted_alerts.add(alert_id)
                                host_alert_counts[key] = host_alert_counts.get(key, 0) + 1
                            update_timestamps(key, a_first, clamp=True)
                            update_timestamps(key, a_last, clamp=True)
                            host_evidence_tags.setdefault(key, set()).add(f"[alert:{row['id']}]")
            except Exception as e:
                logger.warning("Error reading incident alerts for case %d: %s", case_id, e)

        # 4. Read canonical telemetry events linked to incident or participating hosts from logintel.db
        all_canonical_keys = sorted(list(set(host_ident_map.values())), key=lambda k: k.lower())
        if self.forensic_db and all_canonical_keys and not scope_is_empty:
            try:
                with self.forensic_db.connection() as conn:
                    cur = conn.cursor()
                    for ckey in all_canonical_keys:
                        display_name = host_raw_labels.get(ckey, ckey)
                        if not _is_host_in_scope(ckey) and not _is_host_in_scope(display_name):
                            continue

                        host_aliases = sorted(
                            host_catalog.resolve_aliases(ckey)
                            | host_catalog.resolve_aliases(display_name)
                            | {k for k in (ckey.strip().lower(), display_name.strip().lower()) if k}
                        )
                        if not host_aliases:
                            continue

                        alias_ph = ",".join("?" for _ in host_aliases)
                        where_clauses = [f"LOWER(host) IN ({alias_ph})"]
                        where_params: List[Any] = list(host_aliases)
                        if scope_start_dt is not None:
                            where_clauses.append("unixepoch(timestamp, 'subsec') >= ?")
                            where_params.append(scope_start_dt.timestamp())
                        if scope_end_dt is not None:
                            where_clauses.append("unixepoch(timestamp, 'subsec') <= ?")
                            where_params.append(scope_end_dt.timestamp())
                        where_sql = " AND ".join(where_clauses)

                        # Authoritative, complete event count without non-deterministic or 500-ID limits
                        counted_events = counted_event_ids.setdefault(ckey, set())
                        cur.execute(
                            f"SELECT COUNT(*) as cnt FROM events WHERE {where_sql}",
                            tuple(where_params),
                        )
                        c_row = cur.fetchone()
                        total_matching = int(c_row["cnt"] or 0) if c_row else 0

                        overlap_cnt = 0
                        if counted_events and total_matching > 0:
                            sorted_ev_ids = sorted(counted_events)
                            for idx in range(0, len(sorted_ev_ids), 500):
                                chunk = sorted_ev_ids[idx : idx + 500]
                                id_ph = ",".join("?" for _ in chunk)
                                cur.execute(
                                    f"SELECT COUNT(*) as cnt FROM events WHERE {where_sql} AND id IN ({id_ph})",
                                    tuple(where_params + chunk),
                                )
                                ov_row = cur.fetchone()
                                if ov_row:
                                    overlap_cnt += int(ov_row["cnt"] or 0)

                        db_cnt = max(0, total_matching - overlap_cnt)
                        host_event_counts[ckey] = host_event_counts.get(ckey, 0) + db_cnt

                        if total_matching > 0:
                            cur.execute(
                                f"""
                                SELECT timestamp FROM events
                                WHERE {where_sql} AND unixepoch(timestamp, 'subsec') IS NOT NULL
                                ORDER BY unixepoch(timestamp, 'subsec') ASC, id ASC
                                LIMIT 1
                                """,
                                tuple(where_params),
                            )
                            min_row = cur.fetchone()
                            if min_row and min_row["timestamp"]:
                                update_timestamps(ckey, min_row["timestamp"])

                            cur.execute(
                                f"""
                                SELECT timestamp FROM events
                                WHERE {where_sql} AND unixepoch(timestamp, 'subsec') IS NOT NULL
                                ORDER BY unixepoch(timestamp, 'subsec') DESC, id DESC
                                LIMIT 1
                                """,
                                tuple(where_params),
                            )
                            max_row = cur.fetchone()
                            if max_row and max_row["timestamp"]:
                                update_timestamps(ckey, max_row["timestamp"])
            except Exception as e:
                logger.warning("Error reading canonical events for case %d: %s", case_id, e)

        # 5. Build lateral movement traces and entity continuities using TemporalReconstructionEngine
        evidence_items = self.engine._harvest_case_evidence(case)
        if not evidence_items:
            for ref in case.evidence_references:
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
                if rec and (rec.get("host") or rec.get("hostname")):
                    item = dict(rec)
                    item["_citation_tag"] = ref.citation_tag
                    item["_source_type"] = ref.source_type
                    item["_source_id"] = str(ref.source_id)
                    item["_ref_id"] = ref.reference_id
                    item["_hash"] = self._compute_hash(rec)
                    ref_ep = self.engine._coerce_epistemic_status(getattr(ref, "epistemic_status", None))
                    item["_epistemic_status"] = ref_ep.value
                    item["epistemic_status"] = ref_ep.value
                    item["_is_authoritative"] = (ref_ep.value == "OBSERVED") and (rec.get("is_authoritative") is not False)
                    ts = rec.get("timestamp") or rec.get("first_seen") or rec.get("created_at") or ref.created_at
                    item["timestamp"] = str(ts) if ts else None
                    if "host" not in item and "hostname" in item:
                        item["host"] = item["hostname"]
                    evidence_items.append(item)
            evidence_items.sort(
                key=lambda it: (
                    parse_iso_datetime(it.get("timestamp")) or datetime.max.replace(tzinfo=timezone.utc),
                    str(it.get("_source_id", "")),
                )
            )

        # Enforce case temporal & target-host scope on harvested evidence items before trace/continuity synthesis
        if not is_scope_unspecified or scope_time_start or scope_time_end or scope_is_empty:
            evidence_items = [
                it for it in evidence_items
                if _is_in_scope_time(it.get("timestamp"))
                and (not (it.get("host") or it.get("hostname")) or _is_host_in_scope(it.get("host") or it.get("hostname")))
            ]

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

        for ckey in distinct_keys:
            display_name = host_raw_labels.get(ckey, ckey)
            if not is_scope_unspecified:
                if not (_is_host_in_scope(ckey) or _is_host_in_scope(display_name)):
                    continue
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

        if scope_is_empty and (scope_time_start or scope_time_end):
            limitations.append(
                "Case scope time bounds are malformed or inverted (time_start > time_end); failing closed with zero matching records."
            )

        scoped_count = sum(1 for h in participating_hosts if h.is_in_target_scope)
        total_hops = sum(tr.hop_count for tr in lateral_traces)

        # 9. Compute deterministic content provenance digest (excluding volatile generated_at)
        prov_payload = {
            "case_id": case_id,
            "incident_id": case.incident_id,
            "is_scope_unspecified": is_scope_unspecified,
            "scope_target_hosts": sorted(target_hosts),
            "scope_time_start": scope_time_start,
            "scope_time_end": scope_time_end,
            "participating_hosts": [
                {
                    "host_id": h.host_id,
                    "hostname": h.hostname,
                    "os_name": h.os_name,
                    "os_version": h.os_version,
                    "is_in_target_scope": h.is_in_target_scope,
                    "first_seen": h.first_seen,
                    "last_seen": h.last_seen,
                    "event_count": h.event_count,
                    "alert_count": h.alert_count,
                    "inbound_lateral_hops": h.inbound_lateral_hops,
                    "outbound_lateral_hops": h.outbound_lateral_hops,
                    "evidence_references": h.evidence_references,
                    "epistemic_status": h.epistemic_status.value,
                    "gaps": [(g.gap_type, g.description) for g in h.telemetry_gaps],
                    "discrepancies": [(d.field, d.catalog_value, d.telemetry_value) for d in h.discrepancies],
                }
                for h in participating_hosts
            ],
            "lateral_traces": [
                {
                    "trace_id": t.trace_id,
                    "source_host": t.source_host,
                    "target_host": t.target_host,
                    "actor": t.actor,
                    "hop_count": t.hop_count,
                    "start_time": t.start_time,
                    "end_time": t.end_time,
                    "epistemic_status": t.epistemic_status.value,
                }
                for t in lateral_traces
            ],
            "entity_continuities": [
                {
                    "continuity_id": c.continuity_id,
                    "type": c.continuity_type.value,
                    "entity_key": c.entity_key,
                    "occurrences": c.occurrences_count,
                    "hosts": c.participating_hosts,
                }
                for c in entity_continuity
            ],
            "overall_visibility_gaps": [(g.gap_type, g.host_identifier, g.description) for g in overall_gaps],
            "completeness_limitations": limitations,
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
        dossier: Optional[CaseMultiHostDossier] = None,
    ) -> HostTimelineResponse:
        """Retrieve host-scoped unified timeline projection within authorized case bounds."""
        case = self.case_repo.get_case(case_id, resolve_evidence=True)
        if not case:
            raise ValueError(f"Investigation case {case_id} not found")

        host_norm = normalize_host_identifier(host_id)
        if not host_norm:
            raise ValueError("Host identifier cannot be empty")

        # Authorize host against case scope, catalog aliases, and evidence
        if dossier is None:
            dossier = self.get_case_dossier(case_id)
        host_catalog = HostCatalogIndex.from_db(self.forensic_db)
        req_aliases = host_catalog.resolve_aliases(host_id)

        matched_host: Optional[CaseHostSummary] = None
        for h in dossier.participating_hosts:
            h_aliases = host_catalog.resolve_aliases(h.host_id) | host_catalog.resolve_aliases(h.hostname)
            if req_aliases & h_aliases:
                matched_host = h
                break

        target_hosts = getattr(case.scope, "target_hosts", []) or []
        if not matched_host or (target_hosts and not matched_host.is_in_target_scope):
            raise ValueError(
                f"Host '{host_id}' not found or not associated with Case {case_id}"
            )

        # Enforce timezone-normalized intersection of case temporal bounds and query parameters
        scope_time_start: Optional[str] = getattr(case.scope, "time_start", None)
        scope_time_end: Optional[str] = getattr(case.scope, "time_end", None)
        eff_start_dt, eff_end_dt, is_empty_window = intersect_time_bounds(
            scope_time_start,
            scope_time_end,
            time_start,
            time_end,
        )
        if is_empty_window:
            return HostTimelineResponse(
                case_id=case_id,
                host_id=matched_host.host_id,
                hostname=matched_host.hostname,
                items=[],
                total=0,
                limit=limit,
                offset=offset,
                first_seen=matched_host.first_seen,
                last_seen=matched_host.last_seen,
                epistemic_breakdown={},
                layer_breakdown={},
                is_truncated=False,
            )

        eff_time_start = eff_start_dt.isoformat().replace("+00:00", "Z") if eff_start_dt else None
        eff_time_end = eff_end_dt.isoformat().replace("+00:00", "Z") if eff_end_dt else None

        # Query unified timeline service with host filter
        params = TimelineFilterParams(
            host=matched_host.host_id,
            limit=limit,
            offset=offset,
            time_start=eff_time_start,
            time_end=eff_time_end,
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
            is_truncated=getattr(t_res, "is_truncated", False),
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

        # Pre-compute or reuse the shared dossier once for all lanes
        shared_dossier = self.get_case_dossier(case_id)

        for hid in clean_hosts:
            try:
                tl = self.get_host_timeline(
                    case_id=case_id,
                    host_id=hid,
                    limit=limit_per_lane,
                    offset=0,
                    time_start=time_start,
                    time_end=time_end,
                    dossier=shared_dossier,
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
            def _normalize_md_text(val: Any) -> str:
                if val is None:
                    return ""
                s = getattr(val, "value", str(val))
                # Normalize CR/LF, standalone CR, and control characters to space
                s = re.sub(r"[\r\n\x00-\x08\x0b\x0c\x0e-\x1f]", " ", str(s))
                return re.sub(r"\s+", " ", s).strip()

            def _escape_md_cell(val: Any, max_len: Optional[int] = None) -> str:
                if val is None:
                    return ""
                s = _normalize_md_text(val)
                if max_len and len(s) > max_len:
                    s = s[:max_len] + "..."
                return s.replace("|", "\\|")

            def _escape_code_span(val: Any) -> str:
                if val is None:
                    return ""
                s = _normalize_md_text(val)
                # Replace backticks to prevent premature termination of code spans
                clean = s.replace("`", "'")
                return f"`{_escape_md_cell(clean)}`"

            for h in dossier.participating_hosts:
                os_str = f"{h.os_name or ''} {h.os_version or ''}".strip() or "Unknown"
                gaps_str = f"{len(h.telemetry_gaps)} gaps" if h.telemetry_gaps else "None"
                status_str = getattr(h.epistemic_status, "value", str(h.epistemic_status))
                lines.append(
                    f"| {_escape_code_span(h.host_id)} | {_escape_md_cell(h.hostname)} | {_escape_md_cell(os_str)} | **{_escape_md_cell(status_str)}** | {h.event_count} | {h.alert_count} | {h.inbound_lateral_hops} | {h.outbound_lateral_hops} | {_escape_md_cell(gaps_str)} |"
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
                        f"| {_escape_code_span(t.trace_id)} | {_escape_code_span(t.source_host)} | {_escape_code_span(t.target_host)} | {_escape_code_span(t.actor)} | {t.hop_count} | {_escape_md_cell(status_str)} | {_escape_md_cell(t.start_time)} → {_escape_md_cell(t.end_time)} |"
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
                    hosts_str = ", ".join(_escape_code_span(h) for h in c.participating_hosts)
                    c_type_str = getattr(c.continuity_type, "value", str(c.continuity_type))
                    lines.append(
                        f"| {_escape_code_span(c.continuity_id)} | {_escape_md_cell(c_type_str)} | {_escape_code_span(c.entity_key)} | {c.occurrences_count} | {hosts_str} | {_escape_md_cell(c.description)} |"
                    )

            lines.extend([
                "",
                "## 5. Visibility Boundaries & Completeness Limitations",
                "",
            ])
            for lim in dossier.completeness_limitations:
                lines.append(f"- {_normalize_md_text(lim)}")

            if dossier.overall_visibility_gaps:
                lines.extend([
                    "",
                    "### Telemetry Collection Gaps",
                    "",
                ])
                for g in dossier.overall_visibility_gaps:
                    remedy = f" (Remedy: {_normalize_md_text(g.remedy_suggestion)})" if g.remedy_suggestion else ""
                    lines.append(f"- **[{_normalize_md_text(g.gap_type)}]** Host {_escape_code_span(g.host_identifier)}: {_normalize_md_text(g.description)}{remedy}")

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

