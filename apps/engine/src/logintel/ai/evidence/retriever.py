"""Deterministic Evidence Retrieval and Synthesis for LogIntel Milestone 5.3.

Coordinates multi-dimensional forensic evidence retrieval across all 7 entity types,
temporal windows, attack paths, MITRE mappings, conflict detection, and visibility gap auditing.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from logintel.ai.domain.bundle import (
    EvidenceConflict,
    EvidenceCoverage,
    EvidenceGap,
    EvidenceItem,
    EvidenceRole,
    InvestigationEvidenceBundle,
)
from logintel.ai.domain.citation import CitationManifest
from logintel.ai.domain.evidence import EvidenceType
from logintel.ai.domain.intelligence import InvestigationIntent
from logintel.logging import get_logger
from logintel.storage.db import Database, db as default_db
from logintel.storage.investigation_repo import InvestigationRepository, investigation_repo as default_inv_repo

logger = get_logger("ai.evidence.retriever")

SUPPORTED_ENTITY_TYPES = {"HOST", "USER", "IP", "PROCESS", "COMMAND", "FILE", "SESSION"}


class EvidenceRetriever:
    """Deterministic evidence retrieval and synthesis engine."""

    def __init__(
        self,
        database: Optional[Database] = None,
        inv_repo: Optional[InvestigationRepository] = None,
    ) -> None:
        self.database = database or default_db
        if inv_repo is not None:
            self.inv_repo = inv_repo
        elif database is not None:
            from logintel.storage.incidents_repo import IncidentsRepository
            inc_repo = IncidentsRepository(database)
            self.inv_repo = InvestigationRepository(database, incidents_repository=inc_repo)
        else:
            self.inv_repo = default_inv_repo

    def retrieve_bundle(
        self,
        incident_id: int,
        target_entity: Optional[str] = None,
        intent: Optional[InvestigationIntent] = None,
        time_window_minutes: int = 60,
        max_items: int = 50,
    ) -> InvestigationEvidenceBundle:
        """Retrieve, score, deduplicate, and synthesize a deterministic evidence bundle."""
        now_iso = datetime.now(timezone.utc).isoformat()
        manifest = CitationManifest()
        items: List[EvidenceItem] = []
        conflicts: List[EvidenceConflict] = []
        gaps: List[EvidenceGap] = []
        seen_evidence_ids: Set[Tuple[str, str]] = set()  # (type, id)

        # 1. Fetch Authoritative Incident Dossier
        dossier = self.inv_repo.get_investigation_dossier(incident_id)
        if not dossier:
            # Empty / non-existent bundle
            coverage = EvidenceCoverage(
                required_evidence_types=sorted([t.value for t in EvidenceType]),
                available_evidence_types=[],
                missing_evidence_types=sorted([t.value for t in EvidenceType]),
                selected_count=0,
                omitted_count=0,
                truncation_reasons=["Incident not found"],
            )
            return InvestigationEvidenceBundle(
                investigation_id=incident_id,
                generated_at=now_iso,
                items=[],
                conflicts=[],
                gaps=[],
                coverage=coverage,
                citation_manifest=manifest,
            )

        def _g(obj: Any, key: str, default: Any = None) -> Any:
            if isinstance(obj, dict):
                return obj.get(key, default)
            return getattr(obj, key, default)

        inc_summary = _g(dossier, "incident", {})
        first_seen = _g(inc_summary, "first_seen", now_iso)
        inc_key = _g(inc_summary, "incident_key", str(incident_id))
        inc_title = _g(inc_summary, "title", f"Incident {incident_id}")
        inc_sev = _g(inc_summary, "severity", "UNKNOWN")
        inc_status = _g(inc_summary, "status", "OPEN")
        inc_host = _g(inc_summary, "primary_host", "")

        # Register incident root item
        inc_tag = f"[incident:{incident_id}]"
        manifest.add(EvidenceType.INCIDENT, str(incident_id), display_label=f"Incident {inc_key}")
        items.append(
            EvidenceItem(
                evidence_id=str(incident_id),
                evidence_type=EvidenceType.INCIDENT,
                source_id=str(incident_id),
                source_table="incidents",
                timestamp=first_seen,
                relevance_score=1.0,
                role=EvidenceRole.PRIMARY,
                citation_tag=inc_tag,
                summary=f"{inc_title} ({inc_sev})",
                metadata={"status": inc_status, "host": inc_host},
            )
        )
        seen_evidence_ids.add(("incident", str(incident_id)))

        # 2. Correlated Operational Alerts & Primary Detection Evidence
        alerts_list = _g(dossier, "alerts", []) or []
        for alt in alerts_list:
            alt_id_str = str(_g(alt, "id"))
            alt_tag = f"[alert:{alt_id_str}]"
            alt_title = _g(alt, "title", f"Alert {alt_id_str}")
            alt_sev = _g(alt, "severity", "UNKNOWN")
            alt_ts = _g(alt, "first_seen", first_seen)
            alt_rule = _g(alt, "rule_id", "")
            alt_host = _g(alt, "host", "")
            manifest.add(EvidenceType.ALERT, alt_id_str, display_label=alt_title)
            items.append(
                EvidenceItem(
                    evidence_id=alt_id_str,
                    evidence_type=EvidenceType.ALERT,
                    source_id=alt_id_str,
                    source_table="alerts",
                    timestamp=alt_ts,
                    relevance_score=0.95,
                    role=EvidenceRole.PRIMARY,
                    citation_tag=alt_tag,
                    summary=f"Alert {alt_title} ({alt_sev})",
                    metadata={"rule_id": alt_rule, "host": alt_host},
                )
            )
            seen_evidence_ids.add(("alert", alt_id_str))

        # 3. Direct Supporting Events (Primary / Secondary roles)
        with self.database.connection() as conn:
            # Query detection evidence events
            det_rows = conn.execute(
                """
                SELECT de.detection_id, de.event_id, de.role, d.rule_id, d.summary as det_summary,
                       e.timestamp, e.source, e.event_type, e.severity, e.action, e.outcome,
                       e.summary as ev_summary, e.raw_message, e.host
                FROM detection_evidence de
                JOIN detections d ON d.id = de.detection_id
                JOIN alerts a ON a.id = d.alert_id
                JOIN incident_alerts ia ON ia.alert_id = a.id
                JOIN events e ON e.id = de.event_id
                WHERE ia.incident_id = ?
                ORDER BY e.timestamp ASC, e.id ASC
                """,
                (incident_id,),
            ).fetchall()

            for row in det_rows:
                ev_id = str(row["event_id"])
                if ("event", ev_id) in seen_evidence_ids:
                    continue
                seen_evidence_ids.add(("event", ev_id))

                ev_tag = f"[event:{ev_id}]"
                manifest.add(EvidenceType.EVENT, ev_id, display_label=f"Event {ev_id}")
                role = EvidenceRole.PRIMARY if row["role"] == "primary" else EvidenceRole.SUPPORTING
                items.append(
                    EvidenceItem(
                        evidence_id=ev_id,
                        evidence_type=EvidenceType.EVENT,
                        source_id=ev_id,
                        source_table="events",
                        timestamp=row["timestamp"],
                        relevance_score=0.90 if role == EvidenceRole.PRIMARY else 0.85,
                        role=role,
                        citation_tag=ev_tag,
                        summary=row["ev_summary"] or row["raw_message"][:120],
                        metadata={
                            "action": row["action"],
                            "outcome": row["outcome"],
                            "source": row["source"],
                            "host": row["host"],
                            "detection_rule": row["rule_id"],
                        },
                    )
                )

        # 4. Entity Pivots & Relationships
        entities_list = _g(dossier, "entities", []) or []
        for ent in entities_list:
            ent_key = _g(ent, "entity_key")
            if not ent_key:
                continue
            if target_entity and target_entity.lower() not in ent_key.lower():
                # If specific entity was requested, deprioritize non-matching entities
                continue
            ent_tag = f"[entity:{ent_key}]"
            disp = _g(ent, "display_name") or ent_key
            ent_type = _g(ent, "entity_type", "UNKNOWN")
            manifest.add(EvidenceType.ENTITY, ent_key, display_label=disp)
            items.append(
                EvidenceItem(
                    evidence_id=ent_key,
                    evidence_type=EvidenceType.ENTITY,
                    source_id=ent_key,
                    source_table="incident_entities",
                    timestamp=first_seen,
                    relevance_score=0.80,
                    role=EvidenceRole.ENTITY_LINK,
                    citation_tag=ent_tag,
                    summary=f"Entity {ent_type}: {disp}",
                    metadata={"entity_type": ent_type},
                )
            )
            seen_evidence_ids.add(("entity", ent_key))

        relationships_list = _g(dossier, "relationships", []) or []
        for rel in relationships_list:
            rel_id_str = str(_g(rel, "id"))
            rel_tag = f"[relationship:{rel_id_str}]"
            src_key = _g(rel, "source_entity_key")
            tgt_key = _g(rel, "target_entity_key")
            rel_type = _g(rel, "relationship_type")
            conf = _g(rel, "confidence", "UNKNOWN")
            manifest.add(EvidenceType.RELATIONSHIP, rel_id_str, display_label=f"{src_key} -> {tgt_key}")
            items.append(
                EvidenceItem(
                    evidence_id=rel_id_str,
                    evidence_type=EvidenceType.RELATIONSHIP,
                    source_id=rel_id_str,
                    source_table="incident_relationships",
                    timestamp=first_seen,
                    relevance_score=0.75,
                    role=EvidenceRole.ENTITY_LINK,
                    citation_tag=rel_tag,
                    summary=f"{src_key} {rel_type} {tgt_key}",
                    metadata={"confidence": conf},
                )
            )
            seen_evidence_ids.add(("relationship", rel_id_str))

        # 5. Attack Path Progression Steps
        attack_path = _g(dossier, "attack_path", None)
        if attack_path:
            steps_list = _g(attack_path, "steps", []) or []
            for step in steps_list:
                step_id = str(_g(step, "step_number"))
                step_tag = f"[step:{step_id}]"
                step_title = _g(step, "title", f"Step {step_id}")
                step_nature = _g(step, "nature")
                step_nature_val = _g(step_nature, "value", str(step_nature))
                manifest.add(EvidenceType.TIMELINE_STEP, step_id, display_label=f"Step {step_id}: {step_title}")
                items.append(
                    EvidenceItem(
                        evidence_id=step_id,
                        evidence_type=EvidenceType.TIMELINE_STEP,
                        source_id=step_id,
                        source_table="attack_path",
                        timestamp=_g(step, "timestamp", first_seen),
                        relevance_score=0.88,
                        role=EvidenceRole.TEMPORAL,
                        citation_tag=step_tag,
                        summary=f"Step {step_id}: {step_title} ({step_nature_val})",
                        metadata={"technique_id": _g(step, "technique_id"), "nature": step_nature_val},
                    )
                )
                seen_evidence_ids.add(("step", step_id))

        # 6. MITRE ATT&CK Mappings
        mitre_list = _g(dossier, "mitre_mappings", []) or []
        for mit in mitre_list:
            mit_id = _g(mit, "technique_id")
            if not mit_id:
                continue
            mit_tag = f"[mitre:{mit_id}]"
            tech_name = _g(mit, "technique_name", "")
            tactic = _g(mit, "tactic", "")
            manifest.add(EvidenceType.MITRE_MAPPING, mit_id, display_label=f"MITRE {mit_id} {tech_name}")
            items.append(
                EvidenceItem(
                    evidence_id=mit_id,
                    evidence_type=EvidenceType.MITRE_MAPPING,
                    source_id=mit_id,
                    source_table="mitre_mappings",
                    timestamp=first_seen,
                    relevance_score=0.70,
                    role=EvidenceRole.SUPPORTING,
                    citation_tag=mit_tag,
                    summary=f"MITRE {mit_id}: {tech_name} ({tactic})",
                    metadata={"evidence_count": _g(mit, "evidence_count", 0)},
                )
            )
            seen_evidence_ids.add(("mitre", mit_id))

        # 7. Conflict Detection Analysis
        conflicts = self._detect_conflicts(items)

        # 8. Visibility Gap Auditing
        gaps = self._audit_visibility_gaps(items, dossier)

        # 8.5 Intent-aware relevance score adjustment
        if intent:
            adjusted_items = []
            for item in items:
                boost = 0.0
                if intent == InvestigationIntent.ENTITY_ANALYSIS and item.evidence_type in (EvidenceType.ENTITY, EvidenceType.RELATIONSHIP):
                    boost = 0.15
                elif intent == InvestigationIntent.TIMELINE and item.evidence_type in (EvidenceType.EVENT, EvidenceType.TIMELINE_STEP):
                    boost = 0.15
                elif intent in (InvestigationIntent.ALERT_EXPLANATION, InvestigationIntent.DETECTION_EXPLANATION) and item.evidence_type in (EvidenceType.ALERT, EvidenceType.EVENT):
                    boost = 0.15
                elif intent == InvestigationIntent.MITRE_EXPLANATION and item.evidence_type == EvidenceType.MITRE_MAPPING:
                    boost = 0.25
                elif intent == InvestigationIntent.ATTACK_PATH_EXPLANATION and item.evidence_type == EvidenceType.TIMELINE_STEP:
                    boost = 0.20
                if boost > 0.0:
                    adjusted_items.append(item.model_copy(update={"relevance_score": min(1.0, item.relevance_score + boost)}))
                else:
                    adjusted_items.append(item)
            items = adjusted_items

        # 9. Deterministic Ranking & Budget Limiting
        # Sort stably: relevance_score DESC, timestamp ASC, evidence_id ASC
        items.sort(key=lambda x: (-x.relevance_score, x.timestamp, x.evidence_id))

        total_extracted = len(items)
        truncation_reasons: List[str] = []
        if len(items) > max_items:
            omitted = len(items) - max_items
            truncation_reasons.append(f"Truncated {omitted} lower-relevance evidence items exceeding budget of {max_items}")
            items = items[:max_items]

        # 10. Compute Evidence Coverage Metadata
        available_types = sorted(list({i.evidence_type.value for i in items}))
        all_types = sorted([t.value for t in EvidenceType])
        missing_types = sorted([t for t in all_types if t not in available_types])

        coverage = EvidenceCoverage(
            required_evidence_types=all_types,
            available_evidence_types=available_types,
            missing_evidence_types=missing_types,
            selected_count=len(items),
            omitted_count=total_extracted - len(items),
            truncation_reasons=truncation_reasons,
        )

        return InvestigationEvidenceBundle(
            investigation_id=incident_id,
            generated_at=now_iso,
            items=items,
            conflicts=conflicts,
            gaps=gaps,
            coverage=coverage,
            citation_manifest=manifest,
            metadata={"total_extracted": total_extracted, "target_entity": target_entity, "intent": intent.value if intent else None},
        )

    def retrieve_entity_evidence(
        self,
        incident_id: int,
        entity_type: str,
        entity_value: str,
    ) -> InvestigationEvidenceBundle:
        """Deterministic entity-centric evidence retrieval across all 7 supported entity types."""
        norm_type = entity_type.upper().strip()
        if norm_type not in SUPPORTED_ENTITY_TYPES:
            raise ValueError(f"Unsupported entity type: '{entity_type}'. Must be one of {sorted(SUPPORTED_ENTITY_TYPES)}")

        clean_val = entity_value.strip()
        target_key = f"{norm_type.lower()}:{clean_val}"
        return self.retrieve_bundle(
            incident_id=incident_id,
            target_entity=target_key,
            intent=InvestigationIntent.ENTITY_ANALYSIS,
        )

    def retrieve_timeline_evidence(
        self,
        incident_id: int,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> List[EvidenceItem]:
        """Deterministic timeline retrieval sorted strictly chronologically (timestamp ASC, stable ID ASC)."""
        bundle = self.retrieve_bundle(incident_id=incident_id, intent=InvestigationIntent.TIMELINE, max_items=100)
        timeline_items = [i for i in bundle.items if i.evidence_type in (EvidenceType.EVENT, EvidenceType.ALERT, EvidenceType.TIMELINE_STEP)]
        if start_time:
            timeline_items = [i for i in timeline_items if i.timestamp >= start_time]
        if end_time:
            timeline_items = [i for i in timeline_items if i.timestamp <= end_time]
        # Strict deterministic chronological sort
        timeline_items.sort(key=lambda x: (x.timestamp, x.evidence_id))
        return timeline_items

    def retrieve_surrounding_events(
        self,
        incident_id: int,
        event_id: str,
        window_seconds: int = 1800,
    ) -> Dict[str, List[EvidenceItem]]:
        """Retrieve events strictly before, during, and after a target event to analyze sequence context."""
        with self.database.connection() as conn:
            target_row = conn.execute(
                "SELECT id, timestamp, host, summary, raw_message FROM events WHERE id = ?",
                (event_id,),
            ).fetchone()

        if not target_row:
            return {"before": [], "target": [], "after": []}

        target_ts_val = target_row["timestamp"]
        target_host = target_row["host"]

        # Parse target timestamp robustly
        if isinstance(target_ts_val, datetime):
            target_dt = target_ts_val
        else:
            ts_clean = str(target_ts_val).replace("Z", "+00:00")
            try:
                target_dt = datetime.fromisoformat(ts_clean)
            except Exception:
                target_dt = datetime.now(timezone.utc)

        start_dt = target_dt - timedelta(seconds=window_seconds)
        end_dt = target_dt + timedelta(seconds=window_seconds)
        start_ts = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_ts = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        with self.database.connection() as conn:
            # Query surrounding events on the same host within the temporal window
            rows = conn.execute(
                """
                SELECT id, timestamp, source, event_type, severity, action, outcome, summary, raw_message, host
                FROM events
                WHERE host = ?
                  AND (
                    (timestamp >= ? AND timestamp <= ?)
                    OR (replace(replace(timestamp, 'T', ' '), 'Z', '') >= replace(replace(?, 'T', ' '), 'Z', '')
                        AND replace(replace(timestamp, 'T', ' '), 'Z', '') <= replace(replace(?, 'T', ' '), 'Z', ''))
                  )
                ORDER BY timestamp ASC, id ASC
                """,
                (target_host, start_ts, end_ts, start_ts, end_ts),
            ).fetchall()

        before_items: List[EvidenceItem] = []
        target_items: List[EvidenceItem] = []
        after_items: List[EvidenceItem] = []

        for r in rows:
            ev_id = str(r["id"])
            tag = f"[event:{ev_id}]"
            is_target = (ev_id == str(event_id))
            role = EvidenceRole.PRIMARY if is_target else EvidenceRole.TEMPORAL
            item = EvidenceItem(
                evidence_id=ev_id,
                evidence_type=EvidenceType.EVENT,
                source_id=ev_id,
                source_table="events",
                timestamp=r["timestamp"],
                relevance_score=1.0 if is_target else 0.70,
                role=role,
                citation_tag=tag,
                summary=r["summary"] or r["raw_message"][:120],
                metadata={
                    "host": r["host"],
                    "action": r["action"],
                    "outcome": r["outcome"],
                    "source": r["source"],
                },
            )
            if is_target:
                target_items.append(item)
            elif str(r["timestamp"]) < str(target_ts_val) or (str(r["timestamp"]) == str(target_ts_val) and ev_id < str(event_id)):
                before_items.append(item)
            else:
                after_items.append(item)

        return {"before": before_items, "target": target_items, "after": after_items}

    def _detect_conflicts(self, items: List[EvidenceItem]) -> List[EvidenceConflict]:
        """Detect potential contradictions or inconsistencies within the evidence items."""
        conflicts: List[EvidenceConflict] = []
        c_idx = 1

        # Check for temporal anomalies: e.g. login success preceding repeated failures from same host/user
        event_items = [i for i in items if i.evidence_type == EvidenceType.EVENT]
        failed_logins = [
            e for e in event_items
            if e.metadata.get("action") == "login" and e.metadata.get("outcome") == "failure"
        ]
        success_logins = [
            e for e in event_items
            if e.metadata.get("action") == "login" and e.metadata.get("outcome") == "success"
        ]

        # If a success occurred after failures, note potential authentication conflict/privilege anomaly
        for succ in success_logins:
            for fail in failed_logins:
                if succ.timestamp < fail.timestamp and succ.metadata.get("host") == fail.metadata.get("host"):
                    conflicts.append(
                        EvidenceConflict(
                            conflict_id=f"conf-{c_idx}",
                            evidence_tag_a=succ.citation_tag,
                            evidence_tag_b=fail.citation_tag,
                            conflict_type="TEMPORAL_SEQUENCE_INCONSISTENCY",
                            explanation=(
                                f"Successful authentication at {succ.timestamp} unexpectedly preceded "
                                f"authentication failure at {fail.timestamp} on host {succ.metadata.get('host')}"
                            ),
                        )
                    )
                    c_idx += 1

        return conflicts

    def _audit_visibility_gaps(self, items: List[EvidenceItem], dossier: Any) -> List[EvidenceGap]:
        """Identify missing telemetry sources or visibility blind spots."""
        gaps: List[EvidenceGap] = []
        g_idx = 1

        sources = {i.metadata.get("source") for i in items if i.evidence_type == EvidenceType.EVENT}
        has_auth = any(s and "auth" in s.lower() for s in sources)
        has_auditd = any(s and "audit" in s.lower() for s in sources)
        has_syslog = any(s and "syslog" in s.lower() for s in sources)

        if not has_auditd:
            gaps.append(
                EvidenceGap(
                    gap_id=f"gap-{g_idx}",
                    category="PROCESS_AUDIT_TELEMETRY",
                    description="No Linux auditd or process execution syscall telemetry is available for this incident.",
                    impact="Subsequent command execution, argument vectors, and spawned child processes cannot be conclusively verified.",
                    suggested_data_source="/var/log/audit/audit.log",
                )
            )
            g_idx += 1

        has_network = any(i.evidence_type == EvidenceType.ENTITY and "ip:" in i.evidence_id for i in items)
        if has_network and not any("net" in str(s).lower() or "firewall" in str(s).lower() for s in sources):
            gaps.append(
                EvidenceGap(
                    gap_id=f"gap-{g_idx}",
                    category="NETWORK_FLOW_TELEMETRY",
                    description="Network entities are present, but dedicated packet filter or connection flow telemetry is missing.",
                    impact="Egress data transfer volumes and connection durations cannot be definitively observed.",
                    suggested_data_source="iptables / ufw / zeek logs",
                )
            )
            g_idx += 1

        return gaps
