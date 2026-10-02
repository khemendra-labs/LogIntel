"""Deterministic Investigation Context Assembler for LogIntel AI.

Extracts, prioritizes, and bounds verified M4 forensic evidence into an
InvestigationContext packet without bypassing trusted repository layers.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from logintel.ai.context.budget import ContextBudget
from logintel.ai.domain.citation import CitationManifest
from logintel.ai.domain.context import GenerationMetadata, InvestigationContext, TruncationMetadata
from logintel.ai.domain.evidence import EvidenceTrustLevel, EvidenceType, UntrustedTelemetryPayload
from logintel.logging import get_logger
from logintel.storage.alerts_repo import AlertsRepository, alerts_repo
from logintel.storage.db import Database, db
from logintel.storage.incidents_repo import IncidentsRepository, incidents_repo
from logintel.storage.investigation_repo import InvestigationRepository, investigation_repo

logger = get_logger("ai.context.assembler")

SEVERITY_WEIGHT = {
    "CRITICAL": 5,
    "ALERT": 4,
    "WARNING": 3,
    "NOTICE": 2,
    "INFORMATIONAL": 1,
    "DEBUG": 0,
}


class InvestigationContextAssembler:
    """Assembles an InvestigationContext deterministically from authoritative M4 data."""

    def __init__(
        self,
        database: Optional[Database] = None,
        incidents_repository: Optional[IncidentsRepository] = None,
        investigation_repository: Optional[InvestigationRepository] = None,
        alerts_repository: Optional[AlertsRepository] = None,
    ) -> None:
        self.db = database or db
        self.incidents_repo = incidents_repository or (IncidentsRepository(self.db) if database else incidents_repo)
        self.investigation_repo = investigation_repository or (InvestigationRepository(self.db) if database else investigation_repo)
        self.alerts_repo = alerts_repository or (AlertsRepository(self.db) if database else alerts_repo)

    def assemble(
        self,
        incident_id: int,
        budget: Optional[ContextBudget] = None,
        generated_at: Optional[str] = None,
    ) -> InvestigationContext:
        """Deterministically assemble an InvestigationContext for the given incident_id.
        
        Args:
            incident_id: ID of the security incident to assemble context for.
            budget: Optional ContextBudget bounding the evidence extraction limits.
            generated_at: Optional fixed ISO-8601 timestamp string. If supplied,
                          enables bit-for-bit identical serialization across repeated runs.
                          If omitted, defaults to current UTC timestamp.
        
        Raises:
            ValueError: If incident_id does not exist in the database.
        """
        budget = budget or ContextBudget()
        manifest = CitationManifest()
        truncation = TruncationMetadata()
        now_iso = generated_at or datetime.now(timezone.utc).isoformat()
        is_seed = generated_at is not None
        gen_meta = GenerationMetadata(
            generated_at=now_iso,
            is_deterministic_seed=is_seed,
            context_version="1.0.0",
        )

        # 1. Tier 1: Incident Dossier Header
        incident = self.incidents_repo.get_incident(incident_id)
        if not incident:
            raise ValueError(f"Incident with ID {incident_id} not found in database")

        dossier_summary: Dict[str, Any] = {
            "id": incident.id,
            "incident_key": incident.incident_key,
            "title": incident.title,
            "summary": incident.summary,
            "severity": incident.severity.value,
            "status": incident.status.value,
            "primary_host": incident.primary_host,
            "primary_user": incident.primary_user,
            "first_seen": incident.first_seen.isoformat() if incident.first_seen else None,
            "last_seen": incident.last_seen.isoformat() if incident.last_seen else None,
            "alert_count": incident.alert_count,
            "event_count": incident.event_count,
        }
        manifest.add(EvidenceType.INCIDENT, str(incident.id), f"Incident {incident.incident_key}")

        # 2. Tier 4: Correlated Alerts
        raw_alerts = self.incidents_repo.get_incident_alerts(incident_id)
        # Sort alerts deterministically: severity desc, first_seen asc, id asc
        sorted_alerts = sorted(
            raw_alerts,
            key=lambda a: (
                -SEVERITY_WEIGHT.get(a.severity.value if hasattr(a.severity, "value") else str(a.severity), 0),
                a.first_seen.isoformat() if a.first_seen else "",
                a.id if a.id is not None else 0,
            ),
        )

        total_alerts = len(sorted_alerts)
        if total_alerts > budget.max_alerts:
            omitted = total_alerts - budget.max_alerts
            truncation.add_omission(
                "alerts",
                omitted,
                f"Omitted {omitted} lower-priority alerts exceeding budget limit of {budget.max_alerts}",
            )
            retained_alerts = sorted_alerts[: budget.max_alerts]
        else:
            retained_alerts = sorted_alerts

        alerts_data: List[Dict[str, Any]] = []
        supporting_event_ids: Set[str] = set()

        for a in retained_alerts:
            a_id_str = str(a.id)
            manifest.add(EvidenceType.ALERT, a_id_str, f"Alert {a.title}")
            alerts_data.append(
                {
                    "id": a.id,
                    "rule_id": a.rule_id,
                    "title": a.title,
                    "description": a.description,
                    "severity": a.severity.value if hasattr(a.severity, "value") else str(a.severity),
                    "status": a.status.value if hasattr(a.status, "value") else str(a.status),
                    "host": a.host,
                    "first_seen": a.first_seen.isoformat() if a.first_seen else None,
                    "last_seen": a.last_seen.isoformat() if a.last_seen else None,
                    "occurrence_count": a.occurrence_count,
                }
            )

        # 3. Tier 2: Direct Supporting Evidence Events
        # Collect event IDs linked directly to alerts / detections / relationships
        rels = self.incidents_repo.get_incident_relationships(incident_id)
        for r in rels:
            if r.evidence_event_ids:
                for eid in r.evidence_event_ids:
                    supporting_event_ids.add(eid)

        # Also get detections linked to alerts via authoritative repository layer
        for a in retained_alerts:
            if a.id is not None:
                alert_details = self.alerts_repo.get_alert_details(a.id)
                if alert_details and "detections" in alert_details:
                    for det in alert_details["detections"]:
                        for ev_item in det.get("evidence", []):
                            eid = ev_item.get("event_id")
                            if eid:
                                supporting_event_ids.add(eid)

        # Fetch and serialize supporting events
        supporting_events: List[UntrustedTelemetryPayload] = []
        raw_supporting_list: List[Dict[str, Any]] = []

        for eid in sorted(supporting_event_ids):
            forensics = self.investigation_repo.get_event_forensics(eid)
            if forensics and forensics.event:
                ev = forensics.event
                raw_supporting_list.append(ev)

        # Sort supporting events deterministically: timestamp asc, id asc
        raw_supporting_list.sort(key=lambda e: (e.get("timestamp") or "", e.get("id") or ""))

        total_supporting = len(raw_supporting_list)
        if total_supporting > budget.max_supporting_events:
            omitted_ev = total_supporting - budget.max_supporting_events
            truncation.add_omission(
                "events",
                omitted_ev,
                f"Omitted {omitted_ev} supporting events exceeding budget limit of {budget.max_supporting_events}",
            )
            retained_supporting = raw_supporting_list[: budget.max_supporting_events]
        else:
            retained_supporting = raw_supporting_list

        for ev in retained_supporting:
            ev_id = ev.get("id", "")
            payload = UntrustedTelemetryPayload(
                event_id=ev_id,
                timestamp=ev.get("timestamp") or "",
                host=ev.get("host") or "",
                source=ev.get("source") or "",
                event_type=ev.get("event_type") or "",
                severity=ev.get("severity") or "",
                outcome=ev.get("outcome") or "",
                raw_message=ev.get("raw_message") or "",
                fingerprint=ev.get("event_fingerprint") or "",
                trust_level=EvidenceTrustLevel.UNTRUSTED_FORENSIC_DATA,
            )
            supporting_events.append(payload)
            manifest.add(EvidenceType.EVENT, ev_id, f"Event {ev_id} ({payload.event_type})")

        # 4. Tier 3: Attack Path Steps
        path_reconstruction = self.investigation_repo.reconstruct_attack_path(incident_id)
        raw_steps = path_reconstruction.steps if path_reconstruction else []
        sorted_steps = sorted(raw_steps, key=lambda s: s.step_number)

        total_steps = len(sorted_steps)
        if total_steps > budget.max_attack_path_steps:
            retained_steps = sorted_steps[: budget.max_attack_path_steps]
        else:
            retained_steps = sorted_steps

        attack_path_steps_data: List[Dict[str, Any]] = []
        for s in retained_steps:
            manifest.add(EvidenceType.ATTACK_PATH_STEP, str(s.step_number), f"Step {s.step_number}: {s.relationship_type}")
            attack_path_steps_data.append(
                {
                    "step_number": s.step_number,
                    "nature": s.nature.value if hasattr(s.nature, "value") else str(s.nature),
                    "relationship_type": s.relationship_type,
                    "confidence": s.confidence,
                    "source_node": s.source_node if isinstance(s.source_node, str) else getattr(s.source_node, "id", str(s.source_node)),
                    "target_node": s.target_node if isinstance(s.target_node, str) else getattr(s.target_node, "id", str(s.target_node)),
                    "derivation_source": s.derivation_source,
                    "inference_reason": s.inference_reason,
                    "evidence_event_ids": s.evidence_event_ids,
                }
            )

        # 5. Tier 5: Correlated Entities and Relationships
        raw_entities = self.incidents_repo.get_incident_entities(incident_id)
        sorted_entities = sorted(raw_entities, key=lambda e: (e.entity_type.value, e.entity_key))

        total_entities = len(sorted_entities)
        if total_entities > budget.max_entities:
            omitted_ent = total_entities - budget.max_entities
            truncation.add_omission(
                "entities",
                omitted_ent,
                f"Omitted {omitted_ent} entities exceeding budget limit of {budget.max_entities}",
            )
            retained_entities = sorted_entities[: budget.max_entities]
        else:
            retained_entities = sorted_entities

        entities_data: List[Dict[str, Any]] = []
        for ent in retained_entities:
            manifest.add(EvidenceType.ENTITY, ent.entity_key, f"{ent.entity_type.value} {ent.display_name}")
            entities_data.append(
                {
                    "entity_key": ent.entity_key,
                    "entity_type": ent.entity_type.value,
                    "display_name": ent.display_name,
                    "metadata": ent.metadata,
                }
            )

        sorted_rels = sorted(
            rels,
            key=lambda r: (
                r.id if r.id is not None else 0,
                r.source_entity_key,
                r.target_entity_key,
                r.relationship_type,
            ),
        )
        if len(sorted_rels) > budget.max_relationships:
            retained_rels = sorted_rels[: budget.max_relationships]
        else:
            retained_rels = sorted_rels

        relationships_data: List[Dict[str, Any]] = []
        for r in retained_rels:
            r_id_str = str(r.id) if r.id is not None else f"{r.source_entity_key}->{r.target_entity_key}"
            manifest.add(EvidenceType.RELATIONSHIP, r_id_str, f"{r.source_entity_key} {r.relationship_type} {r.target_entity_key}")
            relationships_data.append(
                {
                    "id": r.id,
                    "source": r.source_entity_key,
                    "target": r.target_entity_key,
                    "relationship_type": r.relationship_type,
                    "confidence": r.confidence.value if hasattr(r.confidence, "value") else str(r.confidence),
                    "evidence_event_ids": r.evidence_event_ids,
                }
            )

        # 6. MITRE ATT&CK Mappings
        raw_mitre = self.investigation_repo.get_incident_mitre_mappings(incident_id)
        sorted_mitre = sorted(raw_mitre, key=lambda m: (m.tactic, m.technique_id, m.rule_id))
        mitre_data: List[Dict[str, Any]] = []
        for m in sorted_mitre:
            manifest.add(EvidenceType.MITRE, m.technique_id, f"MITRE {m.technique_id} ({m.technique_name})")
            mitre_data.append(
                {
                    "technique_id": m.technique_id,
                    "technique_name": m.technique_name,
                    "tactic": m.tactic,
                    "rule_id": m.rule_id,
                    "supporting_alert_ids": m.supporting_alert_ids,
                    "evidence_event_count": m.evidence_event_count,
                }
            )

        # 7. Tier 6: Non-Tombstoned Analyst Notes
        raw_notes = self.investigation_repo.list_notes(incident_id, include_deleted=False)
        sorted_notes = sorted(
            raw_notes,
            key=lambda n: (
                n.created_at.isoformat() if n.created_at else "",
                n.id or 0,
                n.author or "",
            ),
        )

        total_notes = len(sorted_notes)
        if total_notes > budget.max_notes:
            omitted_notes = total_notes - budget.max_notes
            truncation.add_omission(
                "notes",
                omitted_notes,
                f"Omitted {omitted_notes} analyst notes exceeding budget limit of {budget.max_notes}",
            )
            retained_notes = sorted_notes[: budget.max_notes]
        else:
            retained_notes = sorted_notes

        notes_data: List[Dict[str, Any]] = []
        for n in retained_notes:
            if n.id is not None:
                manifest.add(EvidenceType.NOTE, str(n.id), f"Note #{n.id} by {n.author}")
            notes_data.append(
                {
                    "id": n.id,
                    "author": n.author,
                    "content": n.content,
                    "created_at": n.created_at.isoformat() if n.created_at else None,
                    "target_type": n.target_type.value if hasattr(n.target_type, "value") else str(n.target_type),
                    "target_id": n.target_id,
                }
            )

        # 8. Tier 7: Contextual Telemetry Events
        # Extract events from timeline that are not already in supporting_events
        timeline_items = self.incidents_repo.get_incident_timeline(incident_id)
        contextual_candidates: List[Dict[str, Any]] = []
        already_included_event_ids = {e.event_id for e in supporting_events}

        for item in timeline_items:
            if item.item_type == "event" and item.item_id not in already_included_event_ids:
                if len(contextual_candidates) < budget.max_contextual_events:
                    forensics = self.investigation_repo.get_event_forensics(item.item_id)
                    if forensics and forensics.event:
                        contextual_candidates.append(forensics.event)

        contextual_candidates.sort(key=lambda e: (e.get("timestamp") or "", e.get("id") or ""))
        contextual_events: List[UntrustedTelemetryPayload] = []

        for ev in contextual_candidates:
            ev_id = ev.get("id", "")
            payload = UntrustedTelemetryPayload(
                event_id=ev_id,
                timestamp=ev.get("timestamp") or "",
                host=ev.get("host") or "",
                source=ev.get("source") or "",
                event_type=ev.get("event_type") or "",
                severity=ev.get("severity") or "",
                outcome=ev.get("outcome") or "",
                raw_message=ev.get("raw_message") or "",
                fingerprint=ev.get("event_fingerprint") or "",
                trust_level=EvidenceTrustLevel.UNTRUSTED_FORENSIC_DATA,
            )
            contextual_events.append(payload)
            manifest.add(EvidenceType.EVENT, ev_id, f"Event {ev_id} ({payload.event_type})")

        return InvestigationContext(
            context_version="1.0.0",
            investigation_id=incident_id,
            generated_at=now_iso,
            generation_metadata=gen_meta,
            dossier_summary=dossier_summary,
            supporting_events=supporting_events,
            attack_path_steps=attack_path_steps_data,
            alerts=alerts_data,
            entities=entities_data,
            relationships=relationships_data,
            mitre_mappings=mitre_data,
            analyst_notes=notes_data,
            contextual_events=contextual_events,
            citation_manifest=manifest,
            truncation=truncation,
        )
