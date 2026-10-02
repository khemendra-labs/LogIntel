"""FastAPI routing and endpoints for LogIntel local IPC/API contract."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from logintel.api.auth import verify_engine_token
from logintel.config import settings
from logintel.health import TelemetryHealthReport, health_service
from logintel.ingestion import ingestion_engine
from logintel.models import CanonicalEvent
from logintel.storage.events_repo import events_repo

router = APIRouter(prefix="/api/v1")
protected_router = APIRouter(dependencies=[Depends(verify_engine_token)])
start_time = time.time()


class HandshakeResponse(BaseModel):
    service: str = "logintel-engine"
    version: str
    api_version: str = "v1"
    status: str = "ready"


@router.get("/handshake", response_model=HandshakeResponse)
def get_handshake() -> HandshakeResponse:
    """Unauthenticated handshake endpoint for Tauri engine identity and compatibility check."""
    return HandshakeResponse(
        service="logintel-engine",
        version=settings.version,
        api_version="v1",
        status="ready",
    )


class SystemStatusResponse(BaseModel):
    app_name: str
    version: str
    host: str
    uptime_seconds: float
    ingestion_running: bool
    database_path: str
    total_events: int


class EventsQueryResponse(BaseModel):
    items: List[Dict[str, Any]]
    total: int
    limit: int
    offset: int


@protected_router.get("/system/status", response_model=SystemStatusResponse)
def get_system_status() -> SystemStatusResponse:
    _, total = events_repo.query_events(limit=1, offset=0)
    return SystemStatusResponse(
        app_name=settings.app_name,
        version=settings.version,
        host=settings.host_name,
        uptime_seconds=round(time.time() - start_time, 1),
        ingestion_running=ingestion_engine._running,
        database_path=str(settings.db_path),
        total_events=total,
    )


@protected_router.get("/telemetry/health", response_model=TelemetryHealthReport)
def get_telemetry_health() -> TelemetryHealthReport:
    return health_service.get_full_health(ingestion_engine.collectors)


@protected_router.get("/events", response_model=EventsQueryResponse)
def list_events(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    source: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    username: Optional[str] = None,
    ip: Optional[str] = None,
    outcome: Optional[str] = None,
    search: Optional[str] = None,
    sort_order: str = Query(default="DESC", pattern="^(?i)(ASC|DESC)$"),
) -> EventsQueryResponse:
    events, total = events_repo.query_events(
        limit=limit,
        offset=offset,
        start_time=start_time,
        end_time=end_time,
        source=source,
        event_type=event_type,
        severity=severity,
        username=username,
        ip=ip,
        outcome=outcome,
        search=search,
        sort_order=sort_order,
    )
    return EventsQueryResponse(
        items=[e.model_dump(mode="json") for e in events],
        total=total,
        limit=limit,
        offset=offset,
    )


@protected_router.get("/events/stats/summary")
def get_event_stats(hours: int = Query(default=24, ge=1, le=720)) -> Dict[str, Any]:
    return events_repo.get_event_statistics(hours=hours)


@protected_router.get("/events/{event_id}")
def get_event_detail(event_id: str) -> Dict[str, Any]:
    event = events_repo.get_event_by_id(event_id)
    if not event:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found.")
    return event.model_dump(mode="json")


@protected_router.get("/sources")
def get_sources() -> List[Dict[str, Any]]:
    return events_repo.get_all_ingestion_states()


@protected_router.post("/ingestion/trigger")
def trigger_ingestion_cycle() -> Dict[str, Any]:
    ingested = ingestion_engine.run_cycle(historical=False)
    return {"status": "ok", "ingested_records": ingested}


# ============================================================================
# DETECTION & ALERT ENDPOINTS
# ============================================================================

class UpdateAlertStatusRequest(BaseModel):
    status: str
    resolution_note: Optional[str] = None


class AlertsQueryResponse(BaseModel):
    items: List[Dict[str, Any]]
    total: int
    limit: int
    offset: int


@protected_router.get("/alerts", response_model=AlertsQueryResponse)
def list_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    host: Optional[str] = None,
    rule_id: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> AlertsQueryResponse:
    from logintel.models.alerts import AlertStatus
    from logintel.models.events import Severity
    from logintel.storage.alerts_repo import alerts_repo

    status_enum: Optional[AlertStatus] = None
    if status:
        try:
            status_enum = AlertStatus(status.upper())
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid alert status '{status}'. Valid values: {[s.value for s in AlertStatus]}",
            )

    sev_enum: Optional[Severity] = None
    if severity:
        try:
            sev_enum = Severity(severity.upper())
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid severity '{severity}'. Valid values: {[s.value for s in Severity]}",
            )

    alerts = alerts_repo.list_alerts(
        status=status_enum,
        severity=sev_enum,
        host=host,
        rule_id=rule_id,
        limit=limit,
        offset=offset,
    )
    total = alerts_repo.count_alerts(
        status=status_enum,
        severity=sev_enum,
        host=host,
        rule_id=rule_id,
    )
    return AlertsQueryResponse(
        items=[a.model_dump(mode="json") for a in alerts],
        total=total,
        limit=limit,
        offset=offset,
    )


@protected_router.get("/alerts/{alert_id}")
def get_alert_detail(alert_id: int) -> Dict[str, Any]:
    from logintel.storage.alerts_repo import alerts_repo
    details = alerts_repo.get_alert_details(alert_id)
    if not details:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return details


@protected_router.patch("/alerts/{alert_id}/status")
def update_alert_status(alert_id: int, req: UpdateAlertStatusRequest) -> Dict[str, Any]:
    from logintel.models.alerts import AlertStatus, InvalidStatusTransitionError
    from logintel.storage.alerts_repo import alerts_repo

    try:
        new_status = AlertStatus(req.status.upper())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid alert status '{req.status}'. Must be one of: {[s.value for s in AlertStatus]}",
        )

    try:
        updated = alerts_repo.update_alert_status(
            alert_id=alert_id,
            new_status=new_status,
            resolution_note=req.resolution_note,
        )
        return updated.model_dump(mode="json")
    except InvalidStatusTransitionError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/detection/rules")
def list_detection_rules(
    category: Optional[str] = None,
    enabled: Optional[bool] = None,
) -> Dict[str, Any]:
    from logintel.detection.registry import get_rule_registry
    registry = get_rule_registry()
    rules = registry.list_rules()

    if category:
        cat_upper = category.upper()
        rules = [r for r in rules if r.category.value == cat_upper]
    if enabled is not None:
        rules = [r for r in rules if r.enabled == enabled]

    items = [
        {
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "severity": r.severity.value,
            "category": r.category.value,
            "rule_type": r.rule_type.value,
            "enabled": r.enabled,
            "cooldown_seconds": r.cooldown_seconds,
            "conditions_count": len(r.conditions.all) if r.conditions.all else len(r.conditions.any or []),
        }
        for r in rules
    ]
    return {"items": items, "total": len(items)}


@protected_router.get("/detection/rules/{rule_id}")
def get_detection_rule(rule_id: str) -> Dict[str, Any]:
    from logintel.detection.registry import get_rule_registry
    registry = get_rule_registry()
    rule = registry.get(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Detection rule '{rule_id}' not found")

    import yaml
    yaml_content = yaml.safe_dump(rule.model_dump(mode="json"), sort_keys=False)
    return {
        "rule": rule.model_dump(mode="json"),
        "yaml_definition": yaml_content,
    }


# =========================================================================
# Incident & Attack Graph Endpoints (Milestone M3.5)
# =========================================================================

class IncidentsQueryResponse(BaseModel):
    items: List[Dict[str, Any]]
    total: int
    limit: int
    offset: int


class UpdateIncidentStatusRequest(BaseModel):
    status: str
    resolution_note: Optional[str] = None


class IncidentGraphResponse(BaseModel):
    incident_id: int
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]


class IncidentTimelineResponse(BaseModel):
    incident_id: int
    items: List[Dict[str, Any]]
    total: int


class CorrelateIncidentsResponse(BaseModel):
    correlated_incidents_count: int
    incident_ids: List[int]


@protected_router.get("/incidents", response_model=IncidentsQueryResponse)
def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    host: Optional[str] = None,
    user: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> IncidentsQueryResponse:
    from logintel.models.events import Severity
    from logintel.models.incidents import IncidentStatus
    from logintel.storage.incidents_repo import incidents_repo

    status_enum: Optional[IncidentStatus] = None
    if status:
        try:
            status_enum = IncidentStatus(status.upper())
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid incident status '{status}'. Valid values: {[s.value for s in IncidentStatus]}",
            )

    sev_enum: Optional[Severity] = None
    if severity:
        try:
            sev_enum = Severity(severity.upper())
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid severity '{severity}'. Valid values: {[s.value for s in Severity]}",
            )

    incidents = incidents_repo.list_incidents(
        status=status_enum,
        severity=sev_enum,
        host=host,
        user=user,
        limit=limit,
        offset=offset,
    )
    total = incidents_repo.count_incidents(
        status=status_enum,
        severity=sev_enum,
        host=host,
        user=user,
    )
    return IncidentsQueryResponse(
        items=[inc.model_dump(mode="json") for inc in incidents],
        total=total,
        limit=limit,
        offset=offset,
    )


@protected_router.get("/incidents/{incident_id}")
def get_incident_detail(incident_id: int) -> Dict[str, Any]:
    from logintel.storage.incidents_repo import incidents_repo
    details = incidents_repo.get_incident_details(incident_id)
    if not details:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return details


@protected_router.get("/incidents/{incident_id}/alerts")
def get_incident_alerts(incident_id: int) -> Dict[str, Any]:
    from logintel.storage.incidents_repo import incidents_repo
    incident = incidents_repo.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    alerts = incidents_repo.get_incident_alerts(incident_id)
    return {
        "incident_id": incident_id,
        "items": [a.model_dump(mode="json") for a in alerts],
        "total": len(alerts),
    }


@protected_router.patch("/incidents/{incident_id}/status")
def update_incident_status(incident_id: int, req: UpdateIncidentStatusRequest) -> Dict[str, Any]:
    from logintel.models.incidents import (
        IncidentStatus,
        InvalidIncidentStatusTransitionError,
    )
    from logintel.storage.incidents_repo import incidents_repo

    try:
        new_status = IncidentStatus(req.status.upper())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid incident status '{req.status}'. Must be one of: {[s.value for s in IncidentStatus]}",
        )

    try:
        updated = incidents_repo.update_incident_status(
            incident_id=incident_id,
            new_status=new_status,
            resolution_note=req.resolution_note,
        )
        return updated.model_dump(mode="json")
    except InvalidIncidentStatusTransitionError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/incidents/{incident_id}/graph", response_model=IncidentGraphResponse)
def get_incident_attack_graph(incident_id: int) -> IncidentGraphResponse:
    from logintel.storage.incidents_repo import incidents_repo
    incident = incidents_repo.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    graph = incidents_repo.get_attack_graph(incident_id)
    return IncidentGraphResponse(
        incident_id=incident_id,
        nodes=graph["nodes"],
        edges=graph["edges"],
    )


@protected_router.get("/incidents/{incident_id}/timeline", response_model=IncidentTimelineResponse)
def get_incident_investigation_timeline(incident_id: int) -> IncidentTimelineResponse:
    from logintel.storage.incidents_repo import incidents_repo
    incident = incidents_repo.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    timeline = incidents_repo.get_incident_timeline(incident_id)
    return IncidentTimelineResponse(
        incident_id=incident_id,
        items=[t.model_dump(mode="json") for t in timeline],
        total=len(timeline),
    )


@protected_router.post("/incidents/correlate", response_model=CorrelateIncidentsResponse)
def trigger_incident_correlation() -> CorrelateIncidentsResponse:
    from logintel.correlation.engine import correlation_engine
    correlated_incidents = correlation_engine.correlate_unassigned_alerts()
    inc_ids = [inc.id for inc in correlated_incidents if inc.id is not None]
    return CorrelateIncidentsResponse(
        correlated_incidents_count=len(inc_ids),
        incident_ids=inc_ids,
    )


# =============================================================================
# Milestone 4 — Investigation Workspace, Threat Hunting & Attack-Path APIs
# =============================================================================

class CreateNoteApiRequest(BaseModel):
    author: str = Field(min_length=1, max_length=128)
    content: str = Field(min_length=1, max_length=4096)
    target_type: str = "incident"
    target_id: Optional[str] = None


class ThreatHuntApiRequest(BaseModel):
    search_text: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    host: Optional[str] = None
    username: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    process_name: Optional[str] = None
    command: Optional[str] = None
    event_type: Optional[str] = None
    source: Optional[str] = None
    severity: Optional[str] = None
    outcome: Optional[str] = None
    rule_id: Optional[str] = None
    alert_id: Optional[int] = None
    ioc: Optional[str] = None
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class ExportInvestigationResponse(BaseModel):
    incident_id: int
    format: str
    content: str
    filename: str


@protected_router.get("/investigations/{incident_id}")
def get_investigation_dossier(incident_id: int) -> Dict[str, Any]:
    """Retrieve full investigation workspace dossier containing incident, attack path, MITRE, notes, and timeline."""
    from logintel.storage.investigation_repo import investigation_repo
    dossier = investigation_repo.get_investigation_dossier(incident_id)
    if not dossier:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return dossier


@protected_router.get("/investigations/{incident_id}/attack-path")
def get_investigation_attack_path(incident_id: int) -> Dict[str, Any]:
    """Retrieve reconstructed attack progression steps with evidence association."""
    from logintel.storage.investigation_repo import investigation_repo
    from logintel.storage.incidents_repo import incidents_repo
    inc = incidents_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    path = investigation_repo.reconstruct_attack_path(incident_id)
    return path.model_dump(mode="json")


@protected_router.get("/investigations/{incident_id}/mitre")
def get_investigation_mitre_mappings(incident_id: int) -> Dict[str, Any]:
    """Retrieve explainable, evidence-backed MITRE ATT&CK technique mappings for an incident."""
    from logintel.storage.investigation_repo import investigation_repo
    from logintel.storage.incidents_repo import incidents_repo
    inc = incidents_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    mappings = investigation_repo.get_incident_mitre_mappings(incident_id)
    return {
        "incident_id": incident_id,
        "items": [m.model_dump(mode="json") for m in mappings],
        "total": len(mappings),
    }


@protected_router.get("/investigations/{incident_id}/notes")
@protected_router.get("/investigations/{incident_id}/notes")
def list_investigation_notes(
    incident_id: int, include_deleted: bool = Query(default=False)
) -> Dict[str, Any]:
    """List all analyst notes and annotations for an investigation. Supports optional tombstone inclusion."""
    from logintel.storage.investigation_repo import investigation_repo
    from logintel.storage.incidents_repo import incidents_repo
    inc = incidents_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    notes = investigation_repo.list_notes(incident_id, include_deleted=include_deleted)
    return {
        "incident_id": incident_id,
        "items": [n.model_dump(mode="json") for n in notes],
        "total": len(notes),
    }


@protected_router.get("/investigations/{incident_id}/notes/audit")
def get_investigation_notes_audit(incident_id: int) -> Dict[str, Any]:
    """Retrieve immutable historical audit ledger for all analyst annotations on an incident."""
    from logintel.storage.investigation_repo import investigation_repo
    from logintel.storage.incidents_repo import incidents_repo
    inc = incidents_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    trail = investigation_repo.get_notes_audit_trail(incident_id)
    return {
        "incident_id": incident_id,
        "items": [a.model_dump(mode="json") for a in trail],
        "total": len(trail),
    }


@protected_router.post("/investigations/{incident_id}/notes", status_code=status.HTTP_201_CREATED)
def create_investigation_note(incident_id: int, req: CreateNoteApiRequest) -> Dict[str, Any]:
    """Create an analyst note associated with an investigation or specific artifact."""
    from logintel.models.investigation import NoteTargetType
    from logintel.storage.investigation_repo import investigation_repo
    from logintel.storage.incidents_repo import incidents_repo
    inc = incidents_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    try:
        ttype = NoteTargetType(req.target_type.lower())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid target_type '{req.target_type}'. Valid values: {[t.value for t in NoteTargetType]}",
        )

    note = investigation_repo.add_note(
        incident_id=incident_id,
        author=req.author,
        content=req.content,
        target_type=ttype,
        target_id=req.target_id,
    )
    return note.model_dump(mode="json")


@protected_router.delete("/investigations/notes/{note_id}")
def delete_investigation_note(
    note_id: int,
    actor: str = Query(default="Analyst"),
    reason: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """Soft delete (tombstone) an analyst note while recording an immutable audit event."""
    from logintel.storage.investigation_repo import investigation_repo
    deleted = investigation_repo.delete_note(note_id, actor=actor, reason=reason)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Note {note_id} not found or already deleted")
    return {"deleted": True, "note_id": note_id, "tombstoned": True}


@protected_router.get("/investigations/events/{event_id}/inspect")
def inspect_event_forensics(event_id: str) -> Dict[str, Any]:
    """Deep forensic inspection of a canonical event with provenance, detections, and incident lineage."""
    from logintel.storage.investigation_repo import investigation_repo
    forensics = investigation_repo.get_event_forensics(event_id)
    if not forensics:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found")
    return forensics.model_dump(mode="json")


@protected_router.get("/investigations/entities/{entity_key}/pivot")
def inspect_entity_pivot(entity_key: str, incident_id: Optional[int] = None) -> Dict[str, Any]:
    """Investigate a specific security entity (IP, Host, User, Process) across telemetry and incidents."""
    from logintel.storage.investigation_repo import investigation_repo
    pivot = investigation_repo.get_entity_pivot(entity_key=entity_key, incident_id=incident_id)
    if not pivot:
        raise HTTPException(status_code=404, detail=f"Entity '{entity_key}' could not be resolved")
    return pivot.model_dump(mode="json")


@protected_router.post("/investigations/hunt")
def execute_threat_hunt(req: ThreatHuntApiRequest) -> Dict[str, Any]:
    """Execute evidence-centric threat hunting query across historical canonical events."""
    from logintel.models.investigation import ThreatHuntFilter
    from logintel.storage.investigation_repo import investigation_repo

    filt = ThreatHuntFilter(
        search_text=req.search_text,
        start_time=req.start_time,
        end_time=req.end_time,
        host=req.host,
        username=req.username,
        src_ip=req.src_ip,
        dst_ip=req.dst_ip,
        process_name=req.process_name,
        command=req.command,
        event_type=req.event_type,
        source=req.source,
        severity=req.severity,
        outcome=req.outcome,
        rule_id=req.rule_id,
        alert_id=req.alert_id,
        ioc=req.ioc,
        limit=req.limit,
        offset=req.offset,
    )
    result = investigation_repo.search_events(filt)
    return result.model_dump(mode="json")


@protected_router.get("/investigations/{incident_id}/export")
def export_investigation_report(
    incident_id: int, format: str = Query(default="markdown", pattern="^(?i)(markdown|json|csv)$")
) -> ExportInvestigationResponse:
    """Export an evidence-backed investigation dossier in Markdown, JSON, or CSV format."""
    from logintel.storage.investigation_repo import investigation_repo
    from logintel.storage.incidents_repo import incidents_repo
    inc = incidents_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    fmt = format.lower()
    content = investigation_repo.export_investigation(incident_id, format=fmt)
    slug = inc.incident_key.replace(":", "_").replace("-", "_")
    ext = "md" if fmt == "markdown" else fmt
    filename = f"investigation_{slug}.{ext}"

    return ExportInvestigationResponse(
        incident_id=incident_id,
        format=fmt,
        content=content,
        filename=filename,
    )


# -------------------------------------------------------------------------
# Local AI Investigation Assistant (Milestone 5.2)
# -------------------------------------------------------------------------

class AIAnalysisRequest(BaseModel):
    task: Optional[str] = Field(default=None, description="Optional custom analytical investigation prompt")
    session_id: Optional[str] = Field(default=None, description="Optional ephemeral session ID")
    strict_citations: bool = Field(default=True, description="Strictly enforce that all citations exist in context")


@protected_router.get("/ai/status")
async def get_ai_status() -> Dict[str, Any]:
    """Diagnostic health check and model availability for the local AI subsystem."""
    from logintel.ai.service import ai_service
    return await ai_service.get_status()


@protected_router.post("/ai/investigations/{incident_id}/analyze")
async def analyze_investigation_with_ai(
    incident_id: int,
    req: Optional[AIAnalysisRequest] = None,
) -> Dict[str, Any]:
    """Execute evidence-grounded local AI analysis for a security incident."""
    from logintel.storage.incidents_repo import incidents_repo
    from logintel.ai.service import ai_service
    from logintel.ai.errors import (
        ModelUnavailable,
        ProviderUnavailable,
        ProviderTimeout,
        ProviderMalformedResponse,
        CrossInvestigationCitation,
        InvalidCitation,
        InvalidEpistemicClaim,
        AIConcurrencyLimit,
        AIError,
    )

    inc = incidents_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    task = req.task if req else None
    session_id = req.session_id if req else None
    strict = req.strict_citations if req else True

    try:
        response = await ai_service.analyze_investigation(
            incident_id=incident_id,
            session_id=session_id,
            task=task,
            strict_citations=strict,
        )
        return response.model_dump(mode="json")
    except ModelUnavailable as e:
        raise HTTPException(status_code=503, detail={"error": e.error_code, "message": e.message, "details": e.details})
    except ProviderUnavailable as e:
        raise HTTPException(status_code=503, detail={"error": e.error_code, "message": e.message, "details": e.details})
    except ProviderTimeout as e:
        raise HTTPException(status_code=504, detail={"error": e.error_code, "message": e.message, "details": e.details})
    except AIConcurrencyLimit as e:
        raise HTTPException(status_code=429, detail={"error": e.error_code, "message": e.message, "details": e.details})
    except (CrossInvestigationCitation, InvalidCitation, InvalidEpistemicClaim, ProviderMalformedResponse) as e:
        raise HTTPException(status_code=502, detail={"error": e.error_code, "message": e.message, "details": e.details})
    except AIError as e:
        raise HTTPException(status_code=500, detail={"error": e.error_code, "message": e.message, "details": e.details})


# -------------------------------------------------------------------------
# Evidence-Grounded Investigation Intelligence (Milestone 5.3)
# -------------------------------------------------------------------------

class AIQuestionRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=4000, description="Analyst investigation question")
    session_id: Optional[str] = Field(default=None, description="Optional ephemeral session ID")
    strict_citations: bool = Field(default=True, description="Strictly enforce that all citations exist in context")


@protected_router.post("/ai/investigations/{incident_id}/question")
async def ask_investigation_question(
    incident_id: int,
    req: AIQuestionRequest,
) -> Dict[str, Any]:
    """Ask an evidence-grounded investigation question with deterministic retrieval and epistemic validation."""
    from logintel.storage.incidents_repo import incidents_repo
    from logintel.ai.service import ai_service
    from logintel.ai.errors import (
        ModelUnavailable,
        ProviderUnavailable,
        ProviderTimeout,
        ProviderMalformedResponse,
        CrossInvestigationCitation,
        InvalidCitation,
        InvalidEpistemicClaim,
        AIConcurrencyLimit,
        AIError,
    )

    inc = incidents_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    try:
        response = await ai_service.ask_question(
            incident_id=incident_id,
            question=req.question,
            session_id=req.session_id,
            strict_citations=req.strict_citations,
        )
        return response.model_dump(mode="json")
    except ModelUnavailable as e:
        raise HTTPException(status_code=503, detail={"error": e.error_code, "message": e.message, "details": e.details})
    except ProviderUnavailable as e:
        raise HTTPException(status_code=503, detail={"error": e.error_code, "message": e.message, "details": e.details})
    except ProviderTimeout as e:
        raise HTTPException(status_code=504, detail={"error": e.error_code, "message": e.message, "details": e.details})
    except AIConcurrencyLimit as e:
        raise HTTPException(status_code=429, detail={"error": e.error_code, "message": e.message, "details": e.details})
    except (CrossInvestigationCitation, InvalidCitation, InvalidEpistemicClaim, ProviderMalformedResponse) as e:
        raise HTTPException(status_code=502, detail={"error": e.error_code, "message": e.message, "details": e.details})
    except AIError as e:
        if e.error_code in ("INVALID_QUESTION", "OVERSIZED_QUESTION"):
            raise HTTPException(status_code=400, detail={"error": e.error_code, "message": e.message, "details": e.details})
        raise HTTPException(status_code=500, detail={"error": e.error_code, "message": e.message, "details": e.details})


@protected_router.get("/ai/investigations/{incident_id}/evidence")
def get_investigation_evidence_bundle(
    incident_id: int,
    target_entity: Optional[str] = Query(default=None, description="Optional entity filter (e.g. 'ip:192.168.1.5')"),
    intent: Optional[str] = Query(default=None, description="Optional investigation intent to bias relevance"),
) -> Dict[str, Any]:
    """Retrieve the deterministic structured evidence bundle for an incident."""
    from logintel.storage.incidents_repo import incidents_repo
    from logintel.ai.service import ai_service
    from logintel.ai.domain.intelligence import InvestigationIntent

    inc = incidents_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    inv_intent = None
    if intent:
        try:
            inv_intent = InvestigationIntent(intent.upper())
        except ValueError:
            pass

    bundle = ai_service.get_evidence_bundle(
        incident_id=incident_id,
        target_entity=target_entity,
        intent=inv_intent,
    )
    return bundle.model_dump(mode="json")


@protected_router.get("/ai/investigations/{incident_id}/coverage")
def get_investigation_evidence_coverage(
    incident_id: int,
) -> Dict[str, Any]:
    """Retrieve deterministic evidence coverage metadata and telemetry gap audits for an incident."""
    from logintel.storage.incidents_repo import incidents_repo
    from logintel.ai.service import ai_service

    inc = incidents_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    coverage = ai_service.get_evidence_coverage(incident_id=incident_id)
    return coverage.model_dump(mode="json")


@protected_router.post("/ai/investigations/{incident_id}/query/preview")
def preview_investigation_query(
    incident_id: int,
    proposal: Dict[str, Any],
) -> Dict[str, Any]:
    """Safely preview a structured query proposal without executing autonomous actions or raw SQL."""
    from logintel.storage.incidents_repo import incidents_repo
    from logintel.ai.service import ai_service
    from logintel.ai.domain.intelligence import QueryProposal

    inc = incidents_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    try:
        valid_keys = {
            "title", "description", "intent", "rationale", "target_entity",
            "entity_key", "source", "filters", "event_types", "host",
            "username", "src_ip", "dst_ip", "process_name", "search_text",
            "relative_time_range"
        }
        if not any(k in proposal for k in valid_keys):
            raise ValueError("Proposal missing identifiable query specification")
        query_proposal = QueryProposal.model_validate(proposal)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid query proposal structure: {str(e)}")

    return ai_service.preview_query_proposal(
        incident_id=incident_id,
        proposal=query_proposal,
    )


# =========================================================================
# Milestone 5.4 — Analyst Investigation Workspace & Explainability APIs
# =========================================================================

class UpdateInvestigationStateRequest(BaseModel):
    state: str
    actor: str = "SecAnalyst-1"
    reason: Optional[str] = None


class CreateHypothesisRequest(BaseModel):
    statement: str
    status: Optional[str] = "OPEN"
    supporting_tags: Optional[List[str]] = None
    contradicting_tags: Optional[List[str]] = None
    gaps: Optional[List[str]] = None
    assessment: Optional[str] = None
    author: str = "SecAnalyst-1"


class UpdateHypothesisRequest(BaseModel):
    status: Optional[str] = None
    assessment: Optional[str] = None
    supporting_tags: Optional[List[str]] = None
    contradicting_tags: Optional[List[str]] = None
    gaps: Optional[List[str]] = None


class ExplainabilityTraceRequest(BaseModel):
    claim_text: str
    citation_tags: List[str]


@protected_router.get("/ai/investigations/{incident_id}/workspace")
def get_investigation_workspace(incident_id: int) -> Dict[str, Any]:
    """Retrieve full analyst investigation workspace state, scope, hypotheses, and evidence candidates."""
    from logintel.storage.incidents_repo import incidents_repo
    from logintel.ai.workspace_service import workspace_service

    inc = incidents_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    ws = workspace_service.get_or_create_workspace(incident_id)
    return ws.model_dump(mode="json")


@protected_router.patch("/ai/investigations/{incident_id}/state")
def update_investigation_state(
    incident_id: int,
    req: UpdateInvestigationStateRequest,
) -> Dict[str, Any]:
    """Explicitly transition investigation state with deterministic validation and audit logging."""
    from logintel.storage.incidents_repo import incidents_repo
    from logintel.ai.domain.workspace import InvestigationState
    from logintel.ai.workspace_service import workspace_service

    inc = incidents_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    try:
        target_state = InvestigationState(req.state.upper())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid investigation state: '{req.state}'")

    try:
        ws = workspace_service.update_state(
            incident_id=incident_id,
            target_state=target_state,
            actor=req.actor,
            reason=req.reason,
        )
        return ws.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@protected_router.put("/ai/investigations/{incident_id}/scope")
def update_investigation_scope(
    incident_id: int,
    scope: Dict[str, Any],
) -> Dict[str, Any]:
    """Update explicit reproducible scope bounds for an investigation."""
    from logintel.storage.incidents_repo import incidents_repo
    from logintel.ai.domain.workspace import InvestigationScope
    from logintel.ai.workspace_service import workspace_service

    inc = incidents_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    try:
        inv_scope = InvestigationScope.model_validate(scope)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid scope format: {str(e)}")

    ws = workspace_service.set_scope(incident_id=incident_id, scope=inv_scope)
    return ws.model_dump(mode="json")


@protected_router.get("/ai/investigations/{incident_id}/hypotheses")
def list_investigation_hypotheses(incident_id: int) -> Dict[str, Any]:
    """List all analyst-owned investigative hypotheses registered for an investigation."""
    from logintel.storage.incidents_repo import incidents_repo
    from logintel.ai.workspace_service import workspace_service

    inc = incidents_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    hyps = workspace_service.list_hypotheses(incident_id)
    return {
        "investigation_id": incident_id,
        "items": [h.model_dump(mode="json") for h in hyps],
        "total": len(hyps),
    }


@protected_router.post("/ai/investigations/{incident_id}/hypotheses")
def create_investigation_hypothesis(
    incident_id: int,
    req: CreateHypothesisRequest,
) -> Dict[str, Any]:
    """Create a new analyst hypothesis with associated supporting/contradicting evidence and gaps."""
    from logintel.storage.incidents_repo import incidents_repo
    from logintel.ai.domain.workspace import HypothesisStatus
    from logintel.ai.workspace_service import workspace_service

    inc = incidents_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    h_status = HypothesisStatus.OPEN
    if req.status:
        try:
            h_status = HypothesisStatus(req.status.upper())
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid hypothesis status: {req.status}")

    hyp = workspace_service.create_hypothesis(
        incident_id=incident_id,
        statement=req.statement,
        status=h_status,
        supporting_tags=req.supporting_tags,
        contradicting_tags=req.contradicting_tags,
        gaps=req.gaps,
        assessment=req.assessment,
        created_by=req.author,
    )
    return hyp.model_dump(mode="json")


@protected_router.patch("/ai/investigations/{incident_id}/hypotheses/{hypothesis_id}")
def update_investigation_hypothesis(
    incident_id: int,
    hypothesis_id: str,
    req: UpdateHypothesisRequest,
) -> Dict[str, Any]:
    """Update hypothesis status, assessment, or evidence linkages."""
    from logintel.storage.incidents_repo import incidents_repo
    from logintel.ai.domain.workspace import HypothesisStatus
    from logintel.ai.workspace_service import workspace_service

    inc = incidents_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    h_status = None
    if req.status:
        try:
            h_status = HypothesisStatus(req.status.upper())
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid hypothesis status: {req.status}")

    try:
        updated = workspace_service.update_hypothesis(
            incident_id=incident_id,
            hypothesis_id=hypothesis_id,
            status=h_status,
            assessment=req.assessment,
            supporting_tags=req.supporting_tags,
            contradicting_tags=req.contradicting_tags,
            gaps=req.gaps,
        )
        return updated.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.post("/ai/investigations/{incident_id}/query/execute")
def execute_approved_investigation_query(
    incident_id: int,
    proposal: Dict[str, Any],
) -> Dict[str, Any]:
    """Execute analyst-approved threat hunting query deterministically and collect evidence candidates."""
    from logintel.storage.incidents_repo import incidents_repo
    from logintel.ai.domain.intelligence import QueryProposal
    from logintel.ai.workspace_service import workspace_service

    inc = incidents_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    try:
        query_proposal = QueryProposal.model_validate(proposal)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid query proposal structure: {str(e)}")

    return workspace_service.execute_approved_query(
        incident_id=incident_id,
        proposal=query_proposal,
    )


@protected_router.get("/ai/investigations/{incident_id}/summary")
def get_investigation_summary(incident_id: int) -> Dict[str, Any]:
    """Retrieve complete deterministic structured investigation summary."""
    from logintel.storage.incidents_repo import incidents_repo
    from logintel.ai.workspace_service import workspace_service

    inc = incidents_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    try:
        summary = workspace_service.generate_investigation_summary(incident_id)
        return summary.model_dump(mode="json")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to assemble summary: {str(e)}")


@protected_router.post("/ai/investigations/{incident_id}/report/draft")
def generate_investigation_report_draft(incident_id: int) -> Dict[str, Any]:
    """Generate an explainable AI report draft distinguishing facts, inferences, hypotheses, and unknowns."""
    from logintel.storage.incidents_repo import incidents_repo
    from logintel.ai.workspace_service import workspace_service

    inc = incidents_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    try:
        draft = workspace_service.generate_report_draft(incident_id)
        return draft.model_dump(mode="json")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate report draft: {str(e)}")


@protected_router.post("/ai/investigations/{incident_id}/explainability")
def trace_claim_explainability(
    incident_id: int,
    req: ExplainabilityTraceRequest,
) -> Dict[str, Any]:
    """Trace cited evidence tags to their authoritative database origin."""
    from logintel.storage.incidents_repo import incidents_repo
    from logintel.ai.workspace_service import workspace_service

    inc = incidents_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    traces = workspace_service.trace_claim_explainability(
        incident_id=incident_id,
        claim_text=req.claim_text,
        citation_tags=req.citation_tags,
    )
    return {
        "incident_id": incident_id,
        "claim_text": req.claim_text,
        "traces": [t.model_dump(mode="json") for t in traces],
    }


# =============================================================================
# M5.5 Persistent Investigation Cases, Case Handoff, and Continuity Endpoints
# =============================================================================

class CreateCaseRequest(BaseModel):
    incident_id: int
    title: Optional[str] = None
    description: str = ""


class UpdateCaseStatusRequest(BaseModel):
    target_status: str
    reason: Optional[str] = None


class HandoffCaseRequest(BaseModel):
    new_owner: str
    handoff_notes: Optional[str] = None


class AssociateEvidenceRequest(BaseModel):
    source_type: str
    source_id: str
    role: str = "SUPPORTING"
    epistemic_status: str = "OBSERVED"
    citation_tag: Optional[str] = None
    annotation: Optional[str] = None


class CreateCaseHypothesisRequest(BaseModel):
    statement: str
    status: str = "OPEN"
    supporting_tags: Optional[List[str]] = None
    contradicting_tags: Optional[List[str]] = None
    gaps: Optional[List[str]] = None
    assessment: Optional[str] = None


class UpdateCaseHypothesisRequest(BaseModel):
    statement: Optional[str] = None
    status: Optional[str] = None
    supporting_tags: Optional[List[str]] = None
    contradicting_tags: Optional[List[str]] = None
    gaps: Optional[List[str]] = None
    assessment: Optional[str] = None


class DraftCaseReportRequest(BaseModel):
    title: Optional[str] = None
    analyst_notes: Optional[str] = None
    is_final: bool = False


@protected_router.get("/cases")
def list_investigation_cases(
    status: Optional[str] = Query(None),
    owner: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List persistent investigation cases with optional status and owner filters."""
    from logintel.ai.case_service import case_service
    from logintel.ai.domain.case import CaseStatus

    filter_status = CaseStatus(status) if status else None
    cases = case_service.list_cases(status=filter_status, owner=owner)
    return [c.model_dump(mode="json") for c in cases]


@protected_router.post("/cases")
def create_or_open_case(req: CreateCaseRequest) -> Dict[str, Any]:
    """Create or load a persistent investigation case."""
    from logintel.ai.case_service import case_service

    try:
        case = case_service.create_or_open_case(
            incident_id=req.incident_id,
            title=req.title,
            description=req.description,
        )
        return case.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@protected_router.get("/cases/{case_id}")
def get_case_detail(case_id: int) -> Dict[str, Any]:
    """Retrieve complete persistent case details including resolved evidence and stale status."""
    from logintel.ai.case_service import case_service

    case = case_service.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    return case.model_dump(mode="json")


@protected_router.post("/cases/{case_id}/state")
def update_case_state(case_id: int, req: UpdateCaseStatusRequest) -> Dict[str, Any]:
    """Execute a validated case lifecycle state transition."""
    from logintel.ai.case_service import case_service
    from logintel.ai.domain.case import CaseStatus

    try:
        target = CaseStatus(req.target_status)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid case status: {req.target_status}")

    try:
        updated = case_service.transition_case_state(
            case_id=case_id,
            target_status=target,
            reason=req.reason,
        )
        return updated.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@protected_router.post("/cases/{case_id}/scope")
def update_case_scope_endpoint(case_id: int, scope: Dict[str, Any]) -> Dict[str, Any]:
    """Update case investigation scope boundaries."""
    from logintel.ai.case_service import case_service
    from logintel.ai.domain.workspace import InvestigationScope

    try:
        scope_obj = InvestigationScope.model_validate(scope)
        updated = case_service.update_scope(case_id=case_id, scope=scope_obj)
        return updated.model_dump(mode="json")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to update scope: {str(e)}")


@protected_router.post("/cases/{case_id}/handoff")
def handoff_case(case_id: int, req: HandoffCaseRequest) -> Dict[str, Any]:
    """Transfer case ownership during analyst handoff with notes."""
    from logintel.ai.case_service import case_service

    try:
        updated = case_service.transfer_case(
            case_id=case_id,
            new_owner=req.new_owner,
            handoff_notes=req.handoff_notes,
        )
        return updated.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@protected_router.get("/cases/{case_id}/hypotheses")
def list_case_hypotheses(case_id: int) -> List[Dict[str, Any]]:
    """List persistent hypotheses for a case."""
    from logintel.ai.case_service import case_service

    case = case_service.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    return [h.model_dump(mode="json") for h in case.hypotheses]


@protected_router.post("/cases/{case_id}/hypotheses")
def create_case_hypothesis(case_id: int, req: CreateCaseHypothesisRequest) -> Dict[str, Any]:
    """Create and persist an analyst-owned hypothesis in the case."""
    from logintel.ai.case_service import case_service
    from logintel.ai.domain.workspace import HypothesisStatus

    try:
        status_enum = HypothesisStatus(req.status)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid hypothesis status: {req.status}")

    try:
        h = case_service.create_hypothesis(
            case_id=case_id,
            statement=req.statement,
            status=status_enum,
            supporting_tags=req.supporting_tags,
            contradicting_tags=req.contradicting_tags,
            gaps=req.gaps,
            assessment=req.assessment,
        )
        return h.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@protected_router.patch("/cases/{case_id}/hypotheses/{hyp_id}")
def update_case_hypothesis_endpoint(
    case_id: int,
    hyp_id: str,
    req: UpdateCaseHypothesisRequest,
) -> Dict[str, Any]:
    """Update an existing persistent hypothesis."""
    from logintel.ai.case_service import case_service
    from logintel.ai.domain.workspace import HypothesisStatus

    status_enum = HypothesisStatus(req.status) if req.status else None
    try:
        h = case_service.update_hypothesis(
            case_id=case_id,
            hypothesis_id=hyp_id,
            statement=req.statement,
            status=status_enum,
            supporting_tags=req.supporting_tags,
            contradicting_tags=req.contradicting_tags,
            gaps=req.gaps,
            assessment=req.assessment,
        )
        return h.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@protected_router.get("/cases/{case_id}/evidence")
def list_case_evidence(case_id: int) -> List[Dict[str, Any]]:
    """List case evidence references with dynamic resolution and stale detection."""
    from logintel.ai.case_service import case_service

    case = case_service.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    return [r.model_dump(mode="json") for r in case.evidence_references]


@protected_router.post("/cases/{case_id}/evidence")
def associate_case_evidence(case_id: int, req: AssociateEvidenceRequest) -> Dict[str, Any]:
    """Associate an authoritative evidence reference with a case."""
    from logintel.ai.case_service import case_service

    try:
        ref = case_service.associate_evidence(
            case_id=case_id,
            source_type=req.source_type,
            source_id=req.source_id,
            role=req.role,
            epistemic_status=req.epistemic_status,
            citation_tag=req.citation_tag,
            annotation=req.annotation,
        )
        return ref.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@protected_router.delete("/cases/{case_id}/evidence/{ref_id}")
def disassociate_case_evidence(case_id: int, ref_id: str) -> Dict[str, Any]:
    """Disassociate an evidence reference from a case."""
    from logintel.ai.case_service import case_service

    success = case_service.disassociate_evidence(case_id=case_id, reference_id=ref_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Reference {ref_id} not found")
    return {"case_id": case_id, "reference_id": ref_id, "deleted": True}


@protected_router.get("/cases/{case_id}/queries")
def list_case_queries(case_id: int) -> List[Dict[str, Any]]:
    """List threat hunting query execution history for a case."""
    from logintel.ai.case_service import case_service

    case = case_service.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    return [q.model_dump(mode="json") for q in case.query_history]


@protected_router.post("/cases/{case_id}/queries/execute")
def execute_case_query(case_id: int, proposal: Dict[str, Any]) -> Dict[str, Any]:
    """Execute analyst-approved threat query, staging candidates and recording in query history."""
    from logintel.ai.case_service import case_service
    from logintel.ai.domain.intelligence import QueryProposal

    try:
        q_proposal = QueryProposal.model_validate(proposal)
        return case_service.execute_approved_query(case_id=case_id, proposal=q_proposal)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Query execution failed: {str(e)}")


@protected_router.get("/cases/{case_id}/reports")
def list_case_reports(case_id: int) -> List[Dict[str, Any]]:
    """List all historical versions of case reports."""
    from logintel.ai.case_service import case_service

    case = case_service.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    return [rep.model_dump(mode="json") for rep in case.reports]


@protected_router.post("/cases/{case_id}/reports/draft")
def draft_case_report(case_id: int, req: DraftCaseReportRequest) -> Dict[str, Any]:
    """Generate or revise a persistent versioned investigation report."""
    from logintel.ai.case_service import case_service

    try:
        rep = case_service.draft_or_revise_report(
            case_id=case_id,
            title=req.title,
            analyst_notes=req.analyst_notes,
            is_final=req.is_final,
        )
        return rep.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@protected_router.get("/cases/{case_id}/reports/{report_id}/compare")
def compare_report_versions_endpoint(
    case_id: int,
    report_id: str,
    v1: int = Query(..., description="First version number to compare"),
    v2: int = Query(..., description="Second version number to compare"),
) -> Dict[str, Any]:
    """Compare two historical report versions to inspect modifications, additions, and notes."""
    from logintel.ai.case_service import case_service

    try:
        return case_service.compare_report_versions(
            case_id=case_id,
            report_id=report_id,
            v1=v1,
            v2=v2,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/audit")
def get_case_audit_history(case_id: int) -> List[Dict[str, Any]]:
    """Fetch complete chronological audit trail of case modifications."""
    from logintel.ai.case_service import case_service

    try:
        audits = case_service.get_audit_history(case_id)
        return [a.model_dump(mode="json") for a in audits]
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/ai-context")
def get_case_ai_context(case_id: int) -> Dict[str, Any]:
    """Deterministically reconstruct AI context from persistent case state without cross-case memory."""
    from logintel.ai.case_service import case_service

    try:
        ctx = case_service.reconstruct_ai_context(case_id)
        return ctx.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# =========================================================================
# M5.6 Investigation Intelligence & Governed Threat Hunting Routes
# =========================================================================

class HuntProposalApiRequest(BaseModel):
    template_id: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    rationale: str
    suggested_by: str = "SecAnalyst-1"


class HuntExecuteApiRequest(BaseModel):
    proposal_id: str
    template_id: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    rationale: str
    suggested_by: str = "SecAnalyst-1"
    approved_by: str = "SecAnalyst-1"


class IntelligenceSynthesisApiRequest(BaseModel):
    prompt: Optional[str] = None
    actor: str = "SecAnalyst-1"


@protected_router.get("/cases/{case_id}/findings")
def get_case_findings(case_id: int) -> Dict[str, Any]:
    """Retrieve deterministic investigation findings and multi-attribute correlations."""
    from logintel.ai.case_service import case_service

    try:
        findings, correlations = case_service.get_findings_and_correlations(case_id)
        return {
            "case_id": case_id,
            "findings": [f.model_dump(mode="json") for f in findings],
            "correlations": [c.model_dump(mode="json") for c in correlations],
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/correlations")
def get_case_correlations(case_id: int) -> List[Dict[str, Any]]:
    """Retrieve deterministic evidence correlations with explicit explanation reasons."""
    from logintel.ai.case_service import case_service

    try:
        _, correlations = case_service.get_findings_and_correlations(case_id)
        return [c.model_dump(mode="json") for c in correlations]
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/timeline")
def get_case_timeline(case_id: int) -> List[Dict[str, Any]]:
    """Retrieve unified investigation timeline with strict provenance demarcation."""
    from logintel.ai.case_service import case_service

    try:
        timeline = case_service.get_case_timeline(case_id)
        return [item.model_dump(mode="json") for item in timeline]
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/evidence-gaps")
def get_case_evidence_gaps(case_id: int) -> List[Dict[str, Any]]:
    """Identify missing telemetry dimensions and safe threat hunt query recommendations."""
    from logintel.ai.case_service import case_service

    try:
        gaps = case_service.get_evidence_gaps(case_id)
        return [g.model_dump(mode="json") for g in gaps]
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/pivots/{entity_type}/{entity_value}")
def get_case_entity_pivot(case_id: int, entity_type: str, entity_value: str) -> Dict[str, Any]:
    """Execute deep entity investigation pivot across events, alerts, and cases without duplicating payloads."""
    from logintel.ai.case_service import case_service

    try:
        pivot = case_service.resolve_entity_pivot(case_id, entity_type, entity_value)
        return pivot.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.post("/cases/{case_id}/hunt/proposals")
def create_case_hunt_proposal(case_id: int, req: HuntProposalApiRequest) -> Dict[str, Any]:
    """Validate and generate a governed threat hunting proposal with read-only preview."""
    from logintel.ai.case_service import case_service

    try:
        proposal = case_service.create_hunt_proposal(
            case_id=case_id,
            template_id=req.template_id,
            parameters=req.parameters,
            rationale=req.rationale,
            suggested_by=req.suggested_by,
        )
        return proposal.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.post("/cases/{case_id}/hunt/execute")
def execute_case_hunt_query(case_id: int, req: HuntExecuteApiRequest) -> Dict[str, Any]:
    """Execute analyst-approved governed threat hunting query and persist to case query history."""
    from logintel.ai.case_service import case_service
    from logintel.ai.domain.investigation_intel import GovernedThreatHuntProposal

    try:
        proposal = GovernedThreatHuntProposal(
            proposal_id=req.proposal_id,
            case_id=case_id,
            template_id=req.template_id,
            parameters=req.parameters,
            rationale=req.rationale,
            suggested_by=req.suggested_by,
        )
        execution = case_service.execute_hunt_query(proposal, approved_by=req.approved_by)
        return execution.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/hypotheses/{hyp_id}/analysis")
def analyze_case_hypothesis_endpoint(case_id: int, hyp_id: str) -> Dict[str, Any]:
    """Perform deterministic evidence support analysis for an analyst-owned hypothesis."""
    from logintel.ai.case_service import case_service

    try:
        analysis = case_service.analyze_hypothesis(case_id, hyp_id)
        return analysis.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/intelligence")
def get_case_intelligence_dossier_endpoint(case_id: int) -> Dict[str, Any]:
    """Retrieve comprehensive aggregated investigation intelligence dossier."""
    from logintel.ai.case_service import case_service

    try:
        dossier = case_service.get_case_intelligence_dossier(case_id)
        return dossier.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.post("/cases/{case_id}/intelligence/synthesis")
def synthesize_case_intelligence(case_id: int, req: Optional[IntelligenceSynthesisApiRequest] = None) -> Dict[str, Any]:
    """Generate structured AI investigation intelligence with application-level containment."""
    from logintel.ai.case_service import case_service

    prompt = req.prompt if req else None
    actor = req.actor if req else "SecAnalyst-1"
    try:
        response = case_service.generate_ai_investigation_intelligence(case_id, prompt=prompt, actor=actor)
        return response.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


router.include_router(protected_router)




