"""FastAPI routing and endpoints for LogIntel local IPC/API contract."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Body, Depends, HTTPException, Query, Response, status
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


@protected_router.get("/investigations/containers")
def get_containers(
    state: Optional[str] = Query(default=None),
    runtime: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> Dict[str, Any]:
    """Retrieve observed container instances across Docker socket and procfs namespaces."""
    from logintel.containers import DockerSocketCollector, NamespaceInspector
    docker_col = DockerSocketCollector()
    containers = docker_col.list_containers(all_containers=True)
    if not containers:
        ns_insp = NamespaceInspector()
        containers = ns_insp.discover_containers()

    if state:
        st_lower = state.lower()
        containers = [c for c in containers if c.state.value == st_lower]

    if runtime:
        rt_lower = runtime.lower()
        containers = [c for c in containers if c.runtime.value == rt_lower]

    paginated = containers[:limit]
    return {
        "total": len(containers),
        "limit": limit,
        "items": [c.model_dump(mode="json") for c in paginated],
    }


@protected_router.get("/investigations/containers/{container_id}")
def get_container_detail(container_id: str) -> Dict[str, Any]:
    """Retrieve detailed properties, capabilities, and process bindings for a specific container."""
    from logintel.containers import DockerSocketCollector, NamespaceInspector
    docker_col = DockerSocketCollector()
    container = docker_col.inspect_container(container_id=container_id)
    if not container:
        ns_insp = NamespaceInspector()
        all_containers = ns_insp.discover_containers()
        matched = [c for c in all_containers if c.container_id == container_id or c.container_id.startswith(container_id)]
        if matched:
            container = matched[0]

    if not container:
        raise HTTPException(status_code=404, detail=f"Container '{container_id}' could not be resolved")
    return container.model_dump(mode="json")


@protected_router.get("/investigations/processes/{pid}/namespace")
def get_process_namespace_profile(pid: int) -> Dict[str, Any]:
    """Retrieve kernel namespace isolation profile and container binding for a host process."""
    from logintel.containers import NamespaceInspector
    ns_insp = NamespaceInspector()
    profile = ns_insp.inspect_process(pid=pid)
    if not profile:
        raise HTTPException(status_code=404, detail=f"Process PID '{pid}' could not be found or inspected")
    return profile.model_dump(mode="json")


@protected_router.get("/investigations/hosts/{host}/graph")
def get_host_telemetry_graph(host: str, limit: int = Query(default=200, ge=1, le=1000)) -> Dict[str, Any]:
    """Retrieve unified Linux host graph from telemetry events for a specified host."""
    from logintel.storage.investigation_repo import investigation_repo
    return investigation_repo.get_host_telemetry_graph(host=host, limit=limit)


@protected_router.get("/investigations/{incident_id}/host-graph")
def get_incident_host_graph(incident_id: int) -> Dict[str, Any]:
    """Retrieve unified Linux host graph contextualized for an incident's primary host and corroborated evidence."""
    from logintel.storage.investigation_repo import investigation_repo
    graph = investigation_repo.get_unified_host_graph(incident_id)
    if not graph:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found or has no host graph")
    return graph


class HostThreatEvaluationRequest(BaseModel):
    host: str = Field(description="Target host name")
    limit: int = Field(default=200, ge=1, le=1000)
    events: Optional[List[Dict[str, Any]]] = None
    alerts: Optional[List[Dict[str, Any]]] = None


@protected_router.get("/detection/host-rules")
def get_host_detection_rules_endpoint() -> Dict[str, Any]:
    """Retrieve all host security detection rules and associated MITRE ATT&CK techniques."""
    from logintel.detection.loader import load_default_rules
    from logintel.correlation.host_threat import TECHNIQUES_CATALOG
    all_rules = load_default_rules()
    host_rules = [r for r in all_rules if r.category == "SECURITY" or r.id.startswith("sec.")]
    
    items = []
    for r in host_rules:
        r_dict = r.model_dump(mode="json")
        matched_tech = None
        for tech in TECHNIQUES_CATALOG.values():
            if tech.name.lower() in r.name.lower() or tech.id.lower() in r.description.lower():
                matched_tech = tech.model_dump()
                break
        r_dict["mitre_technique"] = matched_tech
        items.append(r_dict)

    return {"items": items, "total": len(items)}


@protected_router.post("/correlation/host-threats/evaluate")
def evaluate_host_threats_endpoint(req: HostThreatEvaluationRequest) -> Dict[str, Any]:
    """Evaluate host telemetry on-demand and produce structured HostThreatAssessment."""
    from logintel.correlation.host_threat import HostThreatCorrelator
    from logintel.storage.investigation_repo import investigation_repo

    if req.events is not None:
        correlator = HostThreatCorrelator()
        assessment = correlator.correlate_host_telemetry(
            host=req.host,
            events=req.events,
            alerts=req.alerts or [],
        )
        return assessment.model_dump(mode="json")
    else:
        return investigation_repo.evaluate_host_telemetry_threat(host=req.host, limit=req.limit)


@protected_router.get("/correlation/host-threats/{incident_id}")
def get_incident_host_threat_assessment_endpoint(incident_id: int) -> Dict[str, Any]:
    """Retrieve structured host threat assessment and MITRE kill chain for an incident."""
    from logintel.storage.investigation_repo import investigation_repo
    assessment = investigation_repo.get_host_threat_assessment(incident_id)
    if not assessment:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found or has no host threat data")
    return assessment


class HostValidationEmulationRequest(BaseModel):
    scenario_type: str = Field(description="Emulated scenario type key")
    host: Optional[str] = Field(default="prod-linux-01", description="Target host name")


@protected_router.get("/system/host-validation")
def get_system_host_validation_endpoint() -> Dict[str, Any]:
    """Execute host readiness checks and full adversary emulation suite (Milestone M6.10)."""
    from logintel.validation.host_emulator import HostScenarioEmulator
    emulator = HostScenarioEmulator()
    report = emulator.run_full_validation_suite()
    return report.model_dump(mode="json")


@protected_router.post("/system/host-validation/emulate")
def emulate_host_scenario_endpoint(req: HostValidationEmulationRequest) -> Dict[str, Any]:
    """Execute specific adversary campaign scenario emulation on-demand (Milestone M6.10)."""
    from logintel.validation.host_emulator import EmulatedScenarioType, HostScenarioEmulator
    try:
        sc_type = EmulatedScenarioType(req.scenario_type)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scenario type '{req.scenario_type}'. Valid types: {[t.value for t in EmulatedScenarioType]}",
        )
    emulator = HostScenarioEmulator()
    result = emulator.emulate_scenario(scenario_type=sc_type, host=req.host or "prod-linux-01")
    return result.model_dump(mode="json")




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
    from logintel.identity.service import identity_service
    forensics = investigation_repo.get_event_forensics(event_id)
    if not forensics:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found")
    data = forensics.model_dump(mode="json")
    try:
        chain = identity_service.get_identity_chain_for_event(event_id)
        if chain:
            data["identity_chain"] = chain.model_dump(mode="json")
    except Exception:
        pass
    return data


@protected_router.get("/investigations/events/{event_id}/identity-chain")
def get_event_identity_chain(event_id: str) -> Dict[str, Any]:
    """Resolve end-to-end identity provenance chain and session continuity for a canonical event."""
    from logintel.identity.service import identity_service
    chain = identity_service.get_identity_chain_for_event(event_id)
    if not chain:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found")
    return chain.model_dump(mode="json")


@protected_router.get("/investigations/sessions/{session_id}")
def get_session_details(session_id: str, host: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve forensic session lifecycle, process executions, and privilege transitions."""
    from logintel.identity.service import identity_service
    session_data = identity_service.get_session_details(session_id=session_id, host=host)
    if not session_data:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")
    return session_data


@protected_router.get("/investigations/network/sockets")
def get_network_sockets(
    state: Optional[str] = Query(default=None),
    protocol: Optional[str] = Query(default=None),
    outbound_only: bool = Query(default=False),
    limit: int = Query(default=100, ge=1, le=500),
) -> Dict[str, Any]:
    """Retrieve active and listening network sockets across host procfs."""
    from logintel.network import SocketStateCollector
    collector = SocketStateCollector()
    snapshot = collector.take_snapshot()
    entries = snapshot.entries

    if state:
        st_upper = state.upper()
        entries = [e for e in entries if e.state.value == st_upper]

    if protocol:
        p_lower = protocol.lower()
        entries = [e for e in entries if e.protocol.value == p_lower]

    if outbound_only:
        entries = [e for e in entries if e.is_outbound]

    paginated = entries[:limit]
    return {
        "host": snapshot.host,
        "timestamp": snapshot.timestamp.isoformat(),
        "total": len(entries),
        "limit": limit,
        "items": [e.model_dump(mode="json") for e in paginated],
    }


@protected_router.get("/investigations/network/connections")
def get_network_connections(
    protocol: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> Dict[str, Any]:
    """Retrieve established network connections (inbound and outbound)."""
    return get_network_sockets(state="ESTABLISHED", protocol=protocol, outbound_only=False, limit=limit)


@protected_router.get("/investigations/filesystem/targets")
def get_filesystem_targets(
    category: Optional[str] = Query(default=None),
    epistemic_status: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> Dict[str, Any]:
    """Retrieve monitored high-value persistence targets and their current integrity states."""
    from logintel.filesystem import FilesystemPersistenceCollector
    collector = FilesystemPersistenceCollector()
    states = collector.scanner.scan_all()
    items = list(states.values())

    if category:
        cat_upper = category.upper()
        items = [s for s in items if s.category.value == cat_upper]

    if epistemic_status:
        ep_upper = epistemic_status.upper()
        items = [s for s in items if s.epistemic_status == ep_upper]

    paginated = items[:limit]
    return {
        "total": len(items),
        "limit": limit,
        "items": [s.model_dump(mode="json") for s in paginated],
    }


@protected_router.get("/investigations/filesystem/transitions")
def get_filesystem_transitions(
    transition_type: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> Dict[str, Any]:
    """Retrieve observed filesystem persistence drops and integrity transitions."""
    from logintel.filesystem import FilesystemPersistenceCollector
    collector = FilesystemPersistenceCollector()
    collector.collect_events()
    transitions = collector.get_transitions()

    if transition_type:
        tt_upper = transition_type.upper()
        transitions = [t for t in transitions if t.transition_type.value == tt_upper]

    paginated = transitions[:limit]
    return {
        "total": len(transitions),
        "limit": limit,
        "items": [t.model_dump(mode="json") for t in paginated],
    }


@protected_router.get("/investigations/systemd/units")
def get_systemd_units(
    unit_type: Optional[str] = Query(default=None),
    state: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> Dict[str, Any]:
    """Retrieve active and loaded systemd units and their operational lifecycle states."""
    from logintel.systemd import SystemdUnitTracker
    tracker = SystemdUnitTracker()
    units = tracker.list_units(unit_type=unit_type)

    if state:
        st_lower = state.lower()
        units = [u for u in units if u.active_state.value == st_lower]

    paginated = units[:limit]
    return {
        "total": len(units),
        "limit": limit,
        "items": [u.model_dump(mode="json") for u in paginated],
    }


@protected_router.get("/investigations/systemd/units/{unit_name}")
def get_systemd_unit_detail(unit_name: str) -> Dict[str, Any]:
    """Retrieve detailed properties and process bindings for a specific systemd unit."""
    from logintel.systemd import SystemdUnitTracker
    tracker = SystemdUnitTracker()
    unit = tracker.get_unit_details(unit_name=unit_name)
    if not unit:
        raise HTTPException(status_code=404, detail=f"Systemd unit '{unit_name}' could not be resolved")
    return unit.model_dump(mode="json")


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


class ReviewFindingApiRequest(BaseModel):
    review_state: str
    analyst_notes: str = ""
    reviewer: str = "SecAnalyst-1"


class DraftReportFromDossierApiRequest(BaseModel):
    title: Optional[str] = None
    analyst_notes: Optional[str] = None
    is_final: bool = False
    actor: str = "SecAnalyst-1"


@protected_router.get("/cases/{case_id}/dossier")
def get_investigation_dossier_endpoint(case_id: int) -> Dict[str, Any]:
    """Retrieve complete, deterministic investigation dossier with provenance manifests (M5.7)."""
    from logintel.ai.case_service import case_service

    try:
        dossier = case_service.get_investigation_dossier(case_id)
        return dossier.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.patch("/cases/{case_id}/findings/{finding_id}/review")
def review_case_finding_endpoint(case_id: int, finding_id: str, req: ReviewFindingApiRequest) -> Dict[str, Any]:
    """Update analyst review state for an investigation finding and record in audit log (M5.7)."""
    from logintel.ai.case_service import case_service

    try:
        review = case_service.update_finding_review(
            case_id=case_id,
            finding_id=finding_id,
            review_state=req.review_state,
            analyst_notes=req.analyst_notes,
            reviewer=req.reviewer,
        )
        return review
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@protected_router.get("/cases/{case_id}/evidence-matrix")
def get_case_evidence_matrix_endpoint(case_id: int) -> List[Dict[str, Any]]:
    """Retrieve deterministic hypothesis evidence matrix for a case (M5.7)."""
    from logintel.ai.case_service import case_service

    try:
        matrix = case_service.get_evidence_matrix(case_id)
        return [entry.model_dump(mode="json") for entry in matrix]
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/evidence-gaps/actions")
def get_case_evidence_gap_actions_endpoint(case_id: int) -> List[Dict[str, Any]]:
    """Retrieve actionable, analyst-controlled next steps derived from evidence gaps (M5.7)."""
    from logintel.ai.case_service import case_service

    try:
        actions = case_service.get_evidence_gap_actions(case_id)
        return [a.model_dump(mode="json") for a in actions]
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/timeline/intelligence")
def get_case_refined_timeline_endpoint(case_id: int) -> List[Dict[str, Any]]:
    """Retrieve multi-source chronological timeline with strict provenance demarcation (M5.7)."""
    from logintel.ai.case_service import case_service

    try:
        timeline = case_service.get_refined_timeline(case_id)
        return [item.model_dump(mode="json") for item in timeline]
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/hunt-results")
def get_case_hunt_results_endpoint(case_id: int) -> List[Dict[str, Any]]:
    """Retrieve governed threat hunting executions recorded for a case (M5.7)."""
    from logintel.ai.case_service import case_service

    try:
        return case_service.get_threat_hunt_results(case_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.post("/cases/{case_id}/briefing")
def get_case_briefing_endpoint(case_id: int) -> Dict[str, Any]:
    """Generate structured incident / case briefing for analyst decision support (M5.7)."""
    from logintel.ai.case_service import case_service

    try:
        briefing = case_service.get_case_briefing(case_id)
        return briefing.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.post("/cases/{case_id}/report/draft")
def draft_report_from_dossier_endpoint(case_id: int, req: Optional[DraftReportFromDossierApiRequest] = None) -> Dict[str, Any]:
    """Generate an immutable versioned report derived deterministically from the dossier (M5.7)."""
    from logintel.ai.case_service import case_service

    title = req.title if req else None
    notes = req.analyst_notes if req else None
    is_final = req.is_final if req else False
    actor = req.actor if req else "SecAnalyst-1"

    try:
        report = case_service.draft_report_from_dossier(
            case_id=case_id,
            title=title,
            analyst_notes=notes,
            is_final=is_final,
            actor=actor,
        )
        return report.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/provenance")
def get_case_provenance_manifest_endpoint(case_id: int) -> List[Dict[str, Any]]:
    """Retrieve verifiable provenance manifest linking statements to sources (M5.7)."""
    from logintel.ai.case_service import case_service

    try:
        manifest = case_service.get_provenance_manifest(case_id)
        return [entry.model_dump(mode="json") for entry in manifest]
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# =============================================================================
# Milestone 5.8: Investigation Graph & Evidence Relationship Intelligence
# =============================================================================

class GraphExplanationApiRequest(BaseModel):
    """Payload to request local AI explanation of a graph edge or path (M5.8)."""
    edge_id: Optional[str] = None
    path_nodes: Optional[List[str]] = None
    question: Optional[str] = None
    include_evidence_citations: bool = True


@protected_router.get("/cases/{case_id}/graph")
def get_investigation_graph_endpoint(
    case_id: int,
    max_nodes: int = 50,
    max_edges: int = 100,
    entity_type: Optional[str] = None,
    relationship_type: Optional[str] = None,
    epistemic_status: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
) -> Dict[str, Any]:
    """Retrieve bounded, evidence-bound investigation graph for a case (M5.8)."""
    from logintel.ai.case_service import case_service

    try:
        graph = case_service.get_investigation_graph(
            case_id=case_id,
            max_nodes=max_nodes,
            max_edges=max_edges,
            entity_type=entity_type,
            relationship_type=relationship_type,
            epistemic_status=epistemic_status,
            start_time=start_time,
            end_time=end_time,
        )
        return graph.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/graph/nodes/{node_id:path}")
def get_graph_node_detail_endpoint(case_id: int, node_id: str) -> Dict[str, Any]:
    """Retrieve detailed node inspection including connected edges and citations (M5.8)."""
    from logintel.ai.case_service import case_service

    try:
        return case_service.get_graph_node_detail(case_id, node_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/graph/edges/{edge_id:path}/evidence")
def get_graph_edge_evidence_endpoint(case_id: int, edge_id: str) -> Dict[str, Any]:
    """Deep forensic inspection for a specific graph edge including all citations (M5.8)."""
    from logintel.ai.case_service import case_service

    try:
        return case_service.get_graph_edge_evidence(case_id, edge_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/graph/pivots/{entity_type}/{entity_value}")
def get_entity_pivot_graph_endpoint(case_id: int, entity_type: str, entity_value: str) -> Dict[str, Any]:
    """Construct case-bounded entity pivot graph showing adjacent relationships (M5.8)."""
    from logintel.ai.case_service import case_service

    try:
        pivot = case_service.get_entity_pivot_graph(case_id, entity_type, entity_value)
        return pivot.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/graph/paths")
def get_investigation_path_endpoint(
    case_id: int,
    source: str,
    target: str,
    max_depth: int = 5,
) -> Dict[str, Any]:
    """Reconstruct bounded investigation path between source and target nodes (M5.8)."""
    from logintel.ai.case_service import case_service

    try:
        path = case_service.get_investigation_path(
            case_id=case_id,
            source_node_id=source,
            target_node_id=target,
            max_depth=max_depth,
        )
        if not path:
            raise HTTPException(status_code=404, detail=f"No connected path found between {source} and {target}")
        return path.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/graph/temporal-chain")
def get_graph_temporal_chain_endpoint(case_id: int) -> Dict[str, Any]:
    """Derive chronological relationship sequence with delta-time annotations (M5.8)."""
    from logintel.ai.case_service import case_service

    try:
        chain = case_service.get_temporal_chain(case_id)
        return chain.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.post("/cases/{case_id}/graph/explain")
def explain_graph_relationship_endpoint(
    case_id: int,
    req: Optional[GraphExplanationApiRequest] = None,
) -> Dict[str, Any]:
    """Generate advisory-only, citation-grounded narrative explanation of graph relationships (M5.8)."""
    from logintel.ai.case_service import case_service

    edge_id = req.edge_id if req else None
    path_nodes = req.path_nodes if req else None
    question = req.question if req else None

    try:
        explanation = case_service.explain_graph_relationship(
            case_id=case_id,
            edge_id=edge_id,
            path_nodes=path_nodes,
            question=question,
        )
        return explanation.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/graph/export")
def export_investigation_graph_endpoint(case_id: int, format: str = "json") -> Dict[str, Any]:
    """Export case investigation graph with full provenance in JSON or GraphML format (M5.8)."""
    from logintel.ai.case_service import case_service

    try:
        content = case_service.export_investigation_graph(case_id, format=format)
        return {"case_id": case_id, "format": format, "content": content}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# =============================================================================
# Milestone 5.9: Advanced Evidence Correlation, Clusters & Decision Support
# =============================================================================

class CorrelationExplanationApiRequest(BaseModel):
    cluster_id: Optional[str] = None
    sequence_id: Optional[str] = None
    question: Optional[str] = None


@protected_router.get("/cases/{case_id}/correlation/clusters")
def get_evidence_clusters_endpoint(case_id: int) -> Dict[str, Any]:
    """Retrieve multi-dimensional evidence clusters, behavioral sequences, and gaps for a case (M5.9)."""
    from logintel.ai.case_service import case_service

    try:
        clusters, sequences, gaps = case_service.get_evidence_clusters(case_id)
        return {
            "case_id": case_id,
            "clusters": [c.model_dump(mode="json") for c in clusters],
            "sequences": [s.model_dump(mode="json") for s in sequences],
            "gaps": [g.model_dump(mode="json") for g in gaps],
            "total_clusters": len(clusters),
            "total_sequences": len(sequences),
            "total_gaps": len(gaps),
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/correlation/clusters/{cluster_id}")
def get_evidence_cluster_detail_endpoint(case_id: int, cluster_id: str) -> Dict[str, Any]:
    """Retrieve single evidence cluster detail by ID (M5.9)."""
    from logintel.ai.case_service import case_service

    try:
        cluster = case_service.get_evidence_cluster_detail(case_id, cluster_id)
        if not cluster:
            raise HTTPException(status_code=404, detail=f"Cluster '{cluster_id}' not found in case {case_id}")
        return cluster.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/correlation/sequences")
def get_behavioral_sequences_endpoint(case_id: int) -> Dict[str, Any]:
    """Retrieve detected behavioral sequences and progression patterns (M5.9)."""
    from logintel.ai.case_service import case_service

    try:
        sequences = case_service.get_behavioral_sequences(case_id)
        return {
            "case_id": case_id,
            "sequences": [s.model_dump(mode="json") for s in sequences],
            "total_sequences": len(sequences),
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/correlation/hypotheses/{hypothesis_id}/support")
def get_hypothesis_correlation_support_endpoint(case_id: int, hypothesis_id: str) -> Dict[str, Any]:
    """Evaluate hypothesis support, contradiction, and gaps across evidence clusters (M5.9)."""
    from logintel.ai.case_service import case_service

    try:
        support = case_service.get_hypothesis_correlation_support(case_id, hypothesis_id)
        return support.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/correlation/gaps")
def get_correlation_evidence_gaps_endpoint(case_id: int) -> Dict[str, Any]:
    """Retrieve identified telemetry and corroboration gaps with recommended governed hunts (M5.9)."""
    from logintel.ai.case_service import case_service

    try:
        gaps = case_service.get_correlation_evidence_gaps(case_id)
        return {
            "case_id": case_id,
            "gaps": [g.model_dump(mode="json") for g in gaps],
            "total_gaps": len(gaps),
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.post("/cases/{case_id}/correlation/findings/generate")
def generate_findings_from_clusters_endpoint(case_id: int, actor: str = "SecAnalyst-1") -> Dict[str, Any]:
    """Deterministically derive investigation findings from evidence clusters and record audit entry (M5.9)."""
    from logintel.ai.case_service import case_service

    try:
        findings = case_service.generate_findings_from_clusters(case_id, actor=actor)
        return {
            "case_id": case_id,
            "generated_findings": [f.model_dump(mode="json") for f in findings],
            "total_generated": len(findings),
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/correlation/workbench/{entity_type}/{entity_value}")
def get_entity_workbench_dossier_endpoint(case_id: int, entity_type: str, entity_value: str) -> Dict[str, Any]:
    """Synthesize deep entity-centric investigation workbench dossier (M5.9)."""
    from logintel.ai.case_service import case_service

    try:
        workbench = case_service.get_entity_workbench_dossier(case_id, entity_type, entity_value)
        return workbench.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.post("/cases/{case_id}/correlation/explain")
def explain_correlation_cluster_endpoint(
    case_id: int,
    req: CorrelationExplanationApiRequest,
) -> Dict[str, Any]:
    """Generate advisory-only local AI explanation of correlation clusters and patterns (M5.9)."""
    from logintel.ai.case_service import case_service

    try:
        explanation = case_service.explain_correlation_cluster(
            case_id=case_id,
            cluster_id=req.cluster_id,
            sequence_id=req.sequence_id,
            question=req.question,
        )
        return explanation.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# =============================================================================
# Milestone 5.10: Temporal Investigation Reconstruction & Campaign Correlation
# =============================================================================

class TransitionReviewApiRequest(BaseModel):
    review_state: str
    analyst_notes: str = ""
    reviewed_by: str = "SecAnalyst-1"


class TemporalExplanationApiRequest(BaseModel):
    target_id: Optional[str] = None
    question: Optional[str] = None


@protected_router.get("/cases/{case_id}/timeline/reconstruction")
def get_temporal_reconstruction_endpoint(case_id: int) -> Dict[str, Any]:
    """Retrieve full deterministic temporal investigation reconstruction dossier (M5.10)."""
    from logintel.ai.case_service import case_service

    try:
        dossier = case_service.get_temporal_reconstruction(case_id)
        return dossier.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/timeline/episodes")
def get_temporal_episodes_endpoint(case_id: int) -> Dict[str, Any]:
    """Retrieve reconstructed temporal episodes for a case (M5.10)."""
    from logintel.ai.case_service import case_service

    try:
        episodes = case_service.get_temporal_episodes(case_id)
        return {
            "case_id": case_id,
            "episodes": [ep.model_dump(mode="json") for ep in episodes],
            "total_episodes": len(episodes),
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/timeline/transitions")
def get_temporal_transitions_endpoint(case_id: int) -> Dict[str, Any]:
    """Retrieve evidence-grounded transitions between entities and episodes (M5.10)."""
    from logintel.ai.case_service import case_service

    try:
        transitions = case_service.get_temporal_transitions(case_id)
        return {
            "case_id": case_id,
            "transitions": [tr.model_dump(mode="json") for tr in transitions],
            "total_transitions": len(transitions),
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/timeline/gaps")
def get_temporal_gaps_endpoint(case_id: int) -> Dict[str, Any]:
    """Retrieve temporal and telemetry visibility gaps for a case (M5.10)."""
    from logintel.ai.case_service import case_service

    try:
        gaps = case_service.get_temporal_gaps(case_id)
        return {
            "case_id": case_id,
            "gaps": [g.model_dump(mode="json") for g in gaps],
            "total_gaps": len(gaps),
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/timeline/sequences")
def get_temporal_sequences_endpoint(case_id: int) -> Dict[str, Any]:
    """Retrieve attack sequence reconstructions with MITRE technique alignment (M5.10)."""
    from logintel.ai.case_service import case_service

    try:
        sequences = case_service.get_temporal_sequences(case_id)
        return {
            "case_id": case_id,
            "attack_sequences": [s.model_dump(mode="json") for s in sequences],
            "total_sequences": len(sequences),
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/timeline/incidents")
def get_campaign_correlations_endpoint(case_id: int) -> Dict[str, Any]:
    """Retrieve categorical campaign-level incident correlations (M5.10)."""
    from logintel.ai.case_service import case_service

    try:
        corrs = case_service.get_campaign_correlations(case_id)
        return {
            "case_id": case_id,
            "campaign_correlations": [c.model_dump(mode="json") for c in corrs],
            "total_correlations": len(corrs),
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/timeline/incidents/{incident_id}/relations")
def get_incident_campaign_relation_endpoint(case_id: int, incident_id: int) -> Dict[str, Any]:
    """Retrieve relationship details for a specific related incident (M5.10)."""
    from logintel.ai.case_service import case_service

    try:
        relation = case_service.get_incident_campaign_relations(case_id, incident_id)
        if not relation:
            raise HTTPException(status_code=404, detail=f"No campaign correlation between case {case_id} and incident {incident_id}")
        return relation.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.post("/cases/{case_id}/timeline/transitions/{transition_id}/review")
def review_temporal_transition_endpoint(
    case_id: int,
    transition_id: str,
    req: TransitionReviewApiRequest,
) -> Dict[str, Any]:
    """Record analyst review for a temporal transition preserving epistemic separation (M5.10)."""
    from logintel.ai.case_service import case_service

    try:
        result = case_service.review_temporal_transition(
            case_id=case_id,
            transition_id=transition_id,
            review_state=req.review_state,
            notes=req.analyst_notes,
            actor=req.reviewed_by,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.post("/cases/{case_id}/timeline/explain")
def explain_temporal_reconstruction_endpoint(
    case_id: int,
    req: TemporalExplanationApiRequest,
) -> Dict[str, Any]:
    """Generate strictly advisory-only local AI explanation of temporal reconstruction (M5.10)."""
    from logintel.ai.case_service import case_service

    try:
        explanation = case_service.explain_temporal_reconstruction(
            case_id=case_id,
            target_id=req.target_id,
            question=req.question,
        )
        return explanation.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/timeline/export")
def export_temporal_reconstruction_endpoint(
    case_id: int,
    format: str = Query(default="json", pattern="^(json|csv|graphml)$"),
) -> Response:
    """Export temporal reconstruction in JSON, CSV, or GraphML format (M5.10)."""
    from fastapi.responses import PlainTextResponse
    from logintel.ai.case_service import case_service

    try:
        content = case_service.export_temporal_reconstruction(case_id, format=format)
        media_type = "application/json"
        if format.lower() == "csv":
            media_type = "text/csv"
        elif format.lower() == "graphml":
            media_type = "application/xml"
        return PlainTextResponse(content=content, media_type=media_type)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# -----------------------------------------------------------------------------
# M5.11 Case Assessment & Investigation Closure Endpoints
# -----------------------------------------------------------------------------

class FindingReviewRequest(BaseModel):
    review_state: str = Field(..., pattern="^(UNREVIEWED|ACCEPTED|REJECTED|DISPUTED)$")
    analyst_notes: str = Field(default="", max_length=2000)
    reviewed_by: str = Field(default="SecAnalyst-1", max_length=100)


class CreateQuestionRequest(BaseModel):
    question: str = Field(..., min_length=5, max_length=1000)
    category: str = Field(default="AUTHENTICATION")
    related_evidence: List[str] = Field(default_factory=list)
    related_entities: List[str] = Field(default_factory=list)
    recommended_query: Optional[str] = Field(default=None, max_length=1000)
    created_by: str = Field(default="SecAnalyst-1", max_length=100)


class UpdateQuestionStatusRequest(BaseModel):
    status: str = Field(..., pattern="^(OPEN|INVESTIGATING|ANSWERED|UNRESOLVED|NOT_APPLICABLE)$")
    resolution_notes: Optional[str] = Field(default=None, max_length=2000)
    actor: str = Field(default="SecAnalyst-1", max_length=100)


class AnalystAssessmentRequest(BaseModel):
    analyst_assessment: str = Field(..., max_length=5000)
    actor: str = Field(default="SecAnalyst-1", max_length=100)


class AssessmentExplanationRequest(BaseModel):
    target_id: Optional[str] = Field(default=None, max_length=120)
    query: Optional[str] = Field(default=None, max_length=1000)


@protected_router.get("/cases/{case_id}/assessment")
def get_case_assessment_endpoint(
    case_id: int,
    refresh: bool = Query(default=False),
) -> Dict[str, Any]:
    """Retrieve or synthesize comprehensive case assessment (M5.11)."""
    from logintel.ai.case_service import case_service

    try:
        assessment = case_service.get_case_assessment(case_id, refresh=refresh)
        return assessment.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/assessment/findings")
def get_case_findings_endpoint(case_id: int) -> Dict[str, Any]:
    """Retrieve key findings for case assessment (M5.11)."""
    from logintel.ai.case_service import case_service

    try:
        findings = case_service.get_case_findings(case_id)
        return {
            "case_id": case_id,
            "findings": [f.model_dump(mode="json") for f in findings],
            "total_findings": len(findings),
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.post("/cases/{case_id}/assessment/findings/{finding_id}/review")
def review_case_finding_endpoint(
    case_id: int,
    finding_id: str,
    req: FindingReviewRequest,
) -> Dict[str, Any]:
    """Record analyst review for a finding preserving epistemic status (M5.11)."""
    from logintel.ai.case_service import case_service

    try:
        result = case_service.review_case_finding(
            case_id=case_id,
            finding_id=finding_id,
            review_state=req.review_state,
            notes=req.analyst_notes,
            actor=req.reviewed_by,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/assessment/hypotheses")
def get_case_hypotheses_endpoint(case_id: int) -> Dict[str, Any]:
    """Retrieve competing hypotheses assessment (M5.11)."""
    from logintel.ai.case_service import case_service

    try:
        hypotheses = case_service.get_case_hypotheses(case_id)
        return {
            "case_id": case_id,
            "hypotheses": [h.model_dump(mode="json") for h in hypotheses],
            "total_hypotheses": len(hypotheses),
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/assessment/questions")
def get_case_questions_endpoint(case_id: int) -> Dict[str, Any]:
    """Retrieve investigation questions for case (M5.11)."""
    from logintel.ai.case_service import case_service

    try:
        questions = case_service.get_case_questions(case_id)
        return {
            "case_id": case_id,
            "questions": [q.model_dump(mode="json") for q in questions],
            "total_questions": len(questions),
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.post("/cases/{case_id}/assessment/questions")
def create_case_question_endpoint(
    case_id: int,
    req: CreateQuestionRequest,
) -> Dict[str, Any]:
    """Create a new investigation question (M5.11)."""
    from logintel.ai.case_service import case_service

    try:
        result = case_service.create_case_question(
            case_id=case_id,
            question=req.question,
            category=req.category,
            related_evidence=req.related_evidence,
            related_entities=req.related_entities,
            recommended_query=req.recommended_query,
            actor=req.created_by,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.post("/cases/{case_id}/assessment/questions/{question_id}/status")
def update_case_question_status_endpoint(
    case_id: int,
    question_id: str,
    req: UpdateQuestionStatusRequest,
) -> Dict[str, Any]:
    """Update status of an investigation question (M5.11)."""
    from logintel.ai.case_service import case_service

    try:
        result = case_service.update_case_question_status(
            case_id=case_id,
            question_id=question_id,
            status=req.status,
            resolution_notes=req.resolution_notes,
            actor=req.actor,
        )
        return result
    except (ValueError, KeyError) as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/assessment/gaps")
def get_case_gaps_endpoint(case_id: int) -> Dict[str, Any]:
    """Retrieve prioritized evidence gaps (M5.11)."""
    from logintel.ai.case_service import case_service

    try:
        gaps = case_service.get_case_gaps(case_id)
        return {
            "case_id": case_id,
            "evidence_gaps": [g.model_dump(mode="json") for g in gaps],
            "total_gaps": len(gaps),
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/assessment/readiness")
def get_case_closure_readiness_endpoint(case_id: int) -> Dict[str, Any]:
    """Retrieve deterministic closure readiness assessment (M5.11)."""
    from logintel.ai.case_service import case_service

    try:
        readiness = case_service.get_closure_readiness(case_id)
        return readiness.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.post("/cases/{case_id}/assessment/analyst-assessment")
def record_analyst_assessment_endpoint(
    case_id: int,
    req: AnalystAssessmentRequest,
) -> Dict[str, Any]:
    """Record analyst-authored case assessment text (M5.11)."""
    from logintel.ai.case_service import case_service

    try:
        assessment = case_service.record_analyst_assessment(
            case_id=case_id,
            analyst_assessment=req.analyst_assessment,
            actor=req.actor,
        )
        return assessment.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/assessment/briefing")
def get_investigation_briefing_endpoint(case_id: int) -> Dict[str, Any]:
    """Retrieve deterministic 15-section investigation briefing (M5.11)."""
    from logintel.ai.case_service import case_service

    try:
        briefing = case_service.get_investigation_briefing(case_id)
        return briefing.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/assessment/handoff")
def get_case_handoff_endpoint(
    case_id: int,
    actor: str = Query(default="SecAnalyst-1"),
) -> Dict[str, Any]:
    """Retrieve structured analyst handoff package (M5.11)."""
    from logintel.ai.case_service import case_service

    try:
        handoff = case_service.get_case_handoff(case_id, actor=actor)
        return handoff.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.post("/cases/{case_id}/assessment/explain")
def explain_case_assessment_endpoint(
    case_id: int,
    req: AssessmentExplanationRequest,
) -> Dict[str, Any]:
    """Generate strictly advisory-only local AI explanation of assessment or finding (M5.11)."""
    from logintel.ai.case_service import case_service

    try:
        explanation = case_service.explain_case_assessment(
            case_id=case_id,
            target_id=req.target_id,
            query=req.query,
        )
        return explanation.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


class BookmarkRequest(BaseModel):
    analyst_note: Optional[str] = None
    actor: str = "SecAnalyst-1"


@protected_router.get("/cases/{case_id}/timeline/unified")
def get_unified_case_timeline_endpoint(
    case_id: int,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
    host: Optional[str] = None,
    layer: Optional[str] = None,
    event_type: Optional[str] = None,
    source: Optional[str] = None,
    entity: Optional[str] = None,
    epistemic_status: Optional[str] = None,
    collection_status: Optional[str] = None,
    bookmarked_only: bool = False,
    search: Optional[str] = Query(default=None, max_length=200),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """Retrieve unified, multi-layer investigation timeline projection with deterministic ordering (M7.2)."""
    from logintel.timeline.service import timeline_service
    from logintel.timeline.models import TimelineFilterParams, EpistemicStatus, CollectionStatus

    try:
        ep_status = EpistemicStatus(epistemic_status) if epistemic_status else None
    except Exception:
        ep_status = None

    try:
        col_status = CollectionStatus(collection_status) if collection_status else None
    except Exception:
        col_status = None

    params = TimelineFilterParams(
        time_start=time_start,
        time_end=time_end,
        host=host,
        layer=layer,
        event_type=event_type,
        source=source,
        entity=entity,
        epistemic_status=ep_status,
        collection_status=col_status,
        bookmarked_only=bookmarked_only,
        search=search,
        limit=limit,
        offset=offset,
    )

    try:
        res = timeline_service.query_timeline(case_id, params)
        return res.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/timeline/replay")
def get_case_timeline_replay_endpoint(
    case_id: int,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
    host: Optional[str] = None,
    layer: Optional[str] = None,
    event_type: Optional[str] = None,
    source: Optional[str] = None,
    entity: Optional[str] = None,
    epistemic_status: Optional[str] = None,
    collection_status: Optional[str] = None,
    bookmarked_only: bool = False,
    search: Optional[str] = Query(default=None, max_length=200),
) -> Dict[str, Any]:
    """Retrieve complete deterministic replay session context with frames and indexes (M7.2)."""
    from logintel.timeline.service import timeline_service
    from logintel.timeline.models import TimelineFilterParams, EpistemicStatus, CollectionStatus

    try:
        ep_status = EpistemicStatus(epistemic_status) if epistemic_status else None
    except Exception:
        ep_status = None

    try:
        col_status = CollectionStatus(collection_status) if collection_status else None
    except Exception:
        col_status = None

    params = TimelineFilterParams(
        time_start=time_start,
        time_end=time_end,
        host=host,
        layer=layer,
        event_type=event_type,
        source=source,
        entity=entity,
        epistemic_status=ep_status,
        collection_status=col_status,
        bookmarked_only=bookmarked_only,
        search=search,
        limit=500,
    )

    try:
        session = timeline_service.get_replay_session(case_id, params)
        return session.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/timeline/context/{timeline_id}")
def get_timeline_context_endpoint(
    case_id: int,
    timeline_id: str,
) -> Dict[str, Any]:
    """Retrieve synchronized context linking timeline event to graph, evidence, and raw source (M7.2)."""
    from logintel.timeline.service import timeline_service

    try:
        ctx = timeline_service.get_timeline_context(case_id, timeline_id)
        return ctx.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.post("/cases/{case_id}/timeline/{timeline_id}/bookmark")
def bookmark_timeline_item_endpoint(
    case_id: int,
    timeline_id: str,
    req: BookmarkRequest,
) -> Dict[str, Any]:
    """Record analyst bookmark reference in cases.db without mutating forensic telemetry (M7.2)."""
    from logintel.timeline.service import timeline_service

    try:
        return timeline_service.bookmark_item(
            case_id=case_id,
            timeline_id=timeline_id,
            analyst_note=req.analyst_note,
            actor=req.actor,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.delete("/cases/{case_id}/timeline/{timeline_id}/bookmark")
def remove_timeline_bookmark_endpoint(
    case_id: int,
    timeline_id: str,
    actor: str = Query(default="SecAnalyst-1"),
) -> Dict[str, Any]:
    """Remove analyst bookmark reference in cases.db (M7.2)."""
    from logintel.timeline.service import timeline_service

    try:
        return timeline_service.remove_bookmark(
            case_id=case_id,
            timeline_id=timeline_id,
            actor=actor,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/timeline/unified/export")
def export_unified_timeline_endpoint(
    case_id: int,
    format: str = Query(default="json", pattern="^(?i)(json|csv)$"),
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
    host: Optional[str] = None,
    layer: Optional[str] = None,
    event_type: Optional[str] = None,
    source: Optional[str] = None,
    entity: Optional[str] = None,
    epistemic_status: Optional[str] = None,
    collection_status: Optional[str] = None,
    bookmarked_only: bool = False,
    search: Optional[str] = Query(default=None, max_length=200),
) -> Response:
    """Export case timeline deterministically in JSON or CSV format (M7.2)."""
    from logintel.timeline.service import timeline_service
    from logintel.timeline.models import TimelineFilterParams, EpistemicStatus, CollectionStatus

    try:
        ep_status = EpistemicStatus(epistemic_status) if epistemic_status else None
    except Exception:
        ep_status = None

    try:
        col_status = CollectionStatus(collection_status) if collection_status else None
    except Exception:
        col_status = None

    params = TimelineFilterParams(
        time_start=time_start,
        time_end=time_end,
        host=host,
        layer=layer,
        event_type=event_type,
        source=source,
        entity=entity,
        epistemic_status=ep_status,
        collection_status=col_status,
        bookmarked_only=bookmarked_only,
        search=search,
        limit=500,
    )

    try:
        content, media_type = timeline_service.export_timeline(case_id, export_format=format, params=params)
        ext = "csv" if format.lower() == "csv" else "json"
        filename = f"case_{case_id}_timeline.{ext}"
        return Response(
            content=content,
            media_type=media_type,
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# -----------------------------------------------------------------------------
# M7.3 Logical Evidence Collections & Evidence Workbench Endpoints
# -----------------------------------------------------------------------------

@protected_router.get("/cases/{case_id}/evidence/collections")
def list_case_evidence_collections_endpoint(
    case_id: int,
    status: Optional[str] = None,
    search_text: Optional[str] = Query(default=None, max_length=512),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> List[Dict[str, Any]]:
    """List logical evidence collections scoped to an investigation case (M7.3)."""
    from logintel.collections.service import workbench_service
    from logintel.collections.models import EvidenceCollectionStatus

    try:
        st = EvidenceCollectionStatus(status) if status else None
    except Exception:
        st = None

    try:
        cols = workbench_service.get_collections(
            case_id=case_id,
            status=st,
            search_text=search_text,
            limit=limit,
            offset=offset,
        )
        return [c.model_dump(mode="json") for c in cols]
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.post("/cases/{case_id}/evidence/collections")
def create_case_evidence_collection_endpoint(
    case_id: int,
    req: Dict[str, Any],
) -> Dict[str, Any]:
    """Create a new logical evidence collection within a case (M7.3)."""
    from logintel.collections.service import workbench_service
    from logintel.collections.models import CreateCollectionRequest

    try:
        validated = CreateCollectionRequest(**req)
        col = workbench_service.create_collection(
            case_id=case_id,
            name=validated.name,
            description=validated.description,
            tags=validated.tags,
            actor="SecAnalyst-1",
        )
        return col.model_dump(mode="json")
    except ValueError as e:
        if "not found" in str(e).lower():
            raise HTTPException(status_code=404, detail=str(e))
        raise HTTPException(status_code=422, detail=str(e))


@protected_router.get("/cases/{case_id}/evidence/collections/{collection_id}")
def get_case_evidence_collection_endpoint(
    case_id: int,
    collection_id: str,
) -> Dict[str, Any]:
    """Get single collection details and its resolved evidence references (M7.3)."""
    from logintel.collections.service import workbench_service

    try:
        col = workbench_service.get_collection(case_id, collection_id)
        return col.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.patch("/cases/{case_id}/evidence/collections/{collection_id}")
def update_case_evidence_collection_endpoint(
    case_id: int,
    collection_id: str,
    req: Dict[str, Any],
) -> Dict[str, Any]:
    """Update collection metadata or lifecycle status (M7.3)."""
    from logintel.collections.service import workbench_service
    from logintel.collections.models import UpdateCollectionRequest

    try:
        validated = UpdateCollectionRequest(**req)
        col = workbench_service.update_collection(
            case_id=case_id,
            collection_id=collection_id,
            name=validated.name,
            description=validated.description,
            status=validated.status,
            tags=validated.tags,
            actor="SecAnalyst-1",
        )
        return col.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.delete("/cases/{case_id}/evidence/collections/{collection_id}")
def delete_case_evidence_collection_endpoint(
    case_id: int,
    collection_id: str,
) -> Dict[str, Any]:
    """Delete an evidence collection without mutating or deleting underlying evidence (M7.3)."""
    from logintel.collections.service import workbench_service

    try:
        workbench_service.delete_collection(case_id, collection_id, actor="SecAnalyst-1")
        return {"success": True, "deleted_collection_id": collection_id}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.post("/cases/{case_id}/evidence/collections/{collection_id}/items")
def add_collection_item_endpoint(
    case_id: int,
    collection_id: str,
    req: Dict[str, Any],
) -> Dict[str, Any]:
    """Add an evidence reference to an investigation collection (M7.3)."""
    from logintel.collections.service import workbench_service
    from logintel.collections.models import AddCollectionItemRequest

    try:
        validated = AddCollectionItemRequest(**req)
        item = workbench_service.add_item_to_collection(
            case_id=case_id,
            collection_id=collection_id,
            source_type=validated.source_type,
            source_id=validated.source_id,
            role=validated.role or "SUPPORTING",
            epistemic_status=validated.epistemic_status,
            citation_tag=validated.citation_tag,
            analyst_annotation=validated.analyst_annotation,
            actor="SecAnalyst-1",
        )
        return item.model_dump(mode="json")
    except ValueError as e:
        if "not found" in str(e).lower():
            raise HTTPException(status_code=404, detail=str(e))
        raise HTTPException(status_code=422, detail=str(e))


@protected_router.patch("/cases/{case_id}/evidence/collections/{collection_id}/items/{item_id}")
def update_collection_item_endpoint(
    case_id: int,
    collection_id: str,
    item_id: str,
    req: Dict[str, Any],
) -> Dict[str, Any]:
    """Update role, annotation, or order index of a collection member (M7.3)."""
    from logintel.collections.service import workbench_service
    from logintel.collections.models import UpdateCollectionItemRequest

    try:
        validated = UpdateCollectionItemRequest(**req)
        item = workbench_service.update_collection_item(
            case_id=case_id,
            collection_id=collection_id,
            item_id=item_id,
            role=validated.role,
            analyst_annotation=validated.analyst_annotation,
            order_index=validated.order_index,
            actor="SecAnalyst-1",
        )
        return item.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.delete("/cases/{case_id}/evidence/collections/{collection_id}/items/{item_id}")
def remove_collection_item_endpoint(
    case_id: int,
    collection_id: str,
    item_id: str,
) -> Dict[str, Any]:
    """Remove an item from a collection without modifying underlying forensic evidence (M7.3)."""
    from logintel.collections.service import workbench_service

    try:
        removed = workbench_service.remove_item_from_collection(
            case_id=case_id,
            collection_id=collection_id,
            item_id=item_id,
            actor="SecAnalyst-1",
        )
        return {"success": removed, "removed_item_id": item_id}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/evidence/workbench")
def get_evidence_workbench_endpoint(
    case_id: int,
    collection_id: Optional[str] = None,
    source_type: Optional[str] = None,
    epistemic_status: Optional[str] = None,
    host: Optional[str] = None,
    search_text: Optional[str] = Query(default=None, max_length=512),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """Retrieve integrated Evidence Workbench state with collections, items, and filters (M7.3)."""
    from logintel.collections.service import workbench_service
    from logintel.collections.models import WorkbenchFilterParams
    from logintel.timeline.models import EpistemicStatus

    try:
        ep_status = EpistemicStatus(epistemic_status) if epistemic_status else None
    except Exception:
        ep_status = None

    params = WorkbenchFilterParams(
        collection_id=collection_id,
        source_type=source_type,
        epistemic_status=ep_status,
        host=host,
        search_text=search_text,
        limit=limit,
        offset=offset,
    )

    try:
        res = workbench_service.get_workbench_data(case_id, params)
        return res.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/evidence/collections/{collection_id}/export")
def export_evidence_collection_endpoint(
    case_id: int,
    collection_id: str,
    format: str = Query(default="json", pattern="^(json|csv)$"),
) -> Response:
    """Export evidence collection deterministically in JSON or CSV format (M7.3)."""
    from logintel.collections.service import workbench_service

    try:
        content = workbench_service.export_collection(case_id, collection_id, format_type=format)
        media_type = "text/csv" if format.lower() == "csv" else "application/json"
        filename = f"case_{case_id}_{collection_id}_export.{format.lower()}"
        return Response(
            content=content,
            media_type=media_type,
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# -----------------------------------------------------------------------------
# M7.4 Findings & Hypothesis Workbench Endpoints
# -----------------------------------------------------------------------------

from logintel.findings.models import (
    AddFindingEvidenceRequest,
    AddHypothesisGapRequest,
    CreateFindingRequest,
    CreateHypothesisM74Request,
    ReviewFindingRequest,
    UpdateFindingRequest,
    UpdateHypothesisM74Request,
)
from logintel.findings.service import findings_workbench_service


@protected_router.get("/cases/{case_id}/findings/workbench")
def get_findings_workbench_endpoint(case_id: int) -> Dict[str, Any]:
    """Retrieve full Findings & Hypothesis Workbench state (M7.4)."""
    try:
        wb = findings_workbench_service.get_findings_workbench(case_id)
        return wb.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/findings/export")
def export_findings_workbench_endpoint(
    case_id: int,
    format: str = Query(default="json", pattern="^(json|csv)$"),
) -> Response:
    """Export findings and hypotheses deterministically in JSON or CSV format (M7.4)."""
    try:
        res = findings_workbench_service.export_findings(case_id, format=format)
        media_type = "text/csv" if format.lower() == "csv" else "application/json"
        filename = f"case_{case_id}_findings_export.{format.lower()}"
        return Response(
            content=res.content,
            media_type=media_type,
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/findings")
def list_case_findings_endpoint(case_id: int) -> Dict[str, Any]:
    """List all analyst-authored findings for a case (M7.4)."""
    try:
        findings = findings_workbench_service.get_findings(case_id)
        return {
            "case_id": case_id,
            "findings": [f.model_dump(mode="json") for f in findings],
            "total_findings": len(findings),
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.post("/cases/{case_id}/findings")
def create_case_finding_endpoint(
    case_id: int,
    req: CreateFindingRequest,
) -> Dict[str, Any]:
    """Create a new analyst-authored finding (M7.4)."""
    try:
        finding = findings_workbench_service.create_finding(case_id, req, actor=req.created_by)
        return finding.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/findings/{finding_id}")
def get_case_finding_endpoint(case_id: int, finding_id: str) -> Dict[str, Any]:
    """Retrieve single finding with version history and evidence references (M7.4)."""
    try:
        finding = findings_workbench_service.get_finding(case_id, finding_id)
        return finding.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.patch("/cases/{case_id}/findings/{finding_id}")
def update_case_finding_endpoint(
    case_id: int,
    finding_id: str,
    req: UpdateFindingRequest,
) -> Dict[str, Any]:
    """Update finding attributes, creating a new deterministic version (M7.4)."""
    try:
        finding = findings_workbench_service.update_finding(case_id, finding_id, req, actor=req.updated_by)
        return finding.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.delete("/cases/{case_id}/findings/{finding_id}")
def delete_case_finding_endpoint(case_id: int, finding_id: str) -> Dict[str, Any]:
    """Delete finding organizational record. Underlying evidence is preserved (M7.4)."""
    try:
        findings_workbench_service.delete_finding(case_id, finding_id)
        return {"status": "DELETED", "finding_id": finding_id, "evidence_preserved": True}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.post("/cases/{case_id}/findings/{finding_id}/evidence")
def add_finding_evidence_endpoint(
    case_id: int,
    finding_id: str,
    req: AddFindingEvidenceRequest,
) -> Dict[str, Any]:
    """Attach supporting or contradicting evidence reference to finding (M7.4)."""
    try:
        finding = findings_workbench_service.add_finding_evidence(case_id, finding_id, req, actor=req.added_by)
        return finding.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.delete("/cases/{case_id}/findings/{finding_id}/evidence/{source_id}")
def remove_finding_evidence_endpoint(
    case_id: int,
    finding_id: str,
    source_id: str,
) -> Dict[str, Any]:
    """Remove evidence reference from finding. Underlying evidence is preserved (M7.4)."""
    try:
        finding = findings_workbench_service.remove_finding_evidence(case_id, finding_id, source_id)
        return finding.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.post("/cases/{case_id}/findings/{finding_id}/review")
def review_finding_m74_endpoint(
    case_id: int,
    finding_id: str,
    req: ReviewFindingRequest,
) -> Dict[str, Any]:
    """Perform analyst review on finding. Epistemic status remains decoupled (M7.4)."""
    try:
        finding = findings_workbench_service.review_finding(case_id, finding_id, req, actor=req.reviewed_by)
        return finding.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/hypotheses/workbench")
def get_hypotheses_workbench_endpoint(case_id: int) -> Dict[str, Any]:
    """List enriched hypotheses with supporting/contradicting evidence and gaps (M7.4)."""
    try:
        hypotheses = findings_workbench_service.get_hypotheses(case_id)
        return {
            "case_id": case_id,
            "hypotheses": [h.model_dump(mode="json") for h in hypotheses],
            "total_hypotheses": len(hypotheses),
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.get("/cases/{case_id}/hypotheses/compare")
def compare_hypotheses_endpoint(case_id: int) -> Dict[str, Any]:
    """Categorical side-by-side comparison of competing hypotheses (M7.4)."""
    try:
        comp = findings_workbench_service.compare_hypotheses(case_id)
        return comp.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.post("/cases/{case_id}/hypotheses/m74")
def create_hypothesis_m74_endpoint(
    case_id: int,
    req: CreateHypothesisM74Request,
) -> Dict[str, Any]:
    """Create an enriched investigative hypothesis (M7.4)."""
    try:
        hyp = findings_workbench_service.create_hypothesis(case_id, req, actor=req.created_by)
        return hyp.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.patch("/cases/{case_id}/hypotheses/m74/{hypothesis_id}")
def update_hypothesis_m74_endpoint(
    case_id: int,
    hypothesis_id: str,
    req: UpdateHypothesisM74Request,
) -> Dict[str, Any]:
    """Update hypothesis statement, status, assessment, or tags (M7.4)."""
    try:
        hyp = findings_workbench_service.update_hypothesis(case_id, hypothesis_id, req, actor=req.updated_by)
        return hyp.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.delete("/cases/{case_id}/hypotheses/m74/{hypothesis_id}")
def delete_hypothesis_m74_endpoint(
    case_id: int,
    hypothesis_id: str,
) -> Dict[str, Any]:
    """Delete hypothesis. Underlying evidence and findings remain preserved (M7.4)."""
    try:
        findings_workbench_service.delete_hypothesis(case_id, hypothesis_id)
        return {"status": "DELETED", "hypothesis_id": hypothesis_id, "evidence_preserved": True}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.post("/cases/{case_id}/hypotheses/{hypothesis_id}/evidence")
def add_hypothesis_evidence_endpoint(
    case_id: int,
    hypothesis_id: str,
    evidence_tag: str = Query(...),
    is_contradicting: bool = Query(default=False),
) -> Dict[str, Any]:
    """Add supporting or contradicting evidence tag to hypothesis (M7.4)."""
    try:
        hyp = findings_workbench_service.add_hypothesis_evidence(
            case_id, hypothesis_id, evidence_tag=evidence_tag, is_contradicting=is_contradicting
        )
        return hyp.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.delete("/cases/{case_id}/hypotheses/{hypothesis_id}/evidence/{evidence_tag}")
def remove_hypothesis_evidence_endpoint(
    case_id: int,
    hypothesis_id: str,
    evidence_tag: str,
) -> Dict[str, Any]:
    """Remove evidence tag from hypothesis. Evidence remains preserved (M7.4)."""
    try:
        hyp = findings_workbench_service.remove_hypothesis_evidence(case_id, hypothesis_id, evidence_tag=evidence_tag)
        return hyp.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@protected_router.post("/cases/{case_id}/hypotheses/{hypothesis_id}/gaps")
def add_hypothesis_gap_endpoint(
    case_id: int,
    hypothesis_id: str,
    req: AddHypothesisGapRequest,
) -> Dict[str, Any]:
    """Record an explicit evidence gap on a hypothesis (M7.4)."""
    try:
        hyp = findings_workbench_service.add_hypothesis_gap(case_id, hypothesis_id, req, actor=req.detected_by)
        return hyp.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


router.include_router(protected_router)






