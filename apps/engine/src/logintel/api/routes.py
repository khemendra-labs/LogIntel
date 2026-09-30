"""FastAPI routing and endpoints for LogIntel local IPC/API contract."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
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


router.include_router(protected_router)


