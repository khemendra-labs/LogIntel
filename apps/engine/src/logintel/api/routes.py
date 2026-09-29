"""FastAPI routing and endpoints for LogIntel local IPC/API contract."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from logintel.config import settings
from logintel.health import TelemetryHealthReport, health_service
from logintel.ingestion import ingestion_engine
from logintel.models import CanonicalEvent
from logintel.storage.events_repo import events_repo

router = APIRouter(prefix="/api/v1")
start_time = time.time()


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


@router.get("/system/status", response_model=SystemStatusResponse)
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


@router.get("/telemetry/health", response_model=TelemetryHealthReport)
def get_telemetry_health() -> TelemetryHealthReport:
    return health_service.get_full_health(ingestion_engine.collectors)


@router.get("/events", response_model=EventsQueryResponse)
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


@router.get("/events/stats/summary")
def get_event_stats(hours: int = Query(default=24, ge=1, le=720)) -> Dict[str, Any]:
    return events_repo.get_event_statistics(hours=hours)


@router.get("/events/{event_id}")
def get_event_detail(event_id: str) -> Dict[str, Any]:
    event = events_repo.get_event_by_id(event_id)
    if not event:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found.")
    return event.model_dump(mode="json")


@router.get("/sources")
def get_sources() -> List[Dict[str, Any]]:
    return events_repo.get_all_ingestion_states()


@router.post("/ingestion/trigger")
def trigger_ingestion_cycle() -> Dict[str, Any]:
    ingested = ingestion_engine.run_cycle(historical=False)
    return {"status": "ok", "ingested_records": ingested}
