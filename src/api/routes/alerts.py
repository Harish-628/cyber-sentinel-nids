"""
SOC Alert Management Routes.
"""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from src.api.alert_store import store
from src.api.schemas import AlertStatusUpdate, SecurityAlert

router = APIRouter(prefix="/alerts", tags=["Security Alerts"])


@router.get("", response_model=List[SecurityAlert])
async def list_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, SUSPICIOUS"),
    status: Optional[str] = Query(None, description="Filter by status: NEW, INVESTIGATING, RESOLVED"),
    limit: int = Query(50, ge=1, le=500, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
):
    """Retrieve chronologically ordered (newest-first) security alerts with multi-criteria filtering."""
    return store.get_alerts(severity=severity, status=status, limit=limit, offset=offset)


@router.get("/{alert_id}", response_model=SecurityAlert)
async def get_alert(alert_id: str):
    """Retrieve detailed metadata and forensic flow metrics for a specific alert."""
    if alert_id in store.alerts_by_id:
        return store.alerts_by_id[alert_id]
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert {alert_id} not found")


@router.patch("/{alert_id}/status", response_model=SecurityAlert)
async def update_alert_status(alert_id: str, payload: AlertStatusUpdate):
    """Update alert triage status (NEW -> INVESTIGATING -> RESOLVED)."""
    updated = store.update_alert_status(alert_id, payload.status)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert {alert_id} not found")

    # Broadcast status change to connected dashboards
    await store.broadcast_event("ALERT_UPDATED", updated.model_dump())
    return updated
