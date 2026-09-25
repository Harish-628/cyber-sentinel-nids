"""
SOC Overview KPI & Threat Level Metrics Routes.
"""

from fastapi import APIRouter
from src.api.alert_store import store
from src.api.schemas import OverviewMetrics

router = APIRouter(prefix="/metrics", tags=["SOC Metrics"])


@router.get("/overview", response_model=OverviewMetrics)
async def get_overview_metrics():
    """
    Returns high-level SOC indicators:
    - Total Traffic Ingested
    - Threat Level & Threat Index (0-100)
    - Active Alerts count
    - Normal vs. Attack flow rate
    - Severity and attack category breakdowns
    """
    return store.get_overview_metrics()
