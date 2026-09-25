"""
Traffic Simulator Controls Route.
"""

from typing import Optional
from fastapi import APIRouter, Query
from pydantic import BaseModel

from src.api.traffic_simulator import simulator

router = APIRouter(prefix="/simulator", tags=["Traffic Simulator"])


class SimulatorStatus(BaseModel):
    is_running: bool
    interval_seconds: float
    attack_probability: float


@router.get("/status", response_model=SimulatorStatus)
async def get_simulator_status():
    """Check if background traffic simulation is running."""
    return SimulatorStatus(
        is_running=simulator.is_running,
        interval_seconds=simulator.flow_interval,
        attack_probability=simulator.attack_probability,
    )


@router.post("/start", response_model=SimulatorStatus)
async def start_simulator(
    interval: float = Query(0.5, ge=0.1, le=5.0, description="Flow push interval in seconds"),
    attack_probability: float = Query(0.20, ge=0.0, le=1.0, description="Probability of generated flow being an attack"),
):
    """Start continuous background network traffic simulation."""
    simulator.start(interval=interval, attack_prob=attack_probability)
    return SimulatorStatus(
        is_running=simulator.is_running,
        interval_seconds=simulator.flow_interval,
        attack_probability=simulator.attack_probability,
    )


@router.post("/stop", response_model=SimulatorStatus)
async def stop_simulator():
    """Stop continuous background traffic simulation."""
    simulator.stop()
    return SimulatorStatus(
        is_running=simulator.is_running,
        interval_seconds=simulator.flow_interval,
        attack_probability=simulator.attack_probability,
    )


@router.post("/inject-attack")
async def inject_attack(
    attack_type: str = Query("PortScan", description="Attack type: PortScan, DoS, DDoS, Brute Force, Web Attack, Botnet")
):
    """Immediately inject a single targeted cyberattack into the NIDS engine."""
    result = await simulator.inject_attack(attack_type=attack_type)
    return {
        "status": "INJECTED",
        "attack_type": attack_type,
        "classification": result.classification,
        "confidence": result.confidence_score,
        "severity": result.severity,
        "alert_id": result.alert.alert_id if result.alert else None,
    }
