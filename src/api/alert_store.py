"""
SOC In-Memory Alert Store & Metric Aggregator.

Maintains:
- Ring buffers for flows and alerts
- Real-time time-series traffic metrics (1-second, 5-second, 1-minute aggregation buckets)
- Alert lifecycle state management (NEW -> INVESTIGATING -> RESOLVED)
- WebSocket client broadcast registry
"""

import asyncio
from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Set
from fastapi import WebSocket

from src.api.schemas import FlowAnalysisResponse, OverviewMetrics, SecurityAlert, TrafficPoint


class AlertStore:
    """Thread-safe state manager for alerts, flows, and metrics."""

    def __init__(self, max_flows: int = 10000, max_alerts: int = 5000):
        self.max_flows = max_flows
        self.max_alerts = max_alerts
        self.flows: Deque[FlowAnalysisResponse] = deque(maxlen=max_flows)
        self.alerts: Deque[SecurityAlert] = deque(maxlen=max_alerts)
        self.alerts_by_id: Dict[str, SecurityAlert] = {}
        
        # Real-time counters
        self.total_flows: int = 0
        self.total_attacks: int = 0
        self.benign_flows: int = 0
        self.attack_distribution: Dict[str, int] = {}
        self.severity_counts: Dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "SUSPICIOUS": 0,
            "NORMAL": 0,
        }

        # Time-series buckets: timestamp_str -> {total, normal, malicious, bytes}
        self.time_series_history: Deque[TrafficPoint] = deque(maxlen=60)
        
        # WebSocket subscriber set
        self.active_websockets: Set[WebSocket] = set()

    async def register_websocket(self, websocket: WebSocket):
        await websocket.accept()
        self.active_websockets.add(websocket)

    def unregister_websocket(self, websocket: WebSocket):
        self.active_websockets.discard(websocket)

    async def broadcast_event(self, event_type: str, data: Any):
        """Broadcast live event to all connected SOC dashboard WebSockets."""
        if not self.active_websockets:
            return
        
        message = {
            "type": event_type,
            "data": data,
            "alert": data if event_type == "NEW_ALERT" else None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        dead_sockets = set()
        
        for ws in self.active_websockets:
            try:
                await ws.send_json(message)
            except Exception:
                dead_sockets.add(ws)

        for dead in dead_sockets:
            self.active_websockets.discard(dead)

    async def add_flow_result(self, result: FlowAnalysisResponse, bytes_transferred: float = 1500.0):
        """Record flow analysis, update metrics, and broadcast."""
        self.flows.append(result)
        self.total_flows += 1

        now_sec = datetime.now(timezone.utc).strftime("%H:%M:%S")

        if result.is_malicious:
            self.total_attacks += 1
            cls = result.classification
            self.attack_distribution[cls] = self.attack_distribution.get(cls, 0) + 1
            self.severity_counts[result.severity] = self.severity_counts.get(result.severity, 0) + 1

            if result.alert:
                self.alerts.append(result.alert)
                self.alerts_by_id[result.alert.alert_id] = result.alert
                await self.broadcast_event("NEW_ALERT", result.alert.model_dump())
        else:
            self.benign_flows += 1
            self.severity_counts["NORMAL"] = self.severity_counts.get("NORMAL", 0) + 1

        # Update time series point
        if self.time_series_history and self.time_series_history[-1].timestamp == now_sec:
            pt = self.time_series_history[-1]
            pt.total_flows += 1
            if result.is_malicious:
                pt.malicious_flows += 1
            else:
                pt.normal_flows += 1
            pt.bytes_transferred += bytes_transferred
        else:
            new_pt = TrafficPoint(
                timestamp=now_sec,
                total_flows=1,
                normal_flows=0 if result.is_malicious else 1,
                malicious_flows=1 if result.is_malicious else 0,
                bytes_transferred=bytes_transferred,
            )
            self.time_series_history.append(new_pt)

        # Broadcast live flow
        await self.broadcast_event("FLOW_INGESTED", {
            "flow_id": result.flow_id,
            "classification": result.classification,
            "is_malicious": result.is_malicious,
            "confidence": result.confidence_score,
            "severity": result.severity,
            "color": result.color,
        })

    def get_alerts(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[SecurityAlert]:
        """Fetch filtered and paginated alerts (newest first)."""
        filtered = list(self.alerts)
        if severity:
            filtered = [a for a in filtered if a.severity.upper() == severity.upper()]
        if status:
            filtered = [a for a in filtered if a.status.upper() == status.upper()]
        
        filtered.reverse()  # Newest first
        return filtered[offset : offset + limit]

    def update_alert_status(self, alert_id: str, new_status: str) -> Optional[SecurityAlert]:
        """Update lifecycle state of an alert."""
        if alert_id in self.alerts_by_id:
            alert = self.alerts_by_id[alert_id]
            alert.status = new_status
            return alert
        return None

    def get_overview_metrics(self) -> OverviewMetrics:
        """Compute SOC overview KPI stats and Threat Level Index."""
        # Active alerts: those with status 'NEW' or 'INVESTIGATING'
        active_alerts = sum(1 for a in self.alerts if a.status in {"NEW", "INVESTIGATING"})
        
        # Calculate dynamic Threat Index (0 - 100)
        # Based on proportion of critical/high attacks in recent traffic window
        recent_flows = list(self.flows)[-100:] if self.flows else []
        recent_attacks = sum(1 for f in recent_flows if f.is_malicious)
        attack_ratio = (recent_attacks / len(recent_flows)) if recent_flows else 0.0
        
        threat_index = min(100.0, round(attack_ratio * 120.0 + (active_alerts * 2.5), 1))
        
        if threat_index >= 75.0:
            threat_level = "CRITICAL"
        elif threat_index >= 45.0:
            threat_level = "HIGH"
        elif threat_index >= 20.0:
            threat_level = "ELEVATED"
        else:
            threat_level = "NORMAL"

        # Calculate flows per second over time series
        fps = 0.0
        aps = 0.0
        if len(self.time_series_history) >= 2:
            recent_pts = list(self.time_series_history)[-10:]
            tot_f = sum(p.total_flows for p in recent_pts)
            tot_a = sum(p.malicious_flows for p in recent_pts)
            duration_secs = max(1, len(recent_pts))
            fps = round(tot_f / duration_secs, 1)
            aps = round(tot_a / duration_secs, 1)

        return OverviewMetrics(
            total_flows=self.total_flows,
            total_attacks=self.total_attacks,
            benign_flows=self.benign_flows,
            active_alerts=active_alerts,
            threat_level=threat_level,
            threat_index=threat_index,
            flows_per_second=fps,
            attacks_per_second=aps,
            severity_counts=self.severity_counts,
            attack_distribution=self.attack_distribution,
            last_updated=datetime.now(timezone.utc).isoformat(),
        )

    def get_time_series(self) -> List[TrafficPoint]:
        """Return history for line chart visualization."""
        return list(self.time_series_history)


# Global alert store singleton
store = AlertStore()
