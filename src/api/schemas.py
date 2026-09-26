"""
Pydantic v2 Schemas for NIDS Flow Analysis, Alert Management, and Metrics.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, IPvAnyAddress, field_validator


class NetworkFlowPayload(BaseModel):
    """Network flow payload simulating real-time TCP/IP traffic."""
    src_ip: str = Field(default="192.168.1.105", description="Source IPv4/IPv6 address")
    dst_ip: str = Field(default="172.16.0.1", description="Destination IPv4/IPv6 address")
    src_port: int = Field(default=54321, ge=0, le=65535, description="Source port")
    dst_port: int = Field(default=80, ge=0, le=65535, description="Destination port")
    protocol: str = Field(default="TCP", description="L4 Protocol: TCP, UDP, ICMP")
    timestamp: Optional[str] = Field(default=None, description="ISO timestamp")

    # Flow statistical features (mapped to CIC-IDS2017 high-impact metrics)
    flow_duration: float = Field(default=150000.0, ge=0.0)
    tot_fwd_pkts: int = Field(default=8, ge=0)
    tot_bwd_pkts: int = Field(default=10, ge=0)
    tot_len_fwd_pkts: float = Field(default=2000.0, ge=0.0)
    tot_len_bwd_pkts: float = Field(default=6500.0, ge=0.0)
    fwd_pkt_len_max: float = Field(default=450.0, ge=0.0)
    fwd_pkt_len_min: float = Field(default=50.0, ge=0.0)
    fwd_pkt_len_mean: float = Field(default=250.0, ge=0.0)
    bwd_pkt_len_max: float = Field(default=975.0, ge=0.0)
    bwd_pkt_len_min: float = Field(default=65.0, ge=0.0)
    bwd_pkt_len_mean: float = Field(default=650.0, ge=0.0)
    flow_bytes_s: float = Field(default=56666.0, ge=0.0)
    flow_pkts_s: float = Field(default=120.0, ge=0.0)
    flow_iat_mean: float = Field(default=8823.0, ge=0.0)
    flow_iat_std: float = Field(default=2500.0, ge=0.0)
    flow_iat_max: float = Field(default=90000.0, ge=0.0)
    fwd_iat_mean: float = Field(default=18750.0, ge=0.0)
    bwd_iat_mean: float = Field(default=15000.0, ge=0.0)
    fwd_header_len: float = Field(default=160.0, ge=0.0)
    bwd_header_len: float = Field(default=200.0, ge=0.0)
    fwd_pkts_s: float = Field(default=53.3, ge=0.0)
    bwd_pkts_s: float = Field(default=66.7, ge=0.0)
    pkt_len_mean: float = Field(default=472.0, ge=0.0)
    pkt_len_std: float = Field(default=120.0, ge=0.0)
    pkt_len_var: float = Field(default=14400.0, ge=0.0)
    syn_flag_count: int = Field(default=0, ge=0, le=1)
    psh_flag_count: int = Field(default=0, ge=0, le=1)
    ack_flag_count: int = Field(default=1, ge=0, le=1)
    urg_flag_count: int = Field(default=0, ge=0, le=1)
    avg_pkt_size: float = Field(default=472.0, ge=0.0)
    subflow_fwd_pkts: int = Field(default=8, ge=0)
    subflow_fwd_bytes: float = Field(default=2000.0, ge=0.0)
    subflow_bwd_pkts: int = Field(default=10, ge=0)
    subflow_bwd_bytes: float = Field(default=6500.0, ge=0.0)
    init_win_bytes_forward: int = Field(default=29200, ge=0)
    init_win_bytes_backward: int = Field(default=29200, ge=0)
    act_data_pkt_fwd: int = Field(default=6, ge=0)
    min_seg_size_forward: int = Field(default=20, ge=0)
    active_mean: float = Field(default=0.0, ge=0.0)
    idle_mean: float = Field(default=0.0, ge=0.0)

    # Allow custom arbitrary feature dict mapping directly to CICFlowMeter column names
    raw_features: Optional[Dict[str, float]] = Field(default=None, description="Raw feature dict from CICFlowMeter")


class SecurityAlert(BaseModel):
    """Structured Enterprise Security Alert."""
    alert_id: str = Field(description="Unique alert UUID")
    timestamp: str = Field(description="ISO 8601 UTC timestamp")
    source_ip: str = Field(description="Originating attacker/client IP")
    destination_ip: str = Field(description="Target internal/external IP")
    source_port: int = Field(description="Source port")
    destination_port: int = Field(description="Target destination port")
    protocol: str = Field(description="L4 Protocol (TCP, UDP, ICMP)")
    classification: str = Field(description="Attack category or BENIGN")
    confidence_score: float = Field(description="Model prediction confidence (0.00 - 1.00)")
    severity: str = Field(description="CRITICAL, HIGH, SUSPICIOUS, NORMAL")
    severity_level: int = Field(description="0 (Normal), 1 (Suspicious), 2 (High), 3 (Critical)")
    color: str = Field(description="red, amber, green, blue")
    mitre_tactic: str = Field(description="Associated MITRE ATT&CK tactic")
    status: str = Field(default="NEW", description="Alert lifecycle: NEW, INVESTIGATING, RESOLVED")
    description: str = Field(description="Detailed explanation of attack pattern")
    mitigation: str = Field(description="Actionable SOC containment recommendation")
    flow_summary: Dict[str, Any] = Field(default_factory=dict, description="Key flow metrics for analyst inspection")


class FlowAnalysisResponse(BaseModel):
    """Result returned for an analyzed network flow."""
    flow_id: str
    timestamp: str
    is_malicious: bool
    classification: str
    confidence_score: float
    severity: str
    color: str
    alert: Optional[SecurityAlert] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    bytes: Optional[float] = None
    packets: Optional[int] = None


class BatchFlowPayload(BaseModel):
    """Batch flow analysis request."""
    flows: List[NetworkFlowPayload]


class BatchFlowResponse(BaseModel):
    """Batch flow analysis results."""
    total_analyzed: int
    malicious_count: int
    alerts_generated: int
    results: List[FlowAnalysisResponse]


class AlertStatusUpdate(BaseModel):
    """Payload to update alert lifecycle status."""
    status: str = Field(description="NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE")

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        valid = {"NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}
        v_upper = v.upper()
        if v_upper not in valid:
            raise ValueError(f"Status must be one of {valid}")
        return v_upper


class OverviewMetrics(BaseModel):
    """High-level SOC dashboard KPI overview."""
    total_flows: int
    total_attacks: int
    benign_flows: int
    active_alerts: int
    threat_level: str
    threat_index: float
    flows_per_second: float
    attacks_per_second: float
    severity_counts: Dict[str, int]
    attack_distribution: Dict[str, int]
    last_updated: str


class TrafficPoint(BaseModel):
    """Single time-series point for live traffic charting."""
    timestamp: str
    total_flows: int
    normal_flows: int
    malicious_flows: int
    bytes_transferred: float
