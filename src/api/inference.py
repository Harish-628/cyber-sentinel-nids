"""
High-Throughput NIDS ML Inference Engine.

Performs:
- Model & Scaler artifact loading and caching
- Dynamic feature vector extraction from incoming NetworkFlowPayloads
- Outlier-resilient scaling (RobustScaler)
- Multi-class classification & calibrated confidence score extraction
- Enterprise SOC Alert synthesis for malicious detections
"""

import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np

# Project root bootstrap
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.api.schemas import FlowAnalysisResponse, NetworkFlowPayload, SecurityAlert
from src.ml.feature_config import SOC_ALERT_METADATA

# Mapping between NetworkFlowPayload fields and CICFlowMeter column names
PAYLOAD_FEATURE_MAP = {
    "Destination Port": lambda p: float(p.dst_port),
    "Flow Duration": lambda p: p.flow_duration,
    "Total Fwd Packets": lambda p: float(p.tot_fwd_pkts),
    "Total Backward Packets": lambda p: float(p.tot_bwd_pkts),
    "Total Length of Fwd Packets": lambda p: p.tot_len_fwd_pkts,
    "Total Length of Bwd Packets": lambda p: p.tot_len_bwd_pkts,
    "Fwd Packet Length Max": lambda p: p.fwd_pkt_len_max,
    "Fwd Packet Length Min": lambda p: p.fwd_pkt_len_min,
    "Fwd Packet Length Mean": lambda p: p.fwd_pkt_len_mean,
    "Bwd Packet Length Max": lambda p: p.bwd_pkt_len_max,
    "Bwd Packet Length Min": lambda p: p.bwd_pkt_len_min,
    "Bwd Packet Length Mean": lambda p: p.bwd_pkt_len_mean,
    "Flow Bytes/s": lambda p: p.flow_bytes_s,
    "Flow Packets/s": lambda p: p.flow_pkts_s,
    "Flow IAT Mean": lambda p: p.flow_iat_mean,
    "Flow IAT Std": lambda p: p.flow_iat_std,
    "Flow IAT Max": lambda p: p.flow_iat_max,
    "Fwd IAT Mean": lambda p: p.fwd_iat_mean,
    "Bwd IAT Mean": lambda p: p.bwd_iat_mean,
    "Fwd Header Length": lambda p: p.fwd_header_len,
    "Bwd Header Length": lambda p: p.bwd_header_len,
    "Fwd Packets/s": lambda p: p.fwd_pkts_s,
    "Bwd Packets/s": lambda p: p.bwd_pkts_s,
    "Packet Length Mean": lambda p: p.pkt_len_mean,
    "Packet Length Std": lambda p: p.pkt_len_std,
    "Packet Length Variance": lambda p: p.pkt_len_var,
    "SYN Flag Count": lambda p: float(p.syn_flag_count),
    "PSH Flag Count": lambda p: float(p.psh_flag_count),
    "ACK Flag Count": lambda p: float(p.ack_flag_count),
    "URG Flag Count": lambda p: float(p.urg_flag_count),
    "Average Packet Size": lambda p: p.avg_pkt_size,
    "Subflow Fwd Packets": lambda p: float(p.subflow_fwd_pkts),
    "Subflow Fwd Bytes": lambda p: p.subflow_fwd_bytes,
    "Subflow Bwd Packets": lambda p: float(p.subflow_bwd_pkts),
    "Subflow Bwd Bytes": lambda p: p.subflow_bwd_bytes,
    "Init_Win_bytes_forward": lambda p: float(p.init_win_bytes_forward),
    "Init_Win_bytes_backward": lambda p: float(p.init_win_bytes_backward),
    "act_data_pkt_fwd": lambda p: float(p.act_data_pkt_fwd),
    "min_seg_size_forward": lambda p: float(p.min_seg_size_forward),
    "Active Mean": lambda p: p.active_mean,
    "Idle Mean": lambda p: p.idle_mean,
}


class NIDSInferenceEngine:
    """Singleton inference engine for real-time traffic classification."""

    def __init__(
        self,
        model_path: str = "models/trained/nids_model.joblib",
        scaler_path: str = "data/processed/scaler.joblib",
        metadata_path: str = "data/processed/feature_metadata.json",
    ):
        self.model_path = Path(model_path)
        self.scaler_path = Path(scaler_path)
        self.metadata_path = Path(metadata_path)
        
        self.model = None
        self.scaler = None
        self.feature_names: List[str] = []
        self.class_mapping: Dict[int, str] = {}
        self.feature_medians: Dict[str, float] = {}
        self.is_loaded = False

    def load(self):
        """Load and warm up model and preprocessor artifacts."""
        if not self.model_path.exists():
            raise FileNotFoundError(f"Model not found at {self.model_path}. Train model first.")
        if not self.scaler_path.exists():
            raise FileNotFoundError(f"Scaler not found at {self.scaler_path}. Run preprocessing first.")
        if not self.metadata_path.exists():
            raise FileNotFoundError(f"Metadata not found at {self.metadata_path}. Run preprocessing first.")

        self.model = joblib.load(self.model_path)
        self.scaler = joblib.load(self.scaler_path)

        with open(self.metadata_path, "r") as f:
            metadata = json.load(f)
            self.feature_names = metadata["feature_names"]
            self.class_mapping = {int(k): v for k, v in metadata["class_mapping"].items()}
            self.feature_medians = metadata.get("feature_medians", {})

        # Optimize for single-flow low-latency stream predictions
        if hasattr(self.model, "n_jobs"):
            self.model.n_jobs = 1

        # Warm up model
        warmup_vector = np.zeros((1, len(self.feature_names)))
        _ = self.model.predict(self.scaler.transform(warmup_vector))

        self.is_loaded = True

    def extract_feature_vector(self, payload: NetworkFlowPayload) -> np.ndarray:
        """Convert a NetworkFlowPayload into the model's exact ordered feature vector."""
        row = np.zeros(len(self.feature_names), dtype=np.float32)

        for idx, feat_name in enumerate(self.feature_names):
            val = None
            # Check raw_features dict first if provided
            if payload.raw_features and feat_name in payload.raw_features:
                val = payload.raw_features[feat_name]
            elif feat_name in PAYLOAD_FEATURE_MAP:
                val = PAYLOAD_FEATURE_MAP[feat_name](payload)
            else:
                val = self.feature_medians.get(feat_name, 0.0)

            # Sanitize inf and nan
            if np.isinf(val) or np.isnan(val):
                val = self.feature_medians.get(feat_name, 0.0)

            row[idx] = float(val)

        return row.reshape(1, -1)

    def analyze_flow(self, payload: NetworkFlowPayload) -> FlowAnalysisResponse:
        """Process a single incoming flow, run classification, and generate security alert if malicious."""
        if not self.is_loaded:
            self.load()

        flow_id = f"flow_{uuid.uuid4().hex[:12]}"
        now_iso = datetime.now(timezone.utc).isoformat()
        ts = payload.timestamp or now_iso

        # 1. Feature extraction & scaling
        vector = self.extract_feature_vector(payload)
        scaled_vector = self.scaler.transform(vector)

        # 2. Model inference
        pred_idx = int(self.model.predict(scaled_vector)[0])
        classification = self.class_mapping.get(pred_idx, "UNKNOWN")

        # 3. Confidence score
        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(scaled_vector)[0]
            confidence = float(probabilities[pred_idx])
        else:
            confidence = 0.95

        # 4. Severity metadata
        meta = SOC_ALERT_METADATA.get(classification, {
            "severity": "NORMAL" if classification == "BENIGN" else "HIGH",
            "color": "green" if classification == "BENIGN" else "red",
            "tactic": "Network Activity",
            "description": f"Classified as {classification}",
            "action": "Inspect packet payload and monitor host.",
        })

        is_malicious = classification != "BENIGN"
        alert = None

        if is_malicious:
            severity_map = {"NORMAL": 0, "SUSPICIOUS": 1, "HIGH": 2, "CRITICAL": 3}
            alert_id = f"ALT-{uuid.uuid4().hex[:8].upper()}"
            
            alert = SecurityAlert(
                alert_id=alert_id,
                timestamp=ts,
                source_ip=payload.src_ip,
                destination_ip=payload.dst_ip,
                source_port=payload.src_port,
                destination_port=payload.dst_port,
                protocol=payload.protocol.upper(),
                classification=classification,
                confidence_score=round(confidence, 4),
                severity=meta["severity"],
                severity_level=severity_map.get(meta["severity"], 2),
                color=meta["color"],
                mitre_tactic=meta["tactic"],
                status="NEW",
                description=meta["description"],
                mitigation=meta["action"],
                flow_summary={
                    "flow_duration_ms": round(payload.flow_duration / 1000.0, 2),
                    "total_packets": payload.tot_fwd_pkts + payload.tot_bwd_pkts,
                    "bytes_transferred": payload.tot_len_fwd_pkts + payload.tot_len_bwd_pkts,
                    "packets_per_sec": round(payload.flow_pkts_s, 1),
                    "bytes_per_sec": round(payload.flow_bytes_s, 1),
                    "flags": {
                        "SYN": payload.syn_flag_count,
                        "PSH": payload.psh_flag_count,
                        "ACK": payload.ack_flag_count,
                        "URG": payload.urg_flag_count,
                    },
                },
            )

        return FlowAnalysisResponse(
            flow_id=flow_id,
            timestamp=ts,
            is_malicious=is_malicious,
            classification=classification,
            confidence_score=round(confidence, 4),
            severity=meta["severity"],
            color=meta["color"],
            alert=alert,
        )


# Global singleton instance
engine = NIDSInferenceEngine()
