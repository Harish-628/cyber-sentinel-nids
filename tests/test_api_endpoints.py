"""
Integration Tests for NIDS FastAPI Backend Endpoints.
"""

import sys
from pathlib import Path
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.api.main import app

def test_nids_api_lifecycle():
    with TestClient(app) as client:
        # 1. Health check
        res = client.get("/api/v1/health")
        assert res.status_code == 200, f"Health check failed: {res.text}"
        health_data = res.json()
        assert health_data["status"] == "HEALTHY"
        assert health_data["model_loaded"] is True
        print("✓ Health check endpoint verified")

        # 2. Test Benign Flow Analysis
        benign_payload = {
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.5",
            "src_port": 50123,
            "dst_port": 443,
            "protocol": "TCP",
            "flow_duration": 120000.0,
            "tot_fwd_pkts": 8,
            "tot_bwd_pkts": 10,
            "tot_len_fwd_pkts": 1800.0,
            "tot_len_bwd_pkts": 6500.0,
            "fwd_pkt_len_max": 500.0,
            "fwd_pkt_len_min": 50.0,
            "fwd_pkt_len_mean": 225.0,
            "bwd_pkt_len_max": 950.0,
            "bwd_pkt_len_min": 60.0,
            "bwd_pkt_len_mean": 650.0,
            "flow_bytes_s": 69166.0,
            "flow_pkts_s": 150.0,
            "flow_iat_mean": 7058.0,
            "syn_flag_count": 0,
            "ack_flag_count": 1,
            "psh_flag_count": 1,
            "avg_pkt_size": 461.0,
            "subflow_fwd_bytes": 1800.0,
            "subflow_bwd_bytes": 6500.0,
            "init_win_bytes_forward": 29200,
            "init_win_bytes_backward": 29200,
            "act_data_pkt_fwd": 6,
        }
        res = client.post("/api/v1/flows/analyze", json=benign_payload)
        assert res.status_code == 200
        data = res.json()
        assert data["classification"] == "BENIGN"
        assert data["is_malicious"] is False
        assert data["confidence_score"] > 0.5
        print(f"✓ Benign flow analysis verified: Class={data['classification']}, Conf={data['confidence_score']:.4f}")

        # 3. Test Attack Flow Analysis (PortScan)
        attack_payload = {
            "src_ip": "45.33.32.156",
            "dst_ip": "10.0.0.5",
            "src_port": 61234,
            "dst_port": 3389,
            "protocol": "TCP",
            "flow_duration": 450.0,
            "tot_fwd_pkts": 1,
            "tot_bwd_pkts": 0,
            "tot_len_fwd_pkts": 0.0,
            "tot_len_bwd_pkts": 0.0,
            "fwd_pkt_len_max": 0.0,
            "fwd_pkt_len_min": 0.0,
            "fwd_pkt_len_mean": 0.0,
            "bwd_pkt_len_mean": 0.0,
            "flow_bytes_s": 0.0,
            "flow_pkts_s": 2222.0,
            "syn_flag_count": 1,
            "ack_flag_count": 0,
            "init_win_bytes_forward": 1024,
            "init_win_bytes_backward": 0,
            "act_data_pkt_fwd": 0,
            "avg_pkt_size": 0.0,
        }
        res = client.post("/api/v1/flows/analyze", json=attack_payload)
        assert res.status_code == 200
        atk_data = res.json()
        assert atk_data["is_malicious"] is True
        assert atk_data["classification"] == "PortScan"
        assert atk_data["alert"] is not None
        alert = atk_data["alert"]
        assert "alert_id" in alert
        assert alert["source_ip"] == "45.33.32.156"
        assert alert["destination_port"] == 3389
        assert alert["severity"] in {"CRITICAL", "HIGH", "SUSPICIOUS"}
        print(f"✓ Attack flow analysis verified: AlertID={alert['alert_id']}, Class={alert['classification']}, Severity={alert['severity']}")

        # 4. Test Alert Retrieval
        res = client.get("/api/v1/alerts")
        assert res.status_code == 200
        alerts = res.json()
        assert len(alerts) > 0
        first_alert_id = alerts[0]["alert_id"]
        print(f"✓ Alerts retrieval verified: Total {len(alerts)} alerts fetched")

        # 5. Test Alert Status Update (Triage)
        res = client.patch(f"/api/v1/alerts/{first_alert_id}/status", json={"status": "INVESTIGATING"})
        assert res.status_code == 200
        assert res.json()["status"] == "INVESTIGATING"
        print(f"✓ Alert triage status update verified: {first_alert_id} -> INVESTIGATING")

        # 6. Test Overview Metrics
        res = client.get("/api/v1/metrics/overview")
        assert res.status_code == 200
        metrics = res.json()
        assert metrics["total_flows"] > 0
        assert metrics["threat_level"] in {"NORMAL", "ELEVATED", "HIGH", "CRITICAL"}
        assert 0.0 <= metrics["threat_index"] <= 100.0
        print(f"✓ Overview metrics verified: ThreatLevel={metrics['threat_level']}, ThreatIndex={metrics['threat_index']}, ActiveAlerts={metrics['active_alerts']}")

        # 7. Test Traffic Deep-Dive
        res = client.get("/api/v1/traffic/deep-dive")
        assert res.status_code == 200
        dive = res.json()
        assert "protocol_distribution" in dive
        assert "top_targeted_ports" in dive
        print("✓ Traffic deep-dive metrics verified")

if __name__ == "__main__":
    test_nids_api_lifecycle()
    print("\n🎉 ALL PHASE 2 API BACKEND INTEGRATION TESTS PASSED!")
