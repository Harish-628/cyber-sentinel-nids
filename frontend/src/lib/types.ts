export type Severity = "CRITICAL" | "HIGH" | "SUSPICIOUS" | "NORMAL";
export type AlertStatus = "NEW" | "INVESTIGATING" | "RESOLVED" | "FALSE_POSITIVE";

export interface SecurityAlert {
  alert_id: string;
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  source_port: number;
  destination_port: number;
  protocol: string;
  classification: string;
  confidence_score: number;
  severity: Severity;
  severity_level: number;
  color: string;
  mitre_tactic: string;
  status: AlertStatus;
  description: string;
  mitigation: string;
  flow_summary: {
    flow_duration_ms?: number;
    total_packets?: number;
    bytes_transferred?: number;
    packets_per_sec?: number;
    bytes_per_sec?: number;
    flags?: {
      SYN?: number;
      PSH?: number;
      ACK?: number;
      URG?: number;
    };
  };
}

export interface OverviewMetrics {
  total_flows: number;
  total_attacks: number;
  benign_flows: number;
  active_alerts: number;
  threat_level: "NORMAL" | "ELEVATED" | "HIGH" | "CRITICAL";
  threat_index: number;
  flows_per_second: number;
  attacks_per_second: number;
  severity_counts: Record<string, number>;
  attack_distribution: Record<string, number>;
  last_updated: string;
}

export interface TrafficPoint {
  timestamp: string;
  total_flows: number;
  normal_flows: number;
  malicious_flows: number;
  bytes_transferred: number;
}

export interface DeepDiveMetrics {
  sampled_flows: number;
  protocol_distribution: Record<string, number>;
  top_targeted_ports: Array<{ port: number; count: number }>;
  total_packets_sampled: number;
  total_volume_bytes: number;
  avg_packet_size_bytes: number;
}

export interface SimulatorStatus {
  is_running: boolean;
  interval_seconds: number;
  attack_probability: number;
}

export interface NetworkInterface {
  name: string;
  state: string;
  type: "WIRELESS" | "ETHERNET" | "LOOPBACK" | "VIRTUAL";
  is_active: boolean;
}

export interface TrafficModeInfo {
  mode: "SIMULATOR" | "LIVE_SNIFFER";
  active_interface: string;
  simulator_running: boolean;
  flow_interval: number;
  attack_probability: number;
}
