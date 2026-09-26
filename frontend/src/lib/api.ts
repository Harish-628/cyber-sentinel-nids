import { DeepDiveMetrics, OverviewMetrics, SecurityAlert, SimulatorStatus, TrafficPoint } from "./types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

export async function fetchOverviewMetrics(): Promise<OverviewMetrics> {
  const res = await fetch(`${API_BASE}/metrics/overview`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch overview metrics");
  return res.json();
}

export async function fetchAlerts(
  severity?: string,
  status?: string,
  limit: number = 100
): Promise<SecurityAlert[]> {
  const params = new URLSearchParams();
  if (severity && severity !== "ALL") params.append("severity", severity);
  if (status && status !== "ALL") params.append("status", status);
  params.append("limit", limit.toString());

  const res = await fetch(`${API_BASE}/alerts?${params.toString()}`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch alerts");
  return res.json();
}

export async function updateAlertStatus(alertId: string, status: string): Promise<SecurityAlert> {
  const res = await fetch(`${API_BASE}/alerts/${alertId}/status`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status }),
  });
  if (!res.ok) throw new Error("Failed to update alert status");
  return res.json();
}

export async function fetchTrafficHistory(): Promise<TrafficPoint[]> {
  const res = await fetch(`${API_BASE}/traffic/history`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch traffic history");
  return res.json();
}

export async function fetchTrafficDeepDive(): Promise<DeepDiveMetrics> {
  const res = await fetch(`${API_BASE}/traffic/deep-dive`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch traffic deep dive");
  return res.json();
}

export async function fetchSimulatorStatus(): Promise<SimulatorStatus> {
  const res = await fetch(`${API_BASE}/simulator/status`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch simulator status");
  return res.json();
}

export async function startSimulator(interval: number = 0.5, attackProb: number = 0.2): Promise<SimulatorStatus> {
  const res = await fetch(`${API_BASE}/simulator/start?interval=${interval}&attack_probability=${attackProb}`, {
    method: "POST",
  });
  if (!res.ok) throw new Error("Failed to start simulator");
  return res.json();
}

export async function stopSimulator(): Promise<SimulatorStatus> {
  const res = await fetch(`${API_BASE}/simulator/stop`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to stop simulator");
  return res.json();
}

export async function injectAttack(attackType: string): Promise<any> {
  const res = await fetch(`${API_BASE}/simulator/inject-attack?attack_type=${encodeURIComponent(attackType)}`, {
    method: "POST",
  });
  if (!res.ok) throw new Error("Failed to inject attack");
  return res.json();
}

export async function analyzeCustomFlow(payload: any): Promise<any> {
  const res = await fetch(`${API_BASE}/flows/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error("Failed to analyze flow");
  return res.json();
}

export async function fetchTrafficMode(): Promise<any> {
  const res = await fetch(`${API_BASE}/traffic/mode`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch traffic mode");
  return res.json();
}

export async function setTrafficMode(mode: string, iface?: string): Promise<any> {
  const res = await fetch(`${API_BASE}/traffic/mode`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mode, interface: iface }),
  });
  if (!res.ok) throw new Error("Failed to set traffic mode");
  return res.json();
}

export async function fetchNetworkInterfaces(): Promise<any> {
  const res = await fetch(`${API_BASE}/traffic/interfaces`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch network interfaces");
  return res.json();
}

export async function clearAllAlerts(): Promise<any> {
  const res = await fetch(`${API_BASE}/alerts/clear`, {
    method: "POST",
  });
  if (!res.ok) throw new Error("Failed to clear alerts");
  return res.json();
}

