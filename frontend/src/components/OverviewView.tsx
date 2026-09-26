"use client";

import React, { useEffect, useState } from "react";
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  CheckCircle2,
  Clock,
  ExternalLink,
  Flame,
  Grid,
  Layers,
  Radio,
  Shield,
  ShieldAlert,
  Terminal,
  Zap,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { OverviewMetrics, SecurityAlert, TrafficPoint } from "@/lib/types";

interface OverviewViewProps {
  metrics: OverviewMetrics | null;
  trafficHistory: TrafficPoint[];
  recentAlerts: SecurityAlert[];
  onSelectAlert: (alert: SecurityAlert) => void;
  onNavigateToAlerts: () => void;
  onNavigateToMitre: () => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  metrics,
  trafficHistory,
  recentAlerts,
  onSelectAlert,
  onNavigateToAlerts,
  onNavigateToMitre,
}) => {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const totalFlows = metrics?.total_flows ?? 0;
  const totalAttacks = metrics?.total_attacks ?? 0;
  const benignFlows = metrics?.benign_flows ?? 0;
  const activeAlerts = metrics?.active_alerts ?? 0;
  const threatIndex = metrics?.threat_index ?? 0;
  const threatLevel = metrics?.threat_level ?? "NORMAL";
  const fps = metrics?.flows_per_second ?? 0;
  const aps = metrics?.attacks_per_second ?? 0;

  const severityCounts = metrics?.severity_counts ?? {
    CRITICAL: 0,
    HIGH: 0,
    SUSPICIOUS: 0,
    NORMAL: 0,
  };

  const attackDist = metrics?.attack_distribution ?? {};
  const sortedAttacks = Object.entries(attackDist).sort((a, b) => b[1] - a[1]);

  return (
    <div className="space-y-3.5 font-mono-tech">
      {/* 4 High-Density KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2.5">
        {/* KPI 1: Ingestion Volume */}
        <div className="bg-[#0d0f17] border border-[#1a1e2e] p-3 rounded-[2px] relative overflow-hidden">
          <div className="flex items-center justify-between text-zinc-500 mb-1">
            <span className="text-[10px] tracking-wider uppercase">INGESTION VOLUME</span>
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="flex items-baseline justify-between">
            <span className="text-2xl font-bold text-white tracking-tight">
              {totalFlows.toLocaleString()}
            </span>
            <span className="text-[10px] text-cyan-400 font-semibold flex items-center gap-0.5">
              <ArrowUpRight className="w-3 h-3" /> {fps} fps
            </span>
          </div>
          <div className="mt-2 flex items-center justify-between text-[9px] text-zinc-500 border-t border-[#1a1e2e] pt-1.5">
            <span>BENIGN: {benignFlows.toLocaleString()}</span>
            <span className="text-zinc-400">ATTACKS: {totalAttacks.toLocaleString()}</span>
          </div>
        </div>

        {/* KPI 2: Threat Level Index */}
        <div className="bg-[#0d0f17] border border-[#1a1e2e] p-3 rounded-[2px] relative overflow-hidden">
          <div className="flex items-center justify-between text-zinc-500 mb-1">
            <span className="text-[10px] tracking-wider uppercase">THREAT INDEX POSTURE</span>
            <Flame className="w-3.5 h-3.5 text-orange-400" />
          </div>
          <div className="flex items-baseline justify-between">
            <span
              className={`text-2xl font-bold tracking-tight ${
                threatLevel === "CRITICAL"
                  ? "text-red-400"
                  : threatLevel === "HIGH"
                  ? "text-orange-400"
                  : threatLevel === "ELEVATED"
                  ? "text-amber-400"
                  : "text-emerald-400"
              }`}
            >
              {threatLevel}
            </span>
            <span className="text-[10px] text-zinc-400">
              {threatIndex.toFixed(1)} / 100
            </span>
          </div>
          <div className="mt-2 h-1 w-full bg-[#161a29] rounded-[1px] overflow-hidden">
            <div
              className={`h-full transition-all duration-500 ${
                threatIndex > 75
                  ? "bg-red-500"
                  : threatIndex > 45
                  ? "bg-orange-500"
                  : threatIndex > 20
                  ? "bg-amber-500"
                  : "bg-emerald-500"
              }`}
              style={{ width: `${Math.min(100, Math.max(4, threatIndex))}%` }}
            />
          </div>
        </div>

        {/* KPI 3: Active Incident Triage */}
        <div className="bg-[#0d0f17] border border-[#1a1e2e] p-3 rounded-[2px] relative overflow-hidden">
          <div className="flex items-center justify-between text-zinc-500 mb-1">
            <span className="text-[10px] tracking-wider uppercase">UNRESOLVED INCIDENTS</span>
            <ShieldAlert className="w-3.5 h-3.5 text-red-500" />
          </div>
          <div className="flex items-baseline justify-between">
            <span className="text-2xl font-bold text-red-400 tracking-tight">
              {activeAlerts}
            </span>
            <span className="text-[10px] text-red-400">
              {aps > 0 ? `+${aps} atk/s` : "STEADY"}
            </span>
          </div>
          <div className="mt-2 flex items-center justify-between text-[9px] border-t border-[#1a1e2e] pt-1.5">
            <span className="text-red-400">CRIT: {severityCounts.CRITICAL || 0}</span>
            <span className="text-orange-400">HIGH: {severityCounts.HIGH || 0}</span>
            <span className="text-amber-400">SUSP: {severityCounts.SUSPICIOUS || 0}</span>
          </div>
        </div>

        {/* KPI 4: Decision Latency & Precision */}
        <div className="bg-[#0d0f17] border border-[#1a1e2e] p-3 rounded-[2px] relative overflow-hidden">
          <div className="flex items-center justify-between text-zinc-500 mb-1">
            <span className="text-[10px] tracking-wider uppercase">AI ENGINE PRECISION</span>
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="flex items-baseline justify-between">
            <span className="text-2xl font-bold text-emerald-400 tracking-tight">
              100.00%
            </span>
            <span className="text-[10px] text-cyan-400">
              ~7.0 ms / flow
            </span>
          </div>
          <div className="mt-2 flex items-center justify-between text-[9px] text-zinc-500 border-t border-[#1a1e2e] pt-1.5">
            <span>BENIGN FPR: 0.000%</span>
            <span className="text-emerald-400">F1-SCORE: 1.00</span>
          </div>
        </div>
      </div>

      {/* Main Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        {/* Real-time Velocity Area Chart (2 Cols) */}
        <div className="lg:col-span-2 bg-[#0d0f17] border border-[#1a1e2e] p-3.5 rounded-[2px]">
          <div className="flex items-center justify-between mb-2.5 border-b border-[#1a1e2e] pb-2">
            <div>
              <h3 className="text-xs font-bold text-zinc-200 uppercase tracking-wider flex items-center gap-2">
                <Activity className="w-3.5 h-3.5 text-red-500" />
                NETWORK FLOW VELOCITY // TIME-SERIES CORRELATION
              </h3>
              <p className="text-[9px] text-zinc-500">
                NORMAL TRAFFIC VS MALICIOUS ATTACK PACKETS (ROLLING 60s)
              </p>
            </div>
            <div className="flex items-center gap-3 text-[9px]">
              <span className="flex items-center gap-1.5 text-emerald-400">
                <span className="w-2.5 h-1 bg-emerald-500 inline-block" /> NORMAL
              </span>
              <span className="flex items-center gap-1.5 text-red-400">
                <span className="w-2.5 h-1 bg-red-500 inline-block" /> MALICIOUS
              </span>
            </div>
          </div>

          <div className="h-60 w-full">
            {mounted && trafficHistory.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trafficHistory} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorNormal" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#10b981" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
                    </linearGradient>
                    <linearGradient id="colorMalicious" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.35} />
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="2 2" stroke="#161a29" vertical={false} />
                  <XAxis
                    dataKey="timestamp"
                    stroke="#4b5563"
                    tick={{ fontSize: 9, fill: "#6b7280", fontFamily: "monospace" }}
                    interval="preserveStartEnd"
                  />
                  <YAxis
                    stroke="#4b5563"
                    tick={{ fontSize: 9, fill: "#6b7280", fontFamily: "monospace" }}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#090b10",
                      borderColor: "#1a1e2e",
                      borderRadius: "2px",
                      fontFamily: "monospace",
                      fontSize: "10px",
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="normal_flows"
                    name="Normal Flows"
                    stroke="#10b981"
                    strokeWidth={1.5}
                    fillOpacity={1}
                    fill="url(#colorNormal)"
                  />
                  <Area
                    type="monotone"
                    dataKey="malicious_flows"
                    name="Malicious Flows"
                    stroke="#ef4444"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorMalicious)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-zinc-600">
                SYNCHRONIZING TELEMETRY STREAM...
              </div>
            )}
          </div>
        </div>

        {/* Attack Vector Distribution (1 Col) */}
        <div className="bg-[#0d0f17] border border-[#1a1e2e] p-3.5 rounded-[2px] flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2.5 border-b border-[#1a1e2e] pb-2">
              <h3 className="text-xs font-bold text-zinc-200 uppercase tracking-wider flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5 text-orange-400" />
                ATTACK TAXONOMY BREAKDOWN
              </h3>
              <span className="text-[9px] text-zinc-500">
                {totalAttacks} DETECTIONS
              </span>
            </div>

            <div className="space-y-2">
              {sortedAttacks.length > 0 ? (
                sortedAttacks.map(([attackName, count]) => {
                  const pct = totalAttacks > 0 ? (count / totalAttacks) * 100 : 0;
                  const barColor =
                    attackName === "DDoS" || attackName === "DoS"
                      ? "bg-red-500"
                      : attackName === "Botnet"
                      ? "bg-purple-500"
                      : attackName === "PortScan"
                      ? "bg-amber-500"
                      : "bg-orange-500";

                  return (
                    <div key={attackName} className="space-y-0.5">
                      <div className="flex justify-between text-[10px]">
                        <span className="text-zinc-300 font-bold">{attackName}</span>
                        <span className="text-zinc-400">
                          {count.toLocaleString()} ({pct.toFixed(1)}%)
                        </span>
                      </div>
                      <div className="h-1.5 w-full bg-[#161a29] rounded-[1px] overflow-hidden">
                        <div
                          className={`h-full ${barColor} transition-all duration-300`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  );
                })
              ) : (
                <div className="text-center py-8 text-xs text-zinc-600">
                  NO ATTACK SIGNATURES RECORDED
                </div>
              )}
            </div>
          </div>

          <div className="mt-3 pt-2.5 border-t border-[#1a1e2e] flex items-center justify-between text-[9px] text-zinc-500">
            <span>STANDARDS: CIC-IDS2017</span>
            <button
              onClick={onNavigateToMitre}
              className="text-red-400 hover:text-red-300 flex items-center gap-1"
            >
              EXPLORE MITRE MATRIX <ExternalLink className="w-2.5 h-2.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Recent High-Priority Incident Feed Ticker */}
      <div className="bg-[#0d0f17] border border-[#1a1e2e] p-3.5 rounded-[2px]">
        <div className="flex items-center justify-between mb-2.5 border-b border-[#1a1e2e] pb-2">
          <div className="flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500"></span>
            </span>
            <h3 className="text-xs font-bold text-zinc-200 uppercase tracking-wider">
              HIGH-PRIORITY NOTABLE INCIDENTS (ACTIVE RADAR STREAM)
            </h3>
          </div>
          <button
            onClick={onNavigateToAlerts}
            className="text-[10px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition font-bold"
          >
            VIEW ALL INCIDENTS FEED <ExternalLink className="w-3 h-3" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead className="bg-[#090b10] text-zinc-500 uppercase text-[9px] border-b border-[#1a1e2e]">
              <tr>
                <th className="py-2 px-2.5">TIMESTAMP (UTC)</th>
                <th className="py-2 px-2.5">SEVERITY</th>
                <th className="py-2 px-2.5">ATTACK VECTOR</th>
                <th className="py-2 px-2.5">SOURCE HOST</th>
                <th className="py-2 px-2.5">TARGET SERVICE</th>
                <th className="py-2 px-2.5">CONFIDENCE</th>
                <th className="py-2 px-2.5 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#161a29]">
              {recentAlerts.length > 0 ? (
                Array.from(
                  new Map(recentAlerts.map((a) => [a.alert_id, a])).values()
                )
                  .slice(0, 5)
                  .map((alert, idx) => {
                    const sevStyle =
                      alert.severity === "CRITICAL"
                        ? "bg-red-950/80 text-red-300 border-red-700/80"
                        : alert.severity === "HIGH"
                        ? "bg-orange-950/80 text-orange-300 border-orange-700/80"
                        : "bg-amber-950/80 text-amber-300 border-amber-700/80";

                    return (
                      <tr
                        key={`${alert.alert_id}-${idx}`}
                        onClick={() => onSelectAlert(alert)}
                        className="hover:bg-[#121522] cursor-pointer transition"
                      >
                      <td className="py-2 px-2.5 text-zinc-400 text-[10px]">
                        {alert.timestamp.split("T")[1]?.slice(0, 8) || alert.timestamp}
                      </td>
                      <td className="py-2 px-2.5">
                        <span className={`px-1.5 py-0.2 text-[9px] border font-bold rounded-[2px] ${sevStyle}`}>
                          {alert.severity}
                        </span>
                      </td>
                      <td className="py-2 px-2.5 text-white font-bold">
                        {alert.classification}
                      </td>
                      <td className="py-2 px-2.5 text-cyan-400">
                        {alert.source_ip}:{alert.source_port}
                      </td>
                      <td className="py-2 px-2.5 text-zinc-300">
                        {alert.destination_ip}:{alert.destination_port} ({alert.protocol})
                      </td>
                      <td className="py-2 px-2.5 text-emerald-400 font-bold">
                        {(alert.confidence_score * 100).toFixed(1)}%
                      </td>
                      <td className="py-2 px-2.5 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectAlert(alert);
                          }}
                          className="px-2 py-0.5 text-[9px] bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 rounded-[2px] transition"
                        >
                          INVESTIGATE
                        </button>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={7} className="py-6 text-center text-zinc-600 text-xs">
                    ALL INGESTED FLOWS CURRENTLY CLASSIFIED AS BENIGN. NO THREAT INCIDENTS ACTIVE.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
