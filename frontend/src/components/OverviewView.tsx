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
      {/* 4 High-Density Glassmorphic KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
        {/* KPI 1: Ingestion Volume */}
        <div className="glass-panel-interactive p-4 rounded-[4px] relative overflow-hidden group">
          <div className="flex items-center justify-between text-zinc-400 mb-1.5">
            <span className="text-[10px] tracking-wider uppercase font-semibold text-zinc-400">INGESTION VOLUME</span>
            <div className="p-1.5 rounded-[3px] bg-cyan-950/60 border border-cyan-500/30 text-cyan-400 group-hover:border-cyan-400 transition">
              <Activity className="w-3.5 h-3.5" />
            </div>
          </div>
          <div className="flex items-baseline justify-between">
            <span className="text-2xl font-bold text-white tracking-tight drop-shadow-sm">
              {totalFlows.toLocaleString()}
            </span>
            <span className="text-[10px] text-cyan-400 font-semibold flex items-center gap-0.5 bg-cyan-950/50 px-1.5 py-0.2 rounded border border-cyan-500/30">
              <ArrowUpRight className="w-3 h-3" /> {fps} fps
            </span>
          </div>
          <div className="mt-2.5 flex items-center justify-between text-[9px] text-zinc-400 border-t border-white/[0.06] pt-2">
            <span>NORMAL: <strong className="text-emerald-400">{benignFlows.toLocaleString()}</strong></span>
            <span>ATTACKS: <strong className="text-red-400">{totalAttacks.toLocaleString()}</strong></span>
          </div>
        </div>

        {/* KPI 2: Threat Level Index */}
        <div className="glass-panel-interactive p-4 rounded-[4px] relative overflow-hidden group">
          <div className="flex items-center justify-between text-zinc-400 mb-1.5">
            <span className="text-[10px] tracking-wider uppercase font-semibold text-zinc-400">THREAT POSTURE DEFCON</span>
            <div className="p-1.5 rounded-[3px] bg-red-950/60 border border-red-500/30 text-red-400 group-hover:border-red-400 transition">
              <Flame className="w-3.5 h-3.5" />
            </div>
          </div>
          <div className="flex items-baseline justify-between">
            <span
              className={`text-2xl font-bold tracking-tight ${
                threatLevel === "CRITICAL"
                  ? "text-red-400 drop-shadow-[0_0_12px_rgba(239,68,68,0.5)]"
                  : threatLevel === "HIGH"
                  ? "text-orange-400 drop-shadow-[0_0_12px_rgba(249,115,22,0.5)]"
                  : threatLevel === "ELEVATED"
                  ? "text-amber-400 drop-shadow-[0_0_12px_rgba(245,158,11,0.5)]"
                  : "text-emerald-400 drop-shadow-[0_0_12px_rgba(16,185,129,0.5)]"
              }`}
            >
              {threatLevel}
            </span>
            <span className="text-[10px] text-zinc-300 bg-white/[0.06] px-1.5 py-0.2 rounded font-mono">
              {threatIndex.toFixed(1)} / 100
            </span>
          </div>
          <div className="mt-2.5 h-1.5 w-full bg-black/60 rounded-full overflow-hidden border border-white/[0.06]">
            <div
              className={`h-full transition-all duration-500 rounded-full ${
                threatIndex > 75
                  ? "bg-gradient-to-r from-orange-500 to-red-500 shadow-[0_0_8px_rgba(239,68,68,0.8)]"
                  : threatIndex > 45
                  ? "bg-gradient-to-r from-amber-500 to-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.8)]"
                  : threatIndex > 20
                  ? "bg-gradient-to-r from-emerald-500 to-amber-500"
                  : "bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)]"
              }`}
              style={{ width: `${Math.min(100, Math.max(4, threatIndex))}%` }}
            />
          </div>
        </div>

        {/* KPI 3: Active Incident Triage */}
        <div className="glass-panel-interactive p-4 rounded-[4px] relative overflow-hidden group">
          <div className="flex items-center justify-between text-zinc-400 mb-1.5">
            <span className="text-[10px] tracking-wider uppercase font-semibold text-zinc-400">UNRESOLVED INCIDENTS</span>
            <div className="p-1.5 rounded-[3px] bg-red-950/60 border border-red-500/30 text-red-500 group-hover:border-red-400 transition">
              <ShieldAlert className="w-3.5 h-3.5" />
            </div>
          </div>
          <div className="flex items-baseline justify-between">
            <span className="text-2xl font-bold text-red-400 tracking-tight drop-shadow-[0_0_10px_rgba(239,68,68,0.4)]">
              {activeAlerts}
            </span>
            <span className="text-[10px] text-red-400 bg-red-950/60 px-1.5 py-0.2 rounded border border-red-700/60">
              {aps > 0 ? `+${aps} atk/s` : "STEADY"}
            </span>
          </div>
          <div className="mt-2.5 flex items-center justify-between text-[9px] border-t border-white/[0.06] pt-2">
            <span className="text-red-400 font-bold">CRIT: {severityCounts.CRITICAL || 0}</span>
            <span className="text-orange-400 font-bold">HIGH: {severityCounts.HIGH || 0}</span>
            <span className="text-amber-400 font-bold">SUSP: {severityCounts.SUSPICIOUS || 0}</span>
          </div>
        </div>

        {/* KPI 4: Decision Latency & Precision */}
        <div className="glass-panel-interactive p-4 rounded-[4px] relative overflow-hidden group">
          <div className="flex items-center justify-between text-zinc-400 mb-1.5">
            <span className="text-[10px] tracking-wider uppercase font-semibold text-zinc-400">AI ENGINE PRECISION</span>
            <div className="p-1.5 rounded-[3px] bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 group-hover:border-emerald-400 transition">
              <CheckCircle2 className="w-3.5 h-3.5" />
            </div>
          </div>
          <div className="flex items-baseline justify-between">
            <span className="text-2xl font-bold text-emerald-400 tracking-tight drop-shadow-[0_0_12px_rgba(16,185,129,0.4)]">
              100.00%
            </span>
            <span className="text-[10px] text-cyan-400 bg-cyan-950/50 px-1.5 py-0.2 rounded border border-cyan-500/30">
              ~7.0 ms / flow
            </span>
          </div>
          <div className="mt-2.5 flex items-center justify-between text-[9px] text-zinc-400 border-t border-white/[0.06] pt-2">
            <span>BENIGN FPR: <strong className="text-white">0.000%</strong></span>
            <span>F1-SCORE: <strong className="text-emerald-400">1.00</strong></span>
          </div>
        </div>
      </div>

      {/* Main Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        {/* Real-time Velocity Area Chart (2 Cols) */}
        <div className="lg:col-span-2 glass-panel p-4 rounded-[4px] border border-white/[0.08]">
          <div className="flex items-center justify-between mb-3 border-b border-white/[0.08] pb-2.5">
            <div>
              <h3 className="text-xs font-bold text-zinc-100 uppercase tracking-wider flex items-center gap-2">
                <Activity className="w-3.5 h-3.5 text-cyan-400" />
                NETWORK FLOW VELOCITY // TIME-SERIES CORRELATION
              </h3>
              <p className="text-[9px] text-zinc-400 mt-0.5">
                BENIGN WIRELESS / ETHERNET TRAFFIC VS DETECTED ATTACK PACKETS (ROLLING 60s)
              </p>
            </div>
            <div className="flex items-center gap-3 text-[9px]">
              <span className="flex items-center gap-1.5 text-emerald-400 font-bold bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-500/30">
                <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block animate-pulse" /> NORMAL
              </span>
              <span className="flex items-center gap-1.5 text-red-400 font-bold bg-red-950/40 px-2 py-0.5 rounded border border-red-500/30">
                <span className="w-2 h-2 rounded-full bg-red-500 inline-block animate-pulse" /> MALICIOUS
              </span>
            </div>
          </div>

          <div className="h-64 w-full">
            {mounted && trafficHistory.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trafficHistory} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorNormal" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#10b981" stopOpacity={0.35} />
                      <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
                    </linearGradient>
                    <linearGradient id="colorMalicious" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.45} />
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="2 2" stroke="rgba(255,255,255,0.06)" vertical={false} />
                  <XAxis
                    dataKey="timestamp"
                    stroke="#4b5563"
                    tick={{ fontSize: 9, fill: "#9ca3af", fontFamily: "monospace" }}
                    interval="preserveStartEnd"
                  />
                  <YAxis
                    stroke="#4b5563"
                    tick={{ fontSize: 9, fill: "#9ca3af", fontFamily: "monospace" }}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "rgba(10, 14, 26, 0.92)",
                      backdropFilter: "blur(16px)",
                      borderColor: "rgba(255, 255, 255, 0.12)",
                      borderRadius: "4px",
                      boxShadow: "0 12px 32px rgba(0,0,0,0.6)",
                      fontFamily: "monospace",
                      fontSize: "10px",
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="normal_flows"
                    name="Normal Flows"
                    stroke="#10b981"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorNormal)"
                  />
                  <Area
                    type="monotone"
                    dataKey="malicious_flows"
                    name="Malicious Flows"
                    stroke="#ef4444"
                    strokeWidth={2.5}
                    fillOpacity={1}
                    fill="url(#colorMalicious)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-zinc-500">
                SYNCHRONIZING TELEMETRY STREAM...
              </div>
            )}
          </div>
        </div>

        {/* Attack Vector Distribution (1 Col) */}
        <div className="glass-panel p-4 rounded-[4px] border border-white/[0.08] flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3 border-b border-white/[0.08] pb-2.5">
              <h3 className="text-xs font-bold text-zinc-100 uppercase tracking-wider flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5 text-orange-400" />
                ATTACK TAXONOMY BREAKDOWN
              </h3>
              <span className="text-[9px] text-zinc-400 bg-white/[0.06] px-1.5 py-0.2 rounded font-mono">
                {totalAttacks} DETECTIONS
              </span>
            </div>

            <div className="space-y-2.5">
              {sortedAttacks.length > 0 ? (
                sortedAttacks.map(([attackName, count]) => {
                  const pct = totalAttacks > 0 ? (count / totalAttacks) * 100 : 0;
                  const barColor =
                    attackName === "DDoS" || attackName === "DoS"
                      ? "bg-gradient-to-r from-orange-500 to-red-500"
                      : attackName === "Botnet"
                      ? "bg-gradient-to-r from-purple-500 to-pink-500"
                      : attackName === "PortScan"
                      ? "bg-gradient-to-r from-amber-500 to-yellow-500"
                      : "bg-gradient-to-r from-cyan-500 to-blue-500";

                  return (
                    <div key={attackName} className="space-y-1">
                      <div className="flex justify-between text-[10px]">
                        <span className="text-zinc-200 font-bold">{attackName}</span>
                        <span className="text-zinc-400">
                          {count.toLocaleString()} ({pct.toFixed(1)}%)
                        </span>
                      </div>
                      <div className="h-1.5 w-full bg-black/60 rounded-full overflow-hidden border border-white/[0.06]">
                        <div
                          className={`h-full ${barColor} transition-all duration-300 rounded-full`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  );
                })
              ) : (
                <div className="text-center py-8 text-xs text-zinc-500">
                  NO ATTACK SIGNATURES RECORDED
                </div>
              )}
            </div>
          </div>

          <div className="mt-3.5 pt-2.5 border-t border-white/[0.08] flex items-center justify-between text-[9px] text-zinc-400">
            <span>STANDARDS: CIC-IDS2017</span>
            <button
              onClick={onNavigateToMitre}
              className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-bold"
            >
              EXPLORE MITRE MATRIX <ExternalLink className="w-2.5 h-2.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Recent High-Priority Incident Feed Ticker */}
      <div className="glass-panel p-4 rounded-[4px] border border-white/[0.08]">
        <div className="flex items-center justify-between mb-3 border-b border-white/[0.08] pb-2.5">
          <div className="flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500"></span>
            </span>
            <h3 className="text-xs font-bold text-zinc-100 uppercase tracking-wider">
              HIGH-PRIORITY NOTABLE INCIDENTS (RADAR STREAM)
            </h3>
          </div>
          <button
            onClick={onNavigateToAlerts}
            className="text-[10px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition font-bold bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-500/30"
          >
            VIEW ALL INCIDENTS FEED <ExternalLink className="w-3 h-3" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead className="bg-white/[0.03] text-zinc-400 uppercase text-[9px] border-b border-white/[0.08]">
              <tr>
                <th className="py-2.5 px-3">TIMESTAMP (UTC)</th>
                <th className="py-2.5 px-3">SEVERITY</th>
                <th className="py-2.5 px-3">ATTACK VECTOR</th>
                <th className="py-2.5 px-3">SOURCE HOST</th>
                <th className="py-2.5 px-3">TARGET SERVICE</th>
                <th className="py-2.5 px-3">CONFIDENCE</th>
                <th className="py-2.5 px-3 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.05]">
              {recentAlerts.length > 0 ? (
                Array.from(
                  new Map(recentAlerts.map((a) => [a.alert_id, a])).values()
                )
                  .slice(0, 5)
                  .map((alert, idx) => {
                    const sevStyle =
                      alert.severity === "CRITICAL"
                        ? "bg-red-950/80 text-red-300 border-red-500/80 shadow-[0_0_8px_rgba(239,68,68,0.3)]"
                        : alert.severity === "HIGH"
                        ? "bg-orange-950/80 text-orange-300 border-orange-500/80 shadow-[0_0_8px_rgba(249,115,22,0.3)]"
                        : "bg-amber-950/80 text-amber-300 border-amber-500/80";

                    return (
                      <tr
                        key={`${alert.alert_id}-${idx}`}
                        onClick={() => onSelectAlert(alert)}
                        className="hover:bg-white/[0.04] cursor-pointer transition select-none"
                      >
                      <td className="py-2.5 px-3 text-zinc-400 text-[10px]">
                        {alert.timestamp.split("T")[1]?.slice(0, 8) || alert.timestamp}
                      </td>
                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 text-[9px] border font-bold rounded-[3px] ${sevStyle}`}>
                          {alert.severity}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-white font-bold">
                        {alert.classification}
                      </td>
                      <td className="py-2.5 px-3 text-cyan-300 font-mono">
                        {alert.source_ip}:{alert.source_port}
                      </td>
                      <td className="py-2.5 px-3 text-zinc-300 font-mono">
                        {alert.destination_ip}:{alert.destination_port} ({alert.protocol})
                      </td>
                      <td className="py-2.5 px-3 text-emerald-400 font-bold">
                        {(alert.confidence_score * 100).toFixed(1)}%
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectAlert(alert);
                          }}
                          className="px-2.5 py-1 text-[9px] bg-white/[0.08] hover:bg-white/[0.15] text-zinc-200 border border-white/[0.12] rounded-[3px] transition font-bold"
                        >
                          INVESTIGATE
                        </button>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-zinc-500 text-xs">
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
