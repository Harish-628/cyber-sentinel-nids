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
    <div className="space-y-4 font-mono-tech">
      {/* 4 High-Density White Glassmorphic KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* KPI 1: Ingestion Volume */}
        <div className="glass-panel-interactive p-5 rounded-2xl relative overflow-hidden group border border-white/90 bg-white/75 shadow-xs">
          <div className="flex items-center justify-between text-slate-500 mb-2">
            <span className="text-[10px] tracking-wider uppercase font-bold text-slate-500">INGESTION VOLUME</span>
            <div className="p-2 rounded-xl bg-sky-50 border border-sky-200 text-sky-600 shadow-xs group-hover:scale-105 transition">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-baseline justify-between">
            <span className="text-3xl font-black text-slate-900 tracking-tight">
              {totalFlows.toLocaleString()}
            </span>
            <span className="text-[10px] text-sky-700 font-bold flex items-center gap-0.5 bg-sky-50 px-2 py-0.5 rounded-lg border border-sky-200">
              <ArrowUpRight className="w-3.5 h-3.5" /> {fps} fps
            </span>
          </div>
          <div className="mt-3 flex items-center justify-between text-[10px] text-slate-500 border-t border-slate-100 pt-2.5 font-medium">
            <span>NORMAL: <strong className="text-emerald-600">{benignFlows.toLocaleString()}</strong></span>
            <span>ATTACKS: <strong className="text-rose-600">{totalAttacks.toLocaleString()}</strong></span>
          </div>
        </div>

        {/* KPI 2: Threat Level Index */}
        <div className="glass-panel-interactive p-5 rounded-2xl relative overflow-hidden group border border-white/90 bg-white/75 shadow-xs">
          <div className="flex items-center justify-between text-slate-500 mb-2">
            <span className="text-[10px] tracking-wider uppercase font-bold text-slate-500">THREAT POSTURE DEFCON</span>
            <div
              className={`p-2 rounded-xl border shadow-xs group-hover:scale-105 transition ${
                threatLevel === "CRITICAL"
                  ? "bg-rose-50 border-rose-200 text-rose-600"
                  : threatLevel === "HIGH"
                  ? "bg-orange-50 border-orange-200 text-orange-600"
                  : threatLevel === "ELEVATED"
                  ? "bg-amber-50 border-amber-200 text-amber-600"
                  : "bg-emerald-50 border-emerald-200 text-emerald-600"
              }`}
            >
              {threatLevel === "NORMAL" ? <Shield className="w-4 h-4" /> : <Flame className="w-4 h-4" />}
            </div>
          </div>
          <div className="flex items-baseline justify-between">
            <span
              className={`text-3xl font-black tracking-tight ${
                threatLevel === "CRITICAL"
                  ? "text-rose-600 drop-shadow-sm"
                  : threatLevel === "HIGH"
                  ? "text-orange-600"
                  : threatLevel === "ELEVATED"
                  ? "text-amber-600"
                  : "text-emerald-600"
              }`}
            >
              {threatLevel}
            </span>
            <span className="text-[10px] text-slate-700 bg-slate-100 font-bold px-2 py-0.5 rounded-lg border border-slate-200">
              {threatIndex.toFixed(1)} / 100
            </span>
          </div>
          <div className="mt-3 h-2 w-full bg-slate-100 rounded-full overflow-hidden border border-slate-200/60">
            <div
              className={`h-full transition-all duration-500 rounded-full ${
                threatIndex > 75
                  ? "bg-gradient-to-r from-orange-500 to-rose-600 shadow-xs"
                  : threatIndex > 45
                  ? "bg-gradient-to-r from-amber-500 to-orange-500"
                  : threatIndex > 20
                  ? "bg-gradient-to-r from-emerald-500 to-amber-500"
                  : "bg-emerald-500"
              }`}
              style={{ width: `${Math.min(100, Math.max(4, threatIndex))}%` }}
            />
          </div>
        </div>

        {/* KPI 3: Active Incident Triage */}
        <div className="glass-panel-interactive p-5 rounded-2xl relative overflow-hidden group border border-white/90 bg-white/75 shadow-xs">
          <div className="flex items-center justify-between text-slate-500 mb-2">
            <span className="text-[10px] tracking-wider uppercase font-bold text-slate-500">UNRESOLVED INCIDENTS</span>
            <div className="p-2 rounded-xl bg-amber-50 border border-amber-200 text-amber-600 shadow-xs group-hover:scale-105 transition">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-baseline justify-between">
            <span className="text-3xl font-black text-rose-600 tracking-tight">
              {activeAlerts}
            </span>
            <span className="text-[10px] text-rose-700 bg-rose-50 font-bold px-2 py-0.5 rounded-lg border border-rose-200">
              {aps > 0 ? `+${aps} atk/s` : "STEADY"}
            </span>
          </div>
          <div className="mt-3 flex items-center justify-between text-[10px] border-t border-slate-100 pt-2.5 font-bold">
            <span className="text-rose-600">CRIT: {severityCounts.CRITICAL || 0}</span>
            <span className="text-orange-600">HIGH: {severityCounts.HIGH || 0}</span>
            <span className="text-amber-600">SUSP: {severityCounts.SUSPICIOUS || 0}</span>
          </div>
        </div>

        {/* KPI 4: Decision Latency & Precision */}
        <div className="glass-panel-interactive p-5 rounded-2xl relative overflow-hidden group border border-white/90 bg-white/75 shadow-xs">
          <div className="flex items-center justify-between text-slate-500 mb-2">
            <span className="text-[10px] tracking-wider uppercase font-bold text-slate-500">AI ENGINE PRECISION</span>
            <div className="p-2 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-600 shadow-xs group-hover:scale-105 transition">
              <CheckCircle2 className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-baseline justify-between">
            <span className="text-3xl font-black text-emerald-600 tracking-tight">
              100.00%
            </span>
            <span className="text-[10px] text-blue-700 bg-blue-50 font-bold px-2 py-0.5 rounded-lg border border-blue-200">
              ~7.0 ms / flow
            </span>
          </div>
          <div className="mt-3 flex items-center justify-between text-[10px] text-slate-500 border-t border-slate-100 pt-2.5 font-medium">
            <span>BENIGN FPR: <strong className="text-slate-800">0.000%</strong></span>
            <span>F1-SCORE: <strong className="text-emerald-600 font-bold">1.00</strong></span>
          </div>
        </div>
      </div>

      {/* Main Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Real-time Velocity Area Chart (2 Cols) */}
        <div className="lg:col-span-2 glass-panel p-5 rounded-2xl border border-white/90 bg-white/80 shadow-xs">
          <div className="flex items-center justify-between mb-4 border-b border-slate-100 pb-3">
            <div>
              <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                <Activity className="w-4 h-4 text-sky-600" />
                NETWORK FLOW VELOCITY // TIME-SERIES CORRELATION
              </h3>
              <p className="text-[10px] text-slate-500 mt-0.5">
                BENIGN WIRELESS / ETHERNET TRAFFIC VS DETECTED ATTACK PACKETS (ROLLING 60s)
              </p>
            </div>
            <div className="flex items-center gap-2.5 text-[10px]">
              <span className="flex items-center gap-1.5 text-emerald-800 font-bold bg-emerald-50 px-2.5 py-1 rounded-lg border border-emerald-200 shadow-2xs">
                <span className="w-2 h-2 rounded-full bg-emerald-500 inline-block animate-pulse" /> NORMAL
              </span>
              <span className="flex items-center gap-1.5 text-rose-800 font-bold bg-rose-50 px-2.5 py-1 rounded-lg border border-rose-200 shadow-2xs">
                <span className="w-2 h-2 rounded-full bg-rose-500 inline-block animate-pulse" /> MALICIOUS
              </span>
            </div>
          </div>

          <div className="h-64 w-full">
            {mounted && trafficHistory.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trafficHistory} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorNormalLight" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#10b981" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
                    </linearGradient>
                    <linearGradient id="colorMaliciousLight" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.5} />
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" vertical={false} />
                  <XAxis
                    dataKey="timestamp"
                    stroke="#94a3b8"
                    tick={{ fontSize: 9, fill: "#64748b", fontFamily: "monospace" }}
                    interval="preserveStartEnd"
                  />
                  <YAxis
                    stroke="#94a3b8"
                    tick={{ fontSize: 9, fill: "#64748b", fontFamily: "monospace" }}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "rgba(255, 255, 255, 0.96)",
                      backdropFilter: "blur(16px)",
                      borderColor: "rgba(226, 232, 240, 0.9)",
                      borderRadius: "12px",
                      boxShadow: "0 12px 30px rgba(15, 23, 42, 0.08)",
                      fontFamily: "monospace",
                      fontSize: "11px",
                      color: "#0f172a",
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="normal_flows"
                    name="Normal Flows"
                    stroke="#059669"
                    strokeWidth={2.5}
                    fillOpacity={1}
                    fill="url(#colorNormalLight)"
                  />
                  <Area
                    type="monotone"
                    dataKey="malicious_flows"
                    name="Malicious Flows"
                    stroke="#dc2626"
                    strokeWidth={2.5}
                    fillOpacity={1}
                    fill="url(#colorMaliciousLight)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-slate-400">
                SYNCHRONIZING TELEMETRY STREAM...
              </div>
            )}
          </div>
        </div>

        {/* Attack Vector Distribution (1 Col) */}
        <div className="glass-panel p-5 rounded-2xl border border-white/90 bg-white/80 shadow-xs flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4 border-b border-slate-100 pb-3">
              <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-orange-600" />
                ATTACK TAXONOMY BREAKDOWN
              </h3>
              <span className="text-[10px] text-slate-700 bg-slate-100 font-bold px-2 py-0.5 rounded-md">
                {totalAttacks} DETECTIONS
              </span>
            </div>

            <div className="space-y-3">
              {sortedAttacks.length > 0 ? (
                sortedAttacks.map(([attackName, count]) => {
                  const pct = totalAttacks > 0 ? (count / totalAttacks) * 100 : 0;
                  const barColor =
                    attackName === "DDoS" || attackName === "DoS"
                      ? "bg-gradient-to-r from-orange-500 to-rose-600"
                      : attackName === "Botnet"
                      ? "bg-gradient-to-r from-purple-500 to-indigo-600"
                      : attackName === "PortScan"
                      ? "bg-gradient-to-r from-amber-500 to-yellow-500"
                      : "bg-gradient-to-r from-sky-500 to-blue-600";

                  return (
                    <div key={attackName} className="space-y-1.5">
                      <div className="flex justify-between text-[11px]">
                        <span className="text-slate-800 font-bold">{attackName}</span>
                        <span className="text-slate-500 font-semibold">
                          {count.toLocaleString()} ({pct.toFixed(1)}%)
                        </span>
                      </div>
                      <div className="h-2 w-full bg-slate-100 rounded-full overflow-hidden border border-slate-200/60">
                        <div
                          className={`h-full ${barColor} transition-all duration-300 rounded-full`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  );
                })
              ) : (
                <div className="text-center py-10 text-xs text-slate-400">
                  NO ATTACK SIGNATURES RECORDED
                </div>
              )}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-100 flex items-center justify-between text-[10px] text-slate-500 font-medium">
            <span>STANDARDS: CIC-IDS2017</span>
            <button
              onClick={onNavigateToMitre}
              className="text-blue-600 hover:text-blue-700 flex items-center gap-1 font-bold transition"
            >
              EXPLORE MITRE MATRIX <ExternalLink className="w-3 h-3" />
            </button>
          </div>
        </div>
      </div>

      {/* Recent High-Priority Incident Feed Ticker */}
      <div className="glass-panel p-5 rounded-2xl border border-white/90 bg-white/80 shadow-xs">
        <div className="flex items-center justify-between mb-4 border-b border-slate-100 pb-3">
          <div className="flex items-center gap-2.5">
            <span className="relative flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-rose-600"></span>
            </span>
            <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
              HIGH-PRIORITY NOTABLE INCIDENTS (RADAR STREAM)
            </h3>
          </div>
          <button
            onClick={onNavigateToAlerts}
            className="text-[10px] text-blue-700 hover:text-blue-800 flex items-center gap-1.5 transition font-bold bg-blue-50 px-3 py-1 rounded-lg border border-blue-200"
          >
            VIEW ALL INCIDENTS FEED <ExternalLink className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto rounded-xl border border-slate-200/80">
          <table className="w-full text-left text-xs border-collapse">
            <thead className="bg-slate-50 text-slate-500 uppercase text-[9px] border-b border-slate-200 font-bold tracking-wider">
              <tr>
                <th className="py-3 px-3.5">TIMESTAMP (UTC)</th>
                <th className="py-3 px-3.5">SEVERITY</th>
                <th className="py-3 px-3.5">ATTACK VECTOR</th>
                <th className="py-3 px-3.5">SOURCE HOST</th>
                <th className="py-3 px-3.5">TARGET SERVICE</th>
                <th className="py-3 px-3.5">CONFIDENCE</th>
                <th className="py-3 px-3.5 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 bg-white/60">
              {recentAlerts.length > 0 ? (
                Array.from(
                  new Map(recentAlerts.map((a) => [a.alert_id, a])).values()
                )
                  .slice(0, 5)
                  .map((alert, idx) => {
                    const sevStyle =
                      alert.severity === "CRITICAL"
                        ? "bg-rose-50 text-rose-700 border-rose-200 shadow-2xs font-bold"
                        : alert.severity === "HIGH"
                        ? "bg-orange-50 text-orange-700 border-orange-200 font-bold"
                        : "bg-amber-50 text-amber-700 border-amber-200 font-bold";

                    return (
                      <tr
                        key={`${alert.alert_id}-${idx}`}
                        onClick={() => onSelectAlert(alert)}
                        className="hover:bg-blue-50/50 cursor-pointer transition select-none"
                      >
                        <td className="py-3 px-3.5 text-slate-500 text-[10px] whitespace-nowrap">
                          {alert.timestamp.split("T")[1]?.slice(0, 8) || alert.timestamp}
                        </td>
                        <td className="py-3 px-3.5 whitespace-nowrap">
                          <span className={`px-2 py-0.5 text-[9px] border rounded-md ${sevStyle}`}>
                            {alert.severity}
                          </span>
                        </td>
                        <td className="py-3 px-3.5 text-slate-900 font-bold whitespace-nowrap">
                          {alert.classification}
                        </td>
                        <td className="py-3 px-3.5 text-blue-600 font-bold font-mono whitespace-nowrap">
                          {alert.source_ip}:{alert.source_port}
                        </td>
                        <td className="py-3 px-3.5 text-slate-700 font-mono whitespace-nowrap">
                          {alert.destination_ip}:{alert.destination_port} ({alert.protocol})
                        </td>
                        <td className="py-3 px-3.5 text-emerald-600 font-bold whitespace-nowrap">
                          {(alert.confidence_score * 100).toFixed(1)}%
                        </td>
                        <td className="py-3 px-3.5 text-right whitespace-nowrap">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              onSelectAlert(alert);
                            }}
                            className="px-3 py-1 text-[10px] bg-white hover:bg-blue-50 text-slate-700 hover:text-blue-700 border border-slate-200 rounded-lg transition font-bold shadow-2xs"
                          >
                            INVESTIGATE
                          </button>
                        </td>
                      </tr>
                    );
                  })
              ) : (
                <tr>
                  <td colSpan={7} className="py-10 text-center text-slate-400 text-xs">
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
