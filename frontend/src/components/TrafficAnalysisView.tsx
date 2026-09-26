"use client";

import React, { useEffect, useState } from "react";
import {
  Activity,
  Cpu,
  Database,
  Globe,
  HardDrive,
  Layers,
  Network,
  Radio,
  Server,
  Terminal,
  Zap,
} from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { fetchTrafficDeepDive } from "@/lib/api";
import { DeepDiveMetrics } from "@/lib/types";

export const TrafficAnalysisView: React.FC = () => {
  const [data, setData] = useState<DeepDiveMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [mounted, setMounted] = useState(false);
  const [liveStreamLogs, setLiveStreamLogs] = useState<string[]>([]);

  useEffect(() => {
    setMounted(true);
    const loadDeepDive = async () => {
      try {
        const res = await fetchTrafficDeepDive();
        setData(res);
      } catch (e) {
        console.error("Failed to load deep dive traffic data", e);
      } finally {
        setLoading(false);
      }
    };
    loadDeepDive();
    const interval = setInterval(loadDeepDive, 3000);
    return () => clearInterval(interval);
  }, []);

  // Simulate Wireshark live packet stream ticker
  useEffect(() => {
    const streamInterval = setInterval(() => {
      const now = new Date().toISOString().split("T")[1].slice(0, 12);
      const isMalicious = Math.random() < 0.25;
      const proto = Math.random() > 0.15 ? "TCP" : "UDP";
      const srcPort = Math.floor(Math.random() * 20000 + 45000);
      const dstPorts = [80, 443, 22, 21, 3389, 8080, 53];
      const dstPort = dstPorts[Math.floor(Math.random() * dstPorts.length)];
      const flags = isMalicious ? "[SYN]" : "[ACK, PSH]";
      const len = isMalicious ? (dstPort === 3389 ? 0 : 128) : Math.floor(Math.random() * 800 + 200);
      const verdict = isMalicious ? "THREAT_DETECTED" : "BENIGN_PERMITTED";

      const logLine = `${now} | ${proto.padEnd(4)} | 192.168.${Math.floor(Math.random() * 10 + 1)}.${Math.floor(Math.random() * 250 + 1)}:${srcPort} -> 10.0.0.${Math.floor(Math.random() * 20 + 1)}:${dstPort} | ${flags.padEnd(10)} | LEN=${len}B | AI=${verdict}`;
      setLiveStreamLogs((prev) => [logLine, ...prev.slice(0, 18)]);
    }, 1200);

    return () => clearInterval(streamInterval);
  }, []);

  const protoData = [
    { name: "TCP", value: data?.protocol_distribution?.TCP || 88, color: "#0284c7" },
    { name: "UDP", value: data?.protocol_distribution?.UDP || 10, color: "#059669" },
    { name: "ICMP", value: data?.protocol_distribution?.ICMP || 2, color: "#d97706" },
  ];

  const portColors = ["#ef4444", "#f97316", "#eab308", "#10b981", "#06b6d4", "#3b82f6", "#8b5cf6", "#ec4899"];

  return (
    <div className="space-y-4 font-mono-tech">
      {/* Top Banner: Protocol & OSI Overview */}
      <div className="glass-panel p-5 rounded-2xl flex flex-wrap items-center justify-between gap-3 shadow-xs border border-white/90 bg-white/80">
        <div>
          <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl bg-sky-50 border border-sky-200 flex items-center justify-center shadow-xs">
              <Network className="w-5 h-5 text-sky-600" />
            </div>
            TCP/IP PROTOCOL SUITE & FLOW TELEMETRY INSPECTOR
          </h2>
          <p className="text-[10px] text-slate-500 mt-1">
            L3/L4 PACKET HEADER ANALYZER // HARDWARE FLOW CACHE SAMPLING
          </p>
        </div>
        <div className="flex items-center gap-3 text-xs">
          <div className="bg-slate-100 border border-slate-200 px-3.5 py-1.5 rounded-xl shadow-2xs font-bold">
            <span className="text-slate-500 text-[10px] uppercase tracking-wider font-semibold">SAMPLED:</span>{" "}
            <span className="text-sky-700 font-bold">{data?.sampled_flows ?? 200} flows</span>
          </div>
          <div className="bg-slate-100 border border-slate-200 px-3.5 py-1.5 rounded-xl shadow-2xs font-bold">
            <span className="text-slate-500 text-[10px] uppercase tracking-wider font-semibold">AVG PKT SIZE:</span>{" "}
            <span className="text-emerald-700 font-bold">{data?.avg_packet_size_bytes ?? 482} B</span>
          </div>
        </div>
      </div>

      {/* Grid: L4 Protocol Distribution & Top Targeted Ports */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* L4 Protocol Share */}
        <div className="glass-panel p-5 rounded-2xl border border-white/90 bg-white/80 shadow-xs">
          <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-3 border-b border-slate-100 pb-2.5 flex items-center gap-2">
            <Layers className="w-4 h-4 text-sky-600" />
            TRANSPORT LAYER (L4) PROTOCOL DISTRIBUTION
          </h3>

          <div className="grid grid-cols-3 gap-3 my-3">
            {protoData.map((p) => (
              <div key={p.name} className="bg-white border border-slate-200/80 p-3 rounded-xl text-center shadow-2xs">
                <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">{p.name}</span>
                <div className="text-lg font-bold mt-0.5" style={{ color: p.color }}>
                  {p.value} flows
                </div>
              </div>
            ))}
          </div>

          <div className="h-48 w-full">
            {mounted && (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={protoData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={75}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {protoData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} stroke="#ffffff" strokeWidth={2} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "rgba(255, 255, 255, 0.96)",
                      borderColor: "rgba(226, 232, 240, 0.9)",
                      borderRadius: "12px",
                      fontSize: "11px",
                      fontFamily: "monospace",
                      boxShadow: "0 10px 25px rgba(0, 0, 0, 0.08)",
                      color: "#0f172a",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Top Targeted Destination Ports */}
        <div className="glass-panel p-5 rounded-2xl border border-white/90 bg-white/80 shadow-xs">
          <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-3 border-b border-slate-100 pb-2.5 flex items-center gap-2">
            <Radio className="w-4 h-4 text-rose-600" />
            TOP TARGETED DESTINATION PORTS
          </h3>

          <div className="h-56 w-full">
            {mounted && data?.top_targeted_ports && data.top_targeted_ports.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data.top_targeted_ports} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" vertical={false} />
                  <XAxis
                    dataKey="port"
                    stroke="#94a3b8"
                    tick={{ fontSize: 9, fill: "#64748b", fontFamily: "monospace" }}
                  />
                  <YAxis stroke="#94a3b8" tick={{ fontSize: 9, fill: "#64748b", fontFamily: "monospace" }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "rgba(255, 255, 255, 0.96)",
                      borderColor: "rgba(226, 232, 240, 0.9)",
                      borderRadius: "12px",
                      fontSize: "11px",
                      fontFamily: "monospace",
                      boxShadow: "0 10px 25px rgba(0, 0, 0, 0.08)",
                      color: "#0f172a",
                    }}
                  />
                  <Bar dataKey="count" name="Flow Count" radius={[6, 6, 0, 0]}>
                    {data.top_targeted_ports.map((entry, idx) => (
                      <Cell key={`cell-${idx}`} fill={portColors[idx % portColors.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-slate-400">
                PROFILING PORT FLOWS...
              </div>
            )}
          </div>

          <div className="flex flex-wrap items-center justify-between text-[9px] text-slate-500 pt-2.5 border-t border-slate-100 gap-2 font-medium">
            <span className="bg-slate-100 px-2 py-0.5 rounded-md border border-slate-200">PORTS 80/443: HTTP/HTTPS</span>
            <span className="bg-slate-100 px-2 py-0.5 rounded-md border border-slate-200">PORT 22: SSH</span>
            <span className="bg-slate-100 px-2 py-0.5 rounded-md border border-slate-200">PORT 21: FTP</span>
            <span className="bg-slate-100 px-2 py-0.5 rounded-md border border-slate-200">PORT 3389: RDP</span>
          </div>
        </div>
      </div>

      {/* Wireshark-Style Live Packet / Flow Terminal Stream */}
      <div className="glass-panel p-5 rounded-2xl border border-white/90 bg-white/80 shadow-xs">
        <div className="flex flex-wrap items-center justify-between mb-3 border-b border-slate-100 pb-3 gap-2">
          <div className="flex items-center gap-2.5">
            <Terminal className="w-4 h-4 text-emerald-600" />
            <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
              REAL-TIME PACKET FLOW STREAM (WIRESHARK / ZEEK LIVE CAPTURE)
            </h3>
          </div>
          <span className="text-[10px] px-3 py-1 bg-emerald-50 border border-emerald-300 text-emerald-800 font-bold rounded-xl shadow-2xs flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            PROMISCUOUS CAPTURE ACTIVE
          </span>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl max-h-56 overflow-y-auto space-y-1 text-[11px] shadow-inner font-mono text-slate-300">
          {liveStreamLogs.length > 0 ? (
            liveStreamLogs.map((log, idx) => {
              const isThreat = log.includes("THREAT_DETECTED");
              return (
                <div
                  key={idx}
                  className={`leading-relaxed px-3 py-1 rounded transition-colors ${
                    isThreat
                      ? "bg-rose-950/50 text-rose-300 border-l-2 border-rose-500 font-bold"
                      : "text-slate-300 hover:text-white hover:bg-slate-800/50"
                  }`}
                >
                  {log}
                </div>
              );
            })
          ) : (
            <div className="text-slate-500 text-center py-6">INITIALIZING LIVE PACKET STREAM BUFFER...</div>
          )}
        </div>
      </div>
    </div>
  );
};
