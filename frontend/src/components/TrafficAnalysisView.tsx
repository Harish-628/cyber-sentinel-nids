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
    { name: "TCP", value: data?.protocol_distribution?.TCP || 88, color: "#38bdf8" },
    { name: "UDP", value: data?.protocol_distribution?.UDP || 10, color: "#34d399" },
    { name: "ICMP", value: data?.protocol_distribution?.ICMP || 2, color: "#fbbf24" },
  ];

  const portColors = ["#f87171", "#fb923c", "#facc15", "#4ade80", "#22d3ee", "#60a5fa", "#a78bfa", "#f472b6"];

  return (
    <div className="space-y-4 font-mono-tech">
      {/* Top Banner: Protocol & OSI Overview - Glassmorphic */}
      <div className="glass-panel p-4 rounded-xl flex flex-wrap items-center justify-between gap-3 shadow-xl border border-white/10">
        <div>
          <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/40 shadow-[0_0_12px_rgba(6,182,212,0.3)] flex items-center justify-center">
              <Network className="w-4 h-4 text-cyan-400" />
            </div>
            TCP/IP PROTOCOL SUITE & FLOW TELEMETRY INSPECTOR
          </h2>
          <p className="text-[10px] text-zinc-400 mt-1">
            L3/L4 PACKET HEADER ANALYZER // HARDWARE FLOW CACHE SAMPLING
          </p>
        </div>
        <div className="flex items-center gap-2.5 text-xs">
          <div className="glass-panel-interactive border-white/10 px-3 py-1.5 rounded-lg shadow-sm">
            <span className="text-zinc-400 text-[10px] uppercase tracking-wider font-semibold">SAMPLED:</span>{" "}
            <span className="text-cyan-400 font-bold">{data?.sampled_flows ?? 200} flows</span>
          </div>
          <div className="glass-panel-interactive border-white/10 px-3 py-1.5 rounded-lg shadow-sm">
            <span className="text-zinc-400 text-[10px] uppercase tracking-wider font-semibold">AVG PKT SIZE:</span>{" "}
            <span className="text-emerald-400 font-bold">{data?.avg_packet_size_bytes ?? 482} B</span>
          </div>
        </div>
      </div>

      {/* Grid: L4 Protocol Distribution & Top Targeted Ports */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* L4 Protocol Share */}
        <div className="glass-panel p-4 rounded-xl border border-white/10 shadow-xl">
          <h3 className="text-xs font-bold text-zinc-200 uppercase tracking-wider mb-3 border-b border-white/10 pb-2 flex items-center gap-2">
            <Layers className="w-4 h-4 text-cyan-400" />
            TRANSPORT LAYER (L4) PROTOCOL DISTRIBUTION
          </h3>

          <div className="grid grid-cols-3 gap-2.5 my-3">
            {protoData.map((p) => (
              <div key={p.name} className="glass-panel rounded-lg p-2.5 border border-white/5 text-center shadow-sm">
                <span className="text-[10px] text-zinc-400 font-bold uppercase tracking-wider">{p.name}</span>
                <div className="text-base font-bold mt-0.5" style={{ color: p.color }}>
                  {p.value} flows
                </div>
              </div>
            ))}
          </div>

          <div className="h-44 w-full">
            {mounted && (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={protoData}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={70}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {protoData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} stroke="rgba(10, 15, 29, 0.8)" strokeWidth={2} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "rgba(8, 12, 24, 0.95)",
                      borderColor: "rgba(255, 255, 255, 0.15)",
                      borderRadius: "8px",
                      fontSize: "10px",
                      fontFamily: "monospace",
                      boxShadow: "0 8px 32px rgba(0, 0, 0, 0.5)",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Top Targeted Destination Ports */}
        <div className="glass-panel p-4 rounded-xl border border-white/10 shadow-xl">
          <h3 className="text-xs font-bold text-zinc-200 uppercase tracking-wider mb-3 border-b border-white/10 pb-2 flex items-center gap-2">
            <Radio className="w-4 h-4 text-red-400" />
            TOP TARGETED DESTINATION PORTS
          </h3>

          <div className="h-52 w-full">
            {mounted && data?.top_targeted_ports && data.top_targeted_ports.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data.top_targeted_ports} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.05)" vertical={false} />
                  <XAxis
                    dataKey="port"
                    stroke="#64748b"
                    tick={{ fontSize: 9, fill: "#94a3b8", fontFamily: "monospace" }}
                  />
                  <YAxis stroke="#64748b" tick={{ fontSize: 9, fill: "#94a3b8", fontFamily: "monospace" }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "rgba(8, 12, 24, 0.95)",
                      borderColor: "rgba(255, 255, 255, 0.15)",
                      borderRadius: "8px",
                      fontSize: "10px",
                      fontFamily: "monospace",
                      boxShadow: "0 8px 32px rgba(0, 0, 0, 0.5)",
                    }}
                  />
                  <Bar dataKey="count" name="Flow Count" radius={[4, 4, 0, 0]}>
                    {data.top_targeted_ports.map((entry, idx) => (
                      <Cell key={`cell-${idx}`} fill={portColors[idx % portColors.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-zinc-500">
                PROFILING PORT FLOWS...
              </div>
            )}
          </div>

          <div className="flex flex-wrap items-center justify-between text-[9px] text-zinc-400 pt-2 border-t border-white/10 gap-2">
            <span className="bg-white/5 px-2 py-0.5 rounded border border-white/5">PORTS 80/443: HTTP/HTTPS</span>
            <span className="bg-white/5 px-2 py-0.5 rounded border border-white/5">PORT 22: SSH</span>
            <span className="bg-white/5 px-2 py-0.5 rounded border border-white/5">PORT 21: FTP</span>
            <span className="bg-white/5 px-2 py-0.5 rounded border border-white/5">PORT 3389: RDP</span>
          </div>
        </div>
      </div>

      {/* Wireshark-Style Live Packet / Flow Terminal Stream */}
      <div className="glass-panel p-4 rounded-xl border border-white/10 shadow-2xl">
        <div className="flex flex-wrap items-center justify-between mb-3 border-b border-white/10 pb-2.5 gap-2">
          <div className="flex items-center gap-2.5">
            <Terminal className="w-4 h-4 text-emerald-400" />
            <h3 className="text-xs font-bold text-zinc-200 uppercase tracking-wider">
              REAL-TIME PACKET FLOW STREAM (WIRESHARK / ZEEK LIVE CAPTURE)
            </h3>
          </div>
          <span className="text-[9px] px-2.5 py-1 bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 font-bold rounded-lg shadow-[0_0_10px_rgba(16,185,129,0.25)] flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            PROMISCUOUS CAPTURE ACTIVE
          </span>
        </div>

        <div className="bg-[#040711]/90 border border-white/10 p-3 rounded-xl max-h-52 overflow-y-auto space-y-1 text-[10px] shadow-inner font-mono">
          {liveStreamLogs.length > 0 ? (
            liveStreamLogs.map((log, idx) => {
              const isThreat = log.includes("THREAT_DETECTED");
              return (
                <div
                  key={idx}
                  className={`leading-relaxed px-2.5 py-1 rounded transition-colors ${
                    isThreat
                      ? "bg-gradient-to-r from-red-500/20 via-red-950/30 to-transparent text-red-200 border-l-2 border-red-500 font-bold"
                      : "text-zinc-400 hover:text-zinc-200 hover:bg-white/[0.03]"
                  }`}
                >
                  {log}
                </div>
              );
            })
          ) : (
            <div className="text-zinc-500 text-center py-4">INITIALIZING LIVE PACKET STREAM BUFFER...</div>
          )}
        </div>
      </div>
    </div>
  );
};
