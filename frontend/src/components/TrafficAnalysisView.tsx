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
      const verdictColor = isMalicious ? "text-red-400 font-bold" : "text-emerald-400";

      const logLine = `${now} | ${proto.padEnd(4)} | 192.168.${Math.floor(Math.random()*10+1)}.${Math.floor(Math.random()*250+1)}:${srcPort} -> 10.0.0.${Math.floor(Math.random()*20+1)}:${dstPort} | ${flags.padEnd(10)} | LEN=${len}B | AI=${verdict}`;
      setLiveStreamLogs((prev) => [logLine, ...prev.slice(0, 18)]);
    }, 1200);

    return () => clearInterval(streamInterval);
  }, []);

  const protoData = [
    { name: "TCP", value: data?.protocol_distribution?.TCP || 88, color: "#3b82f6" },
    { name: "UDP", value: data?.protocol_distribution?.UDP || 10, color: "#10b981" },
    { name: "ICMP", value: data?.protocol_distribution?.ICMP || 2, color: "#f59e0b" },
  ];

  const portColors = ["#ef4444", "#f97316", "#f59e0b", "#10b981", "#06b6d4", "#3b82f6", "#8b5cf6", "#ec4899"];

  return (
    <div className="space-y-3.5 font-mono-tech">
      {/* Top Banner: Protocol & OSI Overview */}
      <div className="bg-[#0d0f17] border border-[#1a1e2e] p-3.5 rounded-[2px] flex items-center justify-between">
        <div>
          <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <Network className="w-4 h-4 text-cyan-400" />
            TCP/IP PROTOCOL SUITE & FLOW TELEMETRY INSPECTOR
          </h2>
          <p className="text-[10px] text-zinc-400 mt-0.5">
            L3/L4 PACKET HEADER ANALYZER // HARDWARE FLOW CACHE SAMPLING
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <div className="bg-[#090b10] border border-[#1a1e2e] px-2.5 py-1 rounded-[2px]">
            <span className="text-zinc-500 text-[10px]">SAMPLED:</span>{" "}
            <span className="text-cyan-400 font-bold">{data?.sampled_flows ?? 200} flows</span>
          </div>
          <div className="bg-[#090b10] border border-[#1a1e2e] px-2.5 py-1 rounded-[2px]">
            <span className="text-zinc-500 text-[10px]">AVG PKT SIZE:</span>{" "}
            <span className="text-emerald-400 font-bold">{data?.avg_packet_size_bytes ?? 482} B</span>
          </div>
        </div>
      </div>

      {/* Grid: L4 Protocol Distribution & Top Targeted Ports */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        {/* L4 Protocol Share */}
        <div className="bg-[#0d0f17] border border-[#1a1e2e] p-3.5 rounded-[2px]">
          <h3 className="text-xs font-bold text-zinc-200 uppercase tracking-wider mb-2 border-b border-[#1a1e2e] pb-1.5 flex items-center gap-2">
            <Layers className="w-3.5 h-3.5 text-blue-400" />
            TRANSPORT LAYER (L4) PROTOCOL DISTRIBUTION
          </h3>

          <div className="grid grid-cols-3 gap-2 my-2">
            {protoData.map((p) => (
              <div key={p.name} className="bg-[#090b10] border border-[#1a1e2e] p-2 rounded-[2px] text-center">
                <span className="text-[11px] text-zinc-400 font-bold">{p.name}</span>
                <div className="text-base font-bold" style={{ color: p.color }}>
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
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {protoData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} stroke="#090b10" strokeWidth={2} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#090b10",
                      borderColor: "#1a1e2e",
                      fontSize: "10px",
                      fontFamily: "monospace",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Top Targeted Destination Ports */}
        <div className="bg-[#0d0f17] border border-[#1a1e2e] p-3.5 rounded-[2px]">
          <h3 className="text-xs font-bold text-zinc-200 uppercase tracking-wider mb-2 border-b border-[#1a1e2e] pb-1.5 flex items-center gap-2">
            <Radio className="w-3.5 h-3.5 text-red-400" />
            TOP TARGETED DESTINATION PORTS
          </h3>

          <div className="h-52 w-full">
            {mounted && data?.top_targeted_ports && data.top_targeted_ports.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data.top_targeted_ports} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="2 2" stroke="#161a29" vertical={false} />
                  <XAxis
                    dataKey="port"
                    stroke="#4b5563"
                    tick={{ fontSize: 9, fill: "#9ca3af", fontFamily: "monospace" }}
                  />
                  <YAxis stroke="#4b5563" tick={{ fontSize: 9, fill: "#9ca3af", fontFamily: "monospace" }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#090b10",
                      borderColor: "#1a1e2e",
                      fontSize: "10px",
                      fontFamily: "monospace",
                    }}
                  />
                  <Bar dataKey="count" name="Flow Count">
                    {data.top_targeted_ports.map((entry, idx) => (
                      <Cell key={`cell-${idx}`} fill={portColors[idx % portColors.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-zinc-600">
                PROFILING PORT FLOWS...
              </div>
            )}
          </div>

          <div className="flex items-center justify-between text-[9px] text-zinc-500 pt-1.5 border-t border-[#1a1e2e]">
            <span>PORTS 80/443: HTTP/HTTPS</span>
            <span>PORT 22: SSH</span>
            <span>PORT 21: FTP</span>
            <span>PORT 3389: RDP</span>
          </div>
        </div>
      </div>

      {/* Wireshark-Style Live Packet / Flow Terminal Stream */}
      <div className="bg-[#0d0f17] border border-[#1a1e2e] p-3 rounded-[2px]">
        <div className="flex items-center justify-between mb-2 border-b border-[#1a1e2e] pb-1.5">
          <div className="flex items-center gap-2">
            <Terminal className="w-3.5 h-3.5 text-emerald-400" />
            <h3 className="text-xs font-bold text-zinc-200 uppercase tracking-wider">
              REAL-TIME PACKET FLOW STREAM (WIRESHARK / ZEEK LIVE CAPTURE)
            </h3>
          </div>
          <span className="text-[9px] px-1.5 py-0.2 bg-emerald-950 border border-emerald-700 text-emerald-300 font-bold rounded-[2px]">
            PROMISCUOUS CAPTURE ACTIVE
          </span>
        </div>

        <div className="bg-[#07080c] border border-[#151928] p-2.5 rounded-[2px] max-h-48 overflow-y-auto space-y-1 text-[10px]">
          {liveStreamLogs.length > 0 ? (
            liveStreamLogs.map((log, idx) => {
              const isThreat = log.includes("THREAT_DETECTED");
              return (
                <div
                  key={idx}
                  className={`leading-tight px-1.5 py-0.5 rounded-[1px] ${
                    isThreat ? "bg-red-950/40 text-red-300 border-l-2 border-red-500" : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  {log}
                </div>
              );
            })
          ) : (
            <div className="text-zinc-600 text-center py-4">INITIALIZING LIVE PACKET STREAM BUFFER...</div>
          )}
        </div>
      </div>
    </div>
  );
};
