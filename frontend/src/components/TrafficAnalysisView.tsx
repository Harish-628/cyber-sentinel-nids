"use client";

import React, { useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  Filter,
  Layers,
  Network,
  Pause,
  Play,
  Radio,
  Search,
  ShieldAlert,
  Terminal,
  Trash2,
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
import { fetchLiveFlows, fetchTrafficDeepDive } from "@/lib/api";
import { DeepDiveMetrics, RealtimeFlowLog } from "@/lib/types";

interface TrafficAnalysisViewProps {
  liveFlows?: RealtimeFlowLog[];
}

export const TrafficAnalysisView: React.FC<TrafficAnalysisViewProps> = ({ liveFlows: externalFlows = [] }) => {
  const [data, setData] = useState<DeepDiveMetrics | null>(null);
  const [localFlows, setLocalFlows] = useState<RealtimeFlowLog[]>([]);
  const [isPaused, setIsPaused] = useState(false);
  const [protocolFilter, setProtocolFilter] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [mounted, setMounted] = useState(false);

  // Fetch initial deep dive & initial flow records on mount
  useEffect(() => {
    setMounted(true);
    const loadData = async () => {
      try {
        const [deepDive, initialFlows] = await Promise.all([
          fetchTrafficDeepDive(),
          fetchLiveFlows(40),
        ]);
        setData(deepDive);
        if (initialFlows && initialFlows.length > 0) {
          setLocalFlows((prev) => (prev.length === 0 ? initialFlows : prev));
        }
      } catch (e) {
        console.error("Failed to load traffic telemetry", e);
      }
    };

    loadData();
    const interval = setInterval(async () => {
      try {
        const deepDive = await fetchTrafficDeepDive();
        setData(deepDive);
      } catch (e) {
        // ignore periodic fetch errors
      }
    }, 4000);

    return () => clearInterval(interval);
  }, []);

  // Sync incoming real-time flows from WebSocket if not paused
  useEffect(() => {
    if (isPaused || !externalFlows || externalFlows.length === 0) return;

    setLocalFlows((prev) => {
      const existingIds = new Set(prev.map((f) => f.flow_id));
      const newItems = externalFlows.filter((f) => !existingIds.has(f.flow_id));
      if (newItems.length === 0) return prev;
      return [...newItems, ...prev].slice(0, 150);
    });
  }, [externalFlows, isPaused]);

  // Filter flows based on user selection
  const filteredFlows = useMemo(() => {
    return localFlows.filter((flow) => {
      if (protocolFilter !== "ALL") {
        if (protocolFilter === "THREATS" && !flow.is_malicious) return false;
        if (protocolFilter === "TCP" && flow.protocol.toUpperCase() !== "TCP") return false;
        if (protocolFilter === "UDP" && flow.protocol.toUpperCase() !== "UDP") return false;
      }
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase().trim();
        const matchesSrc = flow.src_ip.toLowerCase().includes(query) || flow.src_port.toString().includes(query);
        const matchesDst = flow.dst_ip.toLowerCase().includes(query) || flow.dst_port.toString().includes(query);
        const matchesClass = flow.classification.toLowerCase().includes(query);
        if (!matchesSrc && !matchesDst && !matchesClass) return false;
      }
      return true;
    });
  }, [localFlows, protocolFilter, searchQuery]);

  // Dynamic L4 protocol distribution
  const protoData = useMemo(() => {
    const counts = { TCP: 0, UDP: 0, ICMP: 0 };
    if (localFlows.length > 0) {
      localFlows.forEach((f) => {
        const p = f.protocol.toUpperCase();
        if (p === "TCP") counts.TCP += 1;
        else if (p === "UDP") counts.UDP += 1;
        else counts.ICMP += 1;
      });
    } else if (data?.protocol_distribution) {
      counts.TCP = data.protocol_distribution.TCP || 0;
      counts.UDP = data.protocol_distribution.UDP || 0;
      counts.ICMP = data.protocol_distribution.ICMP || 0;
    } else {
      counts.TCP = 1;
    }

    return [
      { name: "TCP", value: counts.TCP, color: "#0284c7" },
      { name: "UDP", value: counts.UDP, color: "#059669" },
      { name: "ICMP", value: counts.ICMP, color: "#d97706" },
    ];
  }, [localFlows, data]);

  // Top Targeted Ports
  const topPortsData = useMemo(() => {
    if (data?.top_targeted_ports && data.top_targeted_ports.length > 0) {
      return data.top_targeted_ports;
    }
    const portMap: Record<number, number> = {};
    localFlows.forEach((f) => {
      portMap[f.dst_port] = (portMap[f.dst_port] || 0) + 1;
    });
    return Object.entries(portMap)
      .map(([port, count]) => ({ port: Number(port), count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  }, [data, localFlows]);

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
            REAL-TIME FLOW TELEMETRY & SOCKET INSPECTOR
          </h2>
          <p className="text-[10px] text-slate-500 mt-1">
            SUB-MILLISECOND AI CLASSIFICATION // LIVE LINUX KERNEL SOCKET CAPTURE
          </p>
        </div>

        <div className="flex items-center gap-3 text-xs flex-wrap">
          <div className="bg-slate-100 border border-slate-200 px-3.5 py-1.5 rounded-xl shadow-2xs font-bold">
            <span className="text-slate-500 text-[10px] uppercase tracking-wider font-semibold">STREAMED:</span>{" "}
            <span className="text-sky-700 font-bold">{localFlows.length} flows</span>
          </div>
          <div className="bg-slate-100 border border-slate-200 px-3.5 py-1.5 rounded-xl shadow-2xs font-bold">
            <span className="text-slate-500 text-[10px] uppercase tracking-wider font-semibold">AVG PKT SIZE:</span>{" "}
            <span className="text-emerald-700 font-bold">{data?.avg_packet_size_bytes ?? 320} B</span>
          </div>
          <div className="bg-slate-100 border border-slate-200 px-3.5 py-1.5 rounded-xl shadow-2xs font-bold">
            <span className="text-slate-500 text-[10px] uppercase tracking-wider font-semibold">STATUS:</span>{" "}
            <span className={isPaused ? "text-amber-600 font-bold" : "text-emerald-600 font-bold"}>
              {isPaused ? "PAUSED" : "LIVE CAPTURE"}
            </span>
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

          <div className="h-44 w-full">
            {mounted && (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={protoData}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={68}
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

          <div className="h-44 w-full">
            {mounted && topPortsData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={topPortsData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
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
                    {topPortsData.map((entry, idx) => (
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

          <div className="flex flex-wrap items-center justify-between text-[9px] text-slate-500 pt-2 border-t border-slate-100 gap-1.5 font-medium">
            <span className="bg-slate-100 px-2 py-0.5 rounded-md border border-slate-200">PORT 8000: BACKEND API</span>
            <span className="bg-slate-100 px-2 py-0.5 rounded-md border border-slate-200">PORT 3000: DASHBOARD UI</span>
            <span className="bg-slate-100 px-2 py-0.5 rounded-md border border-slate-200">PORTS 80/443: HTTP/HTTPS</span>
            <span className="bg-slate-100 px-2 py-0.5 rounded-md border border-slate-200">PORT 53: DNS</span>
          </div>
        </div>
      </div>

      {/* Real-Time Live Packet Flow Stream Console */}
      <div className="glass-panel p-5 rounded-2xl border border-white/90 bg-white/80 shadow-xs">
        {/* Stream Header & Interactive Controls */}
        <div className="flex flex-wrap items-center justify-between mb-4 border-b border-slate-100 pb-3 gap-3">
          <div className="flex items-center gap-2.5">
            <Terminal className="w-4 h-4 text-emerald-600" />
            <div>
              <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                REAL-TIME INGESTION STREAM (LIVE NETWORK SOCKETS & ML VERDICTS)
              </h3>
              <p className="text-[10px] text-slate-500">
                GENUINE HOST FLOWS ANALYZED WITH CIC-IDS2017 GRADIENT BOOSTING MODEL
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {/* Search Input */}
            <div className="relative">
              <Search className="w-3 h-3 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Filter by IP, Port, or Type..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-7 pr-2.5 py-1 text-[11px] bg-slate-50 border border-slate-200 rounded-lg text-slate-800 placeholder-slate-400 focus:outline-none focus:border-sky-500 w-44"
              />
            </div>

            {/* Protocol Buttons */}
            <div className="flex items-center gap-1 bg-slate-100 p-0.5 rounded-lg border border-slate-200 text-[10px]">
              {(["ALL", "TCP", "UDP", "THREATS"] as const).map((proto) => (
                <button
                  key={proto}
                  onClick={() => setProtocolFilter(proto)}
                  className={`px-2 py-1 rounded-md font-bold transition-all ${
                    protocolFilter === proto
                      ? proto === "THREATS"
                        ? "bg-rose-500 text-white shadow-2xs"
                        : "bg-sky-600 text-white shadow-2xs"
                      : "text-slate-600 hover:text-slate-900"
                  }`}
                >
                  {proto}
                </button>
              ))}
            </div>

            {/* Pause / Resume Button */}
            <button
              onClick={() => setIsPaused(!isPaused)}
              className={`flex items-center gap-1 px-2.5 py-1 rounded-lg text-[10px] font-bold border transition-all ${
                isPaused
                  ? "bg-emerald-50 text-emerald-700 border-emerald-300 hover:bg-emerald-100"
                  : "bg-amber-50 text-amber-700 border-amber-300 hover:bg-amber-100"
              }`}
            >
              {isPaused ? (
                <>
                  <Play className="w-3 h-3 text-emerald-600" /> RESUME
                </>
              ) : (
                <>
                  <Pause className="w-3 h-3 text-amber-600" /> PAUSE
                </>
              )}
            </button>

            {/* Clear Button */}
            <button
              onClick={() => setLocalFlows([])}
              className="flex items-center gap-1 px-2.5 py-1 rounded-lg text-[10px] font-bold bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-200 transition-all"
              title="Clear current stream buffer"
            >
              <Trash2 className="w-3 h-3" /> CLEAR
            </button>

            {/* Live Indicator */}
            <span className="text-[10px] px-2.5 py-1 bg-emerald-50 border border-emerald-300 text-emerald-800 font-bold rounded-lg shadow-2xs flex items-center gap-1.5">
              <span className={`w-2 h-2 rounded-full ${isPaused ? "bg-amber-500" : "bg-emerald-500 animate-pulse"}`} />
              {isPaused ? "BUFFER FROZEN" : "REAL-TIME SYNC"}
            </span>
          </div>
        </div>

        {/* Live Terminal Table */}
        <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-inner font-mono text-[11px]">
          {/* Table Header */}
          <div className="grid grid-cols-12 gap-2 bg-slate-900/90 border-b border-slate-800 p-2.5 text-[10px] uppercase font-bold text-slate-400">
            <div className="col-span-2">TIMESTAMP</div>
            <div className="col-span-1 text-center">PROTO</div>
            <div className="col-span-4">SOURCE → DESTINATION</div>
            <div className="col-span-2 text-right">VOLUME</div>
            <div className="col-span-3 text-right">AI VERDICT & SEVERITY</div>
          </div>

          {/* Table Rows */}
          <div className="max-h-72 overflow-y-auto divide-y divide-slate-900 space-y-0.5 p-1">
            {filteredFlows.length > 0 ? (
              filteredFlows.map((flow) => {
                const timeStr = flow.timestamp.includes("T")
                  ? flow.timestamp.split("T")[1].slice(0, 12)
                  : flow.timestamp;

                return (
                  <div
                    key={flow.flow_id}
                    className={`grid grid-cols-12 gap-2 items-center px-2 py-1.5 rounded transition-colors ${
                      flow.is_malicious
                        ? "bg-rose-950/40 text-rose-300 border-l-2 border-rose-500 font-semibold"
                        : "text-slate-300 hover:text-white hover:bg-slate-900/60"
                    }`}
                  >
                    {/* Timestamp */}
                    <div className="col-span-2 text-[10px] text-slate-400 font-mono">
                      {timeStr}
                    </div>

                    {/* Protocol */}
                    <div className="col-span-1 text-center">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                          flow.protocol.toUpperCase() === "TCP"
                            ? "bg-sky-950 text-sky-300 border border-sky-800"
                            : "bg-emerald-950 text-emerald-300 border border-emerald-800"
                        }`}
                      >
                        {flow.protocol}
                      </span>
                    </div>

                    {/* Source -> Destination */}
                    <div className="col-span-4 flex items-center gap-1.5 truncate text-[10px]">
                      <span className="text-slate-300 font-bold truncate">
                        {flow.src_ip}:{flow.src_port}
                      </span>
                      <ArrowRight className="w-2.5 h-2.5 text-slate-500 shrink-0" />
                      <span className="text-slate-300 font-bold truncate">
                        {flow.dst_ip}:{flow.dst_port}
                      </span>
                    </div>

                    {/* Volume (Bytes & Packets) */}
                    <div className="col-span-2 text-right text-[10px] text-slate-400">
                      <span className="text-slate-200 font-semibold">{Math.round(flow.bytes)} B</span>
                      <span className="text-slate-500 ml-1">({flow.packets} pkts)</span>
                    </div>

                    {/* AI Verdict */}
                    <div className="col-span-3 text-right flex items-center justify-end gap-1.5">
                      {flow.is_malicious ? (
                        <>
                          <ShieldAlert className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                          <span className="text-[10px] font-bold text-rose-300 bg-rose-950/70 border border-rose-800 px-2 py-0.5 rounded">
                            {flow.classification} ({(flow.confidence * 100).toFixed(0)}%)
                          </span>
                        </>
                      ) : (
                        <>
                          <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0" />
                          <span className="text-[10px] font-semibold text-emerald-300 bg-emerald-950/70 border border-emerald-800 px-2 py-0.5 rounded">
                            BENIGN ({(flow.confidence * 100).toFixed(0)}%)
                          </span>
                        </>
                      )}
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="text-slate-500 text-center py-8 text-xs">
                {localFlows.length === 0
                  ? "LISTENING FOR LIVE NETWORK TRAFFIC ON HOST ADAPTER..."
                  : "NO FLOWS MATCH ACTIVE FILTERS"}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
