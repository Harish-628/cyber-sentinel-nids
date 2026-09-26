"use client";

import React, { useEffect, useState } from "react";
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  ChevronDown,
  Clock,
  Cpu,
  Flame,
  Globe,
  Layers,
  Pause,
  Play,
  Radio,
  RefreshCw,
  Shield,
  ShieldAlert,
  Terminal,
  Wifi,
  Copy,
  Check,
  Zap,
} from "lucide-react";
import { injectAttack, setTrafficMode as apiSetTrafficMode, startSimulator, stopSimulator } from "@/lib/api";
import { NetworkInterface, OverviewMetrics, SimulatorStatus, TrafficModeInfo } from "@/lib/types";

interface SOCHeaderProps {
  metrics: OverviewMetrics | null;
  simulatorStatus: SimulatorStatus | null;
  trafficMode: TrafficModeInfo | null;
  interfaces: NetworkInterface[];
  isWsConnected: boolean;
  timeRange: string;
  onTimeRangeChange: (r: string) => void;
  onRefresh: () => void;
  onAttackInjected: (type: string) => void;
  onModeChanged?: (mode: string, iface?: string) => void;
}

export const SOCHeader: React.FC<SOCHeaderProps> = ({
  metrics,
  simulatorStatus,
  trafficMode,
  interfaces,
  isWsConnected,
  timeRange,
  onTimeRangeChange,
  onRefresh,
  onAttackInjected,
  onModeChanged,
}) => {
  const [timeStr, setTimeStr] = useState<string>("");
  const [isInjecting, setIsInjecting] = useState<boolean>(false);
  const [simRunning, setSimRunning] = useState<boolean>(simulatorStatus?.is_running ?? true);
  const [showInjectMenu, setShowInjectMenu] = useState<boolean>(false);
  const [showNetworkMenu, setShowNetworkMenu] = useState<boolean>(false);
  const [copiedCmd, setCopiedCmd] = useState<boolean>(false);

  useEffect(() => {
    if (simulatorStatus) {
      setSimRunning(simulatorStatus.is_running);
    }
  }, [simulatorStatus]);

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTimeStr(now.toUTCString().replace("GMT", "UTC"));
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleToggleSimulator = async () => {
    try {
      if (simRunning) {
        await stopSimulator();
        setSimRunning(false);
      } else {
        await startSimulator(0.8, 0.2);
        setSimRunning(true);
      }
    } catch (e) {
      console.error("Failed to toggle simulator", e);
    }
  };

  const handleInject = async (type: string) => {
    setIsInjecting(true);
    setShowInjectMenu(false);
    try {
      await injectAttack(type);
      onAttackInjected(type);
    } catch (e) {
      console.error("Failed to inject attack", e);
    } finally {
      setIsInjecting(false);
    }
  };

  const threatLevel = metrics?.threat_level || "NORMAL";
  const isLiveSniffer = trafficMode?.mode === "LIVE_SNIFFER";
  const activeIface = trafficMode?.active_interface || "wlp44s0";

  const handleToggleMode = async (newMode: string, iface?: string) => {
    try {
      await apiSetTrafficMode(newMode, iface || activeIface);
      if (onModeChanged) onModeChanged(newMode, iface || activeIface);
      onRefresh();
    } catch (e) {
      console.error("Failed to switch traffic mode", e);
    }
  };

  const copySnifferCommand = () => {
    const cmd = `sudo .venv/bin/python scripts/live_sniffer.py --interface ${activeIface}`;
    navigator.clipboard.writeText(cmd);
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2500);
  };

  const threatBadgeColors = {
    CRITICAL: "bg-red-950/70 text-red-300 border-red-500/80 shadow-[0_0_20px_rgba(239,68,68,0.3)]",
    HIGH: "bg-orange-950/70 text-orange-300 border-orange-500/80 shadow-[0_0_20px_rgba(249,115,22,0.3)]",
    ELEVATED: "bg-amber-950/70 text-amber-300 border-amber-500/80 shadow-[0_0_15px_rgba(245,158,11,0.2)]",
    NORMAL: "bg-emerald-950/70 text-emerald-300 border-emerald-500/80 shadow-[0_0_15px_rgba(16,185,129,0.2)]",
  }[threatLevel];

  const attackPresets = [
    { label: "PortScan (SYN Recon)", val: "PortScan", color: "text-amber-400" },
    { label: "Volumetric DDoS Flood", val: "DDoS", color: "text-red-400" },
    { label: "DoS (Slowloris/Hulk)", val: "DoS", color: "text-red-400" },
    { label: "SSH-Patator Brute Force", val: "Brute Force", color: "text-orange-400" },
    { label: "Web SQL Injection", val: "Web Attack", color: "text-purple-400" },
    { label: "Botnet C2 Beaconing", val: "Botnet", color: "text-red-500" },
  ];

  return (
    <header className="h-14 glass-header px-4 flex items-center justify-between select-none z-30 relative sticky top-0">
      {/* Brand & System Status */}
      <div className="flex items-center gap-3.5">
        <div className="flex items-center gap-2.5 group cursor-pointer">
          <div className="w-8 h-8 bg-red-950/60 border border-red-600/70 flex items-center justify-center rounded-[3px] shadow-[0_0_15px_rgba(239,68,68,0.3)] group-hover:border-red-400 transition">
            <ShieldAlert className="w-4.5 h-4.5 text-red-500 group-hover:scale-105 transition" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="font-extrabold text-[13px] tracking-wider text-white font-mono-tech">
                CYBER<span className="text-red-500">SENTINEL</span>
              </span>
              <span className="text-[9px] px-1.5 py-0.2 bg-white/[0.06] border border-white/[0.1] text-zinc-300 font-mono-tech rounded-[2px] backdrop-blur-md">
                SOC-XDR
              </span>
            </div>
            <p className="text-[9px] text-zinc-500 font-mono-tech tracking-tight leading-none">
              AI INTRUSION ENGINE // CIC-IDS2017
            </p>
          </div>
        </div>

        <div className="h-5 w-px bg-white/[0.08]" />

        {/* Global Sensor State */}
        <div className="flex items-center gap-2 glass-pill px-2.5 py-1 rounded-[3px]">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          <span className="text-[10px] font-mono-tech text-zinc-200 font-semibold tracking-wider">
            SENSOR: ONLINE
          </span>
        </div>

        {/* WebSocket Stream Indicator */}
        <div className="flex items-center gap-1.5 text-[10px] font-mono-tech text-zinc-400">
          <Radio className={`w-3 h-3 ${isWsConnected ? "text-emerald-400" : "text-amber-500 animate-spin"}`} />
          <span>{isWsConnected ? "TELEMETRY: LIVE" : "CONNECTING..."}</span>
        </div>
      </div>

      {/* Center Threat Posture Pill */}
      <div className="flex items-center gap-3">
        <div className={`flex items-center gap-2 px-3 py-1 border text-[11px] font-mono-tech font-bold tracking-wider rounded-[3px] backdrop-blur-md transition ${threatBadgeColors}`}>
          <AlertOctagon className="w-3.5 h-3.5" />
          <span>POSTURE: DEFCON // {threatLevel}</span>
          <span className="text-[10px] opacity-80 font-normal">({metrics?.threat_index?.toFixed(1) ?? "0.0"}%)</span>
        </div>

        {/* Dual Mode Traffic Source Selector (Real Network vs Simulator) */}
        <div className="relative">
          <button
            onClick={() => setShowNetworkMenu(!showNetworkMenu)}
            className={`flex items-center gap-2 px-3 py-1 rounded-[3px] text-[10px] font-mono-tech font-bold transition border ${
              isLiveSniffer
                ? "bg-cyan-950/70 border-cyan-400/80 text-cyan-300 shadow-[0_0_18px_rgba(6,182,212,0.35)]"
                : "bg-indigo-950/50 border-indigo-400/40 text-indigo-300 hover:border-indigo-400/80"
            }`}
          >
            {isLiveSniffer ? (
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-80" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-400" />
              </span>
            ) : (
              <Activity className="w-3 h-3 text-indigo-400" />
            )}
            <span className="tracking-wider">
              {isLiveSniffer ? `📡 LIVE WI-FI (${activeIface})` : "🧪 SYNTHETIC SIMULATOR"}
            </span>
            <ChevronDown className="w-3 h-3 opacity-60" />
          </button>

          {/* Network Mode & Interface Modal Popover */}
          {showNetworkMenu && (
            <div className="absolute left-0 mt-2 w-80 glass-panel rounded-[4px] p-3 z-50 font-mono-tech text-xs shadow-2xl border border-white/[0.12]">
              <div className="flex items-center justify-between pb-2 border-b border-white/[0.08] mb-2.5">
                <span className="text-[10px] font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
                  <Wifi className="w-3 h-3 text-cyan-400" /> TRAFFIC SOURCE CONTROLLER
                </span>
                <span className="text-[9px] px-1.5 py-0.2 bg-white/[0.06] rounded text-zinc-400">
                  {activeIface}
                </span>
              </div>

              {/* Mode Toggle Buttons */}
              <div className="grid grid-cols-2 gap-1.5 p-1 bg-black/40 rounded-[3px] border border-white/[0.06] mb-3">
                <button
                  onClick={() => handleToggleMode("LIVE_SNIFFER")}
                  className={`px-2 py-1.5 text-[10px] rounded font-bold transition flex items-center justify-center gap-1.5 ${
                    isLiveSniffer
                      ? "bg-cyan-600 text-white shadow-[0_0_12px_rgba(6,182,212,0.5)]"
                      : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  <Wifi className="w-3 h-3" /> REAL WI-FI
                </button>
                <button
                  onClick={() => handleToggleMode("SIMULATOR")}
                  className={`px-2 py-1.5 text-[10px] rounded font-bold transition flex items-center justify-center gap-1.5 ${
                    !isLiveSniffer
                      ? "bg-indigo-600 text-white shadow-[0_0_12px_rgba(99,102,241,0.5)]"
                      : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  <Activity className="w-3 h-3" /> SIMULATOR
                </button>
              </div>

              {/* Interface List */}
              <div className="mb-3">
                <div className="text-[9px] text-zinc-400 uppercase mb-1">AVAILABLE HOST ADAPTERS:</div>
                <div className="space-y-1 max-h-24 overflow-y-auto">
                  {interfaces.map((iface) => (
                    <div
                      key={iface.name}
                      onClick={() => handleToggleMode(trafficMode?.mode || "LIVE_SNIFFER", iface.name)}
                      className={`flex items-center justify-between px-2 py-1 rounded-[2px] cursor-pointer transition text-[10px] ${
                        activeIface === iface.name
                          ? "bg-cyan-950/60 border border-cyan-500/50 text-cyan-200 font-bold"
                          : "hover:bg-white/[0.04] text-zinc-400"
                      }`}
                    >
                      <div className="flex items-center gap-1.5">
                        <span className={`w-1.5 h-1.5 rounded-full ${iface.is_active ? "bg-emerald-400" : "bg-zinc-600"}`} />
                        <span>{iface.name}</span>
                      </div>
                      <span className="text-[8px] text-zinc-500">{iface.type}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Terminal Command Helper */}
              <div className="p-2 bg-black/60 border border-white/[0.08] rounded-[3px]">
                <div className="flex items-center justify-between text-[9px] text-zinc-400 mb-1">
                  <span>REAL PACKET SNIFFER COMMAND:</span>
                  <button
                    onClick={copySnifferCommand}
                    className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300 font-bold"
                  >
                    {copiedCmd ? <Check className="w-2.5 h-2.5 text-emerald-400" /> : <Copy className="w-2.5 h-2.5" />}
                    <span>{copiedCmd ? "COPIED" : "COPY"}</span>
                  </button>
                </div>
                <code className="block text-[9px] text-emerald-400 bg-zinc-950 p-1 rounded font-mono truncate select-all">
                  sudo .venv/bin/python scripts/live_sniffer.py --interface {activeIface}
                </code>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Right Controls: Time Range, Attack Injection, Simulator, UTC Clock */}
      <div className="flex items-center gap-2.5">
        {/* Time Range Selector */}
        <div className="flex items-center glass-pill rounded-[3px] p-0.5">
          {["LIVE", "5M", "15M", "1H"].map((range) => (
            <button
              key={range}
              onClick={() => onTimeRangeChange(range)}
              className={`px-2 py-0.5 text-[10px] font-mono-tech rounded-[2px] transition ${
                timeRange === range
                  ? "bg-white/[0.12] text-white font-bold shadow-xs"
                  : "text-zinc-500 hover:text-zinc-300"
              }`}
            >
              {range}
            </button>
          ))}
        </div>

        {/* Attack Injector Dropdown */}
        <div className="relative">
          <button
            onClick={() => setShowInjectMenu(!showInjectMenu)}
            disabled={isInjecting}
            className="flex items-center gap-1.5 px-2.5 py-1 text-[10px] font-mono-tech font-semibold glass-panel-interactive border border-amber-500/30 text-amber-300 hover:border-amber-400/60 rounded-[3px] transition"
          >
            <Zap className="w-3 h-3 text-amber-400" />
            <span>INJECT ATTACK</span>
            <ChevronDown className="w-3 h-3 text-zinc-500" />
          </button>

          {showInjectMenu && (
            <div className="absolute right-0 mt-1.5 w-60 glass-panel shadow-2xl rounded-[3px] z-50 p-1.5 font-mono-tech border border-white/[0.12]">
              <div className="text-[9px] text-zinc-400 uppercase px-2 py-1 border-b border-white/[0.08]">
                CIC-IDS2017 ATTACK VECTORS
              </div>
              <div className="space-y-0.5 mt-1">
                {attackPresets.map((p) => (
                  <button
                    key={p.val}
                    onClick={() => handleInject(p.val)}
                    className="w-full text-left px-2 py-1.5 text-[11px] text-zinc-300 hover:text-white hover:bg-white/[0.08] rounded-[2px] flex items-center justify-between transition"
                  >
                    <span className={p.color}>{p.label}</span>
                    <span className="text-[8px] px-1 py-0.2 bg-white/[0.05] text-zinc-400 rounded">TRIGGER</span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Live Traffic Simulator Play/Pause */}
        <button
          onClick={handleToggleSimulator}
          className={`flex items-center gap-1.5 px-2.5 py-1 text-[10px] font-mono-tech font-semibold rounded-[3px] border transition ${
            simRunning
              ? "glass-pill text-zinc-300 hover:bg-white/[0.08]"
              : "bg-emerald-950/70 border-emerald-500/80 text-emerald-300 hover:bg-emerald-900/80 shadow-[0_0_12px_rgba(16,185,129,0.3)]"
          }`}
          title={simRunning ? "Pause traffic simulator" : "Resume traffic simulator"}
        >
          {simRunning ? <Pause className="w-3 h-3 text-amber-400" /> : <Play className="w-3 h-3 text-emerald-400" />}
          <span>{simRunning ? "STREAMING" : "PAUSED"}</span>
        </button>

        {/* Refresh Sync */}
        <button
          onClick={onRefresh}
          className="p-1.5 glass-pill text-zinc-400 hover:text-zinc-100 hover:bg-white/[0.08] rounded-[3px] transition"
          title="Manual Telemetry Poll"
        >
          <RefreshCw className="w-3 h-3" />
        </button>

        {/* UTC Clock */}
        <div className="glass-pill px-2.5 py-1 rounded-[3px] text-right border border-white/[0.08]">
          <div className="text-[10px] font-mono-tech font-bold text-zinc-200">
            {timeStr || "00:00:00 UTC"}
          </div>
        </div>
      </div>
    </header>
  );
};
