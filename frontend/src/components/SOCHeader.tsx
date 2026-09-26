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
  RotateCcw,
} from "lucide-react";
import { clearAllAlerts, injectAttack, setTrafficMode as apiSetTrafficMode, startSimulator, stopSimulator } from "@/lib/api";
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

  const [isClearing, setIsClearing] = useState(false);
  const handleClearAlerts = async () => {
    setIsClearing(true);
    try {
      await clearAllAlerts();
      onRefresh();
    } catch (e) {
      console.error("Failed to clear alerts", e);
    } finally {
      setIsClearing(false);
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
    CRITICAL: "bg-rose-50 text-rose-700 border-rose-300 shadow-[0_0_16px_rgba(244,63,94,0.18)]",
    HIGH: "bg-orange-50 text-orange-700 border-orange-300 shadow-[0_0_16px_rgba(249,115,22,0.18)]",
    ELEVATED: "bg-amber-50 text-amber-700 border-amber-300 shadow-[0_0_16px_rgba(245,158,11,0.18)]",
    NORMAL: "bg-emerald-50 text-emerald-700 border-emerald-300 shadow-[0_0_16px_rgba(16,185,129,0.18)]",
  }[threatLevel];

  const attackPresets = [
    { label: "PortScan (SYN Recon)", val: "PortScan", color: "text-amber-600 font-bold" },
    { label: "Volumetric DDoS Flood", val: "DDoS", color: "text-rose-600 font-bold" },
    { label: "DoS (Slowloris/Hulk)", val: "DoS", color: "text-rose-600 font-bold" },
    { label: "SSH-Patator Brute Force", val: "Brute Force", color: "text-orange-600 font-bold" },
    { label: "Web SQL Injection", val: "Web Attack", color: "text-purple-600 font-bold" },
    { label: "Botnet C2 Beaconing", val: "Botnet", color: "text-rose-700 font-bold" },
  ];

  return (
    <header className="h-16 glass-header px-5 flex items-center justify-between select-none z-30 relative sticky top-0 shadow-sm border-b border-slate-200/80">
      {/* Brand & System Status */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-3 group cursor-pointer">
          <div className="w-9 h-9 bg-gradient-to-br from-rose-500 to-red-600 border border-rose-400 flex items-center justify-center rounded-xl shadow-md shadow-rose-500/25 group-hover:scale-105 transition-all duration-200">
            <ShieldAlert className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-extrabold text-sm tracking-wider text-slate-900 font-mono-tech">
                CYBER<span className="text-rose-600">SENTINEL</span>
              </span>
              <span className="text-[9px] px-2 py-0.5 bg-slate-100 border border-slate-200 text-slate-700 font-mono-tech font-bold rounded-md">
                SOC-XDR
              </span>
            </div>
            <p className="text-[9px] text-slate-400 font-mono-tech tracking-tight leading-none mt-0.5 font-medium">
              AI INTRUSION ENGINE // CIC-IDS2017
            </p>
          </div>
        </div>

        <div className="h-6 w-px bg-slate-200" />

        {/* Global Sensor State */}
        <div className="flex items-center gap-2 bg-emerald-50 border border-emerald-200 px-3 py-1 rounded-lg shadow-xs">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-600"></span>
          </span>
          <span className="text-[10px] font-mono-tech text-emerald-800 font-bold tracking-wider">
            SENSOR: ONLINE
          </span>
        </div>

        {/* WebSocket Stream Indicator */}
        <div className="flex items-center gap-1.5 text-[10px] font-mono-tech text-slate-500 font-semibold">
          <Radio className={`w-3.5 h-3.5 ${isWsConnected ? "text-emerald-500" : "text-amber-500 animate-spin"}`} />
          <span>{isWsConnected ? "TELEMETRY: LIVE" : "CONNECTING..."}</span>
        </div>
      </div>

      {/* Center Threat Posture Pill */}
      <div className="flex items-center gap-3">
        <div className={`flex items-center gap-2 px-3.5 py-1.5 border text-xs font-mono-tech font-bold tracking-wider rounded-xl backdrop-blur-md transition ${threatBadgeColors}`}>
          <AlertOctagon className="w-4 h-4" />
          <span>POSTURE: DEFCON // {threatLevel}</span>
          <span className="text-[10px] opacity-80 font-normal">({metrics?.threat_index?.toFixed(1) ?? "0.0"}%)</span>
        </div>

        {/* Dual Mode Traffic Source Selector (Real Network vs Simulator) */}
        <div className="relative">
          <button
            onClick={() => setShowNetworkMenu(!showNetworkMenu)}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-xl text-[10px] font-mono-tech font-bold transition border shadow-xs ${
              isLiveSniffer
                ? "bg-sky-50 border-sky-300 text-sky-800 shadow-[0_0_15px_rgba(14,165,233,0.18)]"
                : "bg-indigo-50 border-indigo-300 text-indigo-800 hover:border-indigo-400"
            }`}
          >
            {isLiveSniffer ? (
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-sky-500 opacity-80" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-sky-600" />
              </span>
            ) : (
              <Activity className="w-3.5 h-3.5 text-indigo-600" />
            )}
            <span className="tracking-wider">
              {isLiveSniffer ? `📡 LIVE WI-FI (${activeIface})` : "🧪 SYNTHETIC SIMULATOR"}
            </span>
            <ChevronDown className="w-3 h-3 opacity-60" />
          </button>

          {/* Network Mode & Interface Modal Popover */}
          {showNetworkMenu && (
            <div className="absolute left-0 mt-2 w-88 glass-panel rounded-2xl p-4 z-50 font-mono-tech text-xs shadow-2xl border border-white bg-white/95">
              <div className="flex items-center justify-between pb-2.5 border-b border-slate-200 mb-3">
                <span className="text-[10px] font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                  <Wifi className="w-3.5 h-3.5 text-sky-600" /> TRAFFIC SOURCE CONTROLLER
                </span>
                <span className="text-[9px] px-2 py-0.5 bg-slate-100 border border-slate-200 rounded-md font-bold text-slate-700">
                  {activeIface}
                </span>
              </div>

              {/* Mode Toggle Buttons */}
              <div className="grid grid-cols-2 gap-2 p-1.5 bg-slate-100/90 rounded-xl border border-slate-200 mb-3.5">
                <button
                  onClick={() => handleToggleMode("LIVE_SNIFFER")}
                  className={`px-3 py-2 text-[10px] rounded-lg font-bold transition flex items-center justify-center gap-2 ${
                    isLiveSniffer
                      ? "bg-sky-600 text-white shadow-md shadow-sky-600/30"
                      : "text-slate-600 hover:text-slate-900 hover:bg-white"
                  }`}
                >
                  <Wifi className="w-3.5 h-3.5" /> REAL WI-FI
                </button>
                <button
                  onClick={() => handleToggleMode("SIMULATOR")}
                  className={`px-3 py-2 text-[10px] rounded-lg font-bold transition flex items-center justify-center gap-2 ${
                    !isLiveSniffer
                      ? "bg-indigo-600 text-white shadow-md shadow-indigo-600/30"
                      : "text-slate-600 hover:text-slate-900 hover:bg-white"
                  }`}
                >
                  <Activity className="w-3.5 h-3.5" /> SIMULATOR
                </button>
              </div>

              {/* Interface List */}
              <div className="mb-3.5">
                <div className="text-[9px] text-slate-500 uppercase font-bold tracking-wider mb-1.5">AVAILABLE HOST ADAPTERS:</div>
                <div className="space-y-1.5 max-h-28 overflow-y-auto">
                  {interfaces.map((iface) => (
                    <div
                      key={iface.name}
                      onClick={() => handleToggleMode(trafficMode?.mode || "LIVE_SNIFFER", iface.name)}
                      className={`flex items-center justify-between px-3 py-1.5 rounded-lg cursor-pointer transition text-[10px] ${
                        activeIface === iface.name
                          ? "bg-sky-50 border border-sky-300 text-sky-900 font-bold shadow-xs"
                          : "hover:bg-slate-100 text-slate-600"
                      }`}
                    >
                      <div className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full ${iface.is_active ? "bg-emerald-500" : "bg-slate-400"}`} />
                        <span className="font-semibold">{iface.name}</span>
                      </div>
                      <span className="text-[8px] bg-slate-200/80 px-1.5 py-0.5 rounded text-slate-600 font-bold">{iface.type}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Terminal Command Helper */}
              <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl text-slate-200 shadow-md">
                <div className="flex items-center justify-between text-[9px] text-slate-400 mb-1.5 font-bold">
                  <span>REAL PACKET SNIFFER COMMAND:</span>
                  <button
                    onClick={copySnifferCommand}
                    className="flex items-center gap-1 text-sky-400 hover:text-sky-300 font-bold"
                  >
                    {copiedCmd ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedCmd ? "COPIED" : "COPY"}</span>
                  </button>
                </div>
                <code className="block text-[9px] text-emerald-300 bg-slate-950 p-2 rounded-lg font-mono truncate select-all">
                  sudo .venv/bin/python scripts/live_sniffer.py --interface {activeIface}
                </code>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Right Controls: Time Range, Attack Injection, Simulator, UTC Clock */}
      <div className="flex items-center gap-3">
        {/* Time Range Selector */}
        <div className="flex items-center bg-slate-100 border border-slate-200 rounded-xl p-1 shadow-xs">
          {["LIVE", "5M", "15M", "1H"].map((range) => (
            <button
              key={range}
              onClick={() => onTimeRangeChange(range)}
              className={`px-2.5 py-1 text-[10px] font-mono-tech rounded-lg transition font-bold ${
                timeRange === range
                  ? "bg-white text-slate-900 shadow-xs"
                  : "text-slate-500 hover:text-slate-800"
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
            className="flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-mono-tech font-bold bg-amber-50 border border-amber-300 text-amber-800 hover:bg-amber-100 rounded-xl shadow-xs transition"
          >
            <Zap className="w-3.5 h-3.5 text-amber-600 fill-amber-500" />
            <span>INJECT ATTACK</span>
            <ChevronDown className="w-3 h-3 opacity-60" />
          </button>

          {showInjectMenu && (
            <div className="absolute right-0 mt-2 w-64 glass-panel shadow-2xl rounded-2xl z-50 p-2 font-mono-tech border border-white bg-white/95">
              <div className="text-[9px] text-slate-400 font-bold uppercase px-2.5 py-1.5 border-b border-slate-200">
                CIC-IDS2017 ATTACK VECTORS
              </div>
              <div className="space-y-1 mt-1.5">
                {attackPresets.map((p) => (
                  <button
                    key={p.val}
                    onClick={() => handleInject(p.val)}
                    className="w-full text-left px-2.5 py-2 text-xs text-slate-700 hover:text-slate-900 hover:bg-slate-100 rounded-lg flex items-center justify-between transition"
                  >
                    <span className={p.color}>{p.label}</span>
                    <span className="text-[8px] px-1.5 py-0.5 bg-slate-200 text-slate-700 font-bold rounded">TRIGGER</span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Clear / Reset Alerts Button */}
        <button
          onClick={handleClearAlerts}
          disabled={isClearing}
          className="flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-mono-tech font-bold bg-slate-100 hover:bg-rose-50 text-slate-600 hover:text-rose-700 border border-slate-200 hover:border-rose-300 rounded-xl shadow-xs transition"
          title="Reset alert log and threat baseline"
        >
          <RotateCcw className={`w-3 h-3 ${isClearing ? "animate-spin text-rose-500" : ""}`} />
          <span>RESET ALERTS</span>
        </button>

        {/* Live Traffic Simulator Play/Pause */}
        <button
          onClick={handleToggleSimulator}
          className={`flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-mono-tech font-bold rounded-xl border transition shadow-xs ${
            simRunning
              ? "bg-slate-100 border-slate-200 text-slate-700 hover:bg-slate-200"
              : "bg-emerald-50 border-emerald-300 text-emerald-800 hover:bg-emerald-100 shadow-[0_0_12px_rgba(16,185,129,0.2)]"
          }`}
          title={simRunning ? "Pause traffic simulator" : "Resume traffic simulator"}
        >
          {simRunning ? <Pause className="w-3.5 h-3.5 text-amber-600" /> : <Play className="w-3.5 h-3.5 text-emerald-600" />}
          <span>{simRunning ? "STREAMING" : "PAUSED"}</span>
        </button>

        {/* Refresh Sync */}
        <button
          onClick={onRefresh}
          className="p-2 bg-slate-100 hover:bg-slate-200 text-slate-600 hover:text-slate-900 border border-slate-200 rounded-xl transition shadow-xs"
          title="Manual Telemetry Poll"
        >
          <RefreshCw className="w-3.5 h-3.5" />
        </button>

        {/* UTC Clock */}
        <div className="bg-white/80 border border-slate-200 px-3 py-1.5 rounded-xl text-right shadow-xs">
          <div className="text-[10px] font-mono-tech font-bold text-slate-700">
            {timeStr || "00:00:00 UTC"}
          </div>
        </div>
      </div>
    </header>
  );
};
