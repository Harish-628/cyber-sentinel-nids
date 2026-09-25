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
  Zap,
} from "lucide-react";
import { injectAttack, startSimulator, stopSimulator } from "@/lib/api";
import { OverviewMetrics, SimulatorStatus } from "@/lib/types";

interface SOCHeaderProps {
  metrics: OverviewMetrics | null;
  simulatorStatus: SimulatorStatus | null;
  isWsConnected: boolean;
  timeRange: string;
  onTimeRangeChange: (r: string) => void;
  onRefresh: () => void;
  onAttackInjected: (type: string) => void;
}

export const SOCHeader: React.FC<SOCHeaderProps> = ({
  metrics,
  simulatorStatus,
  isWsConnected,
  timeRange,
  onTimeRangeChange,
  onRefresh,
  onAttackInjected,
}) => {
  const [timeStr, setTimeStr] = useState<string>("");
  const [isInjecting, setIsInjecting] = useState<boolean>(false);
  const [simRunning, setSimRunning] = useState<boolean>(simulatorStatus?.is_running ?? true);
  const [showInjectMenu, setShowInjectMenu] = useState<boolean>(false);

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
  const threatBadgeColors = {
    CRITICAL: "bg-red-950/80 text-red-300 border-red-600/90 shadow-red-950/50 shadow-md",
    HIGH: "bg-orange-950/80 text-orange-300 border-orange-600/90 shadow-orange-950/50 shadow-md",
    ELEVATED: "bg-amber-950/80 text-amber-300 border-amber-600/90",
    NORMAL: "bg-emerald-950/80 text-emerald-300 border-emerald-600/90",
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
    <header className="h-13 border-b border-[#1a1e2e] bg-[#090b10] px-3.5 flex items-center justify-between select-none z-30 relative">
      {/* Brand & System Status */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 bg-red-950/60 border border-red-700/80 flex items-center justify-center rounded-[2px] shadow-xs shadow-red-900/40">
            <ShieldAlert className="w-4 h-4 text-red-500" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="font-extrabold text-[13px] tracking-wider text-white font-mono-tech">
                CYBER<span className="text-red-500">SENTINEL</span>
              </span>
              <span className="text-[9px] px-1 py-0.2 bg-[#121624] border border-[#232a3f] text-zinc-400 font-mono-tech rounded-[2px]">
                SOC-XDR
              </span>
            </div>
            <p className="text-[9px] text-zinc-500 font-mono-tech tracking-tight leading-none">
              AI ENGINE // CIC-IDS2017
            </p>
          </div>
        </div>

        <div className="h-5 w-px bg-[#1a1e2e]" />

        {/* Global Sensor State */}
        <div className="flex items-center gap-2 bg-[#0d0f17] border border-[#1a1e2e] px-2.5 py-1 rounded-[2px]">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          <span className="text-[10px] font-mono-tech text-zinc-300 font-semibold tracking-wider">
            SENSOR: ONLINE
          </span>
        </div>

        {/* WebSocket Stream Indicator */}
        <div className="flex items-center gap-1.5 text-[10px] font-mono-tech text-zinc-400">
          <Radio className={`w-3 h-3 ${isWsConnected ? "text-emerald-400" : "text-amber-500 animate-spin"}`} />
          <span>{isWsConnected ? "STREAM: ACTIVE" : "STREAM: CONNECTING"}</span>
        </div>
      </div>

      {/* Center Threat Posture Pill */}
      <div className="flex items-center gap-2">
        <div className={`flex items-center gap-2 px-3 py-1 border text-[11px] font-mono-tech font-bold tracking-wider rounded-[2px] ${threatBadgeColors}`}>
          <AlertOctagon className="w-3.5 h-3.5" />
          <span>POSTURE: DEFCON // {threatLevel}</span>
          <span className="text-[10px] opacity-80 font-normal">({metrics?.threat_index?.toFixed(1) ?? "0.0"}%)</span>
        </div>
      </div>

      {/* Right Controls: Time Range, Attack Injection, Simulator, UTC Clock */}
      <div className="flex items-center gap-2.5">
        {/* Time Range Selector (CrowdStrike / Datadog style) */}
        <div className="flex items-center bg-[#0d0f17] border border-[#1a1e2e] rounded-[2px] p-0.5">
          {["LIVE", "5M", "15M", "1H"].map((range) => (
            <button
              key={range}
              onClick={() => onTimeRangeChange(range)}
              className={`px-2 py-0.5 text-[10px] font-mono-tech rounded-[2px] transition ${
                timeRange === range
                  ? "bg-[#1f2638] text-white font-bold"
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
            className="flex items-center gap-1.5 px-2.5 py-1 text-[10px] font-mono-tech font-semibold bg-[#121522] border border-[#232a3f] text-amber-300 hover:bg-[#1a2034] rounded-[2px] transition"
          >
            <Zap className="w-3 h-3 text-amber-400" />
            <span>INJECT ATTACK</span>
            <ChevronDown className="w-3 h-3 text-zinc-500" />
          </button>

          {showInjectMenu && (
            <div className="absolute right-0 mt-1 w-56 bg-[#0d0f17] border border-[#232a3f] shadow-2xl rounded-[2px] z-50 p-1 font-mono-tech">
              <div className="text-[9px] text-zinc-500 uppercase px-2 py-1 border-b border-[#1a1e2e]">
                CIC-IDS2017 ATTACK VECTORS
              </div>
              <div className="space-y-0.5 mt-1">
                {attackPresets.map((p) => (
                  <button
                    key={p.val}
                    onClick={() => handleInject(p.val)}
                    className="w-full text-left px-2 py-1.5 text-[11px] text-zinc-300 hover:text-white hover:bg-[#1a2034] rounded-[2px] flex items-center justify-between transition"
                  >
                    <span className={p.color}>{p.label}</span>
                    <span className="text-[9px] text-zinc-600">TRIGGER</span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Live Traffic Simulator Play/Pause */}
        <button
          onClick={handleToggleSimulator}
          className={`flex items-center gap-1.5 px-2.5 py-1 text-[10px] font-mono-tech font-semibold border rounded-[2px] transition ${
            simRunning
              ? "bg-[#10131d] border-zinc-700 text-zinc-300 hover:bg-[#181d2c]"
              : "bg-emerald-950/70 border-emerald-700 text-emerald-300 hover:bg-emerald-900/80"
          }`}
          title={simRunning ? "Pause traffic simulator" : "Resume traffic simulator"}
        >
          {simRunning ? <Pause className="w-3 h-3 text-amber-400" /> : <Play className="w-3 h-3 text-emerald-400" />}
          <span>{simRunning ? "TRAFFIC: STREAMING" : "TRAFFIC: PAUSED"}</span>
        </button>

        {/* Refresh Sync */}
        <button
          onClick={onRefresh}
          className="p-1.5 bg-[#0d0f17] border border-[#1a1e2e] text-zinc-400 hover:text-zinc-100 hover:bg-[#151928] rounded-[2px] transition"
          title="Manual Telemetry Poll"
        >
          <RefreshCw className="w-3 h-3" />
        </button>

        {/* UTC Clock */}
        <div className="bg-[#0d0f17] border border-[#1a1e2e] px-2.5 py-1 rounded-[2px] text-right">
          <div className="text-[10px] font-mono-tech font-bold text-zinc-200">
            {timeStr || "00:00:00 UTC"}
          </div>
        </div>
      </div>
    </header>
  );
};
