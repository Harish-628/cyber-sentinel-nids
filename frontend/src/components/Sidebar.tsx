"use client";

import React from "react";
import {
  Activity,
  BarChart3,
  Cpu,
  Database,
  Grid,
  Layers,
  Network,
  Radio,
  Server,
  Shield,
  ShieldAlert,
  Terminal,
} from "lucide-react";

interface SidebarProps {
  currentTab: string;
  onTabChange: (tab: string) => void;
  activeAlertCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onTabChange,
  activeAlertCount,
}) => {
  const navItems = [
    {
      id: "overview",
      label: "THREAT POSTURE",
      icon: Activity,
      badge: null,
    },
    {
      id: "alerts",
      label: "INCIDENT TRIAGE",
      icon: ShieldAlert,
      badge: activeAlertCount > 0 ? activeAlertCount : null,
      badgeColor: "bg-red-950/80 text-red-300 border-red-700/80 font-bold",
    },
    {
      id: "mitre",
      label: "MITRE ATT&CK MATRIX",
      icon: Grid,
      badge: "FRAMEWORK",
      badgeColor: "bg-[#181c2b] text-zinc-400 border-zinc-700",
    },
    {
      id: "traffic",
      label: "NETWORK FORENSICS",
      icon: Network,
      badge: null,
    },
    {
      id: "tester",
      label: "ADVERSARIAL LAB",
      icon: Terminal,
      badge: "LIVE",
      badgeColor: "bg-emerald-950 text-emerald-300 border-emerald-800",
    },
    {
      id: "model",
      label: "MODEL TELEMETRY",
      icon: Cpu,
      badge: null,
    },
  ];

  return (
    <aside className="w-64 glass-panel border-r border-white/[0.08] flex flex-col justify-between select-none z-20">
      <div>
        {/* Navigation Group */}
        <div className="p-3">
          <p className="text-[9px] font-mono-tech tracking-wider text-zinc-500 uppercase px-2.5 py-1">
            SOC CONSOLE VIEWS
          </p>
          <nav className="space-y-1 mt-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onTabChange(item.id)}
                  className={`w-full flex items-center justify-between px-3 py-2 text-[11px] font-mono-tech rounded-[3px] transition ${
                    isActive
                      ? "bg-cyan-950/50 text-cyan-100 border-l-2 border-cyan-400 font-bold shadow-[0_0_15px_rgba(6,182,212,0.2)] inset-shadow-sm"
                      : "text-zinc-400 hover:text-zinc-100 hover:bg-white/[0.05] border-l-2 border-transparent"
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <Icon className={`w-4 h-4 ${isActive ? "text-cyan-400" : "text-zinc-500"}`} />
                    <span>{item.label}</span>
                  </div>
                  {item.badge !== null && (
                    <span
                      className={`text-[9px] px-1.5 py-0.2 border rounded-[2px] ${
                        item.badgeColor || "bg-white/[0.06] text-zinc-300 border-white/[0.1]"
                      }`}
                    >
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Live Ingestion Interfaces Widget */}
        <div className="px-3 pt-1">
          <p className="text-[9px] font-mono-tech tracking-wider text-zinc-500 uppercase px-2.5 py-1">
            PACKET INGESTION ENGINE
          </p>
          <div className="glass-panel p-2.5 rounded-[3px] space-y-2 mt-1 border border-white/[0.08]">
            <div className="flex items-center justify-between text-[10px] font-mono-tech">
              <span className="text-zinc-400 flex items-center gap-1.5">
                <Radio className="w-3 h-3 text-cyan-400" /> Active Adapter
              </span>
              <span className="text-cyan-300 font-bold bg-cyan-950/60 px-1.5 py-0.2 rounded border border-cyan-500/40">
                wlp44s0 (Wi-Fi)
              </span>
            </div>
            <div className="flex items-center justify-between text-[10px] font-mono-tech">
              <span className="text-zinc-400 flex items-center gap-1.5">
                <Database className="w-3 h-3 text-emerald-400" /> Flow Extraction
              </span>
              <span className="text-emerald-300 font-bold">41 Metrics</span>
            </div>
            <div className="flex items-center justify-between text-[10px] font-mono-tech">
              <span className="text-zinc-400 flex items-center gap-1.5">
                <Server className="w-3 h-3 text-purple-400" /> AI Classification
              </span>
              <span className="text-emerald-400 font-bold flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" /> ONLINE
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Model Spec Mini-Panel at Footer */}
      <div className="p-3 border-t border-white/[0.08] bg-black/40">
        <div className="text-[9px] font-mono-tech text-zinc-500 mb-2 uppercase tracking-wider flex items-center justify-between">
          <span className="flex items-center gap-1 text-zinc-400">
            <Cpu className="w-3 h-3 text-cyan-400" /> AI SENSOR TELEMETRY
          </span>
          <span className="text-emerald-400 text-[8px] font-bold px-1 py-0.2 bg-emerald-950/80 border border-emerald-500/40 rounded">
            PASS
          </span>
        </div>
        <div className="space-y-1.5 text-[10px] font-mono-tech">
          <div className="flex justify-between">
            <span className="text-zinc-500">Architecture:</span>
            <span className="text-zinc-200 font-medium">Random Forest (100)</span>
          </div>
          <div className="flex justify-between">
            <span className="text-zinc-500">Benchmark Acc:</span>
            <span className="text-emerald-400 font-bold">100.00%</span>
          </div>
          <div className="flex justify-between">
            <span className="text-zinc-500">Benign FPR:</span>
            <span className="text-emerald-400 font-bold">0.000%</span>
          </div>
          <div className="flex justify-between">
            <span className="text-zinc-500">Inference Latency:</span>
            <span className="text-cyan-400 font-bold">~7.0 ms</span>
          </div>
        </div>
      </div>
    </aside>
  );
};
