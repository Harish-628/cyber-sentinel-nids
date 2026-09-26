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
      badgeColor: "bg-rose-500 text-white font-bold shadow-xs",
    },
    {
      id: "mitre",
      label: "MITRE ATT&CK MATRIX",
      icon: Grid,
      badge: "v15",
      badgeColor: "bg-slate-200 text-slate-700 font-bold",
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
      badgeColor: "bg-emerald-100 text-emerald-800 border border-emerald-300 font-bold",
    },
    {
      id: "model",
      label: "MODEL TELEMETRY",
      icon: Cpu,
      badge: null,
    },
  ];

  return (
    <aside className="w-64 glass-panel border-r border-slate-200/80 bg-white/75 backdrop-blur-2xl flex flex-col justify-between select-none z-20 shadow-sm">
      <div>
        {/* Navigation Group */}
        <div className="p-3.5">
          <p className="text-[10px] font-mono-tech tracking-wider text-slate-400 font-bold uppercase px-3 py-1.5">
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
                  className={`w-full flex items-center justify-between px-3.5 py-2.5 text-xs font-mono-tech rounded-xl transition-all duration-150 ${
                    isActive
                      ? "bg-gradient-to-r from-blue-600 to-indigo-600 text-white font-bold shadow-md shadow-blue-500/25"
                      : "text-slate-600 hover:text-slate-900 hover:bg-slate-100/80 font-semibold"
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <Icon className={`w-4 h-4 ${isActive ? "text-white" : "text-slate-400"}`} />
                    <span>{item.label}</span>
                  </div>
                  {item.badge !== null && (
                    <span
                      className={`text-[9px] px-2 py-0.5 rounded-full ${
                        item.badgeColor || "bg-slate-100 text-slate-700"
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
        <div className="px-3.5 pt-1">
          <p className="text-[10px] font-mono-tech tracking-wider text-slate-400 font-bold uppercase px-3 py-1.5">
            PACKET INGESTION ENGINE
          </p>
          <div className="glass-panel p-3 rounded-xl space-y-2.5 mt-1 border border-slate-200/80 bg-white/80 shadow-xs">
            <div className="flex items-center justify-between text-[10px] font-mono-tech">
              <span className="text-slate-500 flex items-center gap-1.5 font-medium">
                <Radio className="w-3.5 h-3.5 text-sky-600" /> Active Adapter
              </span>
              <span className="text-sky-800 font-bold bg-sky-50 px-2 py-0.5 rounded-md border border-sky-200">
                wlp44s0 (Wi-Fi)
              </span>
            </div>
            <div className="flex items-center justify-between text-[10px] font-mono-tech">
              <span className="text-slate-500 flex items-center gap-1.5 font-medium">
                <Database className="w-3.5 h-3.5 text-emerald-600" /> Flow Extraction
              </span>
              <span className="text-emerald-700 font-bold">41 Metrics</span>
            </div>
            <div className="flex items-center justify-between text-[10px] font-mono-tech">
              <span className="text-slate-500 flex items-center gap-1.5 font-medium">
                <Server className="w-3.5 h-3.5 text-purple-600" /> AI Classification
              </span>
              <span className="text-emerald-700 font-bold flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" /> ONLINE
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Model Spec Mini-Panel at Footer */}
      <div className="p-3.5 border-t border-slate-200/80 bg-slate-50/80">
        <div className="text-[9px] font-mono-tech text-slate-500 mb-2 uppercase tracking-wider flex items-center justify-between font-bold">
          <span className="flex items-center gap-1 text-slate-600">
            <Cpu className="w-3.5 h-3.5 text-blue-600" /> AI SENSOR TELEMETRY
          </span>
          <span className="text-emerald-700 text-[8px] font-bold px-1.5 py-0.5 bg-emerald-50 border border-emerald-300 rounded-md">
            PASS
          </span>
        </div>
        <div className="space-y-1.5 text-[10px] font-mono-tech">
          <div className="flex justify-between">
            <span className="text-slate-500 font-medium">Architecture:</span>
            <span className="text-slate-800 font-bold">Random Forest (100)</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500 font-medium">Benchmark Acc:</span>
            <span className="text-emerald-600 font-bold">100.00%</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500 font-medium">Benign FPR:</span>
            <span className="text-emerald-600 font-bold">0.000%</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500 font-medium">Inference Latency:</span>
            <span className="text-blue-600 font-bold">~7.0 ms</span>
          </div>
        </div>
      </div>
    </aside>
  );
};
