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
    <aside className="w-60 border-r border-[#1a1e2e] bg-[#090b10] flex flex-col justify-between select-none">
      <div>
        {/* Navigation Group */}
        <div className="p-2.5">
          <p className="text-[9px] font-mono-tech tracking-wider text-zinc-500 uppercase px-2.5 py-1">
            SOC CONSOLE VIEWS
          </p>
          <nav className="space-y-0.5 mt-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onTabChange(item.id)}
                  className={`w-full flex items-center justify-between px-2.5 py-2 text-[11px] font-mono-tech rounded-[2px] transition ${
                    isActive
                      ? "bg-[#161a29] text-white border-l-2 border-red-500 font-bold shadow-xs"
                      : "text-zinc-400 hover:text-zinc-200 hover:bg-[#10131d] border-l-2 border-transparent"
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <Icon className={`w-3.5 h-3.5 ${isActive ? "text-red-400" : "text-zinc-500"}`} />
                    <span>{item.label}</span>
                  </div>
                  {item.badge !== null && (
                    <span
                      className={`text-[9px] px-1.5 py-0.2 border rounded-[2px] ${
                        item.badgeColor || "bg-zinc-800 text-zinc-300 border-zinc-700"
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
        <div className="px-2.5 pt-1">
          <p className="text-[9px] font-mono-tech tracking-wider text-zinc-500 uppercase px-2.5 py-1">
            INGESTION INTERFACES
          </p>
          <div className="bg-[#0d0f17] border border-[#1a1e2e] p-2.5 rounded-[2px] space-y-1.5 mt-1">
            <div className="flex items-center justify-between text-[10px] font-mono-tech">
              <span className="text-zinc-400 flex items-center gap-1.5">
                <Radio className="w-2.5 h-2.5 text-emerald-400" /> SPAN / TAP
              </span>
              <span className="text-emerald-400 font-bold">1,000 Mbps</span>
            </div>
            <div className="flex items-center justify-between text-[10px] font-mono-tech">
              <span className="text-zinc-400 flex items-center gap-1.5">
                <Database className="w-2.5 h-2.5 text-blue-400" /> Flow Collector
              </span>
              <span className="text-zinc-300">41 Feats</span>
            </div>
            <div className="flex items-center justify-between text-[10px] font-mono-tech">
              <span className="text-zinc-400 flex items-center gap-1.5">
                <Server className="w-2.5 h-2.5 text-purple-400" /> ML Classifier
              </span>
              <span className="text-emerald-400 font-bold">ONLINE</span>
            </div>
          </div>
        </div>
      </div>

      {/* Model Spec Mini-Panel at Footer */}
      <div className="p-2.5 border-t border-[#1a1e2e] bg-[#0d0f17]">
        <div className="text-[9px] font-mono-tech text-zinc-500 mb-1.5 uppercase tracking-wider flex items-center justify-between">
          <span>AI SENSOR TELEMETRY</span>
          <span className="text-emerald-400 text-[8px] font-bold">PASS</span>
        </div>
        <div className="space-y-1 text-[10px] font-mono-tech">
          <div className="flex justify-between">
            <span className="text-zinc-500">Architecture:</span>
            <span className="text-zinc-200">Balanced RF (100)</span>
          </div>
          <div className="flex justify-between">
            <span className="text-zinc-500">Accuracy:</span>
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
