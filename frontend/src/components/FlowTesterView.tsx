"use client";

import React, { useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Cpu,
  Flame,
  Play,
  RotateCcw,
  Shield,
  ShieldAlert,
  Terminal,
  Zap,
} from "lucide-react";
import { analyzeCustomFlow } from "@/lib/api";

const PRESETS: Record<string, any> = {
  benign_web: {
    name: "Normal HTTPS Web Session",
    desc: "Standard TLS handshake and HTTP/2 packet exchange to port 443.",
    payload: {
      src_ip: "192.168.1.105",
      dst_ip: "172.16.0.1",
      src_port: 54321,
      dst_port: 443,
      protocol: "TCP",
      flow_duration: 150000.0,
      tot_fwd_pkts: 8,
      tot_bwd_pkts: 10,
      tot_len_fwd_pkts: 2000.0,
      tot_len_bwd_pkts: 6500.0,
      fwd_pkt_len_max: 450.0,
      fwd_pkt_len_min: 50.0,
      fwd_pkt_len_mean: 250.0,
      bwd_pkt_len_max: 975.0,
      bwd_pkt_len_min: 65.0,
      bwd_pkt_len_mean: 650.0,
      flow_bytes_s: 56666.0,
      flow_pkts_s: 120.0,
      syn_flag_count: 0,
      ack_flag_count: 1,
      psh_flag_count: 1,
      init_win_bytes_forward: 29200,
      init_win_bytes_backward: 29200,
      act_data_pkt_fwd: 6,
      avg_pkt_size: 472.0,
    },
  },
  syn_portscan: {
    name: "Stealth SYN PortScan",
    desc: "Rapid TCP probe to closed RDP port (3389) with 0 payload and SYN set.",
    payload: {
      src_ip: "45.33.32.156",
      dst_ip: "192.168.1.50",
      src_port: 60124,
      dst_port: 3389,
      protocol: "TCP",
      flow_duration: 450.0,
      tot_fwd_pkts: 1,
      tot_bwd_pkts: 0,
      tot_len_fwd_pkts: 0.0,
      tot_len_bwd_pkts: 0.0,
      fwd_pkt_len_max: 0.0,
      fwd_pkt_len_min: 0.0,
      fwd_pkt_len_mean: 0.0,
      bwd_pkt_len_mean: 0.0,
      flow_bytes_s: 0.0,
      flow_pkts_s: 2222.0,
      syn_flag_count: 1,
      ack_flag_count: 0,
      psh_flag_count: 0,
      init_win_bytes_forward: 1024,
      init_win_bytes_backward: 0,
      act_data_pkt_fwd: 0,
      avg_pkt_size: 0.0,
    },
  },
  ddos_flood: {
    name: "Volumetric DDoS TCP Flood",
    desc: "High-rate forward packet storm saturating gateway buffers.",
    payload: {
      src_ip: "185.220.101.5",
      dst_ip: "172.16.0.80",
      src_port: 52199,
      dst_port: 80,
      protocol: "TCP",
      flow_duration: 35000000.0,
      tot_fwd_pkts: 220,
      tot_bwd_pkts: 2,
      tot_len_fwd_pkts: 28160.0,
      tot_len_bwd_pkts: 80.0,
      fwd_pkt_len_max: 128.0,
      fwd_pkt_len_min: 128.0,
      fwd_pkt_len_mean: 128.0,
      bwd_pkt_len_mean: 40.0,
      flow_bytes_s: 806000.0,
      flow_pkts_s: 6300.0,
      syn_flag_count: 1,
      ack_flag_count: 0,
      psh_flag_count: 0,
      init_win_bytes_forward: 1024,
      init_win_bytes_backward: 0,
      act_data_pkt_fwd: 220,
      avg_pkt_size: 128.0,
    },
  },
  web_sqli: {
    name: "Web Application SQL Injection",
    desc: "Heavy forward HTTP payload containing SQL exploit tokens.",
    payload: {
      src_ip: "91.240.118.7",
      dst_ip: "172.16.0.80",
      src_port: 48991,
      dst_port: 8080,
      protocol: "TCP",
      flow_duration: 340000.0,
      tot_fwd_pkts: 12,
      tot_bwd_pkts: 9,
      tot_len_fwd_pkts: 11400.0,
      tot_len_bwd_pkts: 4200.0,
      fwd_pkt_len_max: 1460.0,
      fwd_pkt_len_min: 80.0,
      fwd_pkt_len_mean: 950.0,
      bwd_pkt_len_mean: 466.0,
      flow_bytes_s: 45800.0,
      flow_pkts_s: 61.0,
      syn_flag_count: 0,
      ack_flag_count: 1,
      psh_flag_count: 1,
      init_win_bytes_forward: 29200,
      init_win_bytes_backward: 29200,
      act_data_pkt_fwd: 10,
      avg_pkt_size: 742.0,
    },
  },
  ssh_patator: {
    name: "SSH-Patator Credential Brute Force",
    desc: "Sequential dictionary credential attempts over port 22.",
    payload: {
      src_ip: "194.26.29.112",
      dst_ip: "172.16.0.22",
      src_port: 55412,
      dst_port: 22,
      protocol: "TCP",
      flow_duration: 1800000.0,
      tot_fwd_pkts: 22,
      tot_bwd_pkts: 18,
      tot_len_fwd_pkts: 1496.0,
      tot_len_bwd_pkts: 1512.0,
      fwd_pkt_len_max: 98.0,
      fwd_pkt_len_min: 44.0,
      fwd_pkt_len_mean: 68.0,
      bwd_pkt_len_mean: 84.0,
      flow_bytes_s: 1671.0,
      flow_pkts_s: 22.0,
      syn_flag_count: 0,
      ack_flag_count: 1,
      psh_flag_count: 1,
      init_win_bytes_forward: 29200,
      init_win_bytes_backward: 29200,
      act_data_pkt_fwd: 18,
      avg_pkt_size: 75.0,
    },
  },
};

export const FlowTesterView: React.FC = () => {
  const [selectedPreset, setSelectedPreset] = useState("benign_web");
  const [formData, setFormData] = useState(PRESETS.benign_web.payload);
  const [isRunning, setIsRunning] = useState(false);
  const [result, setResult] = useState<any>(null);

  const handlePresetSelect = (key: string) => {
    setSelectedPreset(key);
    setFormData(PRESETS[key].payload);
    setResult(null);
  };

  const handleInputChange = (field: string, val: any) => {
    setFormData((prev: any) => ({
      ...prev,
      [field]: val,
    }));
  };

  const handleRunInference = async () => {
    setIsRunning(true);
    try {
      const res = await analyzeCustomFlow(formData);
      setResult(res);
    } catch (e: any) {
      console.error("Inference test failed", e);
      setResult({ error: e.message || "Failed to execute inference" });
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Top Banner */}
      <div className="bg-[#0f111a] border border-[#1b1f2e] p-4 rounded-sm flex items-center justify-between">
        <div>
          <h2 className="text-sm font-bold font-mono-tech text-white uppercase tracking-wider flex items-center gap-2">
            <Terminal className="w-4 h-4 text-emerald-400" />
            NIDS FLOW INSPECTOR & ADVERSARIAL TESTING LAB
          </h2>
          <p className="text-[11px] font-mono-tech text-zinc-400 mt-0.5">
            CRAFT ARBITRARY TCP/IP FLOWS // TEST LIVE AI MODEL CLASSIFICATION & ALERT RESPONSE
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Left 1 Col: Scenario Presets */}
        <div className="space-y-3">
          <div className="bg-[#0f111a] border border-[#1b1f2e] p-3 rounded-sm">
            <h3 className="text-xs font-mono-tech font-bold text-zinc-300 uppercase tracking-wider mb-2 border-b border-[#1b1f2e] pb-1.5 flex items-center gap-2">
              <Zap className="w-3.5 h-3.5 text-amber-400" />
              ATTACK SCENARIOS & BENCHMARKS
            </h3>

            <div className="space-y-1.5">
              {Object.entries(PRESETS).map(([key, item]) => (
                <button
                  key={key}
                  onClick={() => handlePresetSelect(key)}
                  className={`w-full text-left p-2.5 rounded-sm border text-xs font-mono-tech transition ${
                    selectedPreset === key
                      ? "bg-[#181d2f] border-red-500 text-white font-semibold"
                      : "bg-[#090a0f] border-[#1b1f2e] text-zinc-400 hover:text-zinc-200 hover:bg-[#121520]"
                  }`}
                >
                  <div className="text-white font-bold">{item.name}</div>
                  <p className="text-[10px] text-zinc-500 mt-0.5 leading-snug">{item.desc}</p>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Center & Right 2 Cols: Interactive Flow Form & Result */}
        <div className="lg:col-span-2 space-y-3">
          <div className="bg-[#0f111a] border border-[#1b1f2e] p-4 rounded-sm font-mono-tech">
            <div className="flex items-center justify-between mb-3 border-b border-[#1b1f2e] pb-2">
              <span className="text-xs font-bold text-zinc-200 uppercase">
                FLOW PARAMETERS (TCP/IP 5-TUPLE + CIC METRICS)
              </span>
              <button
                onClick={() => setFormData(PRESETS[selectedPreset].payload)}
                className="text-[10px] text-zinc-400 hover:text-white flex items-center gap-1 transition"
              >
                <RotateCcw className="w-3 h-3" /> RESET VALUES
              </button>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs mb-4">
              <div>
                <label className="text-zinc-500 block text-[10px] mb-1">SOURCE IP</label>
                <input
                  type="text"
                  value={formData.src_ip}
                  onChange={(e) => handleInputChange("src_ip", e.target.value)}
                  className="w-full bg-[#090a0f] border border-[#1b1f2e] px-2 py-1 text-cyan-400 rounded-sm focus:outline-none"
                />
              </div>

              <div>
                <label className="text-zinc-500 block text-[10px] mb-1">SOURCE PORT</label>
                <input
                  type="number"
                  value={formData.src_port}
                  onChange={(e) => handleInputChange("src_port", parseInt(e.target.value) || 0)}
                  className="w-full bg-[#090a0f] border border-[#1b1f2e] px-2 py-1 text-zinc-200 rounded-sm focus:outline-none"
                />
              </div>

              <div>
                <label className="text-zinc-500 block text-[10px] mb-1">TARGET IP</label>
                <input
                  type="text"
                  value={formData.dst_ip}
                  onChange={(e) => handleInputChange("dst_ip", e.target.value)}
                  className="w-full bg-[#090a0f] border border-[#1b1f2e] px-2 py-1 text-orange-400 rounded-sm focus:outline-none"
                />
              </div>

              <div>
                <label className="text-zinc-500 block text-[10px] mb-1">TARGET PORT</label>
                <input
                  type="number"
                  value={formData.dst_port}
                  onChange={(e) => handleInputChange("dst_port", parseInt(e.target.value) || 0)}
                  className="w-full bg-[#090a0f] border border-[#1b1f2e] px-2 py-1 text-zinc-200 rounded-sm focus:outline-none"
                />
              </div>

              <div>
                <label className="text-zinc-500 block text-[10px] mb-1">FLOW DURATION (µs)</label>
                <input
                  type="number"
                  value={formData.flow_duration}
                  onChange={(e) => handleInputChange("flow_duration", parseFloat(e.target.value) || 0)}
                  className="w-full bg-[#090a0f] border border-[#1b1f2e] px-2 py-1 text-zinc-200 rounded-sm focus:outline-none"
                />
              </div>

              <div>
                <label className="text-zinc-500 block text-[10px] mb-1">TOTAL FWD PACKETS</label>
                <input
                  type="number"
                  value={formData.tot_fwd_pkts}
                  onChange={(e) => handleInputChange("tot_fwd_pkts", parseInt(e.target.value) || 0)}
                  className="w-full bg-[#090a0f] border border-[#1b1f2e] px-2 py-1 text-zinc-200 rounded-sm focus:outline-none"
                />
              </div>

              <div>
                <label className="text-zinc-500 block text-[10px] mb-1">SYN FLAG</label>
                <select
                  value={formData.syn_flag_count}
                  onChange={(e) => handleInputChange("syn_flag_count", parseInt(e.target.value))}
                  className="w-full bg-[#090a0f] border border-[#1b1f2e] px-2 py-1 text-zinc-200 rounded-sm focus:outline-none"
                >
                  <option value={0}>0 (OFF)</option>
                  <option value={1}>1 (SET)</option>
                </select>
              </div>

              <div>
                <label className="text-zinc-500 block text-[10px] mb-1">ACK FLAG</label>
                <select
                  value={formData.ack_flag_count}
                  onChange={(e) => handleInputChange("ack_flag_count", parseInt(e.target.value))}
                  className="w-full bg-[#090a0f] border border-[#1b1f2e] px-2 py-1 text-zinc-200 rounded-sm focus:outline-none"
                >
                  <option value={0}>0 (OFF)</option>
                  <option value={1}>1 (SET)</option>
                </select>
              </div>
            </div>

            <button
              onClick={handleRunInference}
              disabled={isRunning}
              className="w-full py-2.5 bg-red-600 hover:bg-red-500 text-white font-bold text-xs font-mono-tech tracking-wider uppercase rounded-sm flex items-center justify-center gap-2 transition shadow-lg shadow-red-950/40"
            >
              {isRunning ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  EVALUATING WITH AI MODEL...
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  EXECUTE NIDS REAL-TIME INFERENCE
                </>
              )}
            </button>
          </div>

          {/* Inference Result Output Box */}
          {result && (
            <div className="bg-[#0f111a] border border-[#1b1f2e] p-4 rounded-sm font-mono-tech">
              <h3 className="text-xs font-bold text-zinc-200 uppercase mb-3 flex items-center gap-2 border-b border-[#1b1f2e] pb-2">
                <Cpu className="w-4 h-4 text-cyan-400" />
                MODEL INFERENCE VERDICT & SOC ALERT OUTPUT
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-4">
                <div className="bg-[#090a0f] border border-[#1b1f2e] p-3 rounded-sm">
                  <span className="text-zinc-500 text-[10px] block">CLASSIFICATION VERDICT</span>
                  <span
                    className={`text-lg font-bold ${
                      result.classification === "BENIGN" ? "text-emerald-400" : "text-red-400"
                    }`}
                  >
                    {result.classification}
                  </span>
                </div>

                <div className="bg-[#090a0f] border border-[#1b1f2e] p-3 rounded-sm">
                  <span className="text-zinc-500 text-[10px] block">CONFIDENCE SCORE</span>
                  <span className="text-lg font-bold text-emerald-400">
                    {(result.confidence_score * 100).toFixed(2)}%
                  </span>
                </div>

                <div className="bg-[#090a0f] border border-[#1b1f2e] p-3 rounded-sm">
                  <span className="text-zinc-500 text-[10px] block">SOC SEVERITY</span>
                  <span
                    className={`text-lg font-bold ${
                      result.severity === "CRITICAL"
                        ? "text-red-400"
                        : result.severity === "HIGH"
                        ? "text-orange-400"
                        : result.severity === "SUSPICIOUS"
                        ? "text-amber-400"
                        : "text-emerald-400"
                    }`}
                  >
                    {result.severity}
                  </span>
                </div>
              </div>

              {result.alert && (
                <div className="bg-[#090a0f] border border-red-800/80 p-3 rounded-sm space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-red-400 font-bold flex items-center gap-1.5">
                      <ShieldAlert className="w-4 h-4" /> GENERATED ALERT ID: {result.alert.alert_id}
                    </span>
                    <span className="text-zinc-400 text-[10px]">{result.alert.timestamp}</span>
                  </div>
                  <p className="text-xs text-amber-300 font-semibold">{result.alert.mitre_tactic}</p>
                  <p className="text-[11px] text-zinc-300">{result.alert.description}</p>
                  <div className="text-[11px] text-emerald-400 border-t border-zinc-800 pt-1.5 mt-2">
                    <span className="font-bold">RECOMMENDED ACTION:</span> {result.alert.mitigation}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
