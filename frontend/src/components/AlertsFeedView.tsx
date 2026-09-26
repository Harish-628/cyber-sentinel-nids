"use client";

import React, { useState } from "react";
import {
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  Check,
  CheckCircle,
  Clock,
  Code,
  Copy,
  Download,
  ExternalLink,
  FileSpreadsheet,
  Filter,
  Info,
  Layers,
  Search,
  Shield,
  ShieldAlert,
  Terminal,
  X,
  Zap,
} from "lucide-react";
import { updateAlertStatus } from "@/lib/api";
import { AlertStatus, SecurityAlert } from "@/lib/types";

interface AlertsFeedViewProps {
  alerts: SecurityAlert[];
  selectedAlert: SecurityAlert | null;
  onSelectAlert: (alert: SecurityAlert | null) => void;
  onAlertStatusUpdated: () => void;
}

export const AlertsFeedView: React.FC<AlertsFeedViewProps> = ({
  alerts,
  selectedAlert,
  onSelectAlert,
  onAlertStatusUpdated,
}) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [updatingId, setUpdatingId] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [drawerTab, setDrawerTab] = useState<"dossier" | "telemetry" | "playbook" | "raw">("dossier");

  const handleStatusChange = async (alertId: string, newStatus: string) => {
    setUpdatingId(alertId);
    try {
      await updateAlertStatus(alertId, newStatus);
      onAlertStatusUpdated();
    } catch (e) {
      console.error("Failed to update alert status", e);
    } finally {
      setUpdatingId(null);
    }
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const exportToCSV = () => {
    if (!filteredAlerts.length) return;
    const headers = [
      "Alert ID",
      "Timestamp",
      "Severity",
      "Classification",
      "Confidence",
      "Source IP",
      "Source Port",
      "Target IP",
      "Target Port",
      "Protocol",
      "Status",
      "MITRE Tactic",
      "Description",
      "Remediation",
    ];
    const rows = filteredAlerts.map((a) => [
      a.alert_id,
      a.timestamp,
      a.severity,
      a.classification,
      a.confidence_score,
      a.source_ip,
      a.source_port,
      a.destination_ip,
      a.destination_port,
      a.protocol,
      a.status,
      `"${a.mitre_tactic}"`,
      `"${a.description.replace(/"/g, '""')}"`,
      `"${a.mitigation.replace(/"/g, '""')}"`,
    ]);
    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map((e) => e.join(","))].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `nids_alerts_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const filteredAlerts = alerts.filter((a) => {
    if (severityFilter !== "ALL" && a.severity !== severityFilter) return false;
    if (statusFilter !== "ALL" && a.status !== statusFilter) return false;
    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      const match =
        a.source_ip.toLowerCase().includes(q) ||
        a.destination_ip.toLowerCase().includes(q) ||
        a.alert_id.toLowerCase().includes(q) ||
        a.classification.toLowerCase().includes(q) ||
        a.destination_port.toString().includes(q) ||
        a.protocol.toLowerCase().includes(q);
      if (!match) return false;
    }
    return true;
  });

  return (
    <div className="space-y-4 font-mono-tech relative">
      {/* Search & Filter Toolbar - Glassmorphic */}
      <div className="glass-panel p-3.5 rounded-xl flex flex-wrap items-center justify-between gap-3 shadow-xl border border-white/10">
        {/* Search Input */}
        <div className="flex items-center gap-2 glass-panel-interactive border-cyan-500/25 px-3 py-1.5 rounded-lg w-full sm:w-80 shadow-[0_0_12px_rgba(6,182,212,0.1)]">
          <Search className="w-3.5 h-3.5 text-cyan-400" />
          <input
            type="text"
            placeholder="Search IP, Port, Attack, Protocol, Alert ID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="bg-transparent text-xs text-zinc-100 placeholder-zinc-500 focus:outline-none w-full tracking-wide"
          />
          {searchTerm && (
            <button onClick={() => setSearchTerm("")} className="text-zinc-400 hover:text-zinc-200">
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Severity Tabs */}
        <div className="flex items-center gap-1.5 bg-[#080d1a]/60 backdrop-blur-md border border-white/10 p-1 rounded-lg">
          <span className="text-[9px] text-zinc-400 font-bold px-2 uppercase tracking-wider">SEVERITY:</span>
          {["ALL", "CRITICAL", "HIGH", "SUSPICIOUS"].map((sev) => {
            const isActive = severityFilter === sev;
            let activeColor = "bg-cyan-500/20 text-cyan-300 border-cyan-500/40 shadow-[0_0_10px_rgba(6,182,212,0.25)]";
            if (sev === "CRITICAL") activeColor = "bg-red-500/20 text-red-300 border-red-500/50 shadow-[0_0_10px_rgba(239,68,68,0.25)]";
            if (sev === "HIGH") activeColor = "bg-orange-500/20 text-orange-300 border-orange-500/50 shadow-[0_0_10px_rgba(249,115,22,0.25)]";
            if (sev === "SUSPICIOUS") activeColor = "bg-amber-500/20 text-amber-300 border-amber-500/50 shadow-[0_0_10px_rgba(245,158,11,0.25)]";

            return (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2.5 py-1 text-[10px] rounded-md transition font-semibold ${
                  isActive
                    ? `${activeColor} border font-bold`
                    : "text-zinc-400 hover:text-zinc-200 hover:bg-white/5 border border-transparent"
                }`}
              >
                {sev}
              </button>
            );
          })}
        </div>

        {/* Status Filter */}
        <div className="flex items-center gap-1.5 bg-[#080d1a]/60 backdrop-blur-md border border-white/10 p-1 rounded-lg">
          <span className="text-[9px] text-zinc-400 font-bold px-2 uppercase tracking-wider">STATUS:</span>
          {["ALL", "NEW", "INVESTIGATING", "RESOLVED"].map((st) => {
            const isActive = statusFilter === st;
            let activeColor = "bg-cyan-500/20 text-cyan-300 border-cyan-500/40 shadow-[0_0_10px_rgba(6,182,212,0.25)]";
            if (st === "NEW") activeColor = "bg-red-500/20 text-red-300 border-red-500/50 shadow-[0_0_10px_rgba(239,68,68,0.25)]";
            if (st === "INVESTIGATING") activeColor = "bg-amber-500/20 text-amber-300 border-amber-500/50 shadow-[0_0_10px_rgba(245,158,11,0.25)]";
            if (st === "RESOLVED") activeColor = "bg-emerald-500/20 text-emerald-300 border-emerald-500/50 shadow-[0_0_10px_rgba(16,185,129,0.25)]";

            return (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`px-2.5 py-1 text-[10px] rounded-md transition font-semibold ${
                  isActive
                    ? `${activeColor} border font-bold`
                    : "text-zinc-400 hover:text-zinc-200 hover:bg-white/5 border border-transparent"
                }`}
              >
                {st}
              </button>
            );
          })}
        </div>

        {/* Export & Counter */}
        <div className="flex items-center gap-3">
          <button
            onClick={exportToCSV}
            className="flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-bold bg-gradient-to-r from-cyan-500/20 to-blue-500/20 hover:from-cyan-500/30 hover:to-blue-500/30 text-cyan-300 border border-cyan-500/40 rounded-lg shadow-[0_0_12px_rgba(6,182,212,0.2)] transition active:scale-95"
          >
            <Download className="w-3.5 h-3.5" /> EXPORT CSV
          </button>
          <div className="text-[10px] text-zinc-400 bg-white/5 px-2.5 py-1 rounded-md border border-white/5">
            <span className="text-cyan-400 font-bold">{filteredAlerts.length}</span> / {alerts.length} ALERTS
          </div>
        </div>
      </div>

      {/* Main Table Grid - Glassmorphic */}
      <div className="glass-panel rounded-xl overflow-hidden border border-white/10 shadow-2xl">
        <div className="overflow-x-auto max-h-[640px]">
          <table className="w-full text-left text-xs border-collapse">
            <thead className="bg-[#090e1c]/90 backdrop-blur-md text-cyan-300/80 uppercase text-[9px] sticky top-0 border-b border-white/10 z-10 font-bold tracking-widest">
              <tr>
                <th className="py-3 px-3.5">TIMESTAMP</th>
                <th className="py-3 px-3.5">ALERT ID</th>
                <th className="py-3 px-3.5">SEVERITY</th>
                <th className="py-3 px-3.5">ATTACK TYPE</th>
                <th className="py-3 px-3.5">SRC IP:PORT</th>
                <th className="py-3 px-3.5">TARGET IP:PORT</th>
                <th className="py-3 px-3.5">PROTO</th>
                <th className="py-3 px-3.5">CONFIDENCE</th>
                <th className="py-3 px-3.5">STATUS</th>
                <th className="py-3 px-3.5 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.05]">
              {filteredAlerts.length > 0 ? (
                Array.from(
                  new Map(filteredAlerts.map((a) => [a.alert_id, a])).values()
                ).map((alert, idx) => {
                  const isSelected = selectedAlert?.alert_id === alert.alert_id;
                  const sevStyle =
                    alert.severity === "CRITICAL"
                      ? "bg-red-500/15 text-red-300 border-red-500/40 shadow-[0_0_10px_rgba(239,68,68,0.2)]"
                      : alert.severity === "HIGH"
                      ? "bg-orange-500/15 text-orange-300 border-orange-500/40 shadow-[0_0_10px_rgba(249,115,22,0.2)]"
                      : "bg-amber-500/15 text-amber-300 border-amber-500/40 shadow-[0_0_10px_rgba(245,158,11,0.2)]";

                  const statusStyle =
                    alert.status === "NEW"
                      ? "bg-red-500/15 text-red-300 border-red-500/30"
                      : alert.status === "INVESTIGATING"
                      ? "bg-amber-500/15 text-amber-300 border-amber-500/30"
                      : "bg-emerald-500/15 text-emerald-300 border-emerald-500/30";

                  return (
                    <tr
                      key={`${alert.alert_id}-${idx}`}
                      onClick={() => onSelectAlert(alert)}
                      className={`cursor-pointer transition-all duration-150 select-none ${
                        isSelected
                          ? "bg-gradient-to-r from-red-500/20 via-red-950/20 to-transparent border-l-2 border-red-500 shadow-[inset_0_0_20px_rgba(239,68,68,0.1)]"
                          : "hover:bg-cyan-500/[0.04]"
                      }`}
                    >
                      <td className="py-2.5 px-3.5 text-zinc-400 text-[10px] whitespace-nowrap">
                        {alert.timestamp.split("T")[1]?.slice(0, 8) || alert.timestamp}
                      </td>
                      <td className="py-2.5 px-3.5 text-zinc-200 font-bold whitespace-nowrap">
                        {alert.alert_id}
                      </td>
                      <td className="py-2.5 px-3.5 whitespace-nowrap">
                        <span className={`px-2 py-0.5 text-[9px] border font-bold rounded-md ${sevStyle}`}>
                          {alert.severity}
                        </span>
                      </td>
                      <td className="py-2.5 px-3.5 text-white font-semibold whitespace-nowrap">
                        {alert.classification}
                      </td>
                      <td className="py-2.5 px-3.5 text-cyan-400 font-medium whitespace-nowrap">
                        {alert.source_ip}:{alert.source_port}
                      </td>
                      <td className="py-2.5 px-3.5 text-zinc-300 whitespace-nowrap">
                        {alert.destination_ip}:{alert.destination_port}
                      </td>
                      <td className="py-2.5 px-3.5 text-zinc-400 font-mono whitespace-nowrap">
                        {alert.protocol}
                      </td>
                      <td className="py-2.5 px-3.5 text-emerald-400 font-bold whitespace-nowrap">
                        {(alert.confidence_score * 100).toFixed(1)}%
                      </td>
                      <td className="py-2.5 px-3.5 whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                        <select
                          value={alert.status}
                          disabled={updatingId === alert.alert_id}
                          onChange={(e) => handleStatusChange(alert.alert_id, e.target.value)}
                          className={`text-[9px] px-2 py-1 border rounded-md bg-[#0a0f1d] focus:outline-none cursor-pointer font-bold ${statusStyle}`}
                        >
                          <option value="NEW">NEW</option>
                          <option value="INVESTIGATING">INVESTIGATING</option>
                          <option value="RESOLVED">RESOLVED</option>
                        </select>
                      </td>
                      <td className="py-2.5 px-3.5 text-right whitespace-nowrap">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectAlert(alert);
                          }}
                          className="px-2.5 py-1 text-[9px] font-semibold bg-white/5 hover:bg-cyan-500/20 hover:text-cyan-300 hover:border-cyan-500/40 text-zinc-300 border border-white/10 rounded-md transition shadow-sm"
                        >
                          INSPECT
                        </button>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={10} className="py-14 text-center text-zinc-500 text-xs">
                    NO ALERTS MATCHING THE ACTIVE FILTERS.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Sliding Right Incident Drawer (CrowdStrike / Splunk Enterprise Glass Style) */}
      {selectedAlert && (
        <div className="fixed inset-y-0 right-0 w-full max-w-xl z-50 glass-drawer border-l border-white/15 shadow-[0_0_60px_rgba(0,0,0,0.85)] flex flex-col justify-between animate-in slide-in-from-right duration-250 font-mono-tech">
          {/* Drawer Header */}
          <div className="glass-header border-b border-white/10 p-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 bg-red-500/20 border border-red-500/40 shadow-[0_0_15px_rgba(239,68,68,0.3)] flex items-center justify-center rounded-lg">
                <ShieldAlert className="w-5 h-5 text-red-400" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                    {selectedAlert.alert_id} // {selectedAlert.classification}
                  </h3>
                  <span className="px-2 py-0.5 text-[9px] bg-red-500/20 text-red-300 border border-red-500/40 rounded-md font-bold shadow-[0_0_10px_rgba(239,68,68,0.25)]">
                    {selectedAlert.severity}
                  </span>
                </div>
                <p className="text-[10px] text-zinc-400 mt-0.5">
                  DETECTED AT: {selectedAlert.timestamp}
                </p>
              </div>
            </div>
            <button
              onClick={() => onSelectAlert(null)}
              className="p-1.5 text-zinc-400 hover:text-white rounded-lg hover:bg-white/10 transition border border-transparent hover:border-white/10"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Drawer Sub-Navigation Tabs */}
          <div className="flex border-b border-white/10 bg-[#080d1a]/80 backdrop-blur-md px-4 gap-1">
            {[
              { id: "dossier", label: "INCIDENT DOSSIER" },
              { id: "telemetry", label: "PACKET EVIDENCE" },
              { id: "playbook", label: "CONTAINMENT PLAYBOOK" },
              { id: "raw", label: "RAW JSON" },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setDrawerTab(tab.id as any)}
                className={`py-2.5 px-3 text-[10px] font-bold border-b-2 transition ${
                  drawerTab === tab.id
                    ? "border-red-500 text-white bg-red-500/10 shadow-[0_4px_12px_rgba(239,68,68,0.2)]"
                    : "border-transparent text-zinc-400 hover:text-zinc-200 hover:bg-white/5"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Drawer Scrollable Content */}
          <div className="flex-1 p-5 overflow-y-auto space-y-4">
            {drawerTab === "dossier" && (
              <div className="space-y-4">
                {/* 5-Tuple Box */}
                <div>
                  <p className="text-[9px] text-zinc-400 uppercase tracking-widest font-bold mb-2">
                    NETWORK 5-TUPLE CONTEXT
                  </p>
                  <div className="grid grid-cols-2 gap-3 glass-panel p-3.5 rounded-xl border border-white/10 text-xs shadow-lg">
                    <div>
                      <span className="text-zinc-500 block text-[9px] font-semibold mb-0.5">SOURCE HOST</span>
                      <span className="text-cyan-400 font-bold">{selectedAlert.source_ip}:{selectedAlert.source_port}</span>
                    </div>
                    <div>
                      <span className="text-zinc-500 block text-[9px] font-semibold mb-0.5">DESTINATION HOST</span>
                      <span className="text-orange-400 font-bold">{selectedAlert.destination_ip}:{selectedAlert.destination_port}</span>
                    </div>
                    <div>
                      <span className="text-zinc-500 block text-[9px] font-semibold mb-0.5">PROTOCOL</span>
                      <span className="text-zinc-200 font-semibold">{selectedAlert.protocol}</span>
                    </div>
                    <div>
                      <span className="text-zinc-500 block text-[9px] font-semibold mb-0.5">MODEL CONFIDENCE</span>
                      <span className="text-emerald-400 font-bold">{(selectedAlert.confidence_score * 100).toFixed(2)}%</span>
                    </div>
                  </div>
                </div>

                {/* MITRE ATT&CK Context */}
                <div className="glass-panel p-4 rounded-xl border border-amber-500/30 bg-amber-950/10 space-y-2 shadow-lg">
                  <div className="flex items-center gap-2 text-zinc-200 text-xs font-bold uppercase tracking-wider">
                    <Info className="w-4 h-4 text-amber-400" /> MITRE ATT&CK TACTIC
                  </div>
                  <p className="text-amber-300 text-xs font-bold">{selectedAlert.mitre_tactic}</p>
                  <p className="text-zinc-300 text-[11px] leading-relaxed">{selectedAlert.description}</p>
                </div>
              </div>
            )}

            {drawerTab === "telemetry" && (
              <div className="space-y-4">
                <p className="text-[9px] text-zinc-400 uppercase tracking-widest font-bold mb-2">
                  CICFLOWMETER EXTRACTED METRICS
                </p>
                <div className="grid grid-cols-2 gap-3 glass-panel p-3.5 rounded-xl border border-white/10 text-xs shadow-lg">
                  <div>
                    <span className="text-zinc-500 block text-[9px] font-semibold mb-0.5">FLOW DURATION</span>
                    <span className="text-zinc-200 font-semibold">{selectedAlert.flow_summary?.flow_duration_ms ?? 0} ms</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 block text-[9px] font-semibold mb-0.5">TOTAL PACKETS</span>
                    <span className="text-zinc-200 font-semibold">{selectedAlert.flow_summary?.total_packets ?? 0}</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 block text-[9px] font-semibold mb-0.5">BYTES TRANSFERRED</span>
                    <span className="text-zinc-200 font-semibold">{selectedAlert.flow_summary?.bytes_transferred ?? 0} B</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 block text-[9px] font-semibold mb-0.5">PACKET RATE</span>
                    <span className="text-zinc-200 font-semibold">{selectedAlert.flow_summary?.packets_per_sec ?? 0} pkts/s</span>
                  </div>
                </div>

                {/* TCP Flags */}
                {selectedAlert.flow_summary?.flags && (
                  <div>
                    <p className="text-[9px] text-zinc-400 uppercase tracking-widest font-bold mb-2">
                      TCP CONTROL FLAGS
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {Object.entries(selectedAlert.flow_summary.flags).map(([flag, val]) => (
                        <span
                          key={flag}
                          className={`px-2.5 py-1 text-xs border rounded-lg font-bold ${
                            val > 0
                              ? "bg-red-500/20 text-red-300 border-red-500/40 shadow-[0_0_10px_rgba(239,68,68,0.2)]"
                              : "bg-white/5 text-zinc-500 border-white/5"
                          }`}
                        >
                          {flag}: {val}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {drawerTab === "playbook" && (
              <div className="space-y-4">
                <div className="glass-panel p-4 rounded-xl border border-emerald-500/30 bg-emerald-950/10 space-y-2 shadow-lg">
                  <div className="flex items-center gap-2 text-zinc-200 text-xs font-bold uppercase tracking-wider">
                    <Shield className="w-4 h-4 text-emerald-400" /> INCIDENT CONTAINMENT ACTIONS
                  </div>
                  <p className="text-zinc-200 text-[11px] leading-relaxed">{selectedAlert.mitigation}</p>
                </div>

                {/* Firewall Rule Generator */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-[10px] text-zinc-400 font-semibold">
                    <span>GENERATED IPTABLES DROP RULE</span>
                    <button
                      onClick={() =>
                        copyToClipboard(
                          `iptables -A INPUT -s ${selectedAlert.source_ip} -j DROP`,
                          "iptables"
                        )
                      }
                      className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1.5 font-bold"
                    >
                      {copiedKey === "iptables" ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedKey === "iptables" ? "COPIED" : "COPY RULE"}</span>
                    </button>
                  </div>
                  <div className="bg-[#050811]/90 border border-red-500/30 p-3 rounded-lg text-xs text-red-300 overflow-x-auto shadow-inner">
                    <code>iptables -A INPUT -s {selectedAlert.source_ip} -j DROP</code>
                  </div>
                </div>

                {/* Snort / Suricata Rule */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-[10px] text-zinc-400 font-semibold">
                    <span>SURICATA / SNORT SIGNATURE</span>
                    <button
                      onClick={() =>
                        copyToClipboard(
                          `drop tcp ${selectedAlert.source_ip} any -> $HOME_NET ${selectedAlert.destination_port} (msg:"CYBER-SENTINEL: ${selectedAlert.classification} Blocked"; sid:9001001; rev:1;)`,
                          "suricata"
                        )
                      }
                      className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1.5 font-bold"
                    >
                      {copiedKey === "suricata" ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedKey === "suricata" ? "COPIED" : "COPY SIGNATURE"}</span>
                    </button>
                  </div>
                  <div className="bg-[#050811]/90 border border-amber-500/30 p-3 rounded-lg text-[11px] text-amber-300 overflow-x-auto shadow-inner">
                    <code>
                      drop tcp {selectedAlert.source_ip} any -&gt; $HOME_NET {selectedAlert.destination_port} (msg:&quot;CYBER-SENTINEL: {selectedAlert.classification} Blocked&quot;; sid:9001001; rev:1;)
                    </code>
                  </div>
                </div>
              </div>
            )}

            {drawerTab === "raw" && (
              <div className="space-y-2">
                <div className="flex justify-end">
                  <button
                    onClick={() => copyToClipboard(JSON.stringify(selectedAlert, null, 2), "raw_json")}
                    className="text-[10px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-bold"
                  >
                    {copiedKey === "raw_json" ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedKey === "raw_json" ? "COPIED" : "COPY JSON"}</span>
                  </button>
                </div>
                <pre className="bg-[#050811]/90 border border-white/10 p-3.5 text-[10px] text-zinc-300 rounded-xl overflow-x-auto max-h-96 shadow-inner">
                  {JSON.stringify(selectedAlert, null, 2)}
                </pre>
              </div>
            )}
          </div>

          {/* Drawer Triage Footer */}
          <div className="glass-panel rounded-none border-t border-white/10 p-4 flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <span className="text-[10px] text-zinc-400 font-bold uppercase tracking-wider">SET STATUS:</span>
              <select
                value={selectedAlert.status}
                onChange={(e) => handleStatusChange(selectedAlert.alert_id, e.target.value)}
                className="bg-[#0a0f1d] border border-white/15 text-xs text-zinc-200 px-3 py-1.5 rounded-lg focus:outline-none focus:border-cyan-500 font-semibold"
              >
                <option value="NEW">NEW</option>
                <option value="INVESTIGATING">INVESTIGATING</option>
                <option value="RESOLVED">RESOLVED</option>
              </select>
            </div>

            <button
              onClick={() => onSelectAlert(null)}
              className="px-4 py-1.5 text-xs bg-white/10 hover:bg-white/15 text-zinc-200 border border-white/10 rounded-lg transition font-semibold"
            >
              CLOSE
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
