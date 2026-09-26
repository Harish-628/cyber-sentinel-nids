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
  Trash2,
} from "lucide-react";
import { clearAllAlerts, updateAlertStatus } from "@/lib/api";
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

  const [isClearing, setIsClearing] = useState(false);
  const handleClearAll = async () => {
    if (!window.confirm("Are you sure you want to clear all alerts and reset baseline?")) return;
    setIsClearing(true);
    try {
      await clearAllAlerts();
      onAlertStatusUpdated();
    } catch (e) {
      console.error("Failed to clear all alerts", e);
    } finally {
      setIsClearing(false);
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
      {/* Search & Filter Toolbar - White Glassmorphic */}
      <div className="glass-panel p-4 rounded-2xl flex flex-wrap items-center justify-between gap-3 shadow-xs border border-white/90 bg-white/80">
        {/* Search Input */}
        <div className="flex items-center gap-2.5 bg-white border border-slate-200 px-3.5 py-2 rounded-xl w-full sm:w-80 shadow-2xs focus-within:border-blue-500 focus-within:ring-2 focus-within:ring-blue-500/20 transition">
          <Search className="w-4 h-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search IP, Port, Attack, Protocol, Alert ID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="bg-transparent text-xs text-slate-900 placeholder-slate-400 focus:outline-none w-full font-medium"
          />
          {searchTerm && (
            <button onClick={() => setSearchTerm("")} className="text-slate-400 hover:text-slate-600">
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Severity Tabs */}
        <div className="flex items-center gap-1 bg-slate-100 border border-slate-200 p-1 rounded-xl">
          <span className="text-[10px] text-slate-500 font-bold px-2 uppercase tracking-wider">SEVERITY:</span>
          {["ALL", "CRITICAL", "HIGH", "SUSPICIOUS"].map((sev) => {
            const isActive = severityFilter === sev;
            let activeColor = "bg-blue-600 text-white shadow-xs";
            if (sev === "CRITICAL") activeColor = "bg-rose-600 text-white shadow-xs";
            if (sev === "HIGH") activeColor = "bg-orange-600 text-white shadow-xs";
            if (sev === "SUSPICIOUS") activeColor = "bg-amber-600 text-white shadow-xs";

            return (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-3 py-1 text-[10px] rounded-lg transition font-bold ${
                  isActive
                    ? `${activeColor}`
                    : "text-slate-600 hover:text-slate-900 hover:bg-white"
                }`}
              >
                {sev}
              </button>
            );
          })}
        </div>

        {/* Status Filter */}
        <div className="flex items-center gap-1 bg-slate-100 border border-slate-200 p-1 rounded-xl">
          <span className="text-[10px] text-slate-500 font-bold px-2 uppercase tracking-wider">STATUS:</span>
          {["ALL", "NEW", "INVESTIGATING", "RESOLVED"].map((st) => {
            const isActive = statusFilter === st;
            let activeColor = "bg-blue-600 text-white shadow-xs";
            if (st === "NEW") activeColor = "bg-rose-600 text-white shadow-xs";
            if (st === "INVESTIGATING") activeColor = "bg-amber-600 text-white shadow-xs";
            if (st === "RESOLVED") activeColor = "bg-emerald-600 text-white shadow-xs";

            return (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`px-3 py-1 text-[10px] rounded-lg transition font-bold ${
                  isActive
                    ? `${activeColor}`
                    : "text-slate-600 hover:text-slate-900 hover:bg-white"
                }`}
              >
                {st}
              </button>
            );
          })}
        </div>

        {/* Export & Counter */}
        <div className="flex items-center gap-2">
          <button
            onClick={handleClearAll}
            disabled={isClearing || alerts.length === 0}
            className="flex items-center gap-1.5 px-3 py-2 text-[10px] font-bold bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 hover:border-rose-300 rounded-xl transition active:scale-95 disabled:opacity-40"
            title="Clear all alerts"
          >
            <Trash2 className="w-3.5 h-3.5" /> CLEAR ALL
          </button>
          <button
            onClick={exportToCSV}
            className="flex items-center gap-2 px-3.5 py-2 text-[10px] font-bold bg-blue-600 hover:bg-blue-700 text-white rounded-xl shadow-md shadow-blue-500/20 transition active:scale-95"
          >
            <Download className="w-3.5 h-3.5" /> EXPORT CSV
          </button>
          <div className="text-[10px] text-slate-600 bg-white border border-slate-200 px-3 py-1.5 rounded-xl font-bold shadow-2xs">
            <span className="text-blue-600 font-black">{filteredAlerts.length}</span> / {alerts.length} ALERTS
          </div>
        </div>
      </div>

      {/* Main Table Grid - White Glassmorphic */}
      <div className="glass-panel rounded-2xl overflow-hidden border border-white/90 bg-white/80 shadow-xs">
        <div className="overflow-x-auto max-h-[640px]">
          <table className="w-full text-left text-xs border-collapse">
            <thead className="bg-slate-50/95 backdrop-blur-md text-slate-600 uppercase text-[9px] sticky top-0 border-b border-slate-200 z-10 font-bold tracking-wider">
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
            <tbody className="divide-y divide-slate-100 bg-white/60">
              {filteredAlerts.length > 0 ? (
                Array.from(
                  new Map(filteredAlerts.map((a) => [a.alert_id, a])).values()
                ).map((alert, idx) => {
                  const isSelected = selectedAlert?.alert_id === alert.alert_id;
                  const sevStyle =
                    alert.severity === "CRITICAL"
                      ? "bg-rose-50 text-rose-700 border-rose-200 shadow-2xs"
                      : alert.severity === "HIGH"
                      ? "bg-orange-50 text-orange-700 border-orange-200"
                      : "bg-amber-50 text-amber-700 border-amber-200";

                  const statusStyle =
                    alert.status === "NEW"
                      ? "bg-rose-50 text-rose-700 border-rose-200 font-bold"
                      : alert.status === "INVESTIGATING"
                      ? "bg-amber-50 text-amber-700 border-amber-200 font-bold"
                      : "bg-emerald-50 text-emerald-700 border-emerald-200 font-bold";

                  return (
                    <tr
                      key={`${alert.alert_id}-${idx}`}
                      onClick={() => onSelectAlert(alert)}
                      className={`cursor-pointer transition-all duration-150 select-none ${
                        isSelected
                          ? "bg-rose-50/60 border-l-4 border-l-rose-500 shadow-inner"
                          : "hover:bg-blue-50/50"
                      }`}
                    >
                      <td className="py-3 px-3.5 text-slate-500 text-[10px] whitespace-nowrap">
                        {alert.timestamp.split("T")[1]?.slice(0, 8) || alert.timestamp}
                      </td>
                      <td className="py-3 px-3.5 text-slate-800 font-bold whitespace-nowrap">
                        {alert.alert_id}
                      </td>
                      <td className="py-3 px-3.5 whitespace-nowrap">
                        <span className={`px-2.5 py-0.5 text-[9px] border font-bold rounded-md ${sevStyle}`}>
                          {alert.severity}
                        </span>
                      </td>
                      <td className="py-3 px-3.5 text-slate-900 font-bold whitespace-nowrap">
                        {alert.classification}
                      </td>
                      <td className="py-3 px-3.5 text-blue-600 font-bold font-mono whitespace-nowrap">
                        {alert.source_ip}:{alert.source_port}
                      </td>
                      <td className="py-3 px-3.5 text-slate-700 font-mono whitespace-nowrap">
                        {alert.destination_ip}:{alert.destination_port}
                      </td>
                      <td className="py-3 px-3.5 text-slate-500 font-mono whitespace-nowrap">
                        {alert.protocol}
                      </td>
                      <td className="py-3 px-3.5 text-emerald-600 font-bold whitespace-nowrap">
                        {(alert.confidence_score * 100).toFixed(1)}%
                      </td>
                      <td className="py-3 px-3.5 whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                        <select
                          value={alert.status}
                          disabled={updatingId === alert.alert_id}
                          onChange={(e) => handleStatusChange(alert.alert_id, e.target.value)}
                          className={`text-[9px] px-2.5 py-1 border rounded-lg bg-white focus:outline-none cursor-pointer ${statusStyle}`}
                        >
                          <option value="NEW">NEW</option>
                          <option value="INVESTIGATING">INVESTIGATING</option>
                          <option value="RESOLVED">RESOLVED</option>
                        </select>
                      </td>
                      <td className="py-3 px-3.5 text-right whitespace-nowrap">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectAlert(alert);
                          }}
                          className="px-3 py-1 text-[10px] font-bold bg-white hover:bg-blue-50 text-slate-700 hover:text-blue-700 border border-slate-200 rounded-lg transition shadow-2xs"
                        >
                          INSPECT
                        </button>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={10} className="py-14 text-center text-slate-400 text-xs">
                    NO ALERTS MATCHING THE ACTIVE FILTERS.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Sliding Right Incident Drawer (White Crystal Falcon Style) */}
      {selectedAlert && (
        <div className="fixed inset-y-0 right-0 w-full max-w-xl z-50 glass-drawer border-l border-slate-200 bg-white/95 backdrop-blur-3xl shadow-2xl flex flex-col justify-between animate-in slide-in-from-right duration-200 font-mono-tech">
          {/* Drawer Header */}
          <div className="bg-white/80 border-b border-slate-200 p-5 flex items-center justify-between">
            <div className="flex items-center gap-3.5">
              <div className="w-10 h-10 bg-rose-50 border border-rose-200 shadow-xs flex items-center justify-center rounded-xl">
                <ShieldAlert className="w-5 h-5 text-rose-600" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                    {selectedAlert.alert_id} // {selectedAlert.classification}
                  </h3>
                  <span className="px-2 py-0.5 text-[9px] bg-rose-50 text-rose-700 border border-rose-200 rounded-md font-bold">
                    {selectedAlert.severity}
                  </span>
                </div>
                <p className="text-[10px] text-slate-500 mt-0.5">
                  DETECTED AT: {selectedAlert.timestamp}
                </p>
              </div>
            </div>
            <button
              onClick={() => onSelectAlert(null)}
              className="p-2 text-slate-400 hover:text-slate-800 rounded-xl hover:bg-slate-100 transition"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Drawer Sub-Navigation Tabs */}
          <div className="flex border-b border-slate-200 bg-slate-50/80 px-4 gap-1">
            {[
              { id: "dossier", label: "INCIDENT DOSSIER" },
              { id: "telemetry", label: "PACKET EVIDENCE" },
              { id: "playbook", label: "CONTAINMENT PLAYBOOK" },
              { id: "raw", label: "RAW JSON" },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setDrawerTab(tab.id as any)}
                className={`py-3 px-3.5 text-[10px] font-bold border-b-2 transition ${
                  drawerTab === tab.id
                    ? "border-rose-600 text-rose-700 bg-rose-50/50"
                    : "border-transparent text-slate-500 hover:text-slate-800 hover:bg-white"
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
                  <p className="text-[10px] text-slate-500 uppercase tracking-wider font-bold mb-2">
                    NETWORK 5-TUPLE CONTEXT
                  </p>
                  <div className="grid grid-cols-2 gap-3 glass-panel p-4 rounded-xl border border-slate-200 bg-white shadow-xs text-xs">
                    <div>
                      <span className="text-slate-400 block text-[9px] font-semibold mb-0.5">SOURCE HOST</span>
                      <span className="text-blue-600 font-bold font-mono">{selectedAlert.source_ip}:{selectedAlert.source_port}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 block text-[9px] font-semibold mb-0.5">DESTINATION HOST</span>
                      <span className="text-orange-600 font-bold font-mono">{selectedAlert.destination_ip}:{selectedAlert.destination_port}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 block text-[9px] font-semibold mb-0.5">PROTOCOL</span>
                      <span className="text-slate-800 font-bold">{selectedAlert.protocol}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 block text-[9px] font-semibold mb-0.5">MODEL CONFIDENCE</span>
                      <span className="text-emerald-600 font-bold">{(selectedAlert.confidence_score * 100).toFixed(2)}%</span>
                    </div>
                  </div>
                </div>

                {/* MITRE ATT&CK Context */}
                <div className="glass-panel p-4 rounded-xl border border-amber-200 bg-amber-50/60 space-y-2 shadow-xs">
                  <div className="flex items-center gap-2 text-amber-900 text-xs font-bold uppercase tracking-wider">
                    <Info className="w-4 h-4 text-amber-600" /> MITRE ATT&CK TACTIC
                  </div>
                  <p className="text-amber-800 text-xs font-bold">{selectedAlert.mitre_tactic}</p>
                  <p className="text-slate-700 text-[11px] leading-relaxed">{selectedAlert.description}</p>
                </div>
              </div>
            )}

            {drawerTab === "telemetry" && (
              <div className="space-y-4">
                <p className="text-[10px] text-slate-500 uppercase tracking-wider font-bold mb-2">
                  CICFLOWMETER EXTRACTED METRICS
                </p>
                <div className="grid grid-cols-2 gap-3 glass-panel p-4 rounded-xl border border-slate-200 bg-white shadow-xs text-xs">
                  <div>
                    <span className="text-slate-400 block text-[9px] font-semibold mb-0.5">FLOW DURATION</span>
                    <span className="text-slate-800 font-bold">{selectedAlert.flow_summary?.flow_duration_ms ?? 0} ms</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[9px] font-semibold mb-0.5">TOTAL PACKETS</span>
                    <span className="text-slate-800 font-bold">{selectedAlert.flow_summary?.total_packets ?? 0}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[9px] font-semibold mb-0.5">BYTES TRANSFERRED</span>
                    <span className="text-slate-800 font-bold">{selectedAlert.flow_summary?.bytes_transferred ?? 0} B</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[9px] font-semibold mb-0.5">PACKET RATE</span>
                    <span className="text-slate-800 font-bold">{selectedAlert.flow_summary?.packets_per_sec ?? 0} pkts/s</span>
                  </div>
                </div>

                {/* TCP Flags */}
                {selectedAlert.flow_summary?.flags && (
                  <div>
                    <p className="text-[10px] text-slate-500 uppercase tracking-wider font-bold mb-2">
                      TCP CONTROL FLAGS
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {Object.entries(selectedAlert.flow_summary.flags).map(([flag, val]) => (
                        <span
                          key={flag}
                          className={`px-3 py-1 text-xs border rounded-lg font-bold ${
                            val > 0
                              ? "bg-rose-50 text-rose-700 border-rose-200 shadow-2xs"
                              : "bg-slate-100 text-slate-400 border-slate-200"
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
                <div className="glass-panel p-4 rounded-xl border border-emerald-200 bg-emerald-50/60 space-y-2 shadow-xs">
                  <div className="flex items-center gap-2 text-emerald-900 text-xs font-bold uppercase tracking-wider">
                    <Shield className="w-4 h-4 text-emerald-600" /> INCIDENT CONTAINMENT ACTIONS
                  </div>
                  <p className="text-slate-800 text-[11px] leading-relaxed">{selectedAlert.mitigation}</p>
                </div>

                {/* Firewall Rule Generator */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-[10px] text-slate-500 font-bold">
                    <span>GENERATED IPTABLES DROP RULE</span>
                    <button
                      onClick={() =>
                        copyToClipboard(
                          `iptables -A INPUT -s ${selectedAlert.source_ip} -j DROP`,
                          "iptables"
                        )
                      }
                      className="text-blue-600 hover:text-blue-700 flex items-center gap-1.5 font-bold"
                    >
                      {copiedKey === "iptables" ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedKey === "iptables" ? "COPIED" : "COPY RULE"}</span>
                    </button>
                  </div>
                  <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-xl text-xs text-rose-400 overflow-x-auto shadow-md">
                    <code>iptables -A INPUT -s {selectedAlert.source_ip} -j DROP</code>
                  </div>
                </div>

                {/* Snort / Suricata Rule */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-[10px] text-slate-500 font-bold">
                    <span>SURICATA / SNORT SIGNATURE</span>
                    <button
                      onClick={() =>
                        copyToClipboard(
                          `drop tcp ${selectedAlert.source_ip} any -> $HOME_NET ${selectedAlert.destination_port} (msg:"CYBER-SENTINEL: ${selectedAlert.classification} Blocked"; sid:9001001; rev:1;)`,
                          "suricata"
                        )
                      }
                      className="text-blue-600 hover:text-blue-700 flex items-center gap-1.5 font-bold"
                    >
                      {copiedKey === "suricata" ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedKey === "suricata" ? "COPIED" : "COPY SIGNATURE"}</span>
                    </button>
                  </div>
                  <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-xl text-[11px] text-amber-300 overflow-x-auto shadow-md">
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
                    className="text-[10px] text-blue-600 hover:text-blue-700 flex items-center gap-1.5 font-bold"
                  >
                    {copiedKey === "raw_json" ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedKey === "raw_json" ? "COPIED" : "COPY JSON"}</span>
                  </button>
                </div>
                <pre className="bg-slate-900 border border-slate-800 p-4 text-[10px] text-slate-200 rounded-xl overflow-x-auto max-h-96 shadow-md font-mono">
                  {JSON.stringify(selectedAlert, null, 2)}
                </pre>
              </div>
            )}
          </div>

          {/* Drawer Triage Footer */}
          <div className="bg-slate-50 border-t border-slate-200 p-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">SET STATUS:</span>
              <select
                value={selectedAlert.status}
                onChange={(e) => handleStatusChange(selectedAlert.alert_id, e.target.value)}
                className="bg-white border border-slate-300 text-xs text-slate-800 px-3 py-1.5 rounded-xl focus:outline-none focus:border-blue-500 font-bold shadow-2xs"
              >
                <option value="NEW">NEW</option>
                <option value="INVESTIGATING">INVESTIGATING</option>
                <option value="RESOLVED">RESOLVED</option>
              </select>
            </div>

            <button
              onClick={() => onSelectAlert(null)}
              className="px-4 py-1.5 text-xs bg-white hover:bg-slate-100 text-slate-700 border border-slate-200 rounded-xl transition font-bold shadow-2xs"
            >
              CLOSE
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
