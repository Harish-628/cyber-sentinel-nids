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
    <div className="space-y-3 font-mono-tech relative">
      {/* Search & Filter Toolbar */}
      <div className="bg-[#0d0f17] border border-[#1a1e2e] p-2.5 rounded-[2px] flex flex-wrap items-center justify-between gap-2.5">
        {/* Search Input */}
        <div className="flex items-center gap-2 bg-[#090b10] border border-[#1a1e2e] px-2.5 py-1.5 rounded-[2px] w-80">
          <Search className="w-3.5 h-3.5 text-zinc-500" />
          <input
            type="text"
            placeholder="Search IP, Port, Attack, Protocol, Alert ID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="bg-transparent text-xs text-zinc-200 placeholder-zinc-600 focus:outline-none w-full"
          />
          {searchTerm && (
            <button onClick={() => setSearchTerm("")} className="text-zinc-500 hover:text-zinc-300">
              <X className="w-3 h-3" />
            </button>
          )}
        </div>

        {/* Severity Tabs */}
        <div className="flex items-center gap-1 bg-[#090b10] border border-[#1a1e2e] p-0.5 rounded-[2px]">
          <span className="text-[9px] text-zinc-500 px-2 uppercase">SEVERITY:</span>
          {["ALL", "CRITICAL", "HIGH", "SUSPICIOUS"].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-2 py-0.5 text-[10px] rounded-[2px] transition ${
                severityFilter === sev
                  ? "bg-[#1f2638] text-white font-bold"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              {sev}
            </button>
          ))}
        </div>

        {/* Status Filter */}
        <div className="flex items-center gap-1 bg-[#090b10] border border-[#1a1e2e] p-0.5 rounded-[2px]">
          <span className="text-[9px] text-zinc-500 px-2 uppercase">STATUS:</span>
          {["ALL", "NEW", "INVESTIGATING", "RESOLVED"].map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`px-2 py-0.5 text-[10px] rounded-[2px] transition ${
                statusFilter === st
                  ? "bg-[#1f2638] text-white font-bold"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              {st}
            </button>
          ))}
        </div>

        {/* Export & Actions */}
        <div className="flex items-center gap-2">
          <button
            onClick={exportToCSV}
            className="flex items-center gap-1.5 px-2.5 py-1 text-[10px] font-bold bg-[#141824] hover:bg-[#1c2234] text-cyan-300 border border-cyan-800/60 rounded-[2px] transition"
          >
            <Download className="w-3 h-3" /> EXPORT CSV
          </button>
          <div className="text-[10px] text-zinc-400 px-1">
            <span className="text-white font-bold">{filteredAlerts.length}</span> / {alerts.length}
          </div>
        </div>
      </div>

      {/* Main Table Grid */}
      <div className="bg-[#0d0f17] border border-[#1a1e2e] rounded-[2px] overflow-hidden">
        <div className="overflow-x-auto max-h-[640px]">
          <table className="w-full text-left text-xs border-collapse">
            <thead className="bg-[#090b10] text-zinc-400 uppercase text-[9px] sticky top-0 border-b border-[#1a1e2e] z-10">
              <tr>
                <th className="py-2.5 px-3">TIMESTAMP</th>
                <th className="py-2.5 px-3">ALERT ID</th>
                <th className="py-2.5 px-3">SEVERITY</th>
                <th className="py-2.5 px-3">ATTACK TYPE</th>
                <th className="py-2.5 px-3">SRC IP:PORT</th>
                <th className="py-2.5 px-3">TARGET IP:PORT</th>
                <th className="py-2.5 px-3">PROTO</th>
                <th className="py-2.5 px-3">CONFIDENCE</th>
                <th className="py-2.5 px-3">STATUS</th>
                <th className="py-2.5 px-3 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#161a29]">
              {filteredAlerts.length > 0 ? (
                Array.from(
                  new Map(filteredAlerts.map((a) => [a.alert_id, a])).values()
                ).map((alert, idx) => {
                  const isSelected = selectedAlert?.alert_id === alert.alert_id;
                  const sevStyle =
                    alert.severity === "CRITICAL"
                      ? "bg-red-950/80 text-red-300 border-red-700/80"
                      : alert.severity === "HIGH"
                      ? "bg-orange-950/80 text-orange-300 border-orange-700/80"
                      : "bg-amber-950/80 text-amber-300 border-amber-700/80";

                  const statusStyle =
                    alert.status === "NEW"
                      ? "bg-red-950/50 text-red-300 border-red-800"
                      : alert.status === "INVESTIGATING"
                      ? "bg-amber-950/50 text-amber-300 border-amber-800"
                      : "bg-emerald-950/50 text-emerald-300 border-emerald-800";

                  return (
                    <tr
                      key={`${alert.alert_id}-${idx}`}
                      onClick={() => onSelectAlert(alert)}
                      className={`cursor-pointer transition select-none ${
                        isSelected
                          ? "bg-[#181d2f] border-l-2 border-red-500"
                          : "hover:bg-[#121522]"
                      }`}
                    >
                      <td className="py-2 px-3 text-zinc-400 text-[10px] whitespace-nowrap">
                        {alert.timestamp.split("T")[1]?.slice(0, 8) || alert.timestamp}
                      </td>
                      <td className="py-2 px-3 text-zinc-300 font-bold whitespace-nowrap">
                        {alert.alert_id}
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap">
                        <span className={`px-1.5 py-0.2 text-[9px] border font-bold rounded-[2px] ${sevStyle}`}>
                          {alert.severity}
                        </span>
                      </td>
                      <td className="py-2 px-3 text-white font-semibold whitespace-nowrap">
                        {alert.classification}
                      </td>
                      <td className="py-2 px-3 text-cyan-400 whitespace-nowrap">
                        {alert.source_ip}:{alert.source_port}
                      </td>
                      <td className="py-2 px-3 text-zinc-300 whitespace-nowrap">
                        {alert.destination_ip}:{alert.destination_port}
                      </td>
                      <td className="py-2 px-3 text-zinc-400 whitespace-nowrap">
                        {alert.protocol}
                      </td>
                      <td className="py-2 px-3 text-emerald-400 font-bold whitespace-nowrap">
                        {(alert.confidence_score * 100).toFixed(1)}%
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                        <select
                          value={alert.status}
                          disabled={updatingId === alert.alert_id}
                          onChange={(e) => handleStatusChange(alert.alert_id, e.target.value)}
                          className={`text-[9px] px-1.5 py-0.5 border rounded-[2px] bg-[#090b10] focus:outline-none cursor-pointer ${statusStyle}`}
                        >
                          <option value="NEW">NEW</option>
                          <option value="INVESTIGATING">INVESTIGATING</option>
                          <option value="RESOLVED">RESOLVED</option>
                        </select>
                      </td>
                      <td className="py-2 px-3 text-right whitespace-nowrap">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectAlert(alert);
                          }}
                          className="px-2 py-0.5 text-[9px] bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 rounded-[2px] transition"
                        >
                          INSPECT
                        </button>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={10} className="py-12 text-center text-zinc-500 text-xs">
                    NO ALERTS MATCHING THE ACTIVE FILTERS.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Sliding Right Incident Drawer (CrowdStrike Falcon Style) */}
      {selectedAlert && (
        <div className="fixed inset-y-0 right-0 w-full max-w-xl z-50 bg-[#0d0f17] border-l border-[#262c40] shadow-2xl flex flex-col justify-between animate-in slide-in-from-right duration-200 font-mono-tech">
          {/* Drawer Header */}
          <div className="bg-[#090b10] border-b border-[#1a1e2e] p-3.5 flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 bg-red-950 border border-red-700 flex items-center justify-center rounded-[2px]">
                <ShieldAlert className="w-4 h-4 text-red-500" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                    {selectedAlert.alert_id} // {selectedAlert.classification}
                  </h3>
                  <span className="px-1.5 py-0.2 text-[9px] bg-red-950 text-red-300 border border-red-700 rounded-[2px] font-bold">
                    {selectedAlert.severity}
                  </span>
                </div>
                <p className="text-[10px] text-zinc-400">
                  DETECTED AT: {selectedAlert.timestamp}
                </p>
              </div>
            </div>
            <button
              onClick={() => onSelectAlert(null)}
              className="p-1 text-zinc-400 hover:text-white rounded-[2px] hover:bg-zinc-800 transition"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Drawer Sub-Navigation Tabs */}
          <div className="flex border-b border-[#1a1e2e] bg-[#0b0d14] px-3">
            {[
              { id: "dossier", label: "INCIDENT DOSSIER" },
              { id: "telemetry", label: "PACKET EVIDENCE" },
              { id: "playbook", label: "CONTAINMENT PLAYBOOK" },
              { id: "raw", label: "RAW JSON" },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setDrawerTab(tab.id as any)}
                className={`py-2 px-3 text-[10px] font-bold border-b-2 transition ${
                  drawerTab === tab.id
                    ? "border-red-500 text-white bg-[#141826]"
                    : "border-transparent text-zinc-400 hover:text-zinc-200"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Drawer Scrollable Content */}
          <div className="flex-1 p-4 overflow-y-auto space-y-4">
            {drawerTab === "dossier" && (
              <div className="space-y-4">
                {/* 5-Tuple Box */}
                <div>
                  <p className="text-[9px] text-zinc-500 uppercase tracking-wider mb-1.5">
                    NETWORK 5-TUPLE CONTEXT
                  </p>
                  <div className="grid grid-cols-2 gap-2 bg-[#090b10] border border-[#1a1e2e] p-3 rounded-[2px] text-xs">
                    <div>
                      <span className="text-zinc-500 block text-[9px]">SOURCE HOST</span>
                      <span className="text-cyan-400 font-bold">{selectedAlert.source_ip}:{selectedAlert.source_port}</span>
                    </div>
                    <div>
                      <span className="text-zinc-500 block text-[9px]">DESTINATION HOST</span>
                      <span className="text-orange-400 font-bold">{selectedAlert.destination_ip}:{selectedAlert.destination_port}</span>
                    </div>
                    <div>
                      <span className="text-zinc-500 block text-[9px]">PROTOCOL</span>
                      <span className="text-zinc-300 font-semibold">{selectedAlert.protocol}</span>
                    </div>
                    <div>
                      <span className="text-zinc-500 block text-[9px]">MODEL CONFIDENCE</span>
                      <span className="text-emerald-400 font-bold">{(selectedAlert.confidence_score * 100).toFixed(2)}%</span>
                    </div>
                  </div>
                </div>

                {/* MITRE ATT&CK Context */}
                <div className="bg-[#090b10] border border-[#1a1e2e] p-3 rounded-[2px] space-y-1.5">
                  <div className="flex items-center gap-2 text-zinc-300 text-xs font-bold uppercase">
                    <Info className="w-3.5 h-3.5 text-blue-400" /> MITRE ATT&CK TACTIC
                  </div>
                  <p className="text-amber-400 text-xs font-semibold">{selectedAlert.mitre_tactic}</p>
                  <p className="text-zinc-400 text-[11px] leading-relaxed">{selectedAlert.description}</p>
                </div>
              </div>
            )}

            {drawerTab === "telemetry" && (
              <div className="space-y-4">
                <p className="text-[9px] text-zinc-500 uppercase tracking-wider mb-1.5">
                  CICFLOWMETER EXTRACTED METRICS
                </p>
                <div className="grid grid-cols-2 gap-2 bg-[#090b10] border border-[#1a1e2e] p-3 rounded-[2px] text-xs">
                  <div>
                    <span className="text-zinc-500 block text-[9px]">FLOW DURATION</span>
                    <span className="text-zinc-200">{selectedAlert.flow_summary?.flow_duration_ms ?? 0} ms</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 block text-[9px]">TOTAL PACKETS</span>
                    <span className="text-zinc-200">{selectedAlert.flow_summary?.total_packets ?? 0}</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 block text-[9px]">BYTES TRANSFERRED</span>
                    <span className="text-zinc-200">{selectedAlert.flow_summary?.bytes_transferred ?? 0} B</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 block text-[9px]">PACKET RATE</span>
                    <span className="text-zinc-200">{selectedAlert.flow_summary?.packets_per_sec ?? 0} pkts/s</span>
                  </div>
                </div>

                {/* TCP Flags */}
                {selectedAlert.flow_summary?.flags && (
                  <div>
                    <p className="text-[9px] text-zinc-500 uppercase tracking-wider mb-1.5">
                      TCP CONTROL FLAGS
                    </p>
                    <div className="flex gap-2">
                      {Object.entries(selectedAlert.flow_summary.flags).map(([flag, val]) => (
                        <span
                          key={flag}
                          className={`px-2 py-0.5 text-xs border rounded-[2px] font-bold ${
                            val > 0
                              ? "bg-red-950 text-red-300 border-red-700"
                              : "bg-[#090b10] text-zinc-600 border-zinc-800"
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
                <div className="bg-[#090b10] border border-[#1a1e2e] p-3 rounded-[2px] space-y-2">
                  <div className="flex items-center gap-2 text-zinc-300 text-xs font-bold uppercase">
                    <Shield className="w-3.5 h-3.5 text-emerald-400" /> INCIDENT CONTAINMENT ACTIONS
                  </div>
                  <p className="text-zinc-300 text-[11px] leading-relaxed">{selectedAlert.mitigation}</p>
                </div>

                {/* Firewall Rule Generator */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-[10px] text-zinc-400">
                    <span>GENERATED IPTABLES DROP RULE</span>
                    <button
                      onClick={() =>
                        copyToClipboard(
                          `iptables -A INPUT -s ${selectedAlert.source_ip} -j DROP`,
                          "iptables"
                        )
                      }
                      className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                    >
                      {copiedKey === "iptables" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedKey === "iptables" ? "COPIED" : "COPY RULE"}</span>
                    </button>
                  </div>
                  <div className="bg-[#090b10] border border-[#1a1e2e] p-2.5 rounded-[2px] text-xs text-red-300 overflow-x-auto">
                    <code>iptables -A INPUT -s {selectedAlert.source_ip} -j DROP</code>
                  </div>
                </div>

                {/* Snort / Suricata Rule */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-[10px] text-zinc-400">
                    <span>SURICATA / SNORT SIGNATURE</span>
                    <button
                      onClick={() =>
                        copyToClipboard(
                          `drop tcp ${selectedAlert.source_ip} any -> $HOME_NET ${selectedAlert.destination_port} (msg:"CYBER-SENTINEL: ${selectedAlert.classification} Blocked"; sid:9001001; rev:1;)`,
                          "suricata"
                        )
                      }
                      className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                    >
                      {copiedKey === "suricata" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedKey === "suricata" ? "COPIED" : "COPY SIGNATURE"}</span>
                    </button>
                  </div>
                  <div className="bg-[#090b10] border border-[#1a1e2e] p-2.5 rounded-[2px] text-[11px] text-amber-300 overflow-x-auto">
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
                    className="text-[10px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                  >
                    {copiedKey === "raw_json" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedKey === "raw_json" ? "COPIED" : "COPY JSON"}</span>
                  </button>
                </div>
                <pre className="bg-[#090b10] border border-[#1a1e2e] p-3 text-[10px] text-zinc-300 rounded-[2px] overflow-x-auto max-h-96">
                  {JSON.stringify(selectedAlert, null, 2)}
                </pre>
              </div>
            )}
          </div>

          {/* Drawer Triage Footer */}
          <div className="bg-[#090a0f] border-t border-[#1a1e2e] p-3 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-zinc-500">SET STATUS:</span>
              <select
                value={selectedAlert.status}
                onChange={(e) => handleStatusChange(selectedAlert.alert_id, e.target.value)}
                className="bg-zinc-900 border border-zinc-700 text-xs text-zinc-200 px-2 py-1 rounded-[2px] focus:outline-none"
              >
                <option value="NEW">NEW</option>
                <option value="INVESTIGATING">INVESTIGATING</option>
                <option value="RESOLVED">RESOLVED</option>
              </select>
            </div>

            <button
              onClick={() => onSelectAlert(null)}
              className="px-3 py-1 text-xs bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 rounded-[2px]"
            >
              CLOSE
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
