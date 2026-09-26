"use client";

import React, { useState } from "react";
import { AlertTriangle, ExternalLink, Filter, Grid, Info, Shield, ShieldAlert, Zap } from "lucide-react";
import { SecurityAlert } from "@/lib/types";

interface MitreMatrixViewProps {
  alerts: SecurityAlert[];
  onSelectAlert: (alert: SecurityAlert) => void;
}

interface MitreTacticColumn {
  id: string;
  name: string;
  code: string;
  techniques: Array<{
    id: string;
    name: string;
    code: string;
    relatedAttacks: string[];
    description: string;
  }>;
}

export const MitreMatrixView: React.FC<MitreMatrixViewProps> = ({
  alerts,
  onSelectAlert,
}) => {
  const [selectedTechnique, setSelectedTechnique] = useState<string | null>("T1595");

  const matrixColumns: MitreTacticColumn[] = [
    {
      id: "recon",
      name: "RECONNAISSANCE",
      code: "TA0043",
      techniques: [
        {
          id: "T1595",
          name: "Active Scanning",
          code: "T1595",
          relatedAttacks: ["PortScan"],
          description: "Scanning IP blocks, open ports, and vulnerable services using SYN or stealth probes.",
        },
        {
          id: "T1590",
          name: "Gather Victim Net Info",
          code: "T1590",
          relatedAttacks: ["PortScan"],
          description: "Identifying subnets, gateways, and DNS records before initiating intrusions.",
        },
      ],
    },
    {
      id: "initial_access",
      name: "INITIAL ACCESS",
      code: "TA0001",
      techniques: [
        {
          id: "T1190",
          name: "Exploit Public Application",
          code: "T1190",
          relatedAttacks: ["Web Attack"],
          description: "Exploiting SQL Injection, XSS, or RCE vulnerabilities on external web applications.",
        },
      ],
    },
    {
      id: "credential_access",
      name: "CREDENTIAL ACCESS",
      code: "TA0006",
      techniques: [
        {
          id: "T1110",
          name: "Brute Force",
          code: "T1110",
          relatedAttacks: ["Brute Force"],
          description: "Dictionary attacks and password spraying against SSH (Port 22) or FTP (Port 21).",
        },
      ],
    },
    {
      id: "lateral_movement",
      name: "LATERAL MOVEMENT",
      code: "TA0008",
      techniques: [
        {
          id: "T1021",
          name: "Remote Services",
          code: "T1021",
          relatedAttacks: ["Infiltration", "PortScan"],
          description: "Using stolen credentials or SMB/RDP tunnels to pivot deeper into the corporate network.",
        },
      ],
    },
    {
      id: "command_control",
      name: "COMMAND & CONTROL",
      code: "TA0011",
      techniques: [
        {
          id: "T1071",
          name: "Application Layer Protocol",
          code: "T1071",
          relatedAttacks: ["Botnet"],
          description: "Periodic beaconing to adversary C2 infrastructure over standard HTTP/HTTPS/IRC.",
        },
      ],
    },
    {
      id: "impact",
      name: "IMPACT",
      code: "TA0040",
      techniques: [
        {
          id: "T1498",
          name: "Network Denial of Service",
          code: "T1498",
          relatedAttacks: ["DoS", "DDoS"],
          description: "Volumetric floods or resource starvation attacks exhausting gateway pipes and memory.",
        },
        {
          id: "T1499",
          name: "Endpoint Denial of Service",
          code: "T1499",
          relatedAttacks: ["DoS"],
          description: "Targeted Slowloris sockets preventing legitimate users from reaching web servers.",
        },
      ],
    },
  ];

  // Map alerts to techniques
  const getAlertsForTechnique = (attacks: string[]) => {
    return alerts.filter((a) => attacks.includes(a.classification));
  };

  const activeTechniqueObj = matrixColumns
    .flatMap((c) => c.techniques)
    .find((t) => t.id === selectedTechnique);

  const matchedAlerts = activeTechniqueObj
    ? getAlertsForTechnique(activeTechniqueObj.relatedAttacks)
    : [];

  return (
    <div className="space-y-4 font-mono-tech">
      {/* Top Banner - White Glassmorphic */}
      <div className="glass-panel p-5 rounded-2xl flex flex-wrap items-center justify-between gap-3 shadow-xs border border-white/90 bg-white/80">
        <div>
          <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl bg-rose-50 border border-rose-200 flex items-center justify-center shadow-xs">
              <Grid className="w-5 h-5 text-rose-600" />
            </div>
            MITRE ATT&CK® ENTERPRISE THREAT MATRIX // NETWORK KILL-CHAIN
          </h2>
          <p className="text-[10px] text-slate-500 mt-1">
            LIVE DETECTION TELEMETRY CORRELATED AGAINST MITRE ATT&CK v15 TACTICS & TECHNIQUES
          </p>
        </div>
        <div className="flex items-center gap-2.5 text-xs">
          <span className="text-[10px] text-slate-500 uppercase tracking-wider font-bold">COVERAGE:</span>
          <span className="px-3.5 py-1.5 bg-rose-50 border border-rose-200 text-rose-700 text-[10px] font-bold rounded-xl shadow-xs">
            6 TACTICS ACTIVE
          </span>
        </div>
      </div>

      {/* MITRE Matrix Columns Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-3.5">
        {matrixColumns.map((col) => {
          const totalAlertsInTactic = col.techniques.reduce((acc, t) => {
            return acc + getAlertsForTechnique(t.relatedAttacks).length;
          }, 0);

          return (
            <div key={col.id} className="glass-panel rounded-2xl overflow-hidden flex flex-col border border-white/90 bg-white/80 shadow-xs">
              {/* Tactic Header */}
              <div className="bg-slate-50 border-b border-slate-200 p-3 flex items-center justify-between">
                <div>
                  <h4 className="text-[10px] font-bold text-slate-800 tracking-wider">
                    {col.name}
                  </h4>
                  <span className="text-[8px] text-blue-600 font-mono font-bold">{col.code}</span>
                </div>
                {totalAlertsInTactic > 0 && (
                  <span className="text-[9px] px-2 py-0.5 bg-rose-50 border border-rose-200 text-rose-700 font-bold rounded-md shadow-2xs">
                    {totalAlertsInTactic}
                  </span>
                )}
              </div>

              {/* Techniques List */}
              <div className="p-2.5 space-y-2 flex-1">
                {col.techniques.map((tech) => {
                  const techAlerts = getAlertsForTechnique(tech.relatedAttacks);
                  const isSelected = selectedTechnique === tech.id;
                  const hasAlerts = techAlerts.length > 0;

                  return (
                    <button
                      key={tech.id}
                      onClick={() => setSelectedTechnique(tech.id)}
                      className={`w-full text-left p-2.5 rounded-xl border text-[10px] transition-all duration-150 ${
                        isSelected
                          ? "bg-rose-50 border-rose-400 text-slate-900 font-bold shadow-xs"
                          : hasAlerts
                          ? "bg-rose-50/30 border-rose-200 text-slate-800 hover:border-rose-300"
                          : "bg-white border-slate-200 text-slate-600 hover:text-slate-900 hover:bg-slate-50"
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-[9px] text-slate-400 font-mono">{tech.code}</span>
                        {hasAlerts && (
                          <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
                        )}
                      </div>
                      <div className="font-bold text-slate-900 mt-1 leading-snug">
                        {tech.name}
                      </div>
                      <div className="mt-1.5 flex items-center justify-between text-[8px]">
                        <span className="text-slate-500 font-medium">{tech.relatedAttacks[0]}</span>
                        <span className={`font-bold ${hasAlerts ? "text-rose-600" : "text-slate-400"}`}>
                          {techAlerts.length} ALTS
                        </span>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>

      {/* Drill-down Detail Panel for Selected Technique */}
      {activeTechniqueObj && (
        <div className="glass-panel p-5 rounded-2xl border border-white/90 bg-white/85 space-y-4 shadow-xs">
          <div className="flex flex-wrap items-center justify-between border-b border-slate-200 pb-3 gap-2">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-rose-50 border border-rose-200 flex items-center justify-center shadow-xs">
                <ShieldAlert className="w-4 h-4 text-rose-600" />
              </div>
              <div>
                <h3 className="text-xs font-bold text-slate-900 tracking-wide">
                  TECHNIQUE: {activeTechniqueObj.name} ({activeTechniqueObj.code})
                </h3>
                <p className="text-[10px] text-slate-500 mt-0.5">
                  {activeTechniqueObj.description}
                </p>
              </div>
            </div>
            <div className="text-[10px] text-slate-600 bg-slate-100 px-3 py-1.5 rounded-lg border border-slate-200 font-bold">
              CORRELATED INCIDENTS: <span className="text-rose-600 font-bold">{matchedAlerts.length}</span>
            </div>
          </div>

          {/* Incidents Table for this technique */}
          <div className="overflow-x-auto rounded-xl border border-slate-200">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 text-slate-600 uppercase text-[9px] border-b border-slate-200 font-bold tracking-wider">
                <tr>
                  <th className="py-3 px-3.5">TIMESTAMP</th>
                  <th className="py-3 px-3.5">ALERT ID</th>
                  <th className="py-3 px-3.5">SEVERITY</th>
                  <th className="py-3 px-3.5">ATTACK VECTOR</th>
                  <th className="py-3 px-3.5">SOURCE IP:PORT</th>
                  <th className="py-3 px-3.5">TARGET IP:PORT</th>
                  <th className="py-3 px-3.5">STATUS</th>
                  <th className="py-3 px-3.5 text-right">ACTION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 bg-white/60">
                {matchedAlerts.length > 0 ? (
                  Array.from(
                    new Map(matchedAlerts.map((x) => [x.alert_id, x])).values()
                  )
                    .slice(0, 8)
                    .map((a, idx) => (
                      <tr
                        key={`${a.alert_id}-${idx}`}
                        className="hover:bg-blue-50/50 transition-colors cursor-pointer"
                        onClick={() => onSelectAlert(a)}
                      >
                        <td className="py-3 px-3.5 text-slate-500 text-[10px] whitespace-nowrap">
                          {a.timestamp.split("T")[1]?.slice(0, 8) || a.timestamp}
                        </td>
                        <td className="py-3 px-3.5 font-bold text-slate-800 whitespace-nowrap">{a.alert_id}</td>
                        <td className="py-3 px-3.5 whitespace-nowrap">
                          <span
                            className={`px-2.5 py-0.5 text-[9px] border font-bold rounded-md ${
                              a.severity === "CRITICAL"
                                ? "bg-rose-50 text-rose-700 border-rose-200"
                                : "bg-orange-50 text-orange-700 border-orange-200"
                            }`}
                          >
                            {a.severity}
                          </span>
                        </td>
                        <td className="py-3 px-3.5 text-slate-900 font-bold whitespace-nowrap">{a.classification}</td>
                        <td className="py-3 px-3.5 text-blue-600 font-bold whitespace-nowrap">{a.source_ip}:{a.source_port}</td>
                        <td className="py-3 px-3.5 text-slate-700 whitespace-nowrap">{a.destination_ip}:{a.destination_port}</td>
                        <td className="py-3 px-3.5 text-slate-600 text-[10px] whitespace-nowrap font-medium">{a.status}</td>
                        <td className="py-3 px-3.5 text-right whitespace-nowrap">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              onSelectAlert(a);
                            }}
                            className="px-3 py-1 text-[10px] bg-white hover:bg-blue-50 text-slate-700 hover:text-blue-700 border border-slate-200 rounded-lg transition font-bold shadow-2xs"
                          >
                            INSPECT
                          </button>
                        </td>
                      </tr>
                    ))
                ) : (
                  <tr>
                    <td colSpan={8} className="py-8 text-center text-slate-400 text-xs">
                      NO ACTIVE DETECTIONS CORRELATED TO {activeTechniqueObj.code} AT THIS TIME.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
