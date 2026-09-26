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
      {/* Top Banner - Glassmorphic */}
      <div className="glass-panel p-4 rounded-xl flex flex-wrap items-center justify-between gap-3 shadow-xl border border-white/10">
        <div>
          <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-red-500/20 border border-red-500/40 shadow-[0_0_12px_rgba(239,68,68,0.3)] flex items-center justify-center">
              <Grid className="w-4 h-4 text-red-400" />
            </div>
            MITRE ATT&CK® ENTERPRISE THREAT MATRIX // NETWORK KILL-CHAIN
          </h2>
          <p className="text-[10px] text-zinc-400 mt-1">
            LIVE DETECTION TELEMETRY CORRELATED AGAINST MITRE ATT&CK v15 TACTICS & TECHNIQUES
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span className="text-[10px] text-zinc-400 uppercase tracking-wider">COVERAGE:</span>
          <span className="px-3 py-1 bg-red-500/20 border border-red-500/40 text-red-300 text-[10px] font-bold rounded-lg shadow-[0_0_12px_rgba(239,68,68,0.25)]">
            6 TACTICS ACTIVE
          </span>
        </div>
      </div>

      {/* MITRE Matrix Columns Grid - Glassmorphic */}
      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {matrixColumns.map((col) => {
          const totalAlertsInTactic = col.techniques.reduce((acc, t) => {
            return acc + getAlertsForTechnique(t.relatedAttacks).length;
          }, 0);

          return (
            <div key={col.id} className="glass-panel rounded-xl overflow-hidden flex flex-col border border-white/10 shadow-lg">
              {/* Tactic Header */}
              <div className="bg-[#0b1020]/90 backdrop-blur-md border-b border-white/10 p-2.5 flex items-center justify-between">
                <div>
                  <h4 className="text-[10px] font-bold text-zinc-100 tracking-wider">
                    {col.name}
                  </h4>
                  <span className="text-[8px] text-cyan-400/80 font-mono">{col.code}</span>
                </div>
                {totalAlertsInTactic > 0 && (
                  <span className="text-[9px] px-2 py-0.5 bg-red-500/20 border border-red-500/40 text-red-300 font-bold rounded-md shadow-[0_0_8px_rgba(239,68,68,0.3)]">
                    {totalAlertsInTactic}
                  </span>
                )}
              </div>

              {/* Techniques List */}
              <div className="p-2 space-y-2 flex-1">
                {col.techniques.map((tech) => {
                  const techAlerts = getAlertsForTechnique(tech.relatedAttacks);
                  const isSelected = selectedTechnique === tech.id;
                  const hasAlerts = techAlerts.length > 0;

                  return (
                    <button
                      key={tech.id}
                      onClick={() => setSelectedTechnique(tech.id)}
                      className={`w-full text-left p-2.5 rounded-lg border text-[10px] transition-all duration-200 ${
                        isSelected
                          ? "bg-gradient-to-r from-red-500/25 to-red-950/40 border-red-500 text-white font-bold shadow-[0_0_15px_rgba(239,68,68,0.25)]"
                          : hasAlerts
                          ? "bg-[#18111e]/80 border-red-500/30 text-zinc-100 hover:border-red-500/50 hover:bg-[#201428]/90"
                          : "glass-panel-interactive border-white/5 text-zinc-400 hover:text-zinc-200 hover:bg-white/5"
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-[9px] text-cyan-400/70 font-mono">{tech.code}</span>
                        {hasAlerts && (
                          <span className="w-2 h-2 rounded-full bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.8)] animate-pulse" />
                        )}
                      </div>
                      <div className="font-semibold text-zinc-100 mt-1 leading-snug">
                        {tech.name}
                      </div>
                      <div className="mt-1.5 flex items-center justify-between text-[8px] text-zinc-400">
                        <span>{tech.relatedAttacks[0]}</span>
                        <span className={`font-bold ${hasAlerts ? "text-red-400" : "text-zinc-500"}`}>
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

      {/* Drill-down Detail Panel for Selected Technique - Glassmorphic */}
      {activeTechniqueObj && (
        <div className="glass-panel p-5 rounded-xl border border-white/10 space-y-4 shadow-2xl">
          <div className="flex flex-wrap items-center justify-between border-b border-white/10 pb-3 gap-2">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-red-500/20 border border-red-500/40 shadow-[0_0_10px_rgba(239,68,68,0.3)] flex items-center justify-center">
                <ShieldAlert className="w-4 h-4 text-red-400" />
              </div>
              <div>
                <h3 className="text-xs font-bold text-white tracking-wide">
                  TECHNIQUE: {activeTechniqueObj.name} ({activeTechniqueObj.code})
                </h3>
                <p className="text-[10px] text-zinc-400 mt-0.5">
                  {activeTechniqueObj.description}
                </p>
              </div>
            </div>
            <div className="text-[10px] text-zinc-400 bg-white/5 px-3 py-1 rounded-md border border-white/10">
              CORRELATED INCIDENTS: <span className="text-red-400 font-bold">{matchedAlerts.length}</span>
            </div>
          </div>

          {/* Incidents Table for this technique */}
          <div className="overflow-x-auto rounded-lg border border-white/10">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#090e1c]/90 backdrop-blur-md text-cyan-300/80 uppercase text-[9px] border-b border-white/10 font-bold tracking-wider">
                <tr>
                  <th className="py-2.5 px-3">TIMESTAMP</th>
                  <th className="py-2.5 px-3">ALERT ID</th>
                  <th className="py-2.5 px-3">SEVERITY</th>
                  <th className="py-2.5 px-3">ATTACK VECTOR</th>
                  <th className="py-2.5 px-3">SOURCE IP:PORT</th>
                  <th className="py-2.5 px-3">TARGET IP:PORT</th>
                  <th className="py-2.5 px-3">STATUS</th>
                  <th className="py-2.5 px-3 text-right">ACTION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.04]">
                {matchedAlerts.length > 0 ? (
                  Array.from(
                    new Map(matchedAlerts.map((x) => [x.alert_id, x])).values()
                  )
                    .slice(0, 8)
                    .map((a, idx) => (
                      <tr
                        key={`${a.alert_id}-${idx}`}
                        className="hover:bg-cyan-500/[0.04] transition-all duration-150 cursor-pointer"
                        onClick={() => onSelectAlert(a)}
                      >
                        <td className="py-2.5 px-3 text-zinc-400 text-[10px] whitespace-nowrap">
                          {a.timestamp.split("T")[1]?.slice(0, 8) || a.timestamp}
                        </td>
                        <td className="py-2.5 px-3 font-bold text-zinc-200 whitespace-nowrap">{a.alert_id}</td>
                        <td className="py-2.5 px-3 whitespace-nowrap">
                          <span
                            className={`px-2 py-0.5 text-[9px] border font-bold rounded-md ${
                              a.severity === "CRITICAL"
                                ? "bg-red-500/20 text-red-300 border-red-500/40 shadow-[0_0_10px_rgba(239,68,68,0.2)]"
                                : "bg-orange-500/20 text-orange-300 border-orange-500/40 shadow-[0_0_10px_rgba(249,115,22,0.2)]"
                            }`}
                          >
                            {a.severity}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-white font-semibold whitespace-nowrap">{a.classification}</td>
                        <td className="py-2.5 px-3 text-cyan-400 whitespace-nowrap">{a.source_ip}:{a.source_port}</td>
                        <td className="py-2.5 px-3 text-zinc-300 whitespace-nowrap">{a.destination_ip}:{a.destination_port}</td>
                        <td className="py-2.5 px-3 text-zinc-400 text-[10px] whitespace-nowrap">{a.status}</td>
                        <td className="py-2.5 px-3 text-right whitespace-nowrap">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              onSelectAlert(a);
                            }}
                            className="px-2.5 py-1 text-[9px] bg-white/5 hover:bg-cyan-500/20 hover:text-cyan-300 hover:border-cyan-500/40 text-zinc-200 border border-white/10 rounded-md transition font-semibold"
                          >
                            INSPECT
                          </button>
                        </td>
                      </tr>
                    ))
                ) : (
                  <tr>
                    <td colSpan={8} className="py-8 text-center text-zinc-500 text-xs">
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
