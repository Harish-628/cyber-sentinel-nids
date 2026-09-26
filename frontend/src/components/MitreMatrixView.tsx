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
      {/* Top Banner */}
      <div className="bg-[#0d0f17] border border-[#1a1e2e] p-3.5 rounded-[2px] flex items-center justify-between">
        <div>
          <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <Grid className="w-4 h-4 text-red-500" />
            MITRE ATT&CK® ENTERPRISE THREAT MATRIX // NETWORK KILL-CHAIN
          </h2>
          <p className="text-[10px] text-zinc-400 mt-0.5">
            LIVE DETECTION TELEMETRY CORRELATED AGAINST MITRE ATT&CK v15 TACTICS & TECHNIQUES
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span className="text-[10px] text-zinc-500">COVERAGE:</span>
          <span className="px-2 py-0.5 bg-red-950/60 border border-red-800 text-red-300 text-[10px] font-bold rounded-[2px]">
            7 TACTICS ACTIVE
          </span>
        </div>
      </div>

      {/* MITRE Matrix Columns Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-2">
        {matrixColumns.map((col) => {
          const totalAlertsInTactic = col.techniques.reduce((acc, t) => {
            return acc + getAlertsForTechnique(t.relatedAttacks).length;
          }, 0);

          return (
            <div key={col.id} className="bg-[#0d0f17] border border-[#1a1e2e] rounded-[2px] overflow-hidden flex flex-col">
              {/* Tactic Header */}
              <div className="bg-[#121624] border-b border-[#1a1e2e] p-2 flex items-center justify-between">
                <div>
                  <h4 className="text-[10px] font-bold text-zinc-200 tracking-wider">
                    {col.name}
                  </h4>
                  <span className="text-[8px] text-zinc-500">{col.code}</span>
                </div>
                {totalAlertsInTactic > 0 && (
                  <span className="text-[9px] px-1.5 py-0.2 bg-red-950 border border-red-700 text-red-300 font-bold rounded-[2px]">
                    {totalAlertsInTactic}
                  </span>
                )}
              </div>

              {/* Techniques List */}
              <div className="p-1.5 space-y-1.5 flex-1">
                {col.techniques.map((tech) => {
                  const techAlerts = getAlertsForTechnique(tech.relatedAttacks);
                  const isSelected = selectedTechnique === tech.id;
                  const hasAlerts = techAlerts.length > 0;

                  return (
                    <button
                      key={tech.id}
                      onClick={() => setSelectedTechnique(tech.id)}
                      className={`w-full text-left p-2 rounded-[2px] border text-[10px] transition ${
                        isSelected
                          ? "bg-[#181d2f] border-red-500 text-white font-bold"
                          : hasAlerts
                          ? "bg-[#14121a] border-red-900/60 text-zinc-200 hover:bg-[#1c1825]"
                          : "bg-[#090a0f] border-[#1a1e2e] text-zinc-500 hover:text-zinc-300 hover:bg-[#10131d]"
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-[9px] text-zinc-400">{tech.code}</span>
                        {hasAlerts && (
                          <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-ping" />
                        )}
                      </div>
                      <div className="font-semibold text-zinc-100 mt-0.5 leading-snug">
                        {tech.name}
                      </div>
                      <div className="mt-1 flex items-center justify-between text-[8px] text-zinc-500">
                        <span>{tech.relatedAttacks[0]}</span>
                        <span className="text-red-400 font-bold">{techAlerts.length} ALTS</span>
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
        <div className="bg-[#0d0f17] border border-[#1a1e2e] p-4 rounded-[2px] space-y-3">
          <div className="flex items-center justify-between border-b border-[#1a1e2e] pb-2">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-500" />
              <div>
                <h3 className="text-xs font-bold text-white">
                  TECHNIQUE: {activeTechniqueObj.name} ({activeTechniqueObj.code})
                </h3>
                <p className="text-[10px] text-zinc-400">
                  {activeTechniqueObj.description}
                </p>
              </div>
            </div>
            <div className="text-[10px] text-zinc-400">
              CORRELATED INCIDENTS: <span className="text-red-400 font-bold">{matchedAlerts.length}</span>
            </div>
          </div>

          {/* Incidents Table for this technique */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#090b10] text-zinc-500 uppercase text-[9px] border-b border-[#1a1e2e]">
                <tr>
                  <th className="py-2 px-2.5">TIMESTAMP</th>
                  <th className="py-2 px-2.5">ALERT ID</th>
                  <th className="py-2 px-2.5">SEVERITY</th>
                  <th className="py-2 px-2.5">ATTACK VECTOR</th>
                  <th className="py-2 px-2.5">SOURCE IP:PORT</th>
                  <th className="py-2 px-2.5">TARGET IP:PORT</th>
                  <th className="py-2 px-2.5">STATUS</th>
                  <th className="py-2 px-2.5 text-right">ACTION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#181c2b]">
                {matchedAlerts.length > 0 ? (
                  Array.from(
                    new Map(matchedAlerts.map((x) => [x.alert_id, x])).values()
                  )
                    .slice(0, 6)
                    .map((a, idx) => (
                      <tr key={`${a.alert_id}-${idx}`} className="hover:bg-[#121625] transition cursor-pointer" onClick={() => onSelectAlert(a)}>
                      <td className="py-2 px-2.5 text-zinc-400 text-[10px]">
                        {a.timestamp.split("T")[1]?.slice(0, 8) || a.timestamp}
                      </td>
                      <td className="py-2 px-2.5 font-bold text-zinc-300">{a.alert_id}</td>
                      <td className="py-2 px-2.5">
                        <span className={`px-1.5 py-0.2 text-[9px] border font-bold rounded-[2px] ${
                          a.severity === "CRITICAL" ? "bg-red-950 text-red-300 border-red-700" : "bg-orange-950 text-orange-300 border-orange-700"
                        }`}>
                          {a.severity}
                        </span>
                      </td>
                      <td className="py-2 px-2.5 text-white font-semibold">{a.classification}</td>
                      <td className="py-2 px-2.5 text-cyan-400">{a.source_ip}:{a.source_port}</td>
                      <td className="py-2 px-2.5 text-zinc-300">{a.destination_ip}:{a.destination_port}</td>
                      <td className="py-2 px-2.5 text-zinc-400 text-[10px]">{a.status}</td>
                      <td className="py-2 px-2.5 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectAlert(a);
                          }}
                          className="px-2 py-0.5 text-[9px] bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 rounded-[2px]"
                        >
                          INSPECT
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={8} className="py-6 text-center text-zinc-600 text-xs">
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
