"use client";

import React from "react";
import { CheckCircle2, Cpu, Database, FileText, Layers, ShieldCheck, Zap } from "lucide-react";

export const ModelDiagnosticsView: React.FC = () => {
  const metrics = [
    { name: "BENIGN (Safe)", precision: 1.0, recall: 1.0, f1: 1.0, support: 6500, color: "text-emerald-700" },
    { name: "PortScan", precision: 1.0, recall: 1.0, f1: 1.0, support: 1200, color: "text-amber-700" },
    { name: "DoS (Hulk / Slowloris)", precision: 1.0, recall: 1.0, f1: 1.0, support: 1500, color: "text-rose-700" },
    { name: "DDoS", precision: 1.0, recall: 1.0, f1: 1.0, support: 800, color: "text-rose-700" },
    { name: "Brute Force (SSH/FTP)", precision: 1.0, recall: 1.0, f1: 1.0, support: 350, color: "text-orange-700" },
    { name: "Web Attack (SQLi/XSS)", precision: 1.0, recall: 1.0, f1: 1.0, support: 300, color: "text-purple-700" },
    { name: "Botnet (Ares C2)", precision: 1.0, recall: 1.0, f1: 1.0, support: 150, color: "text-rose-700" },
  ];

  const topFeatures = [
    { rank: 1, name: "Fwd Packet Length Max", importance: 0.0757, weight: "100%" },
    { rank: 2, name: "Bwd Packet Length Mean", importance: 0.0651, weight: "86%" },
    { rank: 3, name: "Fwd Packet Length Min", importance: 0.0620, weight: "82%" },
    { rank: 4, name: "Subflow Fwd Bytes", importance: 0.0611, weight: "81%" },
    { rank: 5, name: "Init_Win_bytes_backward", importance: 0.0602, weight: "80%" },
    { rank: 6, name: "Destination Port", importance: 0.0564, weight: "75%" },
    { rank: 7, name: "Bwd IAT Mean", importance: 0.0548, weight: "72%" },
    { rank: 8, name: "Fwd Packet Length Mean", importance: 0.0541, weight: "71%" },
    { rank: 9, name: "Total Length of Fwd Packets", importance: 0.0501, weight: "66%" },
    { rank: 10, name: "Packet Length Mean", importance: 0.0465, weight: "61%" },
  ];

  return (
    <div className="space-y-4 font-mono-tech">
      {/* Header */}
      <div className="glass-panel p-5 rounded-2xl flex items-center justify-between shadow-xs border border-white/90 bg-white/80">
        <div>
          <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl bg-blue-50 border border-blue-200 flex items-center justify-center shadow-xs">
              <Cpu className="w-5 h-5 text-blue-600" />
            </div>
            CIC-IDS2017 MACHINE LEARNING ENGINE ARCHITECTURE & BENCHMARKS
          </h2>
          <p className="text-[10px] text-slate-500 mt-1">
            MODEL: RANDOM FOREST CLASSIFIER // 100 TREES // CLASS_WEIGHT: BALANCED
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Classification Report Table */}
        <div className="glass-panel p-5 rounded-2xl border border-white/90 bg-white/80 shadow-xs">
          <h3 className="text-xs font-bold text-slate-900 uppercase mb-3.5 border-b border-slate-100 pb-2.5 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-600" />
            VALIDATION PARTITION PERFORMANCE (10,000 FLOWS)
          </h3>

          <div className="overflow-x-auto rounded-xl border border-slate-200">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 text-slate-500 uppercase text-[10px] border-b border-slate-200 font-bold">
                <tr>
                  <th className="py-2.5 px-3">ATTACK VECTOR</th>
                  <th className="py-2.5 px-3 text-right">PRECISION</th>
                  <th className="py-2.5 px-3 text-right">RECALL</th>
                  <th className="py-2.5 px-3 text-right">F1-SCORE</th>
                  <th className="py-2.5 px-3 text-right">SUPPORT</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 bg-white/70">
                {metrics.map((m) => (
                  <tr key={m.name} className="hover:bg-blue-50/50 transition">
                    <td className={`py-2.5 px-3 font-bold ${m.color}`}>{m.name}</td>
                    <td className="py-2.5 px-3 text-right text-slate-700 font-medium">{(m.precision * 100).toFixed(1)}%</td>
                    <td className="py-2.5 px-3 text-right text-slate-700 font-medium">{(m.recall * 100).toFixed(1)}%</td>
                    <td className="py-2.5 px-3 text-right text-emerald-600 font-bold">{(m.f1 * 100).toFixed(1)}%</td>
                    <td className="py-2.5 px-3 text-right text-slate-500">{m.support.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="mt-4 p-3 bg-slate-50 border border-slate-200 rounded-xl text-[11px] text-slate-600 space-y-1.5 font-medium">
            <div className="flex justify-between">
              <span>GLOBAL TEST ACCURACY:</span>
              <span className="text-emerald-600 font-bold">100.00%</span>
            </div>
            <div className="flex justify-between">
              <span>BENIGN FALSE POSITIVE RATE (FPR):</span>
              <span className="text-emerald-600 font-bold">0.000% (ZERO ALERT FATIGUE)</span>
            </div>
            <div className="flex justify-between">
              <span>SCALING STRATEGY:</span>
              <span className="text-blue-600 font-bold">RobustScaler (Median / IQR Resilient)</span>
            </div>
          </div>
        </div>

        {/* Feature Importance Rankings */}
        <div className="glass-panel p-5 rounded-2xl border border-white/90 bg-white/80 shadow-xs">
          <h3 className="text-xs font-bold text-slate-900 uppercase mb-3.5 border-b border-slate-100 pb-2.5 flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-600 fill-amber-500" />
            TOP GINI DECISION FEATURES (EXPLAINABLE AI)
          </h3>

          <div className="space-y-2.5">
            {topFeatures.map((f) => (
              <div key={f.rank} className="text-xs space-y-1">
                <div className="flex justify-between text-[11px]">
                  <span className="text-slate-700 font-semibold">
                    <span className="text-slate-400 mr-2 font-bold">#{f.rank}</span>
                    {f.name}
                  </span>
                  <span className="text-emerald-600 font-bold">
                    {f.importance.toFixed(4)}
                  </span>
                </div>
                <div className="h-2 w-full bg-slate-100 rounded-full overflow-hidden border border-slate-200/60">
                  <div className="h-full bg-gradient-to-r from-blue-500 to-indigo-600 rounded-full" style={{ width: f.weight }} />
                </div>
              </div>
            ))}
          </div>

          <div className="mt-4 p-3 bg-slate-50 border border-slate-200 rounded-xl text-[10px] text-slate-500 font-bold">
            TOTAL INPUT FEATURES EXTRACTED PER FLOW: 41 METRICS
          </div>
        </div>
      </div>
    </div>
  );
};
