"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  fetchAlerts,
  fetchOverviewMetrics,
  fetchSimulatorStatus,
  fetchTrafficHistory,
} from "@/lib/api";
import { OverviewMetrics, SecurityAlert, SimulatorStatus, TrafficPoint } from "@/lib/types";
import { AlertsFeedView } from "@/components/AlertsFeedView";
import { FlowTesterView } from "@/components/FlowTesterView";
import { MitreMatrixView } from "@/components/MitreMatrixView";
import { ModelDiagnosticsView } from "@/components/ModelDiagnosticsView";
import { OverviewView } from "@/components/OverviewView";
import { Sidebar } from "@/components/Sidebar";
import { SOCHeader } from "@/components/SOCHeader";
import { TrafficAnalysisView } from "@/components/TrafficAnalysisView";

export default function Home() {
  const [currentTab, setCurrentTab] = useState<string>("overview");
  const [timeRange, setTimeRange] = useState<string>("LIVE");
  const [metrics, setMetrics] = useState<OverviewMetrics | null>(null);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [trafficHistory, setTrafficHistory] = useState<TrafficPoint[]>([]);
  const [simulatorStatus, setSimulatorStatus] = useState<SimulatorStatus | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null);
  const [isWsConnected, setIsWsConnected] = useState<boolean>(false);
  const [toastAlert, setToastAlert] = useState<SecurityAlert | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  // Sync state from REST API
  const refreshData = useCallback(async () => {
    try {
      const [m, a, th, sim] = await Promise.allSettled([
        fetchOverviewMetrics(),
        fetchAlerts(),
        fetchTrafficHistory(),
        fetchSimulatorStatus(),
      ]);

      if (m.status === "fulfilled") setMetrics(m.value);
      if (a.status === "fulfilled") {
        setAlerts((prev) => {
          const map = new Map<string, SecurityAlert>();
          // Index API alerts first
          for (const item of a.value) {
            map.set(item.alert_id, item);
          }
          // Merge in any alerts currently in state that might not be in API response yet
          for (const item of prev) {
            if (!map.has(item.alert_id)) {
              map.set(item.alert_id, item);
            }
          }
          return Array.from(map.values())
            .sort((x, y) => new Date(y.timestamp).getTime() - new Date(x.timestamp).getTime())
            .slice(0, 500);
        });
      }
      if (th.status === "fulfilled") setTrafficHistory(th.value);
      if (sim.status === "fulfilled") setSimulatorStatus(sim.value);
    } catch (e) {
      console.error("Failed to sync SOC data", e);
    }
  }, []);

  // Initial load + periodic polling fallback
  useEffect(() => {
    refreshData();
    const interval = setInterval(refreshData, 2000);
    return () => clearInterval(interval);
  }, [refreshData]);

  // WebSocket Live Streaming connection
  useEffect(() => {
    const wsUrl = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000/api/v1/stream/live";
    let socket: WebSocket;

    try {
      socket = new WebSocket(wsUrl);
      wsRef.current = socket;

      socket.onopen = () => {
        setIsWsConnected(true);
      };

      socket.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === "NEW_ALERT") {
            const newAlert: SecurityAlert = msg.data;
            setAlerts((prev) => {
              const filtered = prev.filter((a) => a.alert_id !== newAlert.alert_id);
              return [newAlert, ...filtered.slice(0, 499)];
            });
            // Show toast for critical/high alerts
            if (newAlert.severity === "CRITICAL" || newAlert.severity === "HIGH") {
              setToastAlert(newAlert);
              setTimeout(() => setToastAlert(null), 4000);
            }
            // Update metrics directly without full alert collision race
            fetchOverviewMetrics().then(setMetrics).catch(() => {});
          } else if (msg.type === "ALERT_UPDATED") {
            const updated: SecurityAlert = msg.data;
            setAlerts((prev) =>
              prev.map((a) => (a.alert_id === updated.alert_id ? updated : a))
            );
          }
        } catch (err) {
          console.error("Error processing websocket message", err);
        }
      };

      socket.onclose = () => {
        setIsWsConnected(false);
      };

      socket.onerror = () => {
        setIsWsConnected(false);
      };
    } catch (e) {
      setIsWsConnected(false);
    }

    return () => {
      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.close();
      }
    };
  }, [refreshData]);

  const activeAlertsCount = metrics?.active_alerts ?? 0;

  return (
    <div className="flex flex-col min-h-screen bg-[#07080c] text-zinc-300 font-mono-tech relative">
      {/* Toast Notification for incoming Critical Alert */}
      {toastAlert && (
        <div
          onClick={() => {
            setSelectedAlert(toastAlert);
            setCurrentTab("alerts");
            setToastAlert(null);
          }}
          className="fixed bottom-4 right-4 z-50 bg-[#160c10] border border-red-700/90 shadow-2xl shadow-red-950 p-3 rounded-[2px] cursor-pointer animate-bounce flex items-center gap-3 max-w-md"
        >
          <div className="w-2.5 h-2.5 rounded-full bg-red-500 animate-ping" />
          <div>
            <div className="text-xs font-bold text-red-300 uppercase">
              HIGH-IMPACT THREAT DETECTED: {toastAlert.classification}
            </div>
            <p className="text-[10px] text-zinc-400">
              {toastAlert.source_ip} -&gt; {toastAlert.destination_ip}:{toastAlert.destination_port} | Confidence: {(toastAlert.confidence_score * 100).toFixed(1)}%
            </p>
          </div>
        </div>
      )}

      {/* Top SOC Status Header */}
      <SOCHeader
        metrics={metrics}
        simulatorStatus={simulatorStatus}
        isWsConnected={isWsConnected}
        timeRange={timeRange}
        onTimeRangeChange={setTimeRange}
        onRefresh={refreshData}
        onAttackInjected={(type) => {
          refreshData();
        }}
      />

      {/* Main Body */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left Navigation Sidebar */}
        <Sidebar
          currentTab={currentTab}
          onTabChange={setCurrentTab}
          activeAlertCount={activeAlertsCount}
        />

        {/* Center Content View Area */}
        <main className="flex-1 p-3.5 overflow-y-auto max-h-[calc(100vh-3.25rem)]">
          {currentTab === "overview" && (
            <OverviewView
              metrics={metrics}
              trafficHistory={trafficHistory}
              recentAlerts={alerts}
              onSelectAlert={(a) => {
                setSelectedAlert(a);
                setCurrentTab("alerts");
              }}
              onNavigateToAlerts={() => setCurrentTab("alerts")}
              onNavigateToMitre={() => setCurrentTab("mitre")}
            />
          )}

          {currentTab === "alerts" && (
            <AlertsFeedView
              alerts={alerts}
              selectedAlert={selectedAlert}
              onSelectAlert={setSelectedAlert}
              onAlertStatusUpdated={refreshData}
            />
          )}

          {currentTab === "mitre" && (
            <MitreMatrixView
              alerts={alerts}
              onSelectAlert={(a) => {
                setSelectedAlert(a);
                setCurrentTab("alerts");
              }}
            />
          )}

          {currentTab === "traffic" && <TrafficAnalysisView />}

          {currentTab === "tester" && <FlowTesterView />}

          {currentTab === "model" && <ModelDiagnosticsView />}
        </main>
      </div>
    </div>
  );
}
