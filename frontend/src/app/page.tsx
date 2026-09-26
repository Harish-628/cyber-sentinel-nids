"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  fetchAlerts,
  fetchNetworkInterfaces,
  fetchOverviewMetrics,
  fetchSimulatorStatus,
  fetchTrafficHistory,
  fetchTrafficMode,
} from "@/lib/api";
import {
  NetworkInterface,
  OverviewMetrics,
  SecurityAlert,
  SimulatorStatus,
  TrafficModeInfo,
  TrafficPoint,
} from "@/lib/types";
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
  const [trafficMode, setTrafficMode] = useState<TrafficModeInfo | null>(null);
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null);
  const [isWsConnected, setIsWsConnected] = useState<boolean>(false);
  const [toastAlert, setToastAlert] = useState<SecurityAlert | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  // Sync state from REST API
  const refreshData = useCallback(async () => {
    try {
      const [m, a, th, sim, tm, ifaces] = await Promise.allSettled([
        fetchOverviewMetrics(),
        fetchAlerts(),
        fetchTrafficHistory(),
        fetchSimulatorStatus(),
        fetchTrafficMode(),
        fetchNetworkInterfaces(),
      ]);

      if (m.status === "fulfilled") setMetrics(m.value);
      if (tm.status === "fulfilled") setTrafficMode(tm.value);
      if (ifaces.status === "fulfilled") setInterfaces(ifaces.value?.interfaces || []);
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
          const payload = JSON.parse(event.data);
          if (payload.type === "INITIAL_STATE" || payload.type === "TELEMETRY_BATCH") {
            const data = payload.data;
            if (data.metrics) setMetrics(data.metrics);
            if (data.traffic_point) {
              setTrafficHistory((prev) => [...prev.slice(-59), data.traffic_point]);
            }
            if (data.alerts && Array.isArray(data.alerts)) {
              setAlerts((prev) => {
                const map = new Map<string, SecurityAlert>();
                for (const item of data.alerts) {
                  map.set(item.alert_id, item);
                }
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
          } else if (payload.type === "NEW_ALERT") {
            const newAlert: SecurityAlert = payload.alert;
            setAlerts((prev) => {
              if (prev.some((a) => a.alert_id === newAlert.alert_id)) return prev;
              return [newAlert, ...prev.slice(0, 499)];
            });
            if (newAlert.severity === "CRITICAL") {
              setToastAlert(newAlert);
              setTimeout(() => setToastAlert(null), 6000);
            }
          }
        } catch (err) {
          console.error("Failed to parse websocket message", err);
        }
      };

      socket.onclose = () => {
        setIsWsConnected(false);
      };

      socket.onerror = () => {
        setIsWsConnected(false);
      };
    } catch (e) {
      console.error("WebSocket connection failure", e);
    }

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  const activeAlertsCount = alerts.filter((a) => a.status === "NEW" || a.status === "INVESTIGATING").length;

  return (
    <div className="flex flex-col min-h-screen bg-transparent text-slate-800 font-mono-tech relative">
      {/* Toast Notification for incoming Critical Alert */}
      {toastAlert && (
        <div
          onClick={() => {
            setSelectedAlert(toastAlert);
            setCurrentTab("alerts");
            setToastAlert(null);
          }}
          className="fixed bottom-5 right-5 z-50 glass-panel border-rose-300 bg-white/95 shadow-2xl shadow-rose-950/15 p-4 rounded-xl cursor-pointer animate-bounce flex items-center gap-3.5 max-w-md border-l-4 border-l-rose-500"
        >
          <div className="w-3 h-3 rounded-full bg-rose-500 animate-ping" />
          <div>
            <div className="text-xs font-bold text-rose-700 uppercase tracking-wide">
              HIGH-IMPACT THREAT DETECTED: {toastAlert.classification}
            </div>
            <p className="text-[10px] text-slate-500 mt-0.5">
              {toastAlert.source_ip} -&gt; {toastAlert.destination_ip}:{toastAlert.destination_port} | Confidence: {(toastAlert.confidence_score * 100).toFixed(1)}%
            </p>
          </div>
        </div>
      )}

      {/* Top SOC Status Header */}
      <SOCHeader
        metrics={metrics}
        simulatorStatus={simulatorStatus}
        trafficMode={trafficMode}
        interfaces={interfaces}
        isWsConnected={isWsConnected}
        timeRange={timeRange}
        onTimeRangeChange={setTimeRange}
        onRefresh={refreshData}
        onAttackInjected={(type) => {
          refreshData();
        }}
        onModeChanged={() => {
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
        <main className="flex-1 p-4 overflow-y-auto max-h-[calc(100vh-3.5rem)]">
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
