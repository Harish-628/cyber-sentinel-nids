#!/usr/bin/env python3
"""
CYBER SENTINEL // Real-Time Physical Network Packet Sniffer.

Captures raw packets from the host network adapter (e.g., wlp44s0, eth0, or any active interface),
assembles bidirectional 5-tuple TCP/UDP/IP flows, computes the 41 statistical CIC-IDS2017 features,
and feeds them to the Cyber Sentinel NIDS FastAPI Engine for sub-millisecond AI classification.

Usage:
    sudo .venv/bin/python scripts/live_sniffer.py --interface wlp44s0
    sudo .venv/bin/python scripts/live_sniffer.py --auto
"""

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
import urllib.request
import numpy as np

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from scapy.all import (
        IP,
        IPv6,
        TCP,
        UDP,
        ICMP,
        Packet,
        conf,
        get_if_list,
        sniff,
    )
except ImportError:
    print("[!] Scapy is required for real packet sniffing. Run: uv pip install scapy")
    sys.exit(1)


@dataclass
class FlowRecord:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    last_time: float
    fwd_pkt_lens: List[int] = field(default_factory=list)
    bwd_pkt_lens: List[int] = field(default_factory=list)
    fwd_timestamps: List[float] = field(default_factory=list)
    bwd_timestamps: List[float] = field(default_factory=list)
    all_timestamps: List[float] = field(default_factory=list)
    fwd_header_len: int = 0
    bwd_header_len: int = 0
    syn_count: int = 0
    ack_count: int = 0
    psh_count: int = 0
    urg_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    init_win_fwd: int = 0
    init_win_bwd: int = 0
    act_data_fwd: int = 0
    has_seen_fin: bool = False
    has_seen_rst: bool = False

    def add_packet(self, pkt: Packet, is_forward: bool, ts: float):
        self.last_time = ts
        self.all_timestamps.append(ts)
        pkt_len = len(pkt)

        if is_forward:
            self.fwd_pkt_lens.append(pkt_len)
            self.fwd_timestamps.append(ts)
            if IP in pkt:
                self.fwd_header_len += int(pkt[IP].ihl * 4) if hasattr(pkt[IP], 'ihl') else 20
            if TCP in pkt:
                self.fwd_header_len += int(pkt[TCP].dataofs * 4) if hasattr(pkt[TCP], 'dataofs') else 20
                if self.init_win_fwd == 0:
                    self.init_win_fwd = int(pkt[TCP].window)
                if len(pkt[TCP].payload) > 0:
                    self.act_data_fwd += 1
        else:
            self.bwd_pkt_lens.append(pkt_len)
            self.bwd_timestamps.append(ts)
            if IP in pkt:
                self.bwd_header_len += int(pkt[IP].ihl * 4) if hasattr(pkt[IP], 'ihl') else 20
            if TCP in pkt:
                self.bwd_header_len += int(pkt[TCP].dataofs * 4) if hasattr(pkt[TCP], 'dataofs') else 20
                if self.init_win_bwd == 0:
                    self.init_win_bwd = int(pkt[TCP].window)

        if TCP in pkt:
            flags = pkt[TCP].flags
            if flags & 0x02:  # SYN
                self.syn_count += 1
            if flags & 0x10:  # ACK
                self.ack_count += 1
            if flags & 0x08:  # PSH
                self.psh_count += 1
            if flags & 0x20:  # URG
                self.urg_count += 1
            if flags & 0x01:  # FIN
                self.fin_count += 1
                self.has_seen_fin = True
            if flags & 0x04:  # RST
                self.rst_count += 1
                self.has_seen_rst = True

    def to_nids_payload(self) -> dict:
        """Calculate the 41 statistical CIC-IDS2017 features and format for NIDS API."""
        duration_sec = max(0.0001, self.last_time - self.start_time)
        duration_us = duration_sec * 1_000_000.0

        tot_fwd_pkts = len(self.fwd_pkt_lens)
        tot_bwd_pkts = len(self.bwd_pkt_lens)
        tot_pkts = tot_fwd_pkts + tot_bwd_pkts

        tot_len_fwd = sum(self.fwd_pkt_lens)
        tot_len_bwd = sum(self.bwd_pkt_lens)
        tot_bytes = tot_len_fwd + tot_len_bwd

        fwd_lens = np.array(self.fwd_pkt_lens) if self.fwd_pkt_lens else np.array([0.0])
        bwd_lens = np.array(self.bwd_pkt_lens) if self.bwd_pkt_lens else np.array([0.0])
        all_lens = np.array(self.fwd_pkt_lens + self.bwd_pkt_lens) if tot_pkts > 0 else np.array([0.0])

        # Inter-arrival times (in microseconds)
        def calc_iats(ts_list: List[float]) -> np.ndarray:
            if len(ts_list) <= 1:
                return np.array([0.0])
            diffs = np.diff(ts_list) * 1_000_000.0
            return diffs

        flow_iats = calc_iats(self.all_timestamps)
        fwd_iats = calc_iats(self.fwd_timestamps)
        bwd_iats = calc_iats(self.bwd_timestamps)

        payload = {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "timestamp": datetime.fromtimestamp(self.start_time, tz=timezone.utc).isoformat(),
            "flow_duration": float(duration_us),
            "tot_fwd_pkts": int(tot_fwd_pkts),
            "tot_bwd_pkts": int(tot_bwd_pkts),
            "tot_len_fwd_pkts": float(tot_len_fwd),
            "tot_len_bwd_pkts": float(tot_len_bwd),
            "fwd_pkt_len_max": float(np.max(fwd_lens)),
            "fwd_pkt_len_min": float(np.min(fwd_lens)),
            "fwd_pkt_len_mean": float(np.mean(fwd_lens)),
            "bwd_pkt_len_max": float(np.max(bwd_lens)),
            "bwd_pkt_len_min": float(np.min(bwd_lens)),
            "bwd_pkt_len_mean": float(np.mean(bwd_lens)),
            "flow_bytes_s": float(tot_bytes / duration_sec),
            "flow_pkts_s": float(tot_pkts / duration_sec),
            "flow_iat_mean": float(np.mean(flow_iats)),
            "flow_iat_std": float(np.std(flow_iats)),
            "flow_iat_max": float(np.max(flow_iats)),
            "fwd_iat_mean": float(np.mean(fwd_iats)),
            "bwd_iat_mean": float(np.mean(bwd_iats)),
            "fwd_header_len": int(self.fwd_header_len),
            "bwd_header_len": int(self.bwd_header_len),
            "fwd_pkts_s": float(tot_fwd_pkts / duration_sec),
            "bwd_pkts_s": float(tot_bwd_pkts / duration_sec),
            "pkt_len_mean": float(np.mean(all_lens)),
            "pkt_len_std": float(np.std(all_lens)),
            "pkt_len_var": float(np.var(all_lens)),
            "syn_flag_count": int(self.syn_count),
            "psh_flag_count": int(self.psh_count),
            "ack_flag_count": int(self.ack_count),
            "urg_flag_count": int(self.urg_count),
            "avg_pkt_size": float(tot_bytes / max(1, tot_pkts)),
            "subflow_fwd_pkts": int(tot_fwd_pkts),
            "subflow_fwd_bytes": float(tot_len_fwd),
            "subflow_bwd_pkts": int(tot_bwd_pkts),
            "subflow_bwd_bytes": float(tot_len_bwd),
            "init_win_bytes_forward": int(self.init_win_fwd),
            "init_win_bytes_backward": int(self.init_win_bwd),
            "act_data_pkt_fwd": int(self.act_data_fwd),
            "min_seg_size_forward": 20.0,
            "active_mean": 0.0,
            "idle_mean": 0.0,
            "raw_features": {
                "Destination Port": float(self.dst_port),
                "Flow Duration": float(duration_us),
                "Total Fwd Packets": float(tot_fwd_pkts),
                "Total Backward Packets": float(tot_bwd_pkts),
                "Total Length of Fwd Packets": float(tot_len_fwd),
                "Total Length of Bwd Packets": float(tot_len_bwd),
                "Fwd Packet Length Max": float(np.max(fwd_lens)),
                "Fwd Packet Length Min": float(np.min(fwd_lens)),
                "Fwd Packet Length Mean": float(np.mean(fwd_lens)),
                "Bwd Packet Length Max": float(np.max(bwd_lens)),
                "Bwd Packet Length Min": float(np.min(bwd_lens)),
                "Bwd Packet Length Mean": float(np.mean(bwd_lens)),
                "Flow Bytes/s": float(tot_bytes / duration_sec),
                "Flow Packets/s": float(tot_pkts / duration_sec),
                "Flow IAT Mean": float(np.mean(flow_iats)),
                "Flow IAT Std": float(np.std(flow_iats)),
                "Flow IAT Max": float(np.max(flow_iats)),
                "Fwd IAT Mean": float(np.mean(fwd_iats)),
                "Bwd IAT Mean": float(np.mean(bwd_iats)),
                "Fwd Header Length": float(self.fwd_header_len),
                "Bwd Header Length": float(self.bwd_header_len),
                "Fwd Packets/s": float(tot_fwd_pkts / duration_sec),
                "Bwd Packets/s": float(tot_bwd_pkts / duration_sec),
                "Packet Length Mean": float(np.mean(all_lens)),
                "Packet Length Std": float(np.std(all_lens)),
                "Packet Length Variance": float(np.var(all_lens)),
                "SYN Flag Count": float(self.syn_count),
                "PSH Flag Count": float(self.psh_count),
                "ACK Flag Count": float(self.ack_count),
                "URG Flag Count": float(self.urg_count),
                "Average Packet Size": float(tot_bytes / max(1, tot_pkts)),
                "Subflow Fwd Packets": float(tot_fwd_pkts),
                "Subflow Fwd Bytes": float(tot_len_fwd),
                "Subflow Bwd Packets": float(tot_bwd_pkts),
                "Subflow Bwd Bytes": float(tot_len_bwd),
                "Init_Win_bytes_forward": float(self.init_win_fwd),
                "Init_Win_bytes_backward": float(self.init_win_bwd),
                "act_data_pkt_fwd": float(self.act_data_fwd),
                "min_seg_size_forward": 20.0,
                "Active Mean": 0.0,
                "Idle Mean": 0.0,
            },
        }
        return payload


class LiveNetworkSniffer:
    """Manages raw socket sniffing, flow aggregation, and API posting."""

    def __init__(
        self,
        interface: Optional[str] = None,
        api_url: str = "http://localhost:8000/api/v1/flows/analyze",
        flow_idle_timeout: float = 2.0,
        flow_max_duration: float = 12.0,
    ):
        self.interface = interface or self._detect_best_interface()
        self.api_url = api_url
        self.flow_idle_timeout = flow_idle_timeout
        self.flow_max_duration = flow_max_duration
        self.active_flows: Dict[Tuple, FlowRecord] = {}
        self.total_packets_captured: int = 0
        self.total_flows_exported: int = 0
        self.total_threats_detected: int = 0
        self.start_time = time.time()

    def _detect_best_interface(self) -> str:
        """Detect the most active network interface (e.g. wlp44s0, eth0, or scapy default)."""
        all_ifaces = get_if_list()
        # Prefer wireless adapters
        for iface in all_ifaces:
            if iface.startswith(("wlp", "wlan", "wifi")):
                return iface
        # Prefer ethernet
        for iface in all_ifaces:
            if iface.startswith(("enp", "eth")):
                return iface
        return conf.iface

    def _get_flow_key(self, pkt: Packet) -> Optional[Tuple[Tuple, bool]]:
        """Extract canonical 5-tuple and determine direction."""
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
        elif IPv6 in pkt:
            src = pkt[IPv6].src
            dst = pkt[IPv6].dst
        else:
            return None

        proto = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else ("ICMP" if ICMP in pkt else "OTHER"))

        src_port = 0
        dst_port = 0
        if TCP in pkt:
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
        elif UDP in pkt:
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)

        # Canonical key: smaller (ip, port) is primary
        forward_tuple = (src, dst, src_port, dst_port, proto)
        backward_tuple = (dst, src, dst_port, src_port, proto)

        if forward_tuple in self.active_flows:
            return forward_tuple, True
        elif backward_tuple in self.active_flows:
            return backward_tuple, False
        else:
            # New flow: canonicalize
            if (src, src_port) <= (dst, dst_port):
                return forward_tuple, True
            else:
                return backward_tuple, False

    def handle_packet(self, pkt: Packet):
        """Callback executed for each intercepted raw packet."""
        self.total_packets_captured += 1
        now = time.time()

        key_info = self._get_flow_key(pkt)
        if not key_info:
            return

        flow_key, is_forward = key_info

        if flow_key not in self.active_flows:
            src_ip, dst_ip, src_port, dst_port, proto = flow_key
            self.active_flows[flow_key] = FlowRecord(
                src_ip=src_ip if is_forward else dst_ip,
                dst_ip=dst_ip if is_forward else src_ip,
                src_port=src_port if is_forward else dst_port,
                dst_port=dst_port if is_forward else src_port,
                protocol=proto,
                start_time=now,
                last_time=now,
            )

        flow = self.active_flows[flow_key]
        flow.add_packet(pkt, is_forward, now)

        # Flow expiration checks
        should_flush = (
            flow.has_seen_rst
            or (flow.has_seen_fin and (now - flow.last_time > 0.5))
            or (now - flow.start_time > self.flow_max_duration)
        )

        if should_flush:
            self._flush_flow(flow_key)

    def _flush_flow(self, flow_key: Tuple):
        """Export flow, calculate features, and send to NIDS API."""
        if flow_key not in self.active_flows:
            return

        flow = self.active_flows.pop(flow_key)
        # Skip flows with 0 packets
        if len(flow.fwd_pkt_lens) == 0 and len(flow.bwd_pkt_lens) == 0:
            return

        payload = flow.to_nids_payload()
        self.total_flows_exported += 1

        try:
            req = urllib.request.Request(
                self.api_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                if resp.status == 200:
                    res_data = json.loads(resp.read().decode("utf-8"))
                    classification = res_data.get("classification", "BENIGN")
                    is_malicious = res_data.get("is_malicious", False)
                    confidence = res_data.get("confidence_score", 0.0)

                    if is_malicious:
                        self.total_threats_detected += 1
                        print(
                            f"\033[91m[🚨 REAL ATTACK DETECTED]\033[0m "
                            f"{flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} "
                            f"| \033[1m{classification}\033[0m ({(confidence * 100):.1f}%)"
                        )
                    else:
                        print(
                            f"\033[92m[✓ NORMAL FLOW]\033[0m "
                            f"{flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} "
                            f"({flow.protocol}) | Pkts: {len(flow.fwd_pkt_lens) + len(flow.bwd_pkt_lens)} "
                            f"| Bytes: {sum(flow.fwd_pkt_lens) + sum(flow.bwd_pkt_lens)}"
                        )
        except Exception as e:
            # Server not reached or transient connection error
            pass

    def flush_stale_flows(self):
        """Periodically flush flows that have timed out due to inactivity."""
        now = time.time()
        stale_keys = [
            k
            for k, f in self.active_flows.items()
            if (now - f.last_time >= self.flow_idle_timeout)
        ]
        for k in stale_keys:
            self._flush_flow(k)

    def start(self):
        """Start capturing packets in the foreground."""
        print("=" * 64)
        print("  CYBER SENTINEL // PHYSICAL NETWORK INTERFACE SNIFFER  ")
        print("=" * 64)
        print(f"[*] Target Network Interface: \033[96m{self.interface}\033[0m")
        print(f"[*] AI Inference Endpoint:   \033[96m{self.api_url}\033[0m")
        print(f"[*] Flow Idle Timeout:        {self.flow_idle_timeout}s")
        print(f"[*] Flow Max Duration:        {self.flow_max_duration}s")
        print("[*] Sniffing live packets... (Press Ctrl+C to terminate)")
        print("-" * 64)

        try:
            # Sniff with periodic stale flow flushes
            def packet_worker(pkt):
                self.handle_packet(pkt)
                if self.total_packets_captured % 25 == 0:
                    self.flush_stale_flows()

            sniff(
                iface=self.interface,
                prn=packet_worker,
                store=False,
            )
        except PermissionError:
            print("\n\033[91m[!] Permission Denied:\033[0m Raw packet sniffing requires root permissions.")
            print("[*] Run with sudo:")
            print(f"    sudo {sys.executable} scripts/live_sniffer.py --interface {self.interface}")
            print("[*] Or grant permanent network capture capability to this Python environment:")
            print(f"    sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f {sys.executable})")
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n[*] Stopping sniffer and flushing remaining flows...")
            for k in list(self.active_flows.keys()):
                self._flush_flow(k)
            duration = max(1.0, time.time() - self.start_time)
            print("-" * 64)
            print(f"[✓] Total Packets Captured: {self.total_packets_captured} ({(self.total_packets_captured / duration):.1f} pkts/s)")
            print(f"[✓] Total Flows Analyzed:   {self.total_flows_exported}")
            print(f"[✓] Threats Detected:       {self.total_threats_detected}")
            print("=" * 64)


def main():
    parser = argparse.ArgumentParser(description="Cyber Sentinel Live Network Sniffer")
    parser.add_argument(
        "-i",
        "--interface",
        type=str,
        default=None,
        help="Network interface to sniff (e.g. wlp44s0, eth0). Defaults to active Wi-Fi or primary.",
    )
    parser.add_argument(
        "--api-url",
        type=str,
        default="http://localhost:8000/api/v1/flows/analyze",
        help="NIDS API flow ingestion endpoint",
    )
    parser.add_argument(
        "--idle-timeout",
        type=float,
        default=2.0,
        help="Idle timeout in seconds before closing inactive flow",
    )
    args = parser.parse_args()

    sniffer = LiveNetworkSniffer(
        interface=args.interface,
        api_url=args.api_url,
        flow_idle_timeout=args.idle_timeout,
    )
    sniffer.start()


if __name__ == "__main__":
    main()
