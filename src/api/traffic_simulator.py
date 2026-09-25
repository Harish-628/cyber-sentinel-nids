"""
Asynchronous Real-Time Traffic & Attack Simulator.

Simulates authentic TCP/IP network flows in the background:
- Periodic legitimate benign traffic (HTTP, HTTPS, DNS)
- Intermittent cyberattack vectors (PortScan, DoS Hulk, DDoS, Brute Force, Web Attacks, Botnet)
- Configurable generation frequency and single-attack on-demand injection
"""

import asyncio
import random
from typing import Dict, Optional
import numpy as np

from src.api.alert_store import store
from src.api.inference import engine
from src.api.schemas import NetworkFlowPayload


class TrafficSimulator:
    """Simulates real-time enterprise network traffic."""

    def __init__(self):
        self.is_running: bool = False
        self.task: Optional[asyncio.Task] = None
        self.flow_interval: float = 0.5  # ~2 flows per second
        self.attack_probability: float = 0.20  # 20% malicious by default
        self.rng = np.random.default_rng(42)

    def generate_random_ip(self, subnet: str = "internal") -> str:
        """Generate realistic internal or external IP."""
        if subnet == "internal":
            return f"192.168.{self.rng.integers(1, 20)}.{self.rng.integers(2, 254)}"
        elif subnet == "dmz":
            return f"10.0.{self.rng.integers(1, 5)}.{self.rng.integers(2, 50)}"
        else: # external WAN attacker
            return f"{self.rng.integers(45, 210)}.{self.rng.integers(10, 200)}.{self.rng.integers(1, 254)}.{self.rng.integers(1, 254)}"

    def create_simulated_payload(self, attack_type: Optional[str] = None) -> NetworkFlowPayload:
        """Create a NetworkFlowPayload corresponding to benign or a specific attack vector."""
        if attack_type is None:
            is_attack = self.rng.random() < self.attack_probability
            if is_attack:
                attack_type = self.rng.choice(["PortScan", "DoS", "DDoS", "Brute Force", "Web Attack", "Botnet"])
            else:
                attack_type = "BENIGN"

        src_ip = self.generate_random_ip("external" if attack_type != "BENIGN" else "internal")
        dst_ip = self.generate_random_ip("dmz")
        src_port = int(self.rng.integers(49152, 65535))

        if attack_type == "PortScan":
            return NetworkFlowPayload(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=int(self.rng.integers(1, 65535)),
                protocol="TCP",
                flow_duration=float(self.rng.uniform(10, 2000)),
                tot_fwd_pkts=int(self.rng.integers(1, 3)),
                tot_bwd_pkts=0,
                tot_len_fwd_pkts=0.0,
                tot_len_bwd_pkts=0.0,
                fwd_pkt_len_max=0.0,
                fwd_pkt_len_min=0.0,
                fwd_pkt_len_mean=0.0,
                bwd_pkt_len_mean=0.0,
                flow_bytes_s=0.0,
                flow_pkts_s=float(self.rng.uniform(500, 2000)),
                syn_flag_count=1,
                ack_flag_count=0,
                init_win_bytes_forward=1024,
                init_win_bytes_backward=0,
                act_data_pkt_fwd=0,
                avg_pkt_size=0.0,
            )
        elif attack_type == "DDoS":
            duration = float(self.rng.uniform(20000000, 60000000))
            fwd_pkts = int(self.rng.integers(100, 350))
            return NetworkFlowPayload(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=int(self.rng.choice([80, 443])),
                protocol="TCP",
                flow_duration=duration,
                tot_fwd_pkts=fwd_pkts,
                tot_bwd_pkts=int(self.rng.integers(0, 3)),
                tot_len_fwd_pkts=fwd_pkts * 128.0,
                tot_len_bwd_pkts=0.0,
                fwd_pkt_len_max=128.0,
                fwd_pkt_len_min=128.0,
                fwd_pkt_len_mean=128.0,
                bwd_pkt_len_mean=0.0,
                flow_bytes_s=float(self.rng.uniform(400000, 1500000)),
                flow_pkts_s=float(self.rng.uniform(3000, 15000)),
                syn_flag_count=1,
                ack_flag_count=0,
                init_win_bytes_forward=1024,
                init_win_bytes_backward=0,
                act_data_pkt_fwd=fwd_pkts,
                avg_pkt_size=128.0,
            )
        elif attack_type == "DoS":
            duration = float(self.rng.uniform(40000000, 100000000))
            fwd_pkts = int(self.rng.integers(25, 70))
            return NetworkFlowPayload(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=int(self.rng.choice([80, 8080])),
                protocol="TCP",
                flow_duration=duration,
                tot_fwd_pkts=fwd_pkts,
                tot_bwd_pkts=int(self.rng.integers(1, 5)),
                tot_len_fwd_pkts=fwd_pkts * 320.0,
                tot_len_bwd_pkts=200.0,
                fwd_pkt_len_max=450.0,
                fwd_pkt_len_min=150.0,
                fwd_pkt_len_mean=320.0,
                bwd_pkt_len_mean=80.0,
                flow_bytes_s=float(self.rng.uniform(500, 5000)),
                flow_pkts_s=float(self.rng.uniform(0.5, 3.0)),
                syn_flag_count=0,
                ack_flag_count=1,
                psh_flag_count=1,
                init_win_bytes_forward=8192,
                init_win_bytes_backward=512,
                act_data_pkt_fwd=fwd_pkts - 2,
                avg_pkt_size=300.0,
            )
        elif attack_type == "Brute Force":
            dst_port = int(self.rng.choice([21, 22]))
            fwd_pkts = int(self.rng.integers(15, 28))
            bwd_pkts = int(self.rng.integers(12, 25))
            return NetworkFlowPayload(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol="TCP",
                flow_duration=float(self.rng.uniform(800000, 4000000)),
                tot_fwd_pkts=fwd_pkts,
                tot_bwd_pkts=bwd_pkts,
                tot_len_fwd_pkts=fwd_pkts * 68.0,
                tot_len_bwd_pkts=bwd_pkts * 84.0,
                fwd_pkt_len_max=120.0,
                fwd_pkt_len_min=48.0,
                fwd_pkt_len_mean=68.0,
                bwd_pkt_len_mean=84.0,
                flow_bytes_s=float(self.rng.uniform(800, 4500)),
                flow_pkts_s=float(self.rng.uniform(10, 40)),
                syn_flag_count=0,
                ack_flag_count=1,
                psh_flag_count=1,
                init_win_bytes_forward=29200,
                init_win_bytes_backward=29200,
                act_data_pkt_fwd=fwd_pkts - 4,
                avg_pkt_size=75.0,
            )
        elif attack_type == "Web Attack":
            fwd_pkts = int(self.rng.integers(8, 18))
            bwd_pkts = int(self.rng.integers(6, 15))
            fwd_len_mean = float(self.rng.uniform(700, 1350))
            return NetworkFlowPayload(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=int(self.rng.choice([80, 443, 8080])),
                protocol="TCP",
                flow_duration=float(self.rng.uniform(50000, 1200000)),
                tot_fwd_pkts=fwd_pkts,
                tot_bwd_pkts=bwd_pkts,
                tot_len_fwd_pkts=fwd_pkts * fwd_len_mean,
                tot_len_bwd_pkts=bwd_pkts * 450.0,
                fwd_pkt_len_max=1460.0,
                fwd_pkt_len_min=120.0,
                fwd_pkt_len_mean=fwd_len_mean,
                bwd_pkt_len_mean=450.0,
                flow_bytes_s=float(self.rng.uniform(25000, 180000)),
                flow_pkts_s=float(self.rng.uniform(25, 120)),
                syn_flag_count=0,
                ack_flag_count=1,
                psh_flag_count=1,
                init_win_bytes_forward=29200,
                init_win_bytes_backward=29200,
                act_data_pkt_fwd=fwd_pkts - 2,
                avg_pkt_size=650.0,
            )
        elif attack_type == "Botnet":
            fwd_pkts = int(self.rng.integers(6, 12))
            bwd_pkts = int(self.rng.integers(4, 8))
            return NetworkFlowPayload(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=int(self.rng.choice([6667, 8080, 1080])),
                protocol="TCP",
                flow_duration=float(self.rng.uniform(20000000, 45000000)),
                tot_fwd_pkts=fwd_pkts,
                tot_bwd_pkts=bwd_pkts,
                tot_len_fwd_pkts=fwd_pkts * 110.0,
                tot_len_bwd_pkts=bwd_pkts * 90.0,
                fwd_pkt_len_max=220.0,
                fwd_pkt_len_min=54.0,
                fwd_pkt_len_mean=110.0,
                bwd_pkt_len_mean=90.0,
                flow_bytes_s=float(self.rng.uniform(80, 400)),
                flow_pkts_s=float(self.rng.uniform(0.2, 0.9)),
                flow_iat_mean=4000000.0,
                flow_iat_std=250.0,
                syn_flag_count=0,
                ack_flag_count=1,
                psh_flag_count=1,
                init_win_bytes_forward=8192,
                init_win_bytes_backward=8192,
                act_data_pkt_fwd=4,
                avg_pkt_size=100.0,
            )
        else: # BENIGN
            fwd_pkts = int(self.rng.poisson(lam=8) + 1)
            bwd_pkts = int(self.rng.poisson(lam=10) + 1)
            fwd_len_mean = float(self.rng.uniform(150, 400))
            bwd_len_mean = float(self.rng.uniform(500, 950))
            duration = float(self.rng.exponential(scale=150000) + 500)
            tot_bytes = (fwd_pkts * fwd_len_mean) + (bwd_pkts * bwd_len_mean)
            duration_sec = max(duration / 1e6, 1e-6)

            return NetworkFlowPayload(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=int(self.rng.choice([80, 443, 53, 8080, 8443, 22])),
                protocol="TCP" if self.rng.random() > 0.1 else "UDP",
                flow_duration=duration,
                tot_fwd_pkts=fwd_pkts,
                tot_bwd_pkts=bwd_pkts,
                tot_len_fwd_pkts=fwd_pkts * fwd_len_mean,
                tot_len_bwd_pkts=bwd_pkts * bwd_len_mean,
                fwd_pkt_len_max=min(1460.0, fwd_len_mean * 1.6),
                fwd_pkt_len_min=40.0,
                fwd_pkt_len_mean=fwd_len_mean,
                bwd_pkt_len_max=min(1460.0, bwd_len_mean * 1.5),
                bwd_pkt_len_min=40.0,
                bwd_pkt_len_mean=bwd_len_mean,
                flow_bytes_s=tot_bytes / duration_sec,
                flow_pkts_s=(fwd_pkts + bwd_pkts) / duration_sec,
                flow_iat_mean=duration / max(fwd_pkts + bwd_pkts - 1, 1),
                syn_flag_count=int(self.rng.choice([0, 1], p=[0.8, 0.2])),
                ack_flag_count=1,
                psh_flag_count=int(self.rng.choice([0, 1], p=[0.6, 0.4])),
                init_win_bytes_forward=int(self.rng.choice([8192, 29200, 65535])),
                init_win_bytes_backward=int(self.rng.choice([8192, 29200, 65535])),
                act_data_pkt_fwd=max(1, fwd_pkts - 2),
                avg_pkt_size=tot_bytes / max(fwd_pkts + bwd_pkts, 1),
            )

    async def _simulation_loop(self):
        """Asynchronous worker that pushes simulated flows into inference engine and alert store."""
        while self.is_running:
            try:
                payload = self.create_simulated_payload()
                result = engine.analyze_flow(payload)
                tot_bytes = payload.tot_len_fwd_pkts + payload.tot_len_bwd_pkts
                await store.add_flow_result(result, bytes_transferred=tot_bytes)
            except Exception as e:
                # Keep running on transient error
                pass
            await asyncio.sleep(self.flow_interval)

    def start(self, interval: float = 0.5, attack_prob: float = 0.20):
        """Start simulation worker."""
        if not self.is_running:
            self.flow_interval = interval
            self.attack_probability = attack_prob
            self.is_running = True
            self.task = asyncio.create_task(self._simulation_loop())

    def stop(self):
        """Stop simulation worker."""
        self.is_running = False
        if self.task:
            self.task.cancel()
            self.task = None

    async def inject_attack(self, attack_type: str):
        """Inject a single targeted cyberattack immediately."""
        payload = self.create_simulated_payload(attack_type=attack_type)
        result = engine.analyze_flow(payload)
        tot_bytes = payload.tot_len_fwd_pkts + payload.tot_len_bwd_pkts
        await store.add_flow_result(result, bytes_transferred=tot_bytes)
        return result


# Global simulator singleton
simulator = TrafficSimulator()
