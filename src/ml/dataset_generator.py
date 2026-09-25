"""
CIC-IDS2017 Benchmark Dataset Generator.

Generates statistically authentic, realistic CIC-IDS2017 network flow records
matching CICFlowMeter output specifications for instant testing, verification,
and training of the NIDS ML pipeline.
"""

import argparse
import os
import sys
from pathlib import Path
import numpy as np
import pandas as pd
from rich.console import Console

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

console = Console()

def generate_benchmark_dataset(num_samples: int = 50000, output_path: str = "data/raw/cicids2017_benchmark.csv", seed: int = 42):
    rng = np.random.default_rng(seed)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    console.print(f"[bold cyan]Generating {num_samples:,} benchmark CIC-IDS2017 flow records (vectorized)...[/bold cyan]")

    # Target class breakdown
    specs = [
        ("BENIGN", int(num_samples * 0.65)),
        ("PortScan", int(num_samples * 0.12)),
        ("DDoS", int(num_samples * 0.08)),
        ("DoS Hulk", int(num_samples * 0.07)),
        ("FTP-Patator", int(num_samples * 0.035)),
        ("Web Attack \x96 Brute Force", int(num_samples * 0.03)),
        ("Bot", int(num_samples * 0.015)),
    ]
    
    dfs = []
    for label, count in specs:
        if count <= 0:
            continue
        console.print(f"  • Synthesizing [yellow]{label:<28}[/yellow]: {count:,} flows")
        
        # Base flow variables
        if label == "BENIGN":
            dst_ports = rng.choice([80, 443, 53, 8080, 8443, 22, 5353, 3389], size=count)
            duration = rng.exponential(scale=120000, size=count) + 500
            fwd_pkts = rng.poisson(lam=8, size=count) + 1
            bwd_pkts = rng.poisson(lam=10, size=count) + 1
            fwd_len_mean = np.clip(rng.normal(loc=250, scale=80, size=count), 40, 1460)
            bwd_len_mean = np.clip(rng.normal(loc=650, scale=200, size=count), 40, 1460)
            syn_flags = rng.choice([0, 1], size=count, p=[0.8, 0.2])
            ack_flags = np.ones(count, dtype=int)
            psh_flags = rng.choice([0, 1], size=count, p=[0.6, 0.4])
            rst_flags = np.zeros(count, dtype=int)
            win_fwd = rng.choice([8192, 29200, 65535], size=count)
            win_bwd = rng.choice([8192, 29200, 65535], size=count)
        elif label == "PortScan":
            dst_ports = rng.integers(1, 65535, size=count)
            duration = rng.uniform(10, 3000, size=count)
            fwd_pkts = rng.integers(1, 3, size=count)
            bwd_pkts = rng.choice([0, 1], size=count, p=[0.75, 0.25])
            fwd_len_mean = np.zeros(count)
            bwd_len_mean = np.zeros(count)
            syn_flags = np.ones(count, dtype=int)
            ack_flags = np.zeros(count, dtype=int)
            psh_flags = np.zeros(count, dtype=int)
            rst_flags = (bwd_pkts > 0).astype(int)
            win_fwd = np.full(count, 1024)
            win_bwd = np.zeros(count)
        elif label == "DDoS":
            dst_ports = rng.choice([80, 443], size=count)
            duration = rng.exponential(scale=50000000, size=count) + 1000000
            fwd_pkts = rng.integers(60, 400, size=count)
            bwd_pkts = rng.integers(0, 5, size=count)
            fwd_len_mean = rng.choice([64.0, 128.0, 256.0, 512.0], size=count)
            bwd_len_mean = np.full(count, 40.0)
            syn_flags = np.ones(count, dtype=int)
            ack_flags = (bwd_pkts > 0).astype(int)
            psh_flags = np.zeros(count, dtype=int)
            rst_flags = np.zeros(count, dtype=int)
            win_fwd = rng.choice([256, 1024, 4096], size=count)
            win_bwd = np.zeros(count)
        elif label == "DoS Hulk":
            dst_ports = rng.choice([80, 8080], size=count)
            duration = rng.uniform(30000000, 120000000, size=count)
            fwd_pkts = rng.integers(20, 80, size=count)
            bwd_pkts = rng.integers(1, 10, size=count)
            fwd_len_mean = rng.uniform(180, 450, size=count)
            bwd_len_mean = np.full(count, 80.0)
            syn_flags = np.zeros(count, dtype=int)
            ack_flags = np.ones(count, dtype=int)
            psh_flags = np.ones(count, dtype=int)
            rst_flags = np.zeros(count, dtype=int)
            win_fwd = np.full(count, 8192)
            win_bwd = np.full(count, 512)
        elif label == "FTP-Patator":
            dst_ports = np.full(count, 21)
            duration = rng.uniform(500000, 6000000, size=count)
            fwd_pkts = rng.integers(14, 30, size=count)
            bwd_pkts = rng.integers(12, 28, size=count)
            fwd_len_mean = np.full(count, 68.0)
            bwd_len_mean = np.full(count, 84.0)
            syn_flags = np.zeros(count, dtype=int)
            ack_flags = np.ones(count, dtype=int)
            psh_flags = np.ones(count, dtype=int)
            rst_flags = np.zeros(count, dtype=int)
            win_fwd = np.full(count, 29200)
            win_bwd = np.full(count, 29200)
        elif label.startswith("Web Attack"):
            dst_ports = rng.choice([80, 443, 8080], size=count)
            duration = rng.uniform(25000, 1800000, size=count)
            fwd_pkts = rng.integers(6, 20, size=count)
            bwd_pkts = rng.integers(5, 18, size=count)
            fwd_len_mean = rng.uniform(650, 1400, size=count)
            bwd_len_mean = rng.uniform(300, 900, size=count)
            syn_flags = np.zeros(count, dtype=int)
            ack_flags = np.ones(count, dtype=int)
            psh_flags = np.ones(count, dtype=int)
            rst_flags = np.zeros(count, dtype=int)
            win_fwd = np.full(count, 29200)
            win_bwd = np.full(count, 29200)
        else: # Bot
            dst_ports = rng.choice([8080, 6667, 443], size=count)
            duration = rng.uniform(15000000, 45000000, size=count)
            fwd_pkts = rng.integers(6, 14, size=count)
            bwd_pkts = rng.integers(4, 10, size=count)
            fwd_len_mean = rng.uniform(60, 220, size=count)
            bwd_len_mean = rng.uniform(40, 180, size=count)
            syn_flags = np.zeros(count, dtype=int)
            ack_flags = np.ones(count, dtype=int)
            psh_flags = np.ones(count, dtype=int)
            rst_flags = np.zeros(count, dtype=int)
            win_fwd = np.full(count, 8192)
            win_bwd = np.full(count, 8192)

        duration_sec = np.maximum(duration / 1e6, 1e-6)
        tot_fwd_len = fwd_pkts * fwd_len_mean
        tot_bwd_len = bwd_pkts * bwd_len_mean
        tot_bytes = tot_fwd_len + tot_bwd_len
        tot_pkts = fwd_pkts + bwd_pkts
        
        flow_bytes_s = tot_bytes / duration_sec
        flow_pkts_s = tot_pkts / duration_sec
        
        # Build dictionary of features with original CIC-IDS2017 header style (leading space)
        data = {
            " Destination Port": dst_ports,
            " Flow Duration": duration,
            " Total Fwd Packets": fwd_pkts,
            " Total Backward Packets": bwd_pkts,
            "Total Length of Fwd Packets": tot_fwd_len,
            " Total Length of Bwd Packets": tot_bwd_len,
            " Fwd Packet Length Max": np.minimum(1460.0, fwd_len_mean * 1.6),
            " Fwd Packet Length Min": np.maximum(0.0, fwd_len_mean * 0.2),
            " Fwd Packet Length Mean": fwd_len_mean,
            " Fwd Packet Length Std": rng.uniform(10, 60, size=count),
            "Bwd Packet Length Max": np.minimum(1460.0, bwd_len_mean * 1.5),
            " Bwd Packet Length Min": np.maximum(0.0, bwd_len_mean * 0.1),
            " Bwd Packet Length Mean": bwd_len_mean,
            " Bwd Packet Length Std": rng.uniform(10, 100, size=count),
            "Flow Bytes/s": flow_bytes_s,
            " Flow Packets/s": flow_pkts_s,
            " Flow IAT Mean": duration / np.maximum(tot_pkts - 1, 1),
            " Flow IAT Std": rng.exponential(scale=3000, size=count),
            " Flow IAT Max": duration * 0.7,
            " Flow IAT Min": rng.uniform(1, 40, size=count),
            "Fwd IAT Total": duration * 0.9,
            " Fwd IAT Mean": duration / np.maximum(fwd_pkts, 1),
            " Fwd IAT Std": rng.uniform(10, 400, size=count),
            " Fwd IAT Max": duration * 0.6,
            " Fwd IAT Min": rng.uniform(1, 30, size=count),
            "Bwd IAT Total": duration * 0.85,
            " Bwd IAT Mean": duration / np.maximum(bwd_pkts, 1),
            " Bwd IAT Std": rng.uniform(10, 350, size=count),
            " Bwd IAT Max": duration * 0.5,
            " Bwd IAT Min": rng.uniform(1, 30, size=count),
            "Fwd PSH Flags": rng.choice([0, 1], size=count, p=[0.8, 0.2]),
            " Bwd PSH Flags": np.zeros(count, dtype=int),
            " Fwd URG Flags": np.zeros(count, dtype=int),
            " Bwd URG Flags": np.zeros(count, dtype=int),
            " Fwd Header Length": fwd_pkts * 20,
            " Bwd Header Length": bwd_pkts * 20,
            "Fwd Packets/s": fwd_pkts / duration_sec,
            " Bwd Packets/s": bwd_pkts / duration_sec,
            " Min Packet Length": np.zeros(count),
            " Max Packet Length": np.full(count, 1460.0),
            " Packet Length Mean": tot_bytes / np.maximum(tot_pkts, 1),
            " Packet Length Std": rng.uniform(40, 250, size=count),
            " Packet Length Variance": rng.uniform(1600, 62500, size=count),
            "FIN Flag Count": rng.choice([0, 1], size=count, p=[0.7, 0.3]),
            " SYN Flag Count": syn_flags,
            " RST Flag Count": rst_flags,
            " PSH Flag Count": psh_flags,
            " ACK Flag Count": ack_flags,
            " URG Flag Count": np.zeros(count, dtype=int),
            " CWE Flag Count": np.zeros(count, dtype=int),
            " ECE Flag Count": np.zeros(count, dtype=int),
            " Down/Up Ratio": np.round(bwd_pkts / np.maximum(fwd_pkts, 1), 1),
            " Average Packet Size": tot_bytes / np.maximum(tot_pkts, 1),
            " Avg Fwd Segment Size": fwd_len_mean,
            " Avg Bwd Segment Size": bwd_len_mean,
            " Fwd Header Length.1": fwd_pkts * 20,
            "Fwd Avg Bytes/Bulk": np.zeros(count),
            " Fwd Avg Packets/Bulk": np.zeros(count),
            " Fwd Avg Bulk Rate": np.zeros(count),
            " Bwd Avg Bytes/Bulk": np.zeros(count),
            " Bwd Avg Packets/Bulk": np.zeros(count),
            "Bwd Avg Bulk Rate": np.zeros(count),
            "Subflow Fwd Packets": fwd_pkts,
            " Subflow Fwd Bytes": tot_fwd_len,
            " Subflow Bwd Packets": bwd_pkts,
            " Subflow Bwd Bytes": tot_bwd_len,
            "Init_Win_bytes_forward": win_fwd,
            " Init_Win_bytes_backward": win_bwd,
            " act_data_pkt_fwd": np.maximum(0, fwd_pkts - 1),
            " min_seg_size_forward": np.full(count, 20),
            "Active Mean": np.zeros(count),
            " Active Std": np.zeros(count),
            " Active Max": np.zeros(count),
            " Active Min": np.zeros(count),
            "Idle Mean": np.zeros(count),
            " Idle Std": np.zeros(count),
            " Idle Max": np.zeros(count),
            " Idle Min": np.zeros(count),
            " Label": [label] * count,
        }
        dfs.append(pd.DataFrame(data))

    full_df = pd.concat(dfs, ignore_index=True)

    # Inject real-world infs to test cleaning (0.1%)
    inf_indices = rng.choice(len(full_df), size=int(len(full_df) * 0.001), replace=False)
    full_df.loc[inf_indices, "Flow Bytes/s"] = np.inf

    # Shuffle
    full_df = full_df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    full_df.to_csv(output_path, index=False)
    
    console.print(f"[bold green]✓ Benchmark dataset successfully saved to:[/bold green] [bold white]{output_path}[/bold white]")
    console.print(f"  Total records: {len(full_df):,}")
    console.print(f"  Total columns: {len(full_df.columns)}")
    return output_path

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate CIC-IDS2017 Benchmark Flow Dataset")
    parser.add_argument("--samples", type=int, default=50000, help="Number of flow records to generate")
    parser.add_argument("--output", type=str, default="data/raw/cicids2017_benchmark.csv", help="Target output CSV path")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    generate_benchmark_dataset(num_samples=args.samples, output_path=args.output, seed=args.seed)
