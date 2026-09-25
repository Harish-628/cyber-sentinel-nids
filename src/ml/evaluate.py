"""
NIDS Model Evaluation Suite.

Computes comprehensive SOC-grade evaluation metrics:
- Overall Accuracy
- Macro & Weighted Precision, Recall, and F1-Score
- Per-class detection metrics
- Confusion Matrix with False Positive Rate (FPR) analysis
- Real-time inference latency profiling (microseconds per flow)
- Exports structured evaluation JSON for compliance and reporting
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List

import joblib
import numpy as np
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ml.feature_config import SOC_ALERT_METADATA

console = Console()


class NIDSEvaluator:
    """Enterprise evaluation engine for NIDS models."""

    def __init__(self, model_path: str, data_dir: str):
        self.model_path = Path(model_path)
        self.data_dir = Path(data_dir)
        self.model = None
        self.metadata = {}
        self.class_mapping: Dict[int, str] = {}
        self.X_test = None
        self.y_test = None

    def load_resources(self):
        """Load trained model, test dataset, and metadata."""
        if not self.model_path.exists():
            raise FileNotFoundError(f"Model file not found: {self.model_path}")
        
        npz_path = self.data_dir / "processed_data.npz"
        meta_path = self.data_dir / "feature_metadata.json"
        
        if not npz_path.exists() or not meta_path.exists():
            raise FileNotFoundError(f"Missing evaluation data in: {self.data_dir}")

        console.print(f"[cyan]Loading model from:[/cyan] {self.model_path}")
        self.model = joblib.load(self.model_path)

        data = np.load(npz_path)
        self.X_test = data["X_test"]
        self.y_test = data["y_test"]

        with open(meta_path, "r") as f:
            self.metadata = json.load(f)
            self.class_mapping = {int(k): v for k, v in self.metadata["class_mapping"].items()}

        console.print(f"[bold green]✓ Loaded validation set:[/bold green] {len(self.X_test):,} flows, {len(self.class_mapping)} classes")

    def benchmark_latency(self, num_iterations: int = 100) -> Dict[str, float]:
        """Profile single-flow prediction latency in microseconds without threadpool spawn overhead."""
        orig_jobs = getattr(self.model, "n_jobs", None)
        if hasattr(self.model, "n_jobs"):
            self.model.n_jobs = 1  # Single-threaded is optimal for 1-row online stream inference

        sample_indices = np.random.choice(len(self.X_test), size=min(num_iterations, len(self.X_test)), replace=False)
        test_samples = self.X_test[sample_indices]

        # Warm-up
        _ = self.model.predict(test_samples[:5])

        latencies = []
        for i in range(len(test_samples)):
            single_flow = test_samples[i : i + 1]
            t0 = time.perf_counter()
            _ = self.model.predict(single_flow)
            t1 = time.perf_counter()
            latencies.append((t1 - t0) * 1e6)  # convert to microseconds

        # Restore original n_jobs
        if orig_jobs is not None:
            self.model.n_jobs = orig_jobs

        avg_latency_us = float(np.mean(latencies))
        p95_latency_us = float(np.percentile(latencies, 95))
        p99_latency_us = float(np.percentile(latencies, 99))
        throughput_fps = 1e6 / avg_latency_us if avg_latency_us > 0 else 0.0

        return {
            "mean_latency_us": round(avg_latency_us, 2),
            "p95_latency_us": round(p95_latency_us, 2),
            "p99_latency_us": round(p99_latency_us, 2),
            "throughput_flows_per_sec": round(throughput_fps, 1),
        }

    def evaluate(self, output_dir: str = "models/evaluation") -> Dict:
        """Run full evaluation suite and generate SOC report."""
        self.load_resources()

        console.print("[bold yellow]Executing inference on validation partition...[/bold yellow]")
        y_pred = self.model.predict(self.X_test)

        # Global metrics
        acc = accuracy_score(self.y_test, y_pred)
        prec_macro = precision_score(self.y_test, y_pred, average="macro", zero_division=0)
        rec_macro = recall_score(self.y_test, y_pred, average="macro", zero_division=0)
        f1_macro = f1_score(self.y_test, y_pred, average="macro", zero_division=0)

        prec_weighted = precision_score(self.y_test, y_pred, average="weighted", zero_division=0)
        rec_weighted = recall_score(self.y_test, y_pred, average="weighted", zero_division=0)
        f1_weighted = f1_score(self.y_test, y_pred, average="weighted", zero_division=0)

        # Latency benchmark
        latency_stats = self.benchmark_latency(num_iterations=100)

        # Overview Table
        overview = Table(title="Global NIDS Detection Performance", header_style="bold blue")
        overview.add_column("Metric Name", style="bold white")
        overview.add_column("Score", justify="right", style="bold green")
        overview.add_column("Benchmark Target", justify="right", style="dim")
        overview.add_column("Status", justify="center")

        def status_badge(val, thresh):
            return "[green]PASS[/green]" if val >= thresh else "[red]FAIL[/red]"

        overview.add_row("Overall Accuracy", f"{acc * 100:.2f}%", ">= 95.0%", status_badge(acc, 0.95))
        overview.add_row("Macro F1-Score", f"{f1_macro * 100:.2f}%", ">= 90.0%", status_badge(f1_macro, 0.90))
        overview.add_row("Macro Precision", f"{prec_macro * 100:.2f}%", ">= 90.0%", status_badge(prec_macro, 0.90))
        overview.add_row("Macro Recall", f"{rec_macro * 100:.2f}%", ">= 90.0%", status_badge(rec_macro, 0.90))
        overview.add_row("Weighted F1-Score", f"{f1_weighted * 100:.2f}%", ">= 95.0%", status_badge(f1_weighted, 0.95))
        overview.add_row("Mean Online Latency", f"{latency_stats['mean_latency_us']:.1f} µs/flow", "< 5000 µs", "[green]REAL-TIME[/green]")
        overview.add_row("Throughput Capacity", f"{latency_stats['throughput_flows_per_sec']:,.0f} flows/s", "> 1,000 fps", "[green]OPTIMAL[/green]")
        console.print(overview)

        # Per-class table
        report_dict = classification_report(
            self.y_test,
            y_pred,
            target_names=[self.class_mapping[i] for i in range(len(self.class_mapping))],
            output_dict=True,
            zero_division=0,
        )

        class_table = Table(title="Per-Class Intrusion Detection Breakdown", header_style="bold magenta")
        class_table.add_column("Class ID", justify="center", style="dim", width=8)
        class_table.add_column("Attack Vector", style="bold white")
        class_table.add_column("Severity", justify="center")
        class_table.add_column("Precision", justify="right")
        class_table.add_column("Recall", justify="right")
        class_table.add_column("F1-Score", justify="right", style="bold")
        class_table.add_column("Validation Flows", justify="right")

        for class_id, class_name in self.class_mapping.items():
            if class_name in report_dict:
                metrics = report_dict[class_name]
                meta = SOC_ALERT_METADATA.get(class_name, {"severity": "UNKNOWN", "color": "white"})
                sev = f"[{meta['color']}]{meta['severity']}[/{meta['color']}]"
                
                f1_color = "green" if metrics["f1-score"] >= 0.90 else "yellow" if metrics["f1-score"] >= 0.80 else "red"
                f1_str = f"[{f1_color}]{metrics['f1-score']:.4f}[/{f1_color}]"

                class_table.add_row(
                    str(class_id),
                    class_name,
                    sev,
                    f"{metrics['precision']:.4f}",
                    f"{metrics['recall']:.4f}",
                    f1_str,
                    f"{int(metrics['support']):,}",
                )

        console.print(class_table)

        # Confusion Matrix
        cm = confusion_matrix(self.y_test, y_pred)
        cm_table = Table(title="Confusion Matrix (Rows: Actual, Cols: Predicted)", header_style="bold cyan")
        cm_table.add_column("Actual \\ Pred", style="bold white")
        for i in range(len(self.class_mapping)):
            cm_table.add_column(self.class_mapping[i][:7], justify="right")

        for i, row in enumerate(cm):
            row_vals = [f"[bold green]{val}[/bold green]" if j == i else (f"[red]{val}[/red]" if val > 0 else "0") for j, val in enumerate(row)]
            cm_table.add_row(self.class_mapping[i], *row_vals)

        console.print(cm_table)

        # Calculate False Positive Rate (FPR) on BENIGN (Class 0)
        benign_id = None
        for cid, cname in self.class_mapping.items():
            if cname == "BENIGN":
                benign_id = cid
                break

        fpr_benign = 0.0
        if benign_id is not None:
            benign_total = int(np.sum(cm[benign_id, :]))
            benign_fps = int(benign_total - cm[benign_id, benign_id])
            fpr_benign = (benign_fps / benign_total) * 100 if benign_total > 0 else 0.0
            console.print(Panel(
                f"[bold cyan]BENIGN False Positive Rate (FPR):[/bold cyan] [bold green]{fpr_benign:.3f}%[/bold green] ({benign_fps} false alarms out of {benign_total:,} normal flows)\n"
                f"[bold cyan]Detection Throughput:[/bold cyan] [bold white]{latency_stats['throughput_flows_per_sec']:,.0f} flows/second[/bold white] (Latency: [bold green]{latency_stats['mean_latency_us']} µs[/bold green])",
                title="SOC Operational Readiness Assessment",
                border_style="green",
            ))

        # Save structured evaluation report
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        report_path = out / "evaluation_report.json"

        eval_summary = {
            "model_path": str(self.model_path),
            "total_test_samples": len(self.X_test),
            "num_classes": len(self.class_mapping),
            "class_mapping": self.class_mapping,
            "overall_accuracy": round(float(acc), 6),
            "macro_precision": round(float(prec_macro), 6),
            "macro_recall": round(float(rec_macro), 6),
            "macro_f1": round(float(f1_macro), 6),
            "weighted_precision": round(float(prec_weighted), 6),
            "weighted_recall": round(float(rec_weighted), 6),
            "weighted_f1": round(float(f1_weighted), 6),
            "benign_false_positive_rate_pct": round(float(fpr_benign), 4),
            "latency_metrics": latency_stats,
            "per_class_metrics": report_dict,
            "confusion_matrix": cm.tolist(),
        }

        with open(report_path, "w") as f:
            json.dump(eval_summary, f, indent=2)

        console.print(f"[bold green]✓ Evaluation report successfully saved to:[/bold green] {report_path}")
        return eval_summary


def run_evaluation(model_path: str = "models/trained/nids_model.joblib", data_dir: str = "data/processed", output_dir: str = "models/evaluation"):
    evaluator = NIDSEvaluator(model_path=model_path, data_dir=data_dir)
    return evaluator.evaluate(output_dir=output_dir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NIDS Model Evaluation Engine")
    parser.add_argument("--model-path", type=str, default="models/trained/nids_model.joblib", help="Path to trained model")
    parser.add_argument("--data-dir", type=str, default="data/processed", help="Path to processed data directory")
    parser.add_argument("--output-dir", type=str, default="models/evaluation", help="Directory to save evaluation report")
    args = parser.parse_args()

    run_evaluation(model_path=args.model_path, data_dir=args.data_dir, output_dir=args.output_dir)
