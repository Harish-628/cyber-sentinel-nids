"""
SOC Alert Export Utility.

Dumps alerts from the live NIDS API into CSV or JSON format for SIEM ingestion.
"""

import argparse
import json
import sys
from pathlib import Path
import httpx
import pandas as pd
from rich.console import Console

console = Console()

def export_alerts(api_url: str = "http://localhost:8000/api/v1/alerts", output_file: str = "alerts_export.csv", format_type: str = "csv"):
    console.print(f"[cyan]Querying alerts from live NIDS engine:[/cyan] {api_url}")
    try:
        res = httpx.get(api_url, timeout=10.0)
        res.raise_for_status()
        alerts = res.json()
    except Exception as e:
        console.print(f"[bold red]Failed to fetch alerts:[/bold red] {e}")
        sys.exit(1)

    if not alerts:
        console.print("[yellow]No alerts found to export.[/yellow]")
        return

    out_path = Path(output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if format_type == "json":
        with open(out_path, "w") as f:
            json.dump(alerts, f, indent=2)
    else:
        # Flatten flow_summary dictionary for clean CSV tabular output
        flat_records = []
        for a in alerts:
            rec = {
                "alert_id": a.get("alert_id"),
                "timestamp": a.get("timestamp"),
                "severity": a.get("severity"),
                "classification": a.get("classification"),
                "confidence_score": a.get("confidence_score"),
                "source_ip": a.get("source_ip"),
                "source_port": a.get("source_port"),
                "destination_ip": a.get("destination_ip"),
                "destination_port": a.get("destination_port"),
                "protocol": a.get("protocol"),
                "status": a.get("status"),
                "mitre_tactic": a.get("mitre_tactic"),
                "description": a.get("description"),
                "mitigation": a.get("mitigation"),
            }
            summary = a.get("flow_summary", {})
            rec["flow_duration_ms"] = summary.get("flow_duration_ms")
            rec["total_packets"] = summary.get("total_packets")
            rec["bytes_transferred"] = summary.get("bytes_transferred")
            flat_records.append(rec)

        df = pd.DataFrame(flat_records)
        df.to_csv(out_path, index=False)

    console.print(f"[bold green]✓ Successfully exported {len(alerts)} alerts to:[/bold green] {out_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export NIDS Alerts to CSV or JSON")
    parser.add_argument("--url", type=str, default="http://localhost:8000/api/v1/alerts", help="API URL")
    parser.add_argument("--output", type=str, default="models/evaluation/alerts_export.csv", help="Target output file path")
    parser.add_argument("--format", type=str, choices=["csv", "json"], default="csv", help="Output format (csv/json)")
    args = parser.parse_args()

    export_alerts(api_url=args.url, output_file=args.output, format_type=args.format)
