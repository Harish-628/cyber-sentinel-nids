"""
CIC-IDS2017 Preprocessing Pipeline.

Loads, cleans, encodes, and normalizes CIC-IDS2017 network flow datasets.
Handles:
- Whitespace in CICFlowMeter headers
- Infinite (inf, -inf) and NaN values in flow rates
- Zero-variance / constant feature removal
- Attack taxonomy categorization & label encoding
- Outlier-resilient scaling (RobustScaler)
- Stratified train/test splitting
- Metadata & artifact serialization for the real-time inference engine
"""

import argparse
import glob
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from rich.console import Console
from rich.table import Table
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, RobustScaler

# Bootstrap project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ml.feature_config import (
    LABEL_TAXONOMY_MAP,
    RAW_NUMERIC_FEATURES,
    SOC_ALERT_METADATA,
    TOP_SELECTED_FEATURES,
    ZERO_VARIANCE_CANDIDATES,
)

console = Console()


class CICIDSPreprocessor:
    """Enterprise preprocessor for CIC-IDS2017 network flow datasets."""

    def __init__(self, use_top_features: bool = True):
        self.use_top_features = use_top_features
        self.scaler = RobustScaler()
        self.label_encoder = LabelEncoder()
        self.feature_names: List[str] = []
        self.target_col: str = "Label"
        self.class_mapping: Dict[int, str] = {}
        self.feature_medians: Dict[str, float] = {}

    def load_data(self, input_path: str) -> pd.DataFrame:
        """Load single CSV file or aggregate all CSV files in a directory."""
        path = Path(input_path)
        if path.is_file():
            console.print(f"[cyan]Loading dataset file:[/cyan] {path.name}")
            df = pd.read_csv(path, low_memory=False)
        elif path.is_dir():
            csv_files = sorted(glob.glob(str(path / "*.csv")))
            if not csv_files:
                raise FileNotFoundError(f"No CSV files found in directory: {path}")
            console.print(f"[cyan]Discovered {len(csv_files)} CSV files in directory:[/cyan] {path}")
            dfs = []
            for f in csv_files:
                console.print(f"  • Ingesting [dim]{Path(f).name}[/dim]")
                dfs.append(pd.read_csv(f, low_memory=False))
            df = pd.concat(dfs, ignore_index=True)
        else:
            raise FileNotFoundError(f"Input path does not exist: {input_path}")

        console.print(f"[bold green]✓ Loaded raw records:[/bold green] {len(df):,} rows, {len(df.columns)} columns")
        return df

    def clean_and_normalize_headers(self, df: pd.DataFrame) -> pd.DataFrame:
        """Strip whitespace from headers and standardize label column."""
        df.columns = df.columns.str.strip()
        
        # Standardize Label column name
        if "Label" not in df.columns:
            for col in df.columns:
                if col.lower() == "label":
                    df.rename(columns={col: "Label"}, inplace=True)
                    break

        if "Label" not in df.columns:
            raise KeyError(f"Missing 'Label' column. Available columns: {list(df.columns)[:5]}...")
            
        return df

    def clean_missing_and_infinite_values(self, df: pd.DataFrame) -> pd.DataFrame:
        """Handle infinite values and NaNs in flow metrics."""
        console.print("[dim]Cleaning infinite and missing values...[/dim]")
        
        # Replace inf and -inf with NaN across all numeric columns
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
        
        # Check null count
        null_counts = df[numeric_cols].isnull().sum().sum()
        if null_counts > 0:
            console.print(f"  [yellow]Found {null_counts:,} null/inf values across numeric columns. Imputing with column medians...[/yellow]")
            for col in numeric_cols:
                if df[col].isnull().any():
                    median_val = df[col].median()
                    if pd.isna(median_val):
                        median_val = 0.0
                    df[col] = df[col].fillna(median_val)
                    self.feature_medians[col] = float(median_val)

        # Drop any records with null Label
        df = df.dropna(subset=["Label"]).copy()
        return df

    def standardize_labels(self, df: pd.DataFrame) -> pd.DataFrame:
        """Map fine-grained attacks to standardized SOC categories."""
        raw_labels = df["Label"].astype(str).str.strip()
        mapped_labels = raw_labels.map(lambda x: LABEL_TAXONOMY_MAP.get(x, x))
        
        # If unmapped, categorize Web Attack variants or DoS variants
        mapped_labels = mapped_labels.apply(
            lambda x: "Web Attack" if "Web Attack" in x
            else "DoS" if ("DoS" in x or "Heartbleed" in x)
            else "Brute Force" if "Patator" in x
            else x
        )
        
        df["Label"] = mapped_labels
        return df

    def select_features(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
        """Select numerical flow features and filter constant/zero-variance features."""
        # Clean candidates
        available_cols = [c for c in df.columns if c != "Label" and np.issubdtype(df[c].dtype, np.number)]
        
        if self.use_top_features:
            selected = [c for c in TOP_SELECTED_FEATURES if c in available_cols]
            console.print(f"[cyan]Using optimized feature subset:[/cyan] {len(selected)} high-impact flow features")
        else:
            # Filter zero variance
            selected = [c for c in available_cols if c not in ZERO_VARIANCE_CANDIDATES]
            # Double check variance
            variances = df[selected].var()
            selected = [c for c in selected if variances[c] > 1e-9]
            console.print(f"[cyan]Using all non-zero-variance features:[/cyan] {len(selected)} features")

        self.feature_names = selected
        X = df[selected].copy()
        y = df["Label"].copy()
        return X, y

    def fit_transform(
        self,
        df: pd.DataFrame,
        test_size: float = 0.2,
        random_state: int = 42,
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Full pipeline: clean -> standardize -> select -> split -> scale -> encode."""
        df = self.clean_and_normalize_headers(df)
        df = self.clean_missing_and_infinite_values(df)
        df = self.standardize_labels(df)
        
        X_df, y_series = self.select_features(df)
        
        # Encode labels
        y_encoded = self.label_encoder.fit_transform(y_series)
        self.class_mapping = {int(idx): str(cls_name) for idx, cls_name in enumerate(self.label_encoder.classes_)}
        
        # Display class distribution
        table = Table(title="Processed Class Distribution (SOC Taxonomy)", show_header=True, header_style="bold magenta")
        table.add_column("Class ID", style="dim", width=8)
        table.add_column("Category", style="bold cyan")
        table.add_column("Count", justify="right")
        table.add_column("Percentage", justify="right")
        table.add_column("Severity", justify="center")

        counts = pd.Series(y_series).value_counts()
        total_rows = len(y_series)
        for class_id, class_name in self.class_mapping.items():
            cnt = counts.get(class_name, 0)
            pct = (cnt / total_rows) * 100
            meta = SOC_ALERT_METADATA.get(class_name, {"severity": "UNKNOWN", "color": "white"})
            sev_str = f"[{meta['color']}]{meta['severity']}[/{meta['color']}]"
            table.add_row(str(class_id), class_name, f"{cnt:,}", f"{pct:.2f}%", sev_str)
        console.print(table)
        
        # Stratified train/test split
        X_train_raw, X_test_raw, y_train, y_test = train_test_split(
            X_df.values,
            y_encoded,
            test_size=test_size,
            random_state=random_state,
            stratify=y_encoded,
        )
        
        # Scale features with RobustScaler
        console.print("[dim]Fitting RobustScaler on training partition...[/dim]")
        X_train_scaled = self.scaler.fit_transform(X_train_raw)
        X_test_scaled = self.scaler.transform(X_test_raw)
        
        # Cache median feature values for inference defaults
        for idx, col in enumerate(self.feature_names):
            self.feature_medians[col] = float(np.median(X_train_raw[:, idx]))
            
        console.print(f"[bold green]✓ Train/Test Split Ready:[/bold green] Train={len(X_train_scaled):,}, Test={len(X_test_scaled):,}")
        return X_train_scaled, X_test_scaled, y_train, y_test

    def save_artifacts(self, output_dir: str):
        """Save scaler, encoder, feature metadata, and processed arrays."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        
        # Save scaler and label encoder
        scaler_path = out / "scaler.joblib"
        encoder_path = out / "label_encoder.joblib"
        metadata_path = out / "feature_metadata.json"
        
        joblib.dump(self.scaler, scaler_path)
        joblib.dump(self.label_encoder, encoder_path)
        
        # Save rich metadata for API ingestion
        metadata = {
            "feature_names": self.feature_names,
            "num_features": len(self.feature_names),
            "class_mapping": self.class_mapping,
            "feature_medians": self.feature_medians,
            "soc_metadata": SOC_ALERT_METADATA,
        }
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)
            
        console.print(f"[bold green]✓ Saved preprocessing artifacts to:[/bold green] {out}")
        console.print(f"  • [dim]{scaler_path.name}[/dim]")
        console.print(f"  • [dim]{encoder_path.name}[/dim]")
        console.print(f"  • [dim]{metadata_path.name}[/dim]")


def run_pipeline(input_path: str, output_dir: str, use_top_features: bool = True):
    preprocessor = CICIDSPreprocessor(use_top_features=use_top_features)
    raw_df = preprocessor.load_data(input_path)
    X_train, X_test, y_train, y_test = preprocessor.fit_transform(raw_df)
    
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    
    # Save processed numpy matrices for fast model training
    np.savez_compressed(
        out / "processed_data.npz",
        X_train=X_train,
        X_test=X_test,
        y_train=y_train,
        y_test=y_test,
    )
    console.print(f"[bold green]✓ Saved processed numpy datasets to:[/bold green] {out / 'processed_data.npz'}")
    
    preprocessor.save_artifacts(output_dir)
    return preprocessor


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CIC-IDS2017 Preprocessing Pipeline")
    parser.add_argument("--input", type=str, default="data/raw/cicids2017_benchmark.csv", help="Input CSV path or directory")
    parser.add_argument("--output-dir", type=str, default="data/processed", help="Output directory for processed data and artifacts")
    parser.add_argument("--all-features", action="store_true", help="Use all non-zero-variance features instead of top subset")
    args = parser.parse_args()

    run_pipeline(
        input_path=args.input,
        output_dir=args.output_dir,
        use_top_features=not args.all_features,
    )
