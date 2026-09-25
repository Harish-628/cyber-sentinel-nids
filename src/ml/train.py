"""
NIDS Model Training Pipeline.

Trains high-performance intrusion detection classifiers on preprocessed CIC-IDS2017 features.
Supports:
- Balanced Random Forest Classifier
- High-throughput HistGradientBoosting (LightGBM equivalent in scikit-learn)
- Parallel multi-core execution
- Feature importance extraction & explainability
- Model serialization to models/trained/nids_model.joblib
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

import joblib
import numpy as np
from rich.console import Console
from rich.table import Table
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

console = Console()


class NIDSModelTrainer:
    """Trainer for NIDS attack classification models."""

    def __init__(self, model_type: str = "random_forest", n_estimators: int = 100, max_depth: int = 25, random_state: int = 42):
        self.model_type = model_type
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.random_state = random_state
        self.model = None
        self.feature_names: List[str] = []
        self.class_mapping: Dict[int, str] = {}
        self.training_time: float = 0.0

    def load_data(self, data_dir: str) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Load preprocessed arrays and metadata."""
        path = Path(data_dir)
        npz_file = path / "processed_data.npz"
        meta_file = path / "feature_metadata.json"

        if not npz_file.exists():
            raise FileNotFoundError(f"Missing processed data file: {npz_file}. Run preprocess.py first.")
        if not meta_file.exists():
            raise FileNotFoundError(f"Missing metadata file: {meta_file}. Run preprocess.py first.")

        console.print(f"[cyan]Loading processed data from:[/cyan] {npz_file}")
        data = np.load(npz_file)
        X_train = data["X_train"]
        X_test = data["X_test"]
        y_train = data["y_train"]
        y_test = data["y_test"]

        with open(meta_file, "r") as f:
            metadata = json.load(f)
            self.feature_names = metadata["feature_names"]
            self.class_mapping = {int(k): v for k, v in metadata["class_mapping"].items()}

        console.print(f"  • Training samples: [bold]{len(X_train):,}[/bold]")
        console.print(f"  • Validation samples: [bold]{len(X_test):,}[/bold]")
        console.print(f"  • Input features: [bold]{len(self.feature_names)}[/bold]")
        console.print(f"  • Attack classes: [bold]{len(self.class_mapping)}[/bold]")
        return X_train, X_test, y_train, y_test

    def build_model(self):
        """Construct selected classifier with balanced weighting."""
        if self.model_type == "random_forest":
            console.print(f"[bold magenta]Initializing Random Forest Classifier[/bold magenta] (n_estimators={self.n_estimators}, max_depth={self.max_depth}, n_jobs=-1, class_weight='balanced')")
            self.model = RandomForestClassifier(
                n_estimators=self.n_estimators,
                max_depth=self.max_depth,
                min_samples_split=5,
                min_samples_leaf=2,
                class_weight="balanced",
                n_jobs=-1,
                random_state=self.random_state,
                verbose=0,
            )
        elif self.model_type == "gradient_boosting":
            console.print(f"[bold magenta]Initializing HistGradientBoosting Classifier[/bold magenta] (max_iter={self.n_estimators}, max_depth={self.max_depth})")
            self.model = HistGradientBoostingClassifier(
                max_iter=self.n_estimators,
                max_depth=self.max_depth,
                class_weight="balanced",
                random_state=self.random_state,
            )
        else:
            raise ValueError(f"Unsupported model type: {self.model_type}")

    def train(self, X_train: np.ndarray, y_train: np.ndarray):
        """Train the classifier on the training partition."""
        self.build_model()
        console.print("[bold yellow]Training attack classification model...[/bold yellow]")
        start_time = time.time()
        self.model.fit(X_train, y_train)
        self.training_time = time.time() - start_time
        console.print(f"[bold green]✓ Training completed in:[/bold green] [bold white]{self.training_time:.2f} seconds[/bold white]")

    def display_feature_importance(self, top_n: int = 15) -> List[Tuple[str, float]]:
        """Extract and display top feature importances."""
        if not hasattr(self.model, "feature_importances_"):
            return []

        importances = self.model.feature_importances_
        sorted_indices = np.argsort(importances)[::-1]
        
        table = Table(title=f"Top {top_n} NIDS Decision Features (Gini Impurity Importance)", header_style="bold cyan")
        table.add_column("Rank", justify="center", style="dim", width=6)
        table.add_column("Flow Feature Name", style="bold white")
        table.add_column("Importance", justify="right", style="green")
        table.add_column("Relative Weight", justify="left")

        top_features = []
        max_imp = importances[sorted_indices[0]] if len(sorted_indices) > 0 else 1.0
        
        for rank, idx in enumerate(sorted_indices[:top_n], start=1):
            feat_name = self.feature_names[idx] if idx < len(self.feature_names) else f"Feature_{idx}"
            imp_val = float(importances[idx])
            bar_len = int((imp_val / max_imp) * 20)
            bar_str = "█" * bar_len + "░" * (20 - bar_len)
            table.add_row(str(rank), feat_name, f"{imp_val:.4f}", f"[{bar_str}]")
            top_features.append((feat_name, imp_val))

        console.print(table)
        return top_features

    def save_model(self, output_dir: str):
        """Serialize trained model and runtime metadata."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        model_path = out / "nids_model.joblib"
        meta_path = out / "model_info.json"

        console.print(f"[dim]Serializing model to {model_path}...[/dim]")
        joblib.dump(self.model, model_path, compress=3)

        info = {
            "model_type": self.model_type,
            "n_estimators": self.n_estimators,
            "max_depth": self.max_depth,
            "training_time_seconds": round(self.training_time, 2),
            "num_features": len(self.feature_names),
            "feature_names": self.feature_names,
            "class_mapping": self.class_mapping,
        }
        with open(meta_path, "w") as f:
            json.dump(info, f, indent=2)

        console.print(f"[bold green]✓ Successfully exported NIDS model:[/bold green] {model_path}")
        console.print(f"[bold green]✓ Successfully exported Model Info:[/bold green] {meta_path}")


def run_training(data_dir: str, model_dir: str, model_type: str = "random_forest", n_estimators: int = 100, max_depth: int = 25):
    trainer = NIDSModelTrainer(model_type=model_type, n_estimators=n_estimators, max_depth=max_depth)
    X_train, X_test, y_train, y_test = trainer.load_data(data_dir)
    trainer.train(X_train, y_train)
    trainer.display_feature_importance(top_n=15)
    trainer.save_model(model_dir)
    return trainer


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NIDS Attack Classifier Training Pipeline")
    parser.add_argument("--data-dir", type=str, default="data/processed", help="Path to processed data directory")
    parser.add_argument("--model-dir", type=str, default="models/trained", help="Path to save trained models")
    parser.add_argument("--model-type", type=str, choices=["random_forest", "gradient_boosting"], default="random_forest")
    parser.add_argument("--n-estimators", type=int, default=100, help="Number of trees / boosting iterations")
    parser.add_argument("--max-depth", type=int, default=25, help="Maximum tree depth")
    args = parser.parse_args()

    run_training(
        data_dir=args.data_dir,
        model_dir=args.model_dir,
        model_type=args.model_type,
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
    )
