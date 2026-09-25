"""
Unit test for Phase 1 ML Pipeline: Preprocessor, Model Inference, and Evaluation.
"""

import json
from pathlib import Path
import joblib
import numpy as np

def test_artifacts_exist():
    base = Path(__file__).resolve().parent.parent
    assert (base / "models/trained/nids_model.joblib").exists(), "Trained model missing"
    assert (base / "data/processed/scaler.joblib").exists(), "Scaler missing"
    assert (base / "data/processed/label_encoder.joblib").exists(), "Encoder missing"
    assert (base / "data/processed/feature_metadata.json").exists(), "Metadata missing"
    assert (base / "models/evaluation/evaluation_report.json").exists(), "Evaluation report missing"

def test_model_inference():
    base = Path(__file__).resolve().parent.parent
    model = joblib.load(base / "models/trained/nids_model.joblib")
    scaler = joblib.load(base / "data/processed/scaler.joblib")
    with open(base / "data/processed/feature_metadata.json", "r") as f:
        meta = json.load(f)
        
    num_features = meta["num_features"]
    mock_flow = np.zeros((1, num_features))
    scaled_flow = scaler.transform(mock_flow)
    
    pred = model.predict(scaled_flow)
    proba = model.predict_proba(scaled_flow)
    
    assert len(pred) == 1
    assert proba.shape[1] == len(meta["class_mapping"])
    assert np.isclose(np.sum(proba), 1.0)
    print(f"Test passed! Prediction: {meta['class_mapping'][str(pred[0])]}, Max Confidence: {np.max(proba):.4f}")

if __name__ == "__main__":
    test_artifacts_exist()
    test_model_inference()
    print("All ML pipeline verification checks passed successfully!")
