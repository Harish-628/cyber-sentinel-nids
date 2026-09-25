#!/usr/bin/env bash
# ==============================================================================
# CYBER SENTINEL // Intelligent NIDS Service Orchestration Script
# ==============================================================================
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_DIR}"

echo "======================================================"
echo "  CYBER SENTINEL // STARTING NIDS SYSTEM              "
echo "======================================================"

# Verify Python virtualenv
if [ ! -d ".venv" ]; then
    echo "[!] Virtual environment (.venv) not found. Setting up..."
    uv venv --python 3.11 .venv
    uv pip install --python .venv/bin/python numpy pandas scikit-learn joblib rich pydantic fastapi uvicorn websockets httpx
fi

# Verify ML model artifacts exist
if [ ! -f "models/trained/nids_model.joblib" ]; then
    echo "[*] Initializing benchmark dataset and training NIDS ML model..."
    .venv/bin/python src/ml/dataset_generator.py --samples 50000 --output data/raw/cicids2017_benchmark.csv
    .venv/bin/python src/ml/preprocess.py --input data/raw/cicids2017_benchmark.csv --output-dir data/processed
    .venv/bin/python src/ml/train.py --data-dir data/processed --model-dir models/trained
fi

# Start FastAPI backend in background
echo "[*] Launching NIDS FastAPI Backend on http://0.0.0.0:8000..."
.venv/bin/python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

# Trap signals for graceful shutdown
cleanup() {
    echo ""
    echo "[!] Shutting down services..."
    kill "$BACKEND_PID" 2>/dev/null || true
    if [ -n "${FRONTEND_PID:-}" ]; then
        kill "$FRONTEND_PID" 2>/dev/null || true
    fi
    echo "[✓] NIDS services gracefully stopped."
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# Start Next.js frontend
echo "[*] Launching SOC Dashboard on http://localhost:3000..."
cd "${PROJECT_DIR}/frontend"
npm run dev -- -p 3000 &
FRONTEND_PID=$!

echo ""
echo "======================================================"
echo "  CYBER SENTINEL SERVICES ACTIVE                      "
echo "  • SOC Dashboard: http://localhost:3000              "
echo "  • Backend API:   http://localhost:8000              "
echo "  • Swagger Docs:  http://localhost:8000/docs         "
echo "======================================================"
echo "Press Ctrl+C to terminate all services."

wait
