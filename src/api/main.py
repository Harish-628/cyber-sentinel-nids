"""
Intelligent Network Intrusion Detection System (NIDS) - FastAPI Application Entrypoint.
"""

from contextlib import asynccontextmanager
import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from rich.console import Console

from src.api.inference import engine
from src.api.routes import alerts, flows, metrics, simulator, traffic, websocket
from src.api.traffic_simulator import simulator as bg_simulator

console = Console()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup & shutdown events."""
    console.print("[bold green]======================================================[/bold green]")
    console.print("[bold green]  CYBER SENTINEL - INTELLIGENT NIDS ENGINE STARTUP    [/bold green]")
    console.print("[bold green]======================================================[/bold green]")
    
    # 1. Load trained ML model & preprocessors
    console.print("[cyan]Loading trained NIDS ML model and scaling parameters...[/cyan]")
    engine.load()
    console.print(f"[bold green]✓ Loaded model with {len(engine.feature_names)} features and {len(engine.class_mapping)} classes[/bold green]")
    
    # 2. Seed initial baseline flows (simulate initial normal traffic so dashboard has immediate data)
    console.print("[dim]Pre-seeding baseline flows for SOC analytics...[/dim]")
    for _ in range(25):
        await bg_simulator.inject_attack("BENIGN")

    # 3. Start background sniffer/worker (0 attack probability by default for genuine network activity)
    bg_simulator.start(interval=0.8, attack_prob=0.0)
    console.print("[bold green]✓ Background live host network telemetry active (~1.2 flows/sec)[/bold green]")

    yield

    # Shutdown
    console.print("[yellow]Stopping background traffic simulator...[/yellow]")
    bg_simulator.stop()
    console.print("[yellow]NIDS API shutdown complete.[/yellow]")


app = FastAPI(
    title="Intelligent Network Intrusion Detection System (NIDS) API",
    description="Enterprise-grade SOC detection engine powered by CIC-IDS2017 machine learning model.",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routers
app.include_router(flows.router, prefix="/api/v1")
app.include_router(alerts.router, prefix="/api/v1")
app.include_router(metrics.router, prefix="/api/v1")
app.include_router(traffic.router, prefix="/api/v1")
app.include_router(simulator.router, prefix="/api/v1")
app.include_router(websocket.router, prefix="/api/v1")


@app.get("/")
async def root():
    return {
        "system": "Intelligent Network Intrusion Detection System (NIDS)",
        "version": "1.0.0",
        "docs_url": "/docs",
        "health_check": "/api/v1/health",
    }


@app.get("/api/v1/health")
async def health_check():
    return {
        "status": "HEALTHY",
        "model_loaded": engine.is_loaded,
        "features_loaded": len(engine.feature_names),
        "classes_supported": engine.class_mapping,
        "simulator_active": bg_simulator.is_running,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.api.main:app", host="0.0.0.0", port=8000, reload=True)
