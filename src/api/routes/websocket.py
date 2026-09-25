"""
Real-Time WebSocket Streaming Endpoint for SOC Dashboard.
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from src.api.alert_store import store

router = APIRouter(tags=["WebSocket Stream"])


@router.websocket("/stream/live")
async def live_stream(websocket: WebSocket):
    """
    Bidirectional WebSocket streaming endpoint for SOC Dashboard:
    Pushes real-time FLOW_INGESTED, NEW_ALERT, and ALERT_UPDATED events.
    """
    await store.register_websocket(websocket)
    try:
        # Keep connection open and handle incoming ping or control frames
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        store.unregister_websocket(websocket)
    except Exception:
        store.unregister_websocket(websocket)
