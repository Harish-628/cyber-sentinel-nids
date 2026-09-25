"""
Flow Ingestion & Analysis Routes.
"""

from typing import List
from fastapi import APIRouter, HTTPException, status

from src.api.alert_store import store
from src.api.inference import engine
from src.api.schemas import (
    BatchFlowPayload,
    BatchFlowResponse,
    FlowAnalysisResponse,
    NetworkFlowPayload,
)

router = APIRouter(prefix="/flows", tags=["Network Flows"])


@router.post("/analyze", response_model=FlowAnalysisResponse, status_code=status.HTTP_200_OK)
async def analyze_flow(payload: NetworkFlowPayload):
    """
    Ingest and analyze a single TCP/IP network flow in real-time.
    Runs the flow through the trained ML model, extracts confidence,
    and creates a security alert if classified as malicious.
    """
    try:
        result = engine.analyze_flow(payload)
        tot_bytes = payload.tot_len_fwd_pkts + payload.tot_len_bwd_pkts
        await store.add_flow_result(result, bytes_transferred=tot_bytes)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference engine failure: {str(e)}",
        )


@router.post("/batch", response_model=BatchFlowResponse, status_code=status.HTTP_200_OK)
async def analyze_batch_flows(batch: BatchFlowPayload):
    """Analyze a batch of up to 500 network flows simultaneously."""
    if len(batch.flows) > 500:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Batch size exceeds maximum limit of 500 flows per request",
        )

    results: List[FlowAnalysisResponse] = []
    malicious_count = 0
    alerts_generated = 0

    for flow in batch.flows:
        res = engine.analyze_flow(flow)
        tot_bytes = flow.tot_len_fwd_pkts + flow.tot_len_bwd_pkts
        await store.add_flow_result(res, bytes_transferred=tot_bytes)
        results.append(res)
        if res.is_malicious:
            malicious_count += 1
            if res.alert:
                alerts_generated += 1

    return BatchFlowResponse(
        total_analyzed=len(results),
        malicious_count=malicious_count,
        alerts_generated=alerts_generated,
        results=results,
    )
