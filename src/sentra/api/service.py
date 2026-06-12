"""
SENTRA API service.

A single FastAPI app exposing the pipeline:

* ``POST /v1/analyze``   -- submit raw telemetry, get an IncidentReport back.
* ``GET  /healthz``      -- liveness/readiness for Kubernetes probes.
* ``GET  /metrics``      -- Prometheus scrape endpoint.

Dependencies (LLM client, retriever, metrics) are built once at startup and
injected into the pipeline, so the same app object can be driven with fakes in
tests. Keeping it one service keeps the demo deployable; the architecture
splits cleanly into ingest/orchestrator services later if throughput demands.
"""

from __future__ import annotations

import os
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException

from sentra.common.schema import SourceType
from sentra.ingest.dispatch import ingest
from sentra.observability import metrics as M
from sentra.orchestrator.llm import OllamaClient
from sentra.orchestrator.pipeline import Pipeline
from sentra.orchestrator.state import IncidentReport, PipelineState
from sentra.rag.retriever import build_retriever

KB_PATH = os.environ.get("SENTRA_KB", "data/attack_kb/techniques.json")


class _Deps:
    """Container for runtime dependencies, assembled at startup."""

    pipeline: Pipeline | None = None


deps = _Deps()


@asynccontextmanager
async def lifespan(app: FastAPI):
    client = OllamaClient(metrics=M.PrometheusMetrics())
    retriever = build_retriever(KB_PATH, prefer_embeddings=True)
    deps.pipeline = Pipeline(client=client, retriever=retriever)
    yield
    deps.pipeline = None


app = FastAPI(title="SENTRA", version="0.1.0", lifespan=lifespan)


class TelemetrySource(BaseModel):
    """One raw telemetry blob plus its (optional) explicit source type."""

    content: str = Field(..., description="Raw telemetry blob")
    source: SourceType | None = Field(
        None, description="Explicit source type; auto-detected if omitted"
    )


class AnalyzeRequest(BaseModel):
    """Accepts either a single source (back-compatible) or a list of sources."""

    content: str | None = Field(None, description="Raw telemetry blob (single source)")
    source: SourceType | None = Field(
        None, description="Explicit source type for `content`; auto-detected if omitted"
    )
    sources: list[TelemetrySource] | None = Field(
        None, description="Multiple telemetry blobs analyzed together as one incident set"
    )

    def to_sources(self) -> list[TelemetrySource]:
        if self.sources:
            return self.sources
        if self.content is not None:
            return [TelemetrySource(content=self.content, source=self.source)]
        raise ValueError("Provide either `content` or `sources`.")


class AnalyzeResponse(BaseModel):
    report: IncidentReport
    trace: list[dict]


@app.get("/healthz", response_class=PlainTextResponse)
async def healthz() -> str:
    return "ok" if deps.pipeline is not None else "starting"


@app.get("/metrics")
async def prometheus_metrics() -> PlainTextResponse:
    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/v1/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    assert deps.pipeline is not None, "pipeline not initialized"

    try:
        requested = req.to_sources()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    events = []
    for ts in requested:
        events.extend(ingest(ts.content, source=ts.source))
    events.sort(key=lambda e: e.timestamp)

    for st in {e.source_type.value for e in events}:
        M.record_ingest(st, sum(1 for e in events if e.source_type.value == st))

    M.PIPELINE_INFLIGHT.inc()
    start = time.perf_counter()
    try:
        state = deps.pipeline.run(PipelineState(events=events))
    finally:
        M.PIPELINE_INFLIGHT.dec()
        M.PIPELINE_LATENCY.observe(time.perf_counter() - start)

    suppressed = len(state.events) - len(state.escalated)
    M.record_triage(len(state.escalated), suppressed)
    for inc in state.incidents:
        M.record_incident(inc.severity.value)

    return AnalyzeResponse(report=state.report, trace=state.trace)
