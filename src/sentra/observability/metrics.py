"""
Observability: Prometheus metrics.

Implements the ``MetricsSink`` protocol the LLM client already depends on, plus
pipeline-level instruments. Nothing in the agent or orchestrator code imports
Prometheus directly -- they only know the protocol -- so metrics can be swapped
for a no-op in tests and the production path stays clean.

Why these specific metrics: on local inference the bottleneck is the model, so
the questions that matter operationally are "how long are calls taking, how many
tokens are we burning, and where in the graph is the cost going". Every
instrument here answers one of those, labelled by node so a Grafana panel can
attribute cost per agent.
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

# -- LLM-call instruments (fed by OllamaClient via record_llm_call) ---------- #
LLM_CALLS = Counter(
    "sentra_llm_calls_total",
    "Total LLM calls made",
    labelnames=("model", "node"),
)
LLM_LATENCY = Histogram(
    "sentra_llm_latency_seconds",
    "LLM call latency",
    labelnames=("model", "node"),
    # Buckets tuned for local 8B inference: sub-second is rare, tens of seconds
    # for big batches is normal -- so the buckets stretch accordingly.
    buckets=(0.5, 1, 2, 4, 8, 15, 30, 60, 120),
)
LLM_PROMPT_TOKENS = Counter(
    "sentra_llm_prompt_tokens_total",
    "Prompt tokens consumed",
    labelnames=("model", "node"),
)
LLM_COMPLETION_TOKENS = Counter(
    "sentra_llm_completion_tokens_total",
    "Completion tokens generated",
    labelnames=("model", "node"),
)

# -- Pipeline-level instruments --------------------------------------------- #
EVENTS_INGESTED = Counter(
    "sentra_events_ingested_total",
    "Security events normalized at ingest",
    labelnames=("source_type",),
)
EVENTS_ESCALATED = Counter(
    "sentra_events_escalated_total",
    "Events escalated by triage",
)
EVENTS_SUPPRESSED = Counter(
    "sentra_events_suppressed_total",
    "Events suppressed by triage (saved from expensive analysis)",
)
INCIDENTS_CREATED = Counter(
    "sentra_incidents_total",
    "Incidents produced",
    labelnames=("severity",),
)
PIPELINE_LATENCY = Histogram(
    "sentra_pipeline_latency_seconds",
    "End-to-end pipeline wall time",
    buckets=(1, 2, 5, 10, 20, 40, 80, 160),
)
PIPELINE_INFLIGHT = Gauge(
    "sentra_pipeline_inflight",
    "Pipelines currently executing",
)


class PrometheusMetrics:
    """Concrete MetricsSink wired to the Prometheus instruments above."""

    def record_llm_call(
        self,
        *,
        model: str,
        node: str,
        latency_s: float,
        prompt_tokens: int,
        completion_tokens: int,
    ) -> None:
        LLM_CALLS.labels(model, node).inc()
        LLM_LATENCY.labels(model, node).observe(latency_s)
        LLM_PROMPT_TOKENS.labels(model, node).inc(prompt_tokens)
        LLM_COMPLETION_TOKENS.labels(model, node).inc(completion_tokens)


def record_ingest(source_type: str, n: int) -> None:
    EVENTS_INGESTED.labels(source_type).inc(n)


def record_triage(escalated: int, suppressed: int) -> None:
    EVENTS_ESCALATED.inc(escalated)
    EVENTS_SUPPRESSED.inc(suppressed)


def record_incident(severity: str) -> None:
    INCIDENTS_CREATED.labels(severity).inc()
