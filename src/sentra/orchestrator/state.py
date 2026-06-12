"""
Orchestration state models.

``PipelineState`` is the single object that flows through the LangGraph graph.
Each node reads the fields it needs and writes its results back, so the full
reasoning trail is reconstructable from one object -- which is what makes the
pipeline auditable (and what the observability layer instruments).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from sentra.common.schema import SecurityEvent, Severity


class TriageDecision(BaseModel):
    """Per-event outcome of the Triage node."""

    event_id: str
    escalate: bool
    priority: Severity
    reason: str = Field(..., description="Why this event was escalated/suppressed")


class TechniqueMapping(BaseModel):
    """An ATT&CK technique the Analyst node mapped an incident to (via RAG)."""

    technique_id: str  # e.g. "T1110.001"
    technique_name: str  # e.g. "Brute Force: Password Guessing"
    rationale: str  # why this maps, grounded in retrieved context


class Incident(BaseModel):
    """A correlated cluster of events the Analyst node treats as one story."""

    incident_id: str
    title: str
    severity: Severity
    primary_indicator: str | None = None
    event_ids: list[str] = Field(default_factory=list)
    techniques: list[TechniqueMapping] = Field(default_factory=list)
    narrative: str = ""  # analyst-facing explanation


class IncidentReport(BaseModel):
    """Final Summarizer output -- the deliverable an analyst reads."""

    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    event_count: int = 0
    escalated_count: int = 0
    incidents: list[Incident] = Field(default_factory=list)
    executive_summary: str = ""
    markdown: str = ""  # rendered human-readable report


class PipelineState(BaseModel):
    """State threaded through the agent graph. Mutated in place by each node."""

    # Input ----------------------------------------------------------------
    events: list[SecurityEvent] = Field(default_factory=list)

    # Triage node output ----------------------------------------------------
    triage: list[TriageDecision] = Field(default_factory=list)
    escalated: list[SecurityEvent] = Field(default_factory=list)

    # Analyst node output ---------------------------------------------------
    incidents: list[Incident] = Field(default_factory=list)

    # Summarizer node output ------------------------------------------------
    report: IncidentReport | None = None

    # Observability ---------------------------------------------------------
    trace: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Append-only log of node decisions for audit + metrics",
    )

    def log(self, node: str, **fields: Any) -> None:
        """Append a structured trace entry from a node."""
        self.trace.append({"node": node, "ts": datetime.now(UTC).isoformat(), **fields})
