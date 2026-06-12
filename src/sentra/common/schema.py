"""
Common Event Schema (CES) for SENTRA.

Every input source -- regardless of its native shape (auth.log lines, Zeek
conn.log TSV, Zeek notice.log, future sources) -- is normalized into a single
``SecurityEvent`` model. Downstream agents reason only over this schema, which
means new telemetry sources can be added by writing one normalizer rather than
touching the agent graph.

This separation (raw -> normalized -> reasoned) is the backbone of the pipeline.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SourceType(str, Enum):
    """Native telemetry source a SecurityEvent was normalized from."""

    AUTH_LOG = "auth_log"  # Linux /var/log/auth.log style records
    ZEEK_CONN = "zeek_conn"  # Zeek conn.log network flow records
    ZEEK_NOTICE = "zeek_notice"  # Zeek notice.log IDS-style alerts
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """Coarse severity assigned at normalization time (pre-triage heuristic).

    The Triage agent may revise this; this is only a cheap first pass so that
    obviously-benign noise can be deprioritized before any inference happens.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NetworkEndpoint(BaseModel):
    """A normalized (host, port) pair. Either field may be unknown."""

    ip: str | None = None
    port: int | None = None
    hostname: str | None = None


class SecurityEvent(BaseModel):
    """Canonical normalized telemetry record.

    Fields are deliberately source-agnostic. Anything specific to the original
    record that does not map cleanly is preserved under ``raw`` so no fidelity
    is lost during normalization.
    """

    event_id: str = Field(..., description="Stable unique id for this event")
    timestamp: datetime = Field(..., description="Event time (UTC)")
    source_type: SourceType
    severity: Severity = Severity.INFO

    # Actor / subject -------------------------------------------------------
    user: str | None = Field(None, description="Associated username, if any")
    process: str | None = Field(None, description="Originating process/service")
    action: str | None = Field(None, description="What happened, normalized verb")
    outcome: str | None = Field(None, description="success | failure | unknown")

    # Network ---------------------------------------------------------------
    src: NetworkEndpoint = Field(default_factory=NetworkEndpoint)
    dst: NetworkEndpoint = Field(default_factory=NetworkEndpoint)

    # Free-form -------------------------------------------------------------
    message: str = Field("", description="Human-readable normalized summary")
    indicators: list[str] = Field(
        default_factory=list,
        description="Extracted IOCs (IPs, users, hashes) for cross-correlation",
    )
    raw: dict[str, Any] = Field(
        default_factory=dict,
        description="Original parsed fields preserved verbatim",
    )

    def short(self) -> str:
        """One-line representation used in agent prompts to control token cost."""
        who = self.user or "-"
        src = self.src.ip or "-"
        return (
            f"[{self.timestamp.isoformat()}] {self.source_type.value} "
            f"sev={self.severity.value} user={who} src={src} "
            f"action={self.action or '-'} outcome={self.outcome or '-'} "
            f":: {self.message}"
        )
