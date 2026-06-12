"""
Summarizer agent (graph node 3).

Produces the analyst-facing deliverable from the structured incidents. The
trust boundary is deliberate:

* The LLM writes ONLY natural-language analysis -- the per-incident narrative
  and the executive summary. It reasons, it does not format.
* All structural content (IDs, counts, technique tables, severity ordering) is
  rendered deterministically in Python from the typed Incident objects.

So a model that miscounts or mangles an ID cannot corrupt the report's facts;
the worst it can do is write a weak paragraph. This is the same reason the
report ships as both structured JSON and rendered Markdown.
"""

from __future__ import annotations

from sentra.common.schema import Severity
from sentra.orchestrator.llm import OllamaClient
from sentra.orchestrator.state import Incident, IncidentReport, PipelineState

NODE = "summarizer"

_SYSTEM = (
    "You are a SOC analyst writing an incident report for responders. Write "
    "clear, factual analysis. No speculation beyond the evidence. Be concise."
)

_SEV_BADGE = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}


def _narrative(client: OllamaClient, inc: Incident, event_lines: list[str]) -> str:
    tech = ", ".join(f"{t.technique_id} ({t.technique_name})" for t in inc.techniques)
    prompt = (
        f"Incident anchor: {inc.primary_indicator or 'n/a'}\n"
        f"Severity: {inc.severity.value}\n"
        f"Mapped ATT&CK techniques: {tech or 'none'}\n\n"
        f"Correlated events (chronological):\n" + "\n".join(event_lines) + "\n\n"
        "Write a 3-5 sentence narrative explaining what happened, the likely "
        "attacker objective, and what a responder should do next. Plain prose."
    )
    return client.generate(prompt, system=_SYSTEM, node=NODE, temperature=0.2).strip()


def _executive_summary(
    client: OllamaClient, incidents: list[Incident], total: int, escalated: int
) -> str:
    if not incidents:
        return (
            f"Reviewed {total} events; none required escalation. "
            "No incidents identified in this batch."
        )
    titles = "; ".join(f"[{i.severity.value}] {i.title}" for i in incidents[:5])
    prompt = (
        f"{total} events triaged, {escalated} escalated, "
        f"{len(incidents)} incident(s) identified: {titles}. "
        "Write a 2-3 sentence executive summary for a shift lead."
    )
    return client.generate(prompt, system=_SYSTEM, node=NODE, temperature=0.2).strip()


def _render_markdown(report: IncidentReport, narratives: dict[str, str]) -> str:
    lines: list[str] = []
    lines.append("# SENTRA Incident Report")
    lines.append("")
    lines.append(f"*Generated: {report.generated_at.isoformat()}*")
    lines.append("")
    lines.append(
        f"**Events triaged:** {report.event_count} &nbsp;|&nbsp; "
        f"**Escalated:** {report.escalated_count} &nbsp;|&nbsp; "
        f"**Incidents:** {len(report.incidents)}"
    )
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(report.executive_summary or "_None._")
    lines.append("")

    if not report.incidents:
        lines.append("_No incidents identified._")
        return "\n".join(lines)

    lines.append("## Incidents")
    for inc in report.incidents:
        lines.append("")
        lines.append(f"### [{_SEV_BADGE[inc.severity]}] {inc.title}")
        lines.append("")
        lines.append(f"- **Incident ID:** `{inc.incident_id}`")
        if inc.primary_indicator:
            lines.append(f"- **Primary indicator:** `{inc.primary_indicator}`")
        lines.append(f"- **Correlated events:** {len(inc.event_ids)}")
        lines.append("")
        # Deterministic technique table -- never LLM-formatted.
        if inc.techniques:
            lines.append("| ATT&CK ID | Technique | Rationale |")
            lines.append("|-----------|-----------|-----------|")
            for t in inc.techniques:
                rat = t.rationale.replace("|", "\\|")
                lines.append(f"| `{t.technique_id}` | {t.technique_name} | {rat} |")
            lines.append("")
        lines.append("**Analysis:**")
        lines.append("")
        lines.append(narratives.get(inc.incident_id, "_No narrative generated._"))
    return "\n".join(lines)


def run(state: PipelineState, client: OllamaClient) -> PipelineState:
    """Graph node entrypoint."""
    by_id = {e.event_id: e for e in state.events}
    narratives: dict[str, str] = {}
    for inc in state.incidents:
        ev_lines = [by_id[eid].short() for eid in inc.event_ids if eid in by_id]
        narratives[inc.incident_id] = _narrative(client, inc, ev_lines)

    exec_summary = _executive_summary(
        client, state.incidents, len(state.events), len(state.escalated)
    )

    report = IncidentReport(
        event_count=len(state.events),
        escalated_count=len(state.escalated),
        incidents=state.incidents,
        executive_summary=exec_summary,
    )
    report.markdown = _render_markdown(report, narratives)
    state.report = report
    state.log(NODE, incidents=len(state.incidents), report_chars=len(report.markdown))
    return state
