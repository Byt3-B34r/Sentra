"""
Triage agent (graph node 1).

Decides, per event, whether it is worth the expensive downstream analysis.
Runs on *every* event, so it must be cheap. Strategy:

1. Heuristic pass: obvious decisions (clearly benign internal success, clearly
   hostile high-severity notices) are made with zero LLM cost.
2. LLM pass: only the ambiguous remainder is sent to the model, batched into a
   single call to amortize inference latency.

This two-tier design is what keeps the pipeline tractable on local hardware:
the model never sees noise it does not need to judge.
"""

from __future__ import annotations

from sentra.common.schema import SecurityEvent, Severity
from sentra.orchestrator.llm import OllamaClient
from sentra.orchestrator.state import PipelineState, TriageDecision

NODE = "triage"

_SYSTEM = (
    "You are a SOC triage assistant. For each security event, decide whether it "
    "warrants escalation to a human analyst. Escalate anything indicating "
    "compromise, lateral movement, privilege escalation, or attacker success. "
    "Suppress routine benign activity. Respond ONLY with JSON."
)


def _heuristic(ev: SecurityEvent) -> TriageDecision | None:
    """Return a decision when it can be made without the LLM, else None."""
    # Clear escalate: high/critical severity, or attacker auth success.
    if ev.severity in (Severity.HIGH, Severity.CRITICAL):
        return TriageDecision(
            event_id=ev.event_id,
            escalate=True,
            priority=ev.severity,
            reason=f"High-severity {ev.action} pre-classified at ingest.",
        )
    if ev.action == "sudo_command" and ev.raw.get("risky"):
        return TriageDecision(
            event_id=ev.event_id,
            escalate=True,
            priority=Severity.HIGH,
            reason="Privilege escalation running a remote payload download.",
        )
    # Clear suppress: benign internal network flows with no auth context.
    if ev.action == "network_flow" and ev.severity == Severity.INFO:
        return TriageDecision(
            event_id=ev.event_id,
            escalate=False,
            priority=Severity.INFO,
            reason="Routine network flow, no anomaly signal.",
        )
    return None  # ambiguous -> defer to LLM


def _llm_batch(client: OllamaClient, events: list[SecurityEvent]) -> list[TriageDecision]:
    """One LLM call judging all ambiguous events at once."""
    if not events:
        return []
    lines = [f"{i}. (id={e.event_id}) {e.short()}" for i, e in enumerate(events)]
    prompt = (
        "Judge each event. Return a JSON array; each item: "
        '{"index": <int>, "escalate": <bool>, "priority": '
        '"info|low|medium|high|critical", "reason": "<short>"}.\n\nEVENTS:\n' + "\n".join(lines)
    )
    data = client.generate_json(prompt, system=_SYSTEM, node=NODE)
    items = data if isinstance(data, list) else data.get("results", [])

    decisions: list[TriageDecision] = []
    by_index = {i: e for i, e in enumerate(events)}
    for item in items:
        ev = by_index.get(int(item.get("index", -1)))
        if ev is None:
            continue
        try:
            prio = Severity(item.get("priority", "medium"))
        except ValueError:
            prio = Severity.MEDIUM
        decisions.append(
            TriageDecision(
                event_id=ev.event_id,
                escalate=bool(item.get("escalate", False)),
                priority=prio,
                reason=str(item.get("reason", "LLM triage")),
            )
        )
    # Fail safe: any event the model skipped is escalated (better to over-review).
    judged = {d.event_id for d in decisions}
    for ev in events:
        if ev.event_id not in judged:
            decisions.append(
                TriageDecision(
                    event_id=ev.event_id,
                    escalate=True,
                    priority=Severity.MEDIUM,
                    reason="LLM returned no verdict; escalated by fail-safe.",
                )
            )
    return decisions


def run(state: PipelineState, client: OllamaClient) -> PipelineState:
    """Graph node entrypoint."""
    heuristic_decisions: list[TriageDecision] = []
    ambiguous: list[SecurityEvent] = []
    for ev in state.events:
        d = _heuristic(ev)
        if d is None:
            ambiguous.append(ev)
        else:
            heuristic_decisions.append(d)

    llm_decisions = _llm_batch(client, ambiguous)
    state.triage = heuristic_decisions + llm_decisions

    by_id = {e.event_id: e for e in state.events}
    state.escalated = [
        by_id[d.event_id] for d in state.triage if d.escalate and d.event_id in by_id
    ]
    state.log(
        NODE,
        total=len(state.events),
        heuristic=len(heuristic_decisions),
        llm_judged=len(ambiguous),
        escalated=len(state.escalated),
    )
    return state
