"""
Analyst agent (graph node 2).

Runs only on escalated events. Three steps:

1. Correlate: cluster escalated events that share an indicator (e.g. the same
   source IP) into a single Incident, so related activity is reasoned about as
   one story rather than disconnected alerts.
2. Retrieve: for each incident, pull the most relevant ATT&CK techniques from
   the knowledge base (RAG).
3. Map: ask the LLM to confirm which retrieved techniques apply and explain
   why, grounded in the incident's events and the retrieved context.

This is the expensive node, which is exactly why Triage gates what reaches it.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict

from sentra.common.schema import SecurityEvent, Severity
from sentra.orchestrator.llm import OllamaClient
from sentra.orchestrator.state import (
    Incident,
    PipelineState,
    TechniqueMapping,
)
from sentra.rag.retriever import Retriever

NODE = "analyst"

_SYSTEM = (
    "You are a senior SOC analyst. Given a cluster of correlated security events "
    "and candidate MITRE ATT&CK techniques retrieved from a knowledge base, "
    "decide which techniques genuinely apply and explain why in one sentence each, "
    "citing the events. Respond ONLY with JSON."
)

_SEV_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _cluster(events: list[SecurityEvent]) -> list[list[SecurityEvent]]:
    """Group events by their strongest shared indicator (union-find lite).

    For the demo's scope, clustering on shared indicators (notably the attacker
    source IP) cleanly groups the brute-force -> access -> exec -> C2 chain.
    """
    # Map indicator -> events containing it.
    by_ind: dict[str, list[SecurityEvent]] = defaultdict(list)
    for ev in events:
        for ind in ev.indicators or [ev.event_id]:
            by_ind[ind].append(ev)

    # Greedy: assign each event to the cluster of its most-connected indicator.
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        parent[find(a)] = find(b)

    for ev in events:
        inds = ev.indicators or [ev.event_id]
        for ind in inds[1:]:
            union(inds[0], ind)

    clusters: dict[str, list[SecurityEvent]] = defaultdict(list)
    for ev in events:
        key = find((ev.indicators or [ev.event_id])[0])
        clusters[key].append(ev)
    return list(clusters.values())


def _incident_severity(events: list[SecurityEvent]) -> Severity:
    return max(events, key=lambda e: _SEV_ORDER[e.severity]).severity


def _map_techniques(
    client: OllamaClient, events: list[SecurityEvent], retriever: Retriever
) -> list[TechniqueMapping]:
    # Build a retrieval query from the incident's normalized messages.
    query = " ".join(e.message for e in events)[:1000]
    candidates = retriever.query(query, top_k=4)
    if not candidates:
        return []

    cand_block = "\n".join(
        f"- {c.doc.technique_id} {c.doc.technique_name}: {c.doc.summary}" for c in candidates
    )
    evt_block = "\n".join(f"- {e.short()}" for e in events[:25])
    prompt = (
        f"EVENTS:\n{evt_block}\n\nCANDIDATE TECHNIQUES:\n{cand_block}\n\n"
        "Return a JSON array of the techniques that apply; each item: "
        '{"technique_id": "...", "technique_name": "...", '
        '"rationale": "<one sentence citing the events>"}.'
    )
    data = client.generate_json(prompt, system=_SYSTEM, node=NODE)
    items = data if isinstance(data, list) else data.get("techniques", [])

    valid_ids = {c.doc.technique_id: c.doc for c in candidates}
    mappings: list[TechniqueMapping] = []
    for item in items:
        tid = str(item.get("technique_id", "")).strip()
        if tid not in valid_ids:  # never accept a hallucinated technique id
            continue
        mappings.append(
            TechniqueMapping(
                technique_id=tid,
                technique_name=valid_ids[tid].technique_name,
                rationale=str(item.get("rationale", "")).strip(),
            )
        )
    return mappings


def run(state: PipelineState, client: OllamaClient, retriever: Retriever) -> PipelineState:
    """Graph node entrypoint."""
    incidents: list[Incident] = []
    for cluster in _cluster(state.escalated):
        if not cluster:
            continue
        primary = None
        # Prefer an external-looking IP indicator as the incident's anchor.
        for ev in cluster:
            for ind in ev.indicators:
                if ind.count(".") == 3:  # crude IPv4 check; fine for demo
                    primary = ind
                    break
            if primary:
                break

        ids = sorted(e.event_id for e in cluster)
        inc_id = hashlib.sha256("|".join(ids).encode()).hexdigest()[:12]
        techniques = _map_techniques(client, cluster, retriever)
        sev = _incident_severity(cluster)

        incidents.append(
            Incident(
                incident_id=inc_id,
                title=(
                    f"Activity involving {primary}"
                    if primary
                    else f"Correlated incident ({len(cluster)} events)"
                ),
                severity=sev,
                primary_indicator=primary,
                event_ids=ids,
                techniques=techniques,
            )
        )

    incidents.sort(key=lambda i: _SEV_ORDER[i.severity], reverse=True)
    state.incidents = incidents
    state.log(
        NODE,
        incidents=len(incidents),
        techniques_total=sum(len(i.techniques) for i in incidents),
    )
    return state
