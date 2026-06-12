"""Agent + pipeline tests using the deterministic fake client."""

from __future__ import annotations

from sentra.agents import analyst, triage
from sentra.orchestrator.pipeline import Pipeline
from sentra.orchestrator.state import PipelineState


# -- RAG -------------------------------------------------------------------- #
def test_rag_retrieves_brute_force(retriever):
    hits = retriever.query("many failed ssh password attempts invalid user", top_k=2)
    assert hits
    assert hits[0].doc.technique_id == "T1110.001"


def test_rag_retrieves_remote_exec(retriever):
    hits = retriever.query("sudo bash curl download script pipe shell execute", top_k=2)
    assert any(h.doc.technique_id == "T1059.004" for h in hits)


# -- Triage ----------------------------------------------------------------- #
def test_triage_uses_heuristics_for_free(fake_client, sample_events):
    state = triage.run(PipelineState(events=sample_events), fake_client)
    tr = state.trace[0]
    # Some events decided without the LLM (high-severity + benign flows).
    assert tr["heuristic"] > 0
    assert tr["escalated"] > 0
    assert tr["total"] == len(sample_events)


def test_triage_escalates_high_severity(fake_client, sample_events):
    state = triage.run(PipelineState(events=sample_events), fake_client)
    escalated_ids = {e.event_id for e in state.escalated}
    high = [e for e in sample_events if e.severity.value in ("high", "critical")]
    for e in high:
        assert e.event_id in escalated_ids


# -- Analyst correlation ---------------------------------------------------- #
def test_analyst_correlates_into_single_incident(fake_client, retriever, sample_events):
    state = PipelineState(events=sample_events)
    state = triage.run(state, fake_client)
    state = analyst.run(state, fake_client, retriever)
    # The attack is one story anchored on the attacker IP.
    assert len(state.incidents) == 1
    inc = state.incidents[0]
    assert inc.primary_indicator == "203.0.113.7"
    assert inc.severity.value == "high"
    assert len(inc.techniques) > 0


def test_analyst_rejects_hallucinated_technique(fake_client, retriever, sample_events):
    state = PipelineState(events=sample_events)
    state = triage.run(state, fake_client)
    state = analyst.run(state, fake_client, retriever)
    # Every mapped technique id must exist in the KB (no invented ids).
    from sentra.rag.retriever import load_kb

    kb_ids = {d.technique_id for d in load_kb("data/attack_kb/techniques.json")}
    for inc in state.incidents:
        for t in inc.techniques:
            assert t.technique_id in kb_ids


# -- Full pipeline ---------------------------------------------------------- #
def test_full_pipeline_produces_report(fake_client, retriever, sample_events):
    pipe = Pipeline(client=fake_client, retriever=retriever)
    state = pipe.run(PipelineState(events=sample_events), prefer_langgraph=False)
    assert state.report is not None
    assert state.report.event_count == len(sample_events)
    assert state.report.escalated_count > 0
    assert "SENTRA Incident Report" in state.report.markdown
    assert [t["node"] for t in state.trace] == ["triage", "analyst", "summarizer"]
