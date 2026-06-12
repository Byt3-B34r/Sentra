"""
Pipeline orchestrator.

Wires the three agent nodes (triage -> analyst -> summarizer) into one runnable
pipeline. Two execution backends, identical semantics:

* ``run_langgraph`` -- production. Builds a LangGraph StateGraph. Gives the
  graph abstraction, explicit edges, and a clean path to future features
  (conditional routing, checkpointing, streaming intermediate state).
* ``run_sequential`` -- dependency-free fallback used in CI and anywhere
  LangGraph is not installed. Executes the same node functions in order.

The node functions live in ``sentra.agents`` and know nothing about which
runner invokes them, so the two backends can never drift in behavior.
"""

from __future__ import annotations

from dataclasses import dataclass

from sentra.agents import analyst, summarizer, triage
from sentra.orchestrator.llm import OllamaClient
from sentra.orchestrator.state import PipelineState
from sentra.rag.retriever import Retriever


@dataclass
class Pipeline:
    """Holds the dependencies the nodes need (LLM client + retriever)."""

    client: OllamaClient
    retriever: Retriever

    # -- node adapters: bind dependencies, keep a uniform (state)->state shape -
    def _triage(self, state: PipelineState) -> PipelineState:
        return triage.run(state, self.client)

    def _analyst(self, state: PipelineState) -> PipelineState:
        return analyst.run(state, self.client, self.retriever)

    def _summarizer(self, state: PipelineState) -> PipelineState:
        return summarizer.run(state, self.client)

    # -- backends ----------------------------------------------------------
    def run_sequential(self, state: PipelineState) -> PipelineState:
        """Dependency-free execution. Used in CI."""
        state = self._triage(state)
        state = self._analyst(state)
        state = self._summarizer(state)
        return state

    def run_langgraph(self, state: PipelineState) -> PipelineState:
        """Production execution via LangGraph StateGraph."""
        from langgraph.graph import END, START, StateGraph

        # LangGraph passes state as a dict; we adapt at the boundary so the
        # node functions keep operating on the typed PipelineState model.
        def wrap(fn):
            def _node(s: dict) -> dict:
                st = s if isinstance(s, PipelineState) else PipelineState(**s)
                return fn(st).model_dump()

            return _node

        graph = StateGraph(dict)
        graph.add_node("triage", wrap(self._triage))
        graph.add_node("analyst", wrap(self._analyst))
        graph.add_node("summarizer", wrap(self._summarizer))
        graph.add_edge(START, "triage")
        graph.add_edge("triage", "analyst")
        graph.add_edge("analyst", "summarizer")
        graph.add_edge("summarizer", END)
        compiled = graph.compile()

        result = compiled.invoke(state.model_dump())
        return PipelineState(**result)

    def run(self, state: PipelineState, *, prefer_langgraph: bool = True) -> PipelineState:
        """Run via LangGraph if available, else sequential. Same result."""
        if prefer_langgraph:
            try:
                return self.run_langgraph(state)
            except Exception:  # noqa: BLE001 -- missing dep or runtime -> fallback
                pass
        return self.run_sequential(state)
