"""Shared test fixtures.

The FakeOllama client makes the whole pipeline deterministic and offline, so CI
needs neither a GPU nor a running Ollama. It mirrors the real client's two
methods and returns plausible structured output keyed on the calling node.
"""

from __future__ import annotations

import re

import pytest

from sentra.ingest.dispatch import ingest_files
from sentra.rag.retriever import build_retriever

KB = "data/attack_kb/techniques.json"
SAMPLES = [
    "data/samples/auth.log",
    "data/samples/conn.log",
    "data/samples/notice.log",
]


class FakeOllama:
    """Deterministic stand-in for OllamaClient."""

    def generate_json(self, prompt, system=None, node="unknown", repair=True):
        if node == "triage":
            out = []
            for line in prompt.splitlines():
                m = re.match(r"\s*(\d+)\.", line)
                if not m:
                    continue
                i = int(m.group(1))
                escalate = any(s in line for s in ("failure", "invalid", "Guessing", "Suspicious"))
                out.append(
                    {
                        "index": i,
                        "escalate": escalate,
                        "priority": "medium" if escalate else "low",
                        "reason": "fake triage",
                    }
                )
            return out
        # analyst node: confirm every candidate technique id in the prompt
        ids: list[str] = []
        for tid in re.findall(r"(T\d{4}(?:\.\d{3})?)", prompt):
            if tid not in ids:
                ids.append(tid)
        return [
            {"technique_id": t, "technique_name": "x", "rationale": f"consistent with {t}"}
            for t in ids
        ]

    def generate(self, prompt, system=None, node="unknown", json_mode=False, temperature=0.1):
        if "executive summary" in prompt:
            return "Brute-force compromise with code execution. Contain immediately."
        return "Repeated SSH failures then success, remote payload executed. Isolate host."


@pytest.fixture
def fake_client():
    return FakeOllama()


@pytest.fixture
def retriever():
    # Keyword retriever: deterministic, no Ollama needed.
    return build_retriever(KB, prefer_embeddings=False)


@pytest.fixture
def sample_events():
    return ingest_files(SAMPLES)
