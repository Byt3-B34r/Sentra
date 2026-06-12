"""
Local LLM client (Ollama).

Thin wrapper over the Ollama HTTP API with two concerns baked in:

1. Observability -- every call records latency and token counts via an
   injectable metrics sink, so the graph's cost is measurable without the
   agents knowing about Prometheus.
2. Structured output -- ``generate_json`` requests JSON-mode and defensively
   parses the result, because agent nodes need typed data, not prose.

Everything runs against a local Ollama instance (default model llama3.1:8b),
keeping the whole system air-gap capable -- no telemetry leaves the host.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from typing import Any, Protocol

import httpx


class MetricsSink(Protocol):
    """Anything that can record an LLM call's cost. Implemented by the
    Prometheus layer in production and a no-op in tests."""

    def record_llm_call(
        self,
        *,
        model: str,
        node: str,
        latency_s: float,
        prompt_tokens: int,
        completion_tokens: int,
    ) -> None: ...


class _NullMetrics:
    def record_llm_call(self, **_: Any) -> None:  # noqa: D401
        return None


class OllamaClient:
    """Client for a local Ollama server."""

    def __init__(
        self,
        model: str | None = None,
        host: str | None = None,
        metrics: MetricsSink | None = None,
        timeout: float = 120.0,
    ) -> None:
        self.model = model or os.environ.get("SENTRA_MODEL", "llama3.1:8b")
        self.host = host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        self.metrics: MetricsSink = metrics or _NullMetrics()
        self.timeout = timeout

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(f"{self.host}{path}", json=payload)
            resp.raise_for_status()
            return resp.json()

    def generate(
        self,
        prompt: str,
        *,
        system: str | None = None,
        node: str = "unknown",
        json_mode: bool = False,
        temperature: float = 0.1,
    ) -> str:
        """Single-shot generation. Returns the raw text completion."""
        payload: dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature},
        }
        if system:
            payload["system"] = system
        if json_mode:
            payload["format"] = "json"

        start = time.perf_counter()
        data = self._post("/api/generate", payload)
        latency = time.perf_counter() - start

        self.metrics.record_llm_call(
            model=self.model,
            node=node,
            latency_s=latency,
            prompt_tokens=int(data.get("prompt_eval_count", 0)),
            completion_tokens=int(data.get("eval_count", 0)),
        )
        return data.get("response", "")

    def generate_json(
        self,
        prompt: str,
        *,
        system: str | None = None,
        node: str = "unknown",
        repair: bool = True,
    ) -> Any:
        """Generate and parse JSON. Tolerates models that wrap output in prose
        or code fences by extracting the first balanced JSON value."""
        raw = self.generate(prompt, system=system, node=node, json_mode=True, temperature=0.0)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            if not repair:
                raise
            return _extract_json(raw)


def _extract_json(text: str) -> Any:
    """Best-effort recovery of a JSON value embedded in noisy text."""
    text = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```")
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        end = text.rfind(closer)
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                continue
    raise ValueError(f"Could not extract JSON from model output: {text[:200]!r}")


# Convenience factory the graph uses; lets tests inject a fake client.
ClientFactory = Callable[[], OllamaClient]
