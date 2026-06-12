"""
ATT&CK knowledge-base retriever.

Exposes a single ``Retriever`` interface with two implementations:

* ``EmbeddingRetriever`` -- production path. Uses LlamaIndex with local Ollama
  embeddings (nomic-embed-text). Air-gap capable; nothing leaves the host.
* ``KeywordRetriever`` -- deterministic fallback for CI and environments with
  no running Ollama. Pure-Python lexical overlap scoring, no dependencies.

The agent depends only on the ``Retriever`` protocol, so the graph is testable
without a GPU and the demo runs real semantic retrieval -- same interface,
swapped implementation.
"""

from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel


class TechniqueDoc(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    summary: str
    indicators: str

    def text(self) -> str:
        return f"{self.technique_name} ({self.tactic}). {self.summary} {self.indicators}"


def load_kb(path: str | Path) -> list[TechniqueDoc]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return [TechniqueDoc(**d) for d in data]


class Retrieved(BaseModel):
    doc: TechniqueDoc
    score: float


class Retriever(Protocol):
    def query(self, text: str, top_k: int = 3) -> list[Retrieved]: ...


# --------------------------------------------------------------------------- #
# Deterministic lexical fallback (no external services)                       #
# --------------------------------------------------------------------------- #
_TOKEN = re.compile(r"[a-z0-9.]+")


def _tokens(s: str) -> list[str]:
    return _TOKEN.findall(s.lower())


class KeywordRetriever:
    """TF-IDF-ish lexical retriever. Deterministic, dependency-free."""

    def __init__(self, docs: list[TechniqueDoc]) -> None:
        self.docs = docs
        self._doc_tokens = [_tokens(d.text()) for d in docs]
        # Inverse document frequency over the small KB.
        df: dict[str, int] = {}
        for toks in self._doc_tokens:
            for t in set(toks):
                df[t] = df.get(t, 0) + 1
        n = len(docs)
        self._idf = {t: math.log((n + 1) / (c + 0.5)) for t, c in df.items()}

    def _score(self, q_tokens: list[str], d_tokens: list[str]) -> float:
        d_set = set(d_tokens)
        return sum(self._idf.get(t, 0.0) for t in q_tokens if t in d_set)

    def query(self, text: str, top_k: int = 3) -> list[Retrieved]:
        q = _tokens(text)
        scored = [
            Retrieved(doc=d, score=self._score(q, dt))
            for d, dt in zip(self.docs, self._doc_tokens, strict=True)
        ]
        scored.sort(key=lambda r: r.score, reverse=True)
        return [r for r in scored if r.score > 0][:top_k]


# --------------------------------------------------------------------------- #
# Production embedding retriever (LlamaIndex + Ollama)                         #
# --------------------------------------------------------------------------- #
class EmbeddingRetriever:
    """Semantic retriever using LlamaIndex with local Ollama embeddings.

    Imported lazily so the package has no hard dependency on LlamaIndex when
    only the fallback is used (e.g. in CI).
    """

    def __init__(
        self,
        docs: list[TechniqueDoc],
        embed_model: str = "nomic-embed-text",
        ollama_host: str = "http://localhost:11434",
    ) -> None:
        from llama_index.core import Document, Settings, VectorStoreIndex
        from llama_index.embeddings.ollama import OllamaEmbedding

        Settings.embed_model = OllamaEmbedding(model_name=embed_model, base_url=ollama_host)
        self._by_text = {d.text(): d for d in docs}
        index = VectorStoreIndex(
            [Document(text=d.text(), metadata={"id": d.technique_id}) for d in docs]
        )
        self._engine = index.as_retriever(similarity_top_k=3)

    def query(self, text: str, top_k: int = 3) -> list[Retrieved]:
        nodes = self._engine.retrieve(text)[:top_k]
        out: list[Retrieved] = []
        for n in nodes:
            doc = self._by_text.get(n.get_content())
            if doc:
                out.append(Retrieved(doc=doc, score=float(n.score or 0.0)))
        return out


def build_retriever(kb_path: str | Path, *, prefer_embeddings: bool = True) -> Retriever:
    """Build the best available retriever, falling back to keyword on failure."""
    docs = load_kb(kb_path)
    if prefer_embeddings:
        try:
            return EmbeddingRetriever(docs)
        except Exception:  # noqa: BLE001 -- any failure -> safe fallback
            pass
    return KeywordRetriever(docs)
