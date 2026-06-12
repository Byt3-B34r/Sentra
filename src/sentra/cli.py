"""
SENTRA command-line interface.

Runs the full pipeline against one or more telemetry files and prints the
incident report. Useful as a no-network demo path (everything local: files in,
report out) and for quick lab use.

Usage:
    sentra analyze data/samples/auth.log data/samples/conn.log
    sentra analyze --json data/samples/*.log
"""

from __future__ import annotations

import argparse
import sys

from sentra.ingest.dispatch import ingest_files
from sentra.orchestrator.llm import OllamaClient
from sentra.orchestrator.pipeline import Pipeline
from sentra.orchestrator.state import PipelineState
from sentra.rag.retriever import build_retriever


def _build_pipeline(kb: str, embeddings: bool) -> Pipeline:
    client = OllamaClient()
    retriever = build_retriever(kb, prefer_embeddings=embeddings)
    return Pipeline(client=client, retriever=retriever)


def cmd_analyze(args: argparse.Namespace) -> int:
    import httpx

    events = ingest_files(args.files)
    if not events:
        print("No events parsed from input.", file=sys.stderr)
        return 1

    pipeline = _build_pipeline(args.kb, embeddings=not args.no_embeddings)
    try:
        state = pipeline.run(PipelineState(events=events), prefer_langgraph=not args.sequential)
    except (httpx.ConnectError, httpx.ConnectTimeout):
        print(
            "Could not reach Ollama at "
            f"{pipeline.client.host}. Start it with `ollama serve` and ensure "
            f"`ollama pull {pipeline.client.model}` has run.",
            file=sys.stderr,
        )
        return 2

    if state.report is None:
        print("Pipeline produced no report.", file=sys.stderr)
        return 1

    if args.json:
        print(state.report.model_dump_json(indent=2))
    else:
        print(state.report.markdown)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentra", description="Agentic SOC triage pipeline")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="Analyze telemetry files")
    a.add_argument("files", nargs="+", help="Telemetry files (auth.log / Zeek logs)")
    a.add_argument(
        "--kb", default="data/attack_kb/techniques.json", help="Path to ATT&CK knowledge base JSON"
    )
    a.add_argument("--json", action="store_true", help="Emit structured JSON report")
    a.add_argument(
        "--sequential", action="store_true", help="Force the sequential runner (skip LangGraph)"
    )
    a.add_argument(
        "--no-embeddings",
        action="store_true",
        help="Use the keyword retriever instead of Ollama embeddings",
    )
    a.set_defaults(func=cmd_analyze)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
