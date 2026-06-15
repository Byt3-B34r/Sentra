# LinkedIn Project Writeup — SENTRA

Two versions: a short "Featured/Projects" blurb and a longer post. Edit the
bracketed bits and drop in your GitLab link.

---

## Short version (Projects section)

**SENTRA — Agentic SOC Triage Pipeline**

Built an agentic security-telemetry triage system that turns raw logs into
analyst-ready incident reports, running entirely on local LLM inference so it
works in air-gapped environments. A graph of LLM agents (triage → analyst →
summarize) ingests heterogeneous telemetry (Linux auth logs, Zeek network
logs), correlates related activity into incidents, and maps each to MITRE
ATT&CK techniques via local RAG. Shipped as containerized microservices with
Prometheus/Grafana observability, Kubernetes manifests, and a GitLab CI
pipeline (lint → test → build → image scan). Python · LangGraph · LlamaIndex ·
FastAPI · Ollama · Podman · Prometheus.

[GitLab link]

---

## Long version (post)

Most "AI for security" demos send your logs to a cloud API. A real SOC handling
sensitive telemetry can't do that. So I built SENTRA to run entirely on local
inference — air-gap capable by design.

SENTRA is an agentic triage pipeline. Raw telemetry in, analyst-ready incident
report out:

→ **Ingest** normalizes different log formats (Linux auth.log, Zeek conn/notice)
into one schema. Adding a source means writing one normalizer, not touching the
agents.

→ **Triage** decides the obvious cases with cheap heuristics and sends only
ambiguous events to the LLM. On local hardware, where inference is the
bottleneck, that cost control is what makes the system usable — not a nice-to-have.

→ **Analyst** correlates events that share an indicator (like an attacker IP)
into a single incident — directly attacking alert fatigue — then uses RAG over a
curated MITRE ATT&CK knowledge base to map techniques, rejecting any technique
ID the model invents.

→ **Summarize** lets the model write the analysis but renders all the facts
(IDs, counts, technique tables) deterministically in code. The model reasons; it
never formats facts.

The part I'm most happy with is the engineering discipline around it: every
component has a production implementation and a dependency-free fallback, so the
full pipeline is testable in CI with no GPU and can't drift from prod behavior.
It ships as containers with a one-command stack, Kubernetes manifests, and a
GitLab CI pipeline that lints, tests (81% coverage), builds, and vulnerability-
scans the image. Prometheus + Grafana make the inference cost — per-agent
latency, token throughput, triage suppression rate — visible in real time.

Stack: Python, LangGraph, LlamaIndex, FastAPI, Ollama (llama3.1:8b), Podman,
Prometheus, Grafana, GitLab CI.

Code + architecture write-up: [GitLab link]

#cybersecurity #AI #LLM #SOC #DevOps #MLOps #infosec
