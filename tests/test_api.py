"""API tests: endpoints, response shape, metrics. Fake pipeline injected."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sentra.api import service
from sentra.orchestrator.pipeline import Pipeline


@pytest.fixture
def client(fake_client, retriever):
    with TestClient(service.app) as c:
        # Replace the lifespan-built (real Ollama) pipeline with a fake one.
        service.deps.pipeline = Pipeline(client=fake_client, retriever=retriever)
        yield c


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.text == "ok"


def test_metrics_endpoint_exposes_prometheus(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "sentra_" in r.text


def test_analyze_returns_report(client):
    content = open("data/samples/auth.log").read()
    r = client.post("/v1/analyze", json={"content": content, "source": "auth_log"})
    assert r.status_code == 200
    body = r.json()
    assert body["report"]["event_count"] > 0
    assert [t["node"] for t in body["trace"]] == ["triage", "analyst", "summarizer"]


def test_analyze_increments_metrics(client):
    content = open("data/samples/auth.log").read()
    client.post("/v1/analyze", json={"content": content, "source": "auth_log"})
    metrics = client.get("/metrics").text
    assert "sentra_events_ingested_total" in metrics
    assert "sentra_events_escalated_total" in metrics

def test_analyze_multi_source_correlates_across_formats(client):
    """All three telemetry formats, sent together, are ingested into one event
    list and correlated into a single incident — the cross-source capability."""
    payload = {
        "sources": [
            {"content": open("data/samples/auth.log").read(), "source": "auth_log"},
            {"content": open("data/samples/conn.log").read(), "source": "zeek_conn"},
            {"content": open("data/samples/notice.log").read(), "source": "zeek_notice"},
        ]
    }
    r = client.post("/v1/analyze", json=payload)
    assert r.status_code == 200
    report = r.json()["report"]
    assert report["event_count"] == 20
    assert len(report["incidents"]) >= 1
    high = [i for i in report["incidents"] if i["severity"] == "high"]
    assert high, "expected a HIGH incident anchored on the attacker"
    assert high[0]["primary_indicator"] == "203.0.113.7"


def test_analyze_single_source_still_supported(client):
    """Backward compatibility: the original single-source request shape works."""
    r = client.post(
        "/v1/analyze",
        json={"content": open("data/samples/auth.log").read(), "source": "auth_log"},
    )
    assert r.status_code == 200
    assert r.json()["report"]["event_count"] == 11


def test_analyze_rejects_empty_request(client):
    """Neither `content` nor `sources` provided is a client error, not a 500."""
    r = client.post("/v1/analyze", json={})
    assert r.status_code >= 400
