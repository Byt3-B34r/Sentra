"""
Ingest dispatcher.

Routes a raw telemetry blob to the correct normalizer based on an explicit
source hint or, failing that, lightweight content sniffing. Returns a unified,
timestamp-sorted list of ``SecurityEvent`` regardless of input type -- this is
the single entry point the API and tests call.
"""

from __future__ import annotations

from sentra.common.schema import SecurityEvent, SourceType
from sentra.ingest import auth_log, zeek


def _sniff(text: str) -> SourceType:
    head = text[:2000]
    if "#fields" in head and "\tnote\t" in head:
        return SourceType.ZEEK_NOTICE
    if "#fields" in head and "id.orig_h" in head:
        return SourceType.ZEEK_CONN
    if "sshd" in head or "sudo:" in head or "Failed password" in head:
        return SourceType.AUTH_LOG
    return SourceType.UNKNOWN


def ingest(text: str, source: SourceType | str | None = None) -> list[SecurityEvent]:
    """Normalize a raw blob into SecurityEvents.

    Args:
        text: raw telemetry content.
        source: optional explicit source type; if omitted, content is sniffed.
    """
    if isinstance(source, str):
        source = SourceType(source)
    if source in (None, SourceType.UNKNOWN):
        source = _sniff(text)

    if source == SourceType.AUTH_LOG:
        events = auth_log.normalize(text)
    elif source == SourceType.ZEEK_CONN:
        events = zeek.normalize_conn(text)
    elif source == SourceType.ZEEK_NOTICE:
        events = zeek.normalize_notice(text)
    else:
        raise ValueError("Could not determine telemetry source; pass `source` explicitly.")

    events.sort(key=lambda e: e.timestamp)
    return events


def ingest_files(paths: list[str]) -> list[SecurityEvent]:
    """Ingest and merge multiple files (each auto-detected), sorted by time."""
    merged: list[SecurityEvent] = []
    for p in paths:
        with open(p, encoding="utf-8", errors="replace") as fh:
            merged.extend(ingest(fh.read()))
    merged.sort(key=lambda e: e.timestamp)
    return merged
