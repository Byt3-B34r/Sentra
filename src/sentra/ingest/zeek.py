"""
Normalizer: Zeek ``conn.log`` and ``notice.log`` -> ``SecurityEvent``.

Zeek logs are TSV with a ``#fields`` header line declaring column order, so
unlike auth.log these are structured. We read the header, map columns by name
(robust to column reordering between Zeek versions), and emit one SecurityEvent
per data row.

Both log types share this parser because they share the Zeek TSV envelope; the
per-type field mapping differs and is selected by ``source_type``.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from sentra.common.schema import (
    NetworkEndpoint,
    SecurityEvent,
    Severity,
    SourceType,
)

_EMPTY = {"-", "(empty)", ""}


def _val(row: dict[str, str], key: str) -> str | None:
    v = row.get(key)
    if v is None or v in _EMPTY:
        return None
    return v


def _event_id(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def _ts(epoch: str | None) -> datetime:
    if not epoch:
        return datetime.now(UTC)
    try:
        return datetime.fromtimestamp(float(epoch), tz=UTC)
    except ValueError:
        return datetime.now(UTC)


def _parse_tsv(text: str) -> tuple[list[str], list[dict[str, str]]]:
    """Return (fields, rows) from a Zeek TSV blob."""
    fields: list[str] = []
    rows: list[dict[str, str]] = []
    for line in text.splitlines():
        if line.startswith("#fields"):
            # "#fields\tts\tuid\t..." -> drop the leading directive token
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#") or not line.strip():
            continue
        if not fields:
            continue
        cols = line.split("\t")
        rows.append(dict(zip(fields, cols, strict=False)))
    return fields, rows


def normalize_conn(text: str) -> list[SecurityEvent]:
    """Normalize a Zeek conn.log blob."""
    _, rows = _parse_tsv(text)
    events: list[SecurityEvent] = []
    for r in rows:
        src_ip = _val(r, "id.orig_h")
        dst_ip = _val(r, "id.resp_h")
        proto = _val(r, "proto") or "?"
        service = _val(r, "service") or proto
        state = _val(r, "conn_state") or "?"
        uid = _val(r, "uid") or _event_id(src_ip or "", dst_ip or "", r.get("ts", ""))

        indicators = [x for x in (src_ip, dst_ip) if x]
        events.append(
            SecurityEvent(
                event_id=_event_id("conn", uid),
                timestamp=_ts(r.get("ts")),
                source_type=SourceType.ZEEK_CONN,
                severity=Severity.INFO,
                process=service,
                action="network_flow",
                outcome="success" if state in {"SF", "S1", "RSTO"} else "unknown",
                src=NetworkEndpoint(
                    ip=src_ip,
                    port=int(r["id.orig_p"]) if _val(r, "id.orig_p") else None,
                ),
                dst=NetworkEndpoint(
                    ip=dst_ip,
                    port=int(r["id.resp_p"]) if _val(r, "id.resp_p") else None,
                ),
                message=(
                    f"{proto}/{service} {src_ip}:{r.get('id.orig_p', '-')} -> "
                    f"{dst_ip}:{r.get('id.resp_p', '-')} state={state}"
                ),
                indicators=indicators,
                raw=r,
            )
        )
    return events


# Zeek notice categories that warrant elevated default severity before triage.
_HIGH_NOTICES = {
    "SSH::Password_Guessing",
    "Scan::Port_Scan",
    "Scan::Address_Scan",
    "SSH::Login_By_Password_Guesser",
}


def normalize_notice(text: str) -> list[SecurityEvent]:
    """Normalize a Zeek notice.log blob (IDS-style alerts)."""
    _, rows = _parse_tsv(text)
    events: list[SecurityEvent] = []
    for r in rows:
        note = _val(r, "note") or "Notice"
        src_ip = _val(r, "src") or _val(r, "id.orig_h")
        dst_ip = _val(r, "dst") or _val(r, "id.resp_h")
        msg = _val(r, "msg") or note
        uid = _val(r, "uid") or _event_id(note, src_ip or "", r.get("ts", ""))

        sev = Severity.HIGH if note in _HIGH_NOTICES else Severity.MEDIUM
        indicators = [x for x in (src_ip, dst_ip) if x]
        events.append(
            SecurityEvent(
                event_id=_event_id("notice", uid, note),
                timestamp=_ts(r.get("ts")),
                source_type=SourceType.ZEEK_NOTICE,
                severity=sev,
                action=note,
                outcome="unknown",
                src=NetworkEndpoint(ip=src_ip),
                dst=NetworkEndpoint(ip=dst_ip),
                message=msg,
                indicators=indicators,
                raw=r,
            )
        )
    return events
