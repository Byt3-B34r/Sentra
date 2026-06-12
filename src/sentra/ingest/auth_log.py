"""
Normalizer: Linux ``auth.log`` -> ``SecurityEvent``.

auth.log is unstructured syslog text, so this normalizer is regex-driven. It
handles the records that actually matter for triage demos -- SSH accepted/failed
auth, invalid users, and sudo escalation -- and falls back to a generic record
for anything it does not recognize (rather than dropping it).
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime

from sentra.common.schema import (
    NetworkEndpoint,
    SecurityEvent,
    Severity,
    SourceType,
)

# Example lines this matches:
#   Failed password for invalid user admin from 203.0.113.7 port 51232 ssh2
#   Failed password for root from 198.51.100.23 port 40022 ssh2
#   Accepted password for alice from 10.0.0.5 port 49210 ssh2
#   Accepted publickey for bob from 10.0.0.9 port 51002 ssh2
_SSH_RE = re.compile(
    r"(?P<result>Failed|Accepted)\s+(?P<method>password|publickey)\s+for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
    r"\s+port\s+(?P<src_port>\d+)"
)
_INVALID_USER_RE = re.compile(r"invalid user\s+(?P<user>\S+)")
# After the syslog prefix (incl. "sudo[pid]:") is stripped, the body looks like:
#   "deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash -c ..."
# We also require the originating process to be sudo (checked at call site).
_SUDO_RE = re.compile(r"^(?P<user>\S+)\s*:.*?COMMAND=(?P<command>.+)$")
# Syslog timestamp prefix, e.g. "Jun  3 04:12:09 host sshd[2211]: ..."
_PREFIX_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-/]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<body>.*)$"
)

_MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1,
    )
}


def _event_id(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8")).hexdigest()[:16]


def _parse_ts(mon: str, day: str, time_str: str, year: int) -> datetime:
    h, m, s = (int(x) for x in time_str.split(":"))
    return datetime(year, _MONTHS.get(mon, 1), int(day), h, m, s, tzinfo=UTC)


def normalize_line(line: str, *, default_year: int | None = None) -> SecurityEvent | None:
    """Normalize a single auth.log line. Returns None for blank lines."""
    line = line.rstrip("\n")
    if not line.strip():
        return None

    year = default_year or datetime.now(UTC).year
    prefix = _PREFIX_RE.match(line)
    if prefix:
        ts = _parse_ts(prefix["mon"], prefix["day"], prefix["time"], year)
        proc = prefix["proc"]
        body = prefix["body"]
    else:  # no recognizable syslog prefix; keep the line, stamp it now
        ts = datetime.now(UTC)
        proc = "unknown"
        body = line

    ssh = _SSH_RE.search(body)
    if ssh:
        failed = ssh["result"] == "Failed"
        invalid = "invalid user" in body
        sev = Severity.MEDIUM if failed else Severity.LOW
        if invalid:
            sev = Severity.MEDIUM
        return SecurityEvent(
            event_id=_event_id(line),
            timestamp=ts,
            source_type=SourceType.AUTH_LOG,
            severity=sev,
            user=ssh["user"],
            process=proc,
            action=f"ssh_{ssh['method']}_auth",
            outcome="failure" if failed else "success",
            src=NetworkEndpoint(ip=ssh["src_ip"], port=int(ssh["src_port"])),
            message=(
                f"{ssh['result']} {ssh['method']} for "
                f"{'invalid ' if invalid else ''}user {ssh['user']} "
                f"from {ssh['src_ip']}"
            ),
            indicators=[ssh["src_ip"], ssh["user"]],
            raw={"line": line, "invalid_user": invalid},
        )

    sudo = _SUDO_RE.search(body) if proc.startswith("sudo") else None
    if sudo:
        cmd = sudo["command"].strip()
        # Heuristic: piping a remote download into a shell is a strong signal.
        risky = any(tok in cmd for tok in ("curl", "wget", "| sh", "|sh", "| bash"))
        return SecurityEvent(
            event_id=_event_id(line),
            timestamp=ts,
            source_type=SourceType.AUTH_LOG,
            severity=Severity.HIGH if risky else Severity.MEDIUM,
            user=sudo["user"],
            process=proc,
            action="sudo_command",
            outcome="success",
            message=f"sudo by {sudo['user']}: {cmd}",
            indicators=[sudo["user"]],
            raw={"line": line, "command": cmd, "risky": risky},
        )

    inv = _INVALID_USER_RE.search(body)
    if inv:
        return SecurityEvent(
            event_id=_event_id(line),
            timestamp=ts,
            source_type=SourceType.AUTH_LOG,
            severity=Severity.MEDIUM,
            user=inv["user"],
            process=proc,
            action="invalid_user",
            outcome="failure",
            message=f"invalid user {inv['user']}",
            indicators=[inv["user"]],
            raw={"line": line},
        )

    # Unrecognized but retained -- never silently drop telemetry.
    return SecurityEvent(
        event_id=_event_id(line),
        timestamp=ts,
        source_type=SourceType.AUTH_LOG,
        severity=Severity.INFO,
        process=proc,
        action="other",
        message=body[:200],
        raw={"line": line},
    )


def normalize(text: str, *, default_year: int | None = None) -> list[SecurityEvent]:
    """Normalize a full auth.log blob into a list of SecurityEvents."""
    events: list[SecurityEvent] = []
    for line in text.splitlines():
        ev = normalize_line(line, default_year=default_year)
        if ev is not None:
            events.append(ev)
    return events
