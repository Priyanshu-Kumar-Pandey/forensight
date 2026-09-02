"""Tests for shared parsing helpers."""
from datetime import datetime, timezone

from app.forensic.parsing import extract_first_timestamp, extract_ips, parse_timestamp


def test_parse_timestamp_iso():
    ts = parse_timestamp("2026-08-20T02:15:00")
    assert ts is not None
    assert ts.year == 2026 and ts.hour == 2 and ts.tzinfo is not None


def test_parse_timestamp_with_microseconds():
    ts = parse_timestamp("2026-08-20 02:15:30.123456")
    assert ts is not None
    assert ts.second == 30


def test_parse_timestamp_syslog_style_fills_year():
    ts = parse_timestamp("Sep 02 10:15:01", default_year=2026)
    assert ts is not None
    assert (ts.year, ts.month, ts.day) == (2026, 9, 2)


def test_parse_timestamp_invalid_returns_none():
    assert parse_timestamp("not a timestamp") is None


def test_extract_ips_dedupes_and_validates():
    ips = extract_ips("src 192.168.1.50 dst 198.51.100.23 again 192.168.1.50")
    assert ips == ["192.168.1.50", "198.51.100.23"]


def test_extract_first_timestamp_from_line():
    ts = extract_first_timestamp("2026-08-20 02:18:30 firewall allow tcp", default_year=None)
    assert isinstance(ts, datetime)
    assert ts.tzinfo == timezone.utc
