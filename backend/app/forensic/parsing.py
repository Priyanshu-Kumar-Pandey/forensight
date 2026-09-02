"""Shared parsing helpers: timestamps, IPs, users, paths, hashes."""
from __future__ import annotations

import re
from datetime import datetime, timezone

# --- timestamp parsing -------------------------------------------------------
_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y/%m/%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S",
    "%b %d %H:%M:%S",          # syslog: "Sep 02 10:15:01" (year filled in)
    "%m/%d/%Y %H:%M:%S",
)


def parse_timestamp(text: str, default_year: int | None = None) -> datetime | None:
    """Try to parse a timestamp string; return a tz-aware UTC datetime or None."""
    text = text.strip()
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(text, fmt)
        except ValueError:
            continue
        if dt.tzinfo is None:
            if "%Y" not in fmt and default_year:
                dt = dt.replace(year=default_year)
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    return None


TS_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"|\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}"
    r"|\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}"
    r"|\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}"
    r"|[A-Za-z]{3} +\d{1,2} \d{2}:\d{2}:\d{2}"
)

# --- common forensic patterns ------------------------------------------------
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
FILE_PATH_RE = re.compile(r"(?:[A-Za-z]:\\|/)[\w./\\-]{2,}")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
USER_RE = re.compile(
    r"\b(?:user|username|user_name|login|account|uid|owner)\s*[=:]\s*['\"]?([A-Za-z0-9_.-]{2,32})",
    re.IGNORECASE,
)
PROCESS_RE = re.compile(
    r"\b(?:process|proc|image|exe|program|cmd)\s*[=:]\s*['\"]?([\w .-]+\.(?:exe|bat|ps1|dll|py|sh|bin))",
    re.IGNORECASE,
)
PORT_RE = re.compile(r"\b(?:port|dst_port|dport)\s*[=:]\s*(\d{1,5})\b", re.IGNORECASE)


def first_match(pattern: re.Pattern[str], text: str) -> str | None:
    m = pattern.search(text)
    return m.group(1) if m.lastindex else (m.group(0) if m else None)


def extract_ips(text: str) -> list[str]:
    return list(dict.fromkeys(IPV4_RE.findall(text)))


def extract_first_timestamp(text: str, default_year: int | None = None) -> datetime | None:
    m = TS_RE.search(text)
    return parse_timestamp(m.group(0), default_year=default_year) if m else None
