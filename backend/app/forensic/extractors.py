"""Artifact extraction: turn raw CSV/JSON/TXT evidence into structured artifacts.

Design:
- One extractor per file type, registered in EXTRACTORS (easy to extend later,
  e.g. registry, PCAP, memory).
- Every record becomes an "event" artifact; entities mentioned in the record
  (user, IP, file, process) become deduplicated "entity" artifacts that the
  correlation engine can link.
- Everything is regex/parsing based — uploaded data is never executed.
"""
from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

from app.forensic.parsing import (
    FILE_PATH_RE,
    HASH_RE,
    PORT_RE,
    PROCESS_RE,
    USER_RE,
    extract_first_timestamp,
    extract_ips,
    parse_timestamp,
)

# --------------------------------------------------------------------------
# Common artifact structure
# --------------------------------------------------------------------------

@dataclass
class ExtractedArtifact:
    artifact_type: str          # login, failed_login, download, execution, network_connection, ...
    value: str                  # human-readable canonical value
    timestamp: datetime | None = None
    source: str = ""            # original file name
    line_number: int | None = None
    metadata: dict = field(default_factory=dict)


# --------------------------------------------------------------------------
# Event classification (shared by all extractors)
# --------------------------------------------------------------------------

EVENT_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    ("failed_login", ("failed password", "failed login", "logon failure",
                      "authentication failed", "auth failure", "login_failed", "failed_logon")),
    ("login", ("accepted password", "accepted publickey", "session opened",
               "login success", "logon success", "successful_logon", "login_success", "logon_successful")),
    # NOTE: execution is checked BEFORE download so that paths like
    # "C:\\Users\\...\\Downloads\\tool.exe" on a process_create record do not
    # cause a misclassification as "download".
    ("execution", ("process create", "process_create", "processcreate", "execut",
                   "process started", "command executed", "spawned")),
    ("download", ("download", "url_download", "file_download", "internet_open_url")),
    ("file_creation", ("file created", "file_create", "filecreate", "created file")),
    ("network_connection", ("network connect", "networkconnection", "connection",
                            "connect ", "firewall", "allow ", "deny ", "outbound", "inbound")),
    ("logoff", ("logoff", "logout", "session closed", "session ended")),
]


def classify_event(text: str) -> str:
    low = text.lower()
    for event_type, keywords in EVENT_KEYWORDS:
        if any(k in low for k in keywords):
            return event_type
    return "log_event"


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    v = value.strip().strip("'\"")
    return v or None


# --------------------------------------------------------------------------
# Record-based extraction (shared by CSV and JSON)
# --------------------------------------------------------------------------

COLUMN_ALIASES: dict[str, set[str]] = {
    "timestamp": {"timestamp", "time", "date_time", "datetime", "date", "@timestamp", "ts", "eventtime"},
    "event": {"event_type", "event", "action", "activity", "type", "eventname", "event_name"},
    "user": {"user", "username", "user_name", "account", "login", "subjectusername", "user_id"},
    "ip": {"ip", "source_ip", "src_ip", "ip_address", "client_ip", "sourceaddress", "source_address", "source"},
    "dst_ip": {"destination_ip", "dst_ip", "dest_ip", "target_ip", "destinationaddress"},
    "port": {"port", "destination_port", "dst_port", "dest_port", "target_port"},
    "file": {"file", "filename", "file_name", "filepath", "file_path", "path", "targetfilename", "target_filename"},
    "process": {"process", "process_name", "image", "processname", "exe", "cmd", "commandline"},
    "hash": {"hash", "sha256", "md5", "sha1", "file_hash", "hashes"},
    "status": {"status", "result", "outcome", "success"},
    "message": {"message", "msg", "description", "details"},
}

ENTITY_FIELDS = ("user", "ip", "dst_ip", "file", "process")

# Reverse lookup: every alias (and canonical name) -> canonical field.
_ALIAS_TO_CANONICAL: dict[str, str] = {}
for _canonical, _aliases in COLUMN_ALIASES.items():
    _ALIAS_TO_CANONICAL[_canonical] = _canonical
    for _alias in _aliases:
        _ALIAS_TO_CANONICAL[_alias] = _canonical


def _map_columns(headers: list[str]) -> dict[str, str]:
    """Map original column names -> canonical field names."""
    mapping: dict[str, str] = {}
    for header in headers:
        low = header.strip().lower()
        for canonical, aliases in COLUMN_ALIASES.items():
            if low in aliases:
                mapping[header] = canonical
                break
    return mapping


def _record_to_artifacts(
    record: dict[str, str],
    source: str,
    line_number: int | None,
) -> list[ExtractedArtifact]:
    """Turn one normalized record (dict) into event + entity artifacts."""
    mapped: dict[str, str] = {}
    for key, value in record.items():
        canonical = _ALIAS_TO_CANONICAL.get(key.strip().lower().replace(" ", "_"))
        if canonical and value is not None and str(value).strip():
            mapped.setdefault(canonical, str(value).strip())

    ts_text = mapped.get("timestamp")
    ts = parse_timestamp(ts_text) if ts_text else None
    if ts is None and ts_text:
        ts = extract_first_timestamp(ts_text)

    classify_text = " ".join(
        mapped.get(f, "") for f in ("event", "message", "status", "process", "file") if mapped.get(f)
    )
    event_type = classify_event(classify_text)

    metadata = {k: v for k, v in mapped.items() if k not in ("timestamp",)}
    if ts is None and ts_text:
        metadata["raw_timestamp"] = ts_text

    summary_parts = [event_type]
    if mapped.get("user"):
        summary_parts.append(f"user={mapped['user']}")
    if mapped.get("ip"):
        summary_parts.append(f"src={mapped['ip']}")
    if mapped.get("dst_ip"):
        summary_parts.append(f"dst={mapped['dst_ip']}")
    if mapped.get("file"):
        summary_parts.append(f"file={mapped['file']}")
    if mapped.get("process"):
        summary_parts.append(f"process={mapped['process']}")

    artifacts = [
        ExtractedArtifact(
            artifact_type=event_type,
            value=" ".join(summary_parts),
            timestamp=ts,
            source=source,
            line_number=line_number,
            metadata=metadata,
        )
    ]

    # Entity artifacts for correlation.
    for field_name in ENTITY_FIELDS:
        raw = mapped.get(field_name)
        entity_value = _clean(raw)
        if not entity_value:
            continue
        if field_name == "dst_ip":
            entity_type = "ip"
        else:
            entity_type = field_name
        artifacts.append(
            ExtractedArtifact(
                artifact_type=entity_type,
                value=entity_value,
                timestamp=ts,
                source=source,
                line_number=line_number,
                metadata={"seen_in": event_type},
            )
        )
    return artifacts


def _dedupe(artifacts: list[ExtractedArtifact]) -> list[ExtractedArtifact]:
    """Keep first occurrence of identical entity artifacts (same type+value)."""
    seen: set[tuple[str, str]] = set()
    result: list[ExtractedArtifact] = []
    for art in artifacts:
        if art.artifact_type in ("user", "ip", "file", "process"):
            key = (art.artifact_type, art.value.lower())
            if key in seen:
                continue
            seen.add(key)
        result.append(art)
    return result


def extract_csv(text: str, source: str) -> list[ExtractedArtifact]:
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return []
    mapping = _map_columns(reader.fieldnames)
    results: list[ExtractedArtifact] = []
    for i, row in enumerate(reader, start=2):
        normalized = {
            mapping.get(original, original.strip().lower()): value
            for original, value in row.items()
            if value is not None
        }
        results.extend(_record_to_artifacts(normalized, source, line_number=i))
    return _dedupe(results)


def extract_json(text: str, source: str) -> list[ExtractedArtifact]:
    data = json.loads(text)
    if isinstance(data, dict):
        # Unwrap common container keys, else treat the dict as a single record.
        for key in ("events", "logs", "records", "data", "items"):
            if key in data and isinstance(data[key], list):
                data = data[key]
                break
        else:
            data = [data]
    if not isinstance(data, list):
        return []

    results: list[ExtractedArtifact] = []
    for i, record in enumerate(data, start=1):
        if not isinstance(record, dict):
            # Flat strings are treated like TXT lines.
            results.extend(extract_line(str(record), source, line_number=i))
            continue
        normalized = {k.strip().lower(): str(v) for k, v in record.items() if v is not None}
        results.extend(_record_to_artifacts(normalized, source, line_number=i))
    return _dedupe(results)


# --------------------------------------------------------------------------
# Line-based extraction (TXT / syslog style)
# --------------------------------------------------------------------------

def extract_line(line: str, source: str, line_number: int) -> list[ExtractedArtifact]:
    if not line.strip():
        return []
    ts = extract_first_timestamp(line)
    event_type = classify_event(line)

    ips = extract_ips(line)
    user = _clean(USER_RE.search(line).group(1)) if USER_RE.search(line) else None
    process = _clean(PROCESS_RE.search(line).group(1)) if PROCESS_RE.search(line) else None
    file_match = FILE_PATH_RE.search(line)
    file_path = _clean(file_match.group(0)) if file_match else None
    port_match = PORT_RE.search(line)
    port = port_match.group(1) if port_match else None
    hash_match = HASH_RE.search(line)
    file_hash = hash_match.group(0) if hash_match else None

    metadata: dict = {}
    if ips:
        metadata["ip"] = ips[0]
        if len(ips) > 1:
            metadata["dst_ip"] = ips[1]
    if user:
        metadata["user"] = user
    if process:
        metadata["process"] = process
    if file_path:
        metadata["file"] = file_path
    if port:
        metadata["port"] = port
    if file_hash:
        metadata["hash"] = file_hash

    summary_parts = [event_type]
    if user:
        summary_parts.append(f"user={user}")
    for label in ("ip", "dst_ip"):
        if label in metadata:
            summary_parts.append(f"{label}={metadata[label]}")
    if file_path:
        summary_parts.append(f"file={file_path}")
    if process:
        summary_parts.append(f"process={process}")

    artifacts = [
        ExtractedArtifact(
            artifact_type=event_type,
            value=" ".join(summary_parts),
            timestamp=ts,
            source=source,
            line_number=line_number,
            metadata=metadata,
        )
    ]

    for entity_type, value in (
        ("ip", metadata.get("ip")),
        ("ip", metadata.get("dst_ip")),
        ("user", user),
        ("file", file_path),
        ("process", process),
    ):
        if value:
            artifacts.append(
                ExtractedArtifact(
                    artifact_type=entity_type,
                    value=value,
                    timestamp=ts,
                    source=source,
                    line_number=line_number,
                    metadata={"seen_in": event_type},
                )
            )
    return artifacts


def extract_txt(text: str, source: str) -> list[ExtractedArtifact]:
    results: list[ExtractedArtifact] = []
    for i, line in enumerate(text.splitlines(), start=1):
        results.extend(extract_line(line, source, line_number=i))
    return _dedupe(results)


# --------------------------------------------------------------------------
# Extractor registry (extend here to support new formats later)
# --------------------------------------------------------------------------

EXTRACTORS: dict[str, Callable[[str, str], list[ExtractedArtifact]]] = {
    "csv": extract_csv,
    "json": extract_json,
    "txt": extract_txt,
    "log": extract_txt,
}


def get_extractor(file_type: str) -> Callable[[str, str], list[ExtractedArtifact]]:
    extractor = EXTRACTORS.get(file_type)
    if extractor is None:
        raise ValueError(f"No extractor registered for file type '{file_type}'")
    return extractor


def extract_file(path: Path, file_type: str) -> list[ExtractedArtifact]:
    """Extract artifacts from a stored evidence file (read as UTF-8 text)."""
    text = path.read_text(encoding="utf-8", errors="replace")
    return get_extractor(file_type)(text, source=path.name)
