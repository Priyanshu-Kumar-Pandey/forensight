"""Timeline reconstruction engine.

Collects event artifacts with timestamps, normalizes and sorts them,
groups bursts, and flags suspicious sequences (failed-logins-then-login,
download-then-execute, execute-then-connect).
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy.orm import Session

from app.models.models import Artifact, RiskLevel, TimelineEvent

EVENT_ORDER = [
    "failed_login", "login", "download", "file_creation",
    "execution", "network_connection", "logoff", "log_event",
]

DESCRIPTIONS = {
    "login": "User login",
    "failed_login": "Failed login attempt",
    "download": "File downloaded",
    "file_creation": "File created",
    "execution": "Process executed",
    "network_connection": "External network connection",
    "logoff": "User logoff",
    "log_event": "Log event",
}

BURST_WINDOW = timedelta(minutes=10)
SEQUENCE_WINDOW = timedelta(minutes=15)


def build_timeline(investigation_id: int, artifacts: list[Artifact], db: Session) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []

    timed = [a for a in artifacts if a.timestamp and a.artifact_type in EVENT_ORDER]
    timed.sort(key=lambda a: (a.timestamp, EVENT_ORDER.index(a.artifact_type)))

    # --- Failed-login burst grouping ------------------------------------
    # Tag consecutive failed logins within the burst window so scoring/rules
    # can mention "burst of failed logins" (also stored on artifact metadata).
    last_failed: dict[str, Artifact] = {}
    for a in timed:
        if a.artifact_type != "failed_login":
            continue
        user = (a.metadata_json or {}).get("user", "?")
        prev = last_failed.get(user)
        if prev and a.timestamp - prev.timestamp <= BURST_WINDOW:
            meta = dict(a.metadata_json or {})
            meta["burst"] = "true"
            a.metadata_json = meta
        last_failed[user] = a

    for a in timed:
        meta = a.metadata_json or {}
        bits = [DESCRIPTIONS.get(a.artifact_type, a.artifact_type)]
        if meta.get("user"):
            bits.append(f"user={meta['user']}")
        if meta.get("file"):
            bits.append(f"file={meta['file']}")
        if meta.get("process"):
            bits.append(f"process={meta['process']}")
        if meta.get("ip"):
            bits.append(f"src={meta['ip']}")
        if meta.get("dst_ip"):
            bits.append(f"dst={meta['dst_ip']}")
        events.append(
            TimelineEvent(
                investigation_id=investigation_id,
                artifact_id=a.id,
                timestamp=a.timestamp,
                event_type=a.artifact_type,
                description=" | ".join(bits),
                risk_level=a.risk_level,
                flags=[],
            )
        )

    # --- Suspicious sequence flags ---------------------------------------
    by_type: dict[str, list[TimelineEvent]] = {}
    for ev in events:
        by_type.setdefault(ev.event_type, []).append(ev)

    def flag(first: TimelineEvent, second: TimelineEvent, flag_name: str) -> None:
        for ev in (first, second):
            if flag_name not in ev.flags:
                ev.flags = ev.flags + [flag_name]

    for failed in by_type.get("failed_login", []):
        for ok in by_type.get("login", []):
            if ok.artifact_id and failed.artifact_id and ok.timestamp > failed.timestamp \
                    and ok.timestamp - failed.timestamp <= SEQUENCE_WINDOW:
                fu = (failed.description or "")
                ou = (ok.description or "")
                flag(failed, ok, "failed_logins_then_success")

    for dl in by_type.get("download", []):
        for ex in by_type.get("execution", []):
            if ex.timestamp > dl.timestamp and ex.timestamp - dl.timestamp <= SEQUENCE_WINDOW:
                flag(dl, ex, "download_then_execute")

    for ex in by_type.get("execution", []):
        for nc in by_type.get("network_connection", []):
            if nc.timestamp > ex.timestamp and nc.timestamp - ex.timestamp <= SEQUENCE_WINDOW:
                flag(ex, nc, "execute_then_connect")

    for ev in events:
        db.add(ev)
    db.flush()
    return events
