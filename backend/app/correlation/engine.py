"""Cross-artifact correlation engine.

Builds explainable relationships between artifacts using shared attributes:
value equality (same user/IP/file/process), temporal proximity of events,
and canonical event patterns (download -> execution, login -> event, event -> IP).

Every relationship carries a human-readable explanation and confidence score.
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy.orm import Session

from app.models.models import Artifact, Relationship

EVENT_TYPES = {
    "login", "failed_login", "download", "file_creation",
    "execution", "network_connection", "logoff", "log_event",
}
ENTITY_TYPES = {"user", "ip", "file", "process"}

TEMPORAL_WINDOW = timedelta(seconds=300)  # 5 minutes


def _same_value(a: Artifact, b: Artifact) -> bool:
    return a.value.lower() == b.value.lower()


def _entity_matches_event(entity: Artifact, event: Artifact) -> bool:
    """An entity matches an event when the event's metadata references that
    entity value (user/ip/file/process) or both come from the same log record."""
    meta = event.metadata_json or {}
    referenced = {
        str(meta[key]).lower()
        for key in ("user", "ip", "dst_ip", "file", "process")
        if meta.get(key)
    }
    if entity.value.lower() in referenced:
        return True
    return (
        event.source == entity.source
        and entity.line_number is not None
        and entity.line_number == event.line_number
    )


def _time_close(a: Artifact, b: Artifact, window: timedelta = TEMPORAL_WINDOW) -> bool:
    if not a.timestamp or not b.timestamp:
        return False
    delta = abs((a.timestamp - b.timestamp).total_seconds())
    return delta <= window.total_seconds()


def correlate(investigation_id: int, artifacts: list[Artifact], db: Session) -> list[Relationship]:
    """Generate relationships for the given artifacts and persist them."""
    relations: list[Relationship] = []
    seen: set[tuple[int, int, str]] = set()

    events = [a for a in artifacts if a.artifact_type in EVENT_TYPES]
    entities = [a for a in artifacts if a.artifact_type in ENTITY_TYPES]

    def add(source: Artifact, target: Artifact, rel_type: str, confidence: float, explanation: str) -> None:
        key = (source.id, target.id, rel_type)
        if key in seen or source.id == target.id:
            return
        seen.add(key)
        relations.append(
            Relationship(
                investigation_id=investigation_id,
                source_artifact_id=source.id,
                target_artifact_id=target.id,
                relationship_type=rel_type,
                confidence_score=round(confidence, 3),
                explanation=explanation,
            )
        )

    # 1. Entity -> Event: the event references the entity (metadata value match
    #    or same source record).
    for event in events:
        for entity in entities:
            if not _entity_matches_event(entity, event):
                continue
            close_in_time = _time_close(entity, event)
            rel_type = {
                "user": "performed_by",
                "ip": "originated_from" if event.artifact_type != "network_connection" else "connected_to",
                "file": "involves_file",
                "process": "executed_by",
            }.get(entity.artifact_type, "related_to")
            same_record = (
                event.source == entity.source
                and entity.line_number is not None
                and entity.line_number == event.line_number
            )
            base = 0.9 if same_record else 0.75
            confidence = min(0.99, base + (0.05 if close_in_time else 0.0))
            how = "same log record" if same_record else "event references this value"
            add(entity, event, rel_type, confidence,
                f"{entity.artifact_type} '{entity.value}' linked to {event.artifact_type} via {how}")

    # 2. Event -> Event temporal chains (download -> execution etc.)
    CHAINS = [
        ("download", "execution", "downloaded_then_executed"),
        ("login", "download", "login_then_download"),
        ("failed_login", "login", "failed_logins_then_success"),
        ("execution", "network_connection", "executed_then_connected"),
    ]
    for source_type, target_type, rel_name in CHAINS:
        sources = [e for e in events if e.artifact_type == source_type and e.timestamp]
        targets = [e for e in events if e.artifact_type == target_type and e.timestamp]
        for s in sources:
            best: tuple[Artifact | None, float] = (None, 0.0)
            for t in targets:
                if t.timestamp is None or s.timestamp is None:
                    continue
                delta = (t.timestamp - s.timestamp).total_seconds()
                if 0 <= delta <= TEMPORAL_WINDOW.total_seconds():
                    # closer in time = higher confidence
                    score = 1.0 - (delta / TEMPORAL_WINDOW.total_seconds()) * 0.4
                    if score > best[1]:
                        best = (t, score)
            if best[0] is not None:
                t = best[0]
                secs = int((t.timestamp - s.timestamp).total_seconds())
                add(s, t, rel_name, best[1],
                    f"{source_type} at {s.timestamp:%H:%M:%S} followed by {target_type} {secs}s later")

    # 3. Same-value entity co-occurrence (same file seen in two sources, etc.)
    by_value: dict[tuple[str, str], list[Artifact]] = {}
    for e in entities:
        by_value.setdefault((e.artifact_type, e.value.lower()), []).append(e)
    for (etype, _), group in by_value.items():
        for i in range(len(group) - 1):
            a, b = group[i], group[i + 1]
            if a.source != b.source or a.id == b.id:
                add(a, b, "co_occurrence", 0.5,
                    f"same {etype} value extracted from different records")

    for rel in relations:
        db.add(rel)
    db.flush()
    return relations
