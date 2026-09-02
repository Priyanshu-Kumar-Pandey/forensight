"""Tests for artifact extraction (CSV / JSON / TXT)."""
from app.forensic.extractors import extract_csv, extract_json, extract_txt, classify_event

AUTH_CSV = (
    "timestamp,username,source_ip,event_type,status\n"
    "2026-08-20 02:15:00,jdoe,203.0.113.45,login_success,success\n"
    "2026-08-20 02:06:00,jdoe,203.0.113.45,login_failed,failure\n"
)

EDR_JSON = """{
  "events": [
    {"timestamp": "2026-08-20T02:16:00", "event_type": "file_download",
     "user": "jdoe", "file_path": "C:\\\\Users\\\\jdoe\\\\Downloads\\\\tool.exe"},
    {"timestamp": "2026-08-20T02:17:00", "event_type": "process_create",
     "user": "jdoe", "process_name": "tool.exe"}
  ]
}"""

FIREWALL_TXT = "2026-08-20 02:18:30 firewall allow tcp jdoe 192.168.1.50 -> 198.51.100.23:4444 outbound\n"


def _by_type(artifacts, artifact_type):
    return [a for a in artifacts if a.artifact_type == artifact_type]


def test_classify_event_keyword_mapping():
    assert classify_event("failed password for jdoe") == "failed_login"
    assert classify_event("accepted password for jdoe") == "login"
    assert classify_event("process_create tool.exe") == "execution"
    assert classify_event("nothing matching here") == "log_event"


def test_extract_csv_events_and_entities():
    artifacts = extract_csv(AUTH_CSV, "auth.csv")
    events = [a for a in artifacts if a.artifact_type in ("login", "failed_login")]
    users = _by_type(artifacts, "user")
    ips = _by_type(artifacts, "ip")

    # 2 event rows; user and IP entities are deduplicated across rows.
    assert len(events) == 2
    assert len(users) == 1 and users[0].value == "jdoe"
    assert len(ips) == 1 and ips[0].value == "203.0.113.45"

    failed = [a for a in events if a.artifact_type == "failed_login"]
    assert len(failed) == 1
    assert failed[0].metadata["user"] == "jdoe"
    assert failed[0].timestamp is not None and failed[0].timestamp.hour == 2
    assert failed[0].line_number == 3  # header is line 1


def test_extract_json_nested_events():
    artifacts = extract_json(EDR_JSON, "edr.json")
    downloads = _by_type(artifacts, "download")
    executions = _by_type(artifacts, "execution")
    files = _by_type(artifacts, "file")
    processes = _by_type(artifacts, "process")

    assert len(downloads) == 1
    assert len(executions) == 1
    assert len(files) == 1 and files[0].value.endswith("tool.exe")
    assert len(processes) == 1


def test_extract_txt_line_parsing():
    artifacts = extract_txt(FIREWALL_TXT, "fw.txt")
    events = _by_type(artifacts, "network_connection")
    assert len(events) == 1
    meta = events[0].metadata
    assert meta["ip"] == "192.168.1.50"
    assert meta["dst_ip"] == "198.51.100.23"
    assert events[0].timestamp is not None


def test_extract_txt_ignores_blank_lines():
    assert extract_txt("\n\n", "empty.txt") == []
