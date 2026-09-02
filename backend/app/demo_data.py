"""Safe synthetic demo dataset: a fully fictional incident scenario.

Scenario (all data is invented, no real malware, TEST-NET IPs per RFC 5737):
  02:10  repeated failed logins for user jdoe from external IP 203.0.113.45
  02:15  successful login for the same user from the same external IP
  02:16  file download of a fake executable 'invoice_scanner.exe'
  02:17  the downloaded executable is executed
  02:18  the process opens an external connection on port 4444 and data exfil begins
  02:30  the user logs off

The files are designed so the pipeline can: extract artifacts, detect anomalies,
correlate events, build a timeline, and generate AI insights.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

BASE = datetime(2026, 8, 20, 2, 0, 0, tzinfo=timezone.utc)
E = "192.168.1.50"        # internal workstation
ATTACKER = "203.0.113.45"  # RFC 5737 TEST-NET-3 (documentation only)


def _t(minute: int, second: int = 0) -> str:
    return (BASE + timedelta(minutes=minute, seconds=second)).strftime("%Y-%m-%d %H:%M:%S")


def generate_auth_csv() -> str:
    rows = [
        "timestamp,username,source_ip,event_type,status",
        # failed login burst (5 attempts)
        *[_ts_failed(i) for i in range(5)],
        # successful login
        f"{_t(15)},jdoe,{ATTACKER},login_success,success",
        # benign logins for contrast
        f"{_t(45)},asmith,10.0.0.23,login_success,success",
        f"{_t(120)},jdoe,{E},login_success,success",
        f"{_t(150)},jdoe,{E},logout,success",
    ]
    return "\n".join(rows) + "\n"


def _ts_failed(i: int) -> str:
    return f"{_t(6 + i * 2)},jdoe,{ATTACKER},login_failed,failure"


def generate_edr_json() -> str:
    events = [
        {
            "timestamp": _t(16), "event_type": "file_download",
            "user": "jdoe", "file_path": "C:\\Users\\jdoe\\Downloads\\invoice_scanner.exe",
            "source_ip": ATTACKER, "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
        {
            "timestamp": _t(17), "event_type": "process_create",
            "user": "jdoe", "process_name": "invoice_scanner.exe",
            "file_path": "C:\\Users\\jdoe\\Downloads\\invoice_scanner.exe",
        },
        {
            "timestamp": _t(18, 30), "event_type": "network_connection",
            "user": "jdoe", "process_name": "invoice_scanner.exe",
            "destination_ip": "198.51.100.23", "destination_port": "4444",
        },
        {
            "timestamp": _t(19), "event_type": "network_connection",
            "user": "jdoe", "process_name": "invoice_scanner.exe",
            "destination_ip": "198.51.100.23", "destination_port": "4444",
        },
        # benign process for contrast
        {
            "timestamp": _t(60), "event_type": "process_create",
            "user": "asmith", "process_name": "chrome.exe",
            "file_path": "C:\\Program Files\\Google\\Chrome\\chrome.exe",
        },
    ]
    return json.dumps({"events": events}, indent=2)


def generate_firewall_txt() -> str:
    lines = [
        f"{_t(18, 30)} firewall allow tcp jdoe {E} -> 198.51.100.23:4444 outbound",
        f"{_t(19)} firewall allow tcp jdoe {E} -> 198.51.100.23:4444 outbound",
        f"{_t(19, 30)} firewall deny tcp jdoe {E} -> 198.51.100.99:8080 outbound",
        f"{_t(90)} firewall allow tcp asmith 10.0.0.23 -> 93.184.216.34:443 outbound",
    ]
    return "\n".join(lines) + "\n"


DEMO_FILES: dict[str, tuple[str, str]] = {
    "auth_log.csv": ("csv", generate_auth_csv()),
    "edr_events.json": ("json", generate_edr_json()),
    "firewall.txt": ("txt", generate_firewall_txt()),
}
