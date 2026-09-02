"""Tests for safe evidence storage (validation + security)."""
from __future__ import annotations

import io

import pytest
from fastapi import HTTPException

from app.forensic.storage import validate_and_store
from app.core.config import settings


class FakeUpload:
    def __init__(self, filename: str, data: bytes):
        self.filename = filename
        self.file = io.BytesIO(data)


def test_valid_csv_upload_is_stored_and_hashed():
    data = b"timestamp,user\n2026-08-20 02:00:00,jdoe\n"
    stored = validate_and_store(FakeUpload("auth_log.csv", data))

    assert stored.file_type == "csv"
    assert stored.file_size == len(data)
    assert len(stored.sha256) == 64
    assert stored.stored_path.exists()
    assert stored.stored_path.read_bytes() == data
    # stored name embeds a hash prefix and keeps the sanitized name
    assert stored.sha256[:16] in stored.stored_path.name


def test_upload_rejects_disallowed_extension():
    with pytest.raises(HTTPException) as exc:
        validate_and_store(FakeUpload("payload.exe", b"MZ..."))
    assert exc.value.status_code == 400
    assert "Unsupported file type" in str(exc.value.detail)


def test_upload_rejects_empty_file():
    with pytest.raises(HTTPException) as exc:
        validate_and_store(FakeUpload("empty.txt", b""))
    assert exc.value.status_code == 400


def test_upload_reject_oversized_file():
    limit = settings.max_upload_bytes
    with pytest.raises(HTTPException) as exc:
        validate_and_store(FakeUpload("big.txt", b"x" * (limit + 1)))
    assert exc.value.status_code == 400
    assert "limit" in str(exc.value.detail)


def test_upload_sanitizes_dangerous_filenames():
    stored = validate_and_store(FakeUpload("../../etc/passwd.txt", b"safe"))
    # path traversal components and slashes removed
    assert "/" not in stored.file_name
    assert ".." not in stored.file_name
    assert stored.file_name.endswith(".txt")
    assert stored.stored_path.parent.exists()


def test_upload_never_executes_content_is_plain_text_roundtrip():
    weird = b"\x00\x01binary-ish content <script>alert(1)</script>"
    stored = validate_and_store(FakeUpload("weird.log", weird))
    assert stored.stored_path.read_bytes() == weird  # byte-identical, untouched
