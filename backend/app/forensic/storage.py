"""Safe evidence storage.

Security rules:
- Uploaded files are NEVER executed, only hashed, stored and parsed as text.
- File names are sanitized; contents are size-checked against the limit.
- Only allow-listed extensions are accepted.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from fastapi import HTTPException, UploadFile

from app.core.config import settings

_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass
class StoredEvidence:
    file_name: str
    file_type: str
    file_size: int
    sha256: str
    stored_path: Path


def _sanitize_name(name: str) -> str:
    name = Path(name).name  # strip any directory components
    name = _NAME_RE.sub("_", name).strip("._") or "evidence"
    return name[:120]


def validate_and_store(upload: UploadFile) -> StoredEvidence:
    """Validate an upload and persist it under the evidence directory.

    Raises HTTPException(400) for bad extensions, empty files, or oversized files.
    """
    original_name = upload.filename or "evidence"
    ext = Path(original_name).suffix.lower()

    if ext not in settings.allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Allowed: {', '.join(settings.allowed_extensions)}",
        )

    # Read in chunks, enforcing the size limit without trusting Content-Length.
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    size = 0
    while chunk := upload.file.read(1024 * 1024):
        size += len(chunk)
        if size > settings.max_upload_bytes:
            raise HTTPException(
                status_code=400,
                detail=f"File exceeds the {settings.max_upload_mb} MB limit.",
            )
        digest.update(chunk)
        chunks.append(chunk)

    if size == 0:
        raise HTTPException(status_code=400, detail="Empty file.")

    safe_name = _sanitize_name(original_name)
    evidence_dir = Path(settings.evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stored_path = evidence_dir / f"{digest.hexdigest()[:16]}_{safe_name}"
    stored_path.write_bytes(b"".join(chunks))

    return StoredEvidence(
        file_name=safe_name,
        file_type=ext.lstrip("."),
        file_size=size,
        sha256=digest.hexdigest(),
        stored_path=stored_path,
    )
