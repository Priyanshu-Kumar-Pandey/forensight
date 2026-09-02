"""Pytest fixtures for ForenSight backend tests.

Environment variables are set BEFORE importing any app module so the
settings object picks up the isolated test database and evidence directory.
"""
from __future__ import annotations

import os

os.environ["FORENSIGHT_DB_URL"] = "sqlite:///./data/test_forensight.db"
os.environ["FORENSIGHT_EVIDENCE_DIR"] = "./data/test_evidence"

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client():
    """Fresh API client with a clean database for each test."""
    from app.core.database import Base, engine
    import app.models  # noqa: F401  (register models before create_all)
    from app.main import app

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as c:
        yield c
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def db_session(client):
    """DB session bound to the same test database used by `client`."""
    from app.core.database import SessionLocal

    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def demo_investigation(client):
    """Create and analyze the synthetic demo investigation via the API."""
    r = client.post("/api/demo/load")
    assert r.status_code == 200
    return r.json()
