"""ForenSight FastAPI application entry point."""
from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.database import init_db
from app.api.routes import api_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("forensight")


def create_app() -> FastAPI:
    app = FastAPI(
        title="ForenSight API",
        description="AI-powered digital forensic investigation and cyber-triage platform",
        version="0.1.0",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(api_router, prefix=settings.api_prefix)

    # Idempotent; done at creation so the app works even without a startup hook.
    init_db()
    settings.ensure_dirs()
    logger.info("ForenSight backend ready (db=%s)", settings.db_url.split("///")[-1])

    return app


app = create_app()
