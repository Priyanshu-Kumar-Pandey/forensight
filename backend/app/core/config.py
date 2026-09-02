"""Application configuration.

All values can be overridden with environment variables prefixed with
``FORENSIGHT_`` (see .env.example). Defaults are tuned for a local
college/hackathon MVP: SQLite database, file-based evidence storage.
"""
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="FORENSIGHT_", env_file=".env", extra="ignore"
    )

    app_name: str = "ForenSight"
    api_prefix: str = "/api"

    # SQLite by default; switch to postgresql+psycopg://user:pass@host/db for prod
    db_url: str = "sqlite:///./data/forensight.db"

    evidence_dir: str = "./data/evidence"
    max_upload_mb: int = 25
    # Only plain text formats are accepted. Uploaded files are NEVER executed.
    allowed_extensions: tuple[str, ...] = (".csv", ".json", ".txt", ".log")

    cors_origins: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024

    def ensure_dirs(self) -> None:
        Path(self.evidence_dir).mkdir(parents=True, exist_ok=True)


settings = Settings()
settings.ensure_dirs()
