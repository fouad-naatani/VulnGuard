"""Application configuration."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


# backend/
BASE_DIR = Path(__file__).resolve().parents[2]

# backend/.env
ENV_FILE = BASE_DIR / ".env"


class Settings(BaseSettings):
    """Typed application settings."""

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ------------------------------------------------------------------
    # Application
    # ------------------------------------------------------------------

    APP_NAME: str = "VulnGuard"
    API_PREFIX: str = "/api"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------

    DATABASE_URL: str = (
        "postgresql+asyncpg://vmp:vmp@localhost:5432/vmp"
    )

    # ------------------------------------------------------------------
    # Security
    # ------------------------------------------------------------------

    SECRET_KEY: str = Field(
        default="CHANGE_THIS_SECRET_KEY"
    )

    JWT_ALGORITHM: str = "HS256"

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7
    PASSWORD_MIN_LENGTH: int = 10

    # ------------------------------------------------------------------
    # CORS
    # ------------------------------------------------------------------

    CORS_ORIGINS: Annotated[list[str], NoDecode] = [
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
    ]

    # ------------------------------------------------------------------
    # Bootstrap admin
    # ------------------------------------------------------------------

    FIRST_ADMIN_EMAIL: str = "admin@vulnguard.com"
    FIRST_ADMIN_PASSWORD: str = "ChangeMe123!"

    # ------------------------------------------------------------------
    # Trivy
    # ------------------------------------------------------------------

    TRIVY_BINARY: str = "trivy"
    TRIVY_TIMEOUT_SECONDS: int = 900

    # ------------------------------------------------------------------
    # Nessus
    # ------------------------------------------------------------------

    NESSUS_URL: str = "https://127.0.0.1:8834"

    NESSUS_ACCESS_KEY: str = ""
    NESSUS_SECRET_KEY: str = ""

    NESSUS_VERIFY_SSL: bool = False

    NESSUS_TIMEOUT_SECONDS: int = 60
    NESSUS_POLL_INTERVAL_SECONDS: int = 5
    NESSUS_SCAN_TIMEOUT_SECONDS: int = 3600
    NESSUS_TEMPLATE_UUID: str | None = None
    

    # ------------------------------------------------------------------
    # Wazuh Manager
    # ------------------------------------------------------------------

    WAZUH_API_URL: str = "https://172.20.10.3:55000"
    WAZUH_API_USER: str = ""
    WAZUH_API_PASSWORD: str = ""
    WAZUH_VERIFY_SSL: bool = False

    # ------------------------------------------------------------------
    # Wazuh Indexer
    # ------------------------------------------------------------------

    WAZUH_INDEXER_URL: str = "https://172.20.10.3:9200"
    WAZUH_INDEXER_USER: str = ""
    WAZUH_INDEXER_PASSWORD: str = ""
    WAZUH_INDEXER_VERIFY_SSL: bool = False

    WAZUH_VULNERABILITY_INDEX: str = (
        "wazuh-states-vulnerabilities-*"
    )

    # ------------------------------------------------------------------
    # OpenSearch
    # ------------------------------------------------------------------

    OPENSEARCH_URL: str = "https://172.20.10.3:9200"
    OPENSEARCH_USER: str = ""
    OPENSEARCH_PASSWORD: str = ""

    # ------------------------------------------------------------------
    # Storage
    # ------------------------------------------------------------------

    REPORTS_DIR: str = "/tmp/vulnguard-reports"

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        """Allow comma-separated CORS origins."""

        if isinstance(value, str):
            return [
                origin.strip()
                for origin in value.split(",")
                if origin.strip()
            ]

        return value


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings."""
    return Settings()


settings = get_settings()


# ----------------------------------------------------------------------
# Debug configuration loading
# ----------------------------------------------------------------------

print("=" * 60)
print("VulnGuard configuration")
print("=" * 60)
print("BASE_DIR:", BASE_DIR)
print("ENV_FILE:", ENV_FILE)
print("ENV_FILE EXISTS:", ENV_FILE.exists())
print("NESSUS_URL:", settings.NESSUS_URL)
print(
    "NESSUS_ACCESS_KEY:",
    "CONFIGURED" if settings.NESSUS_ACCESS_KEY else "MISSING",
)
print(
    "NESSUS_SECRET_KEY:",
    "CONFIGURED" if settings.NESSUS_SECRET_KEY else "MISSING",
)
print("=" * 60)