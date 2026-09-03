"""
Centralized configuration — pydantic-settings.

Validates all required fields at instantiation time. If GROQ_API_KEY is
not set in the environment or .env file, Settings() raises a clear
ValidationError naming the exact missing field — not a cryptic stack trace
on the first request.

Model names are config values, not constants (execute.txt §1). They default
to known-good free-tier models but are overridable via environment variables
and updated dynamically from /models at startup if available.
"""


import os
from pathlib import Path

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings loaded from environment variables / .env file."""

    groq_api_key: str = Field(
        ...,
        description="Groq API key — required, never hardcoded, never client-side",
    )
    primary_model: str = Field(
        default="openai/gpt-oss-120b",
        description="Primary (larger, higher-quality) model for NL → IR conversion",
    )
    fallback_model: str = Field(
        default="openai/gpt-oss-20b",
        description="Fallback model — used only when primary rate-limits (429)",
    )
    max_rule_length: int = Field(
        default=4000,
        ge=100,
        le=12000,
        description="Bounded rule input length; long enough for multi-stage analyst requests",
    )
    max_llm_calls_per_request: int = Field(
        default=3,
        description="Hard cap on total LLM calls per single rule parse request",
    )
    max_llm_output_tokens: int = Field(
        default=4096,
        ge=512,
        le=8192,
        description="Hard cap on one structured IR response",
    )
    rate_limit_per_minute: int = Field(
        default=10,
        description="Max /api/parse-rule requests per minute per IP",
    )
    request_timeout_s: int = Field(
        default=30,
        description="Timeout in seconds for each Groq API call",
    )
    port: int = Field(default=3000, description="Server port")
    env: str = Field(
        default="development",
        description="Environment — controls logging verbosity (development/production)",
    )
    rag_enabled: bool = Field(
        default=True,
        description="Enable authoring-time local retrieval; never affects watcher runtime",
    )
    rag_shadow_mode: bool = Field(
        default=False,
        description="Build and trace retrieval without injecting it into the LLM prompt",
    )
    rag_max_documents: int = Field(default=7, ge=1, le=12)
    rag_max_context_chars: int = Field(default=12000, ge=1000, le=30000)
    rag_min_score: float = Field(default=0.22, ge=0.0, le=1.0)

    # FIX (fail-closed auth): the GEKKO_API_TOKEN check in main.py's
    # local_api_auth middleware only activates when that env var happens to
    # be set (desktop.py's native launcher sets it automatically). A
    # standalone `uvicorn app.main:app` launch — the README's own Quick
    # Start command — previously ran fully unauthenticated with no warning.
    # Default False means: no token AND this not explicitly set => refuse to
    # serve /api/* rather than silently allow it. Must be deliberately set
    # true in .env for local no-token development.
    gekko_allow_unauthenticated_local: bool = Field(
        default=False,
        description=(
            "Explicit opt-in for running /api/* without GEKKO_API_TOKEN. "
            "Default False means a token-less standalone launch fails closed. "
            "Only set true for local development outside desktop.py's native launcher."
        ),
    )

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
        "extra": "ignore",
    }

    @property
    def is_development(self) -> bool:
        return self.env.lower() == "development"


# ── Lazy singleton ──────────────────────────────────────────────────────
# NOT instantiated at import time so that importing config.py doesn't
# crash before a .env file is in place. First call to get_settings()
# validates everything and raises if GROQ_API_KEY is missing.

_settings: Settings | None = None


def _maybe_load_dpapi_secrets() -> None:
    """
    Prefer a DPAPI-encrypted GROQ_API_KEY over the plaintext .env value when
    one exists (see shared/secret_store.py). Sets the environment variable
    before Settings() reads it, so this is a pure precedence layer — no
    change to how Settings itself resolves values. Silently no-ops if no
    encrypted secret has been migrated yet (see scripts/migrate_secret_to_dpapi.py).
    """
    try:
        from shared.secret_store import load_encrypted_secret, dpapi_available
    except ImportError:
        return
    if not dpapi_available():
        return
    secret_path = Path(__file__).resolve().parent.parent / "data" / "secrets" / "groq_api_key.dpapi"
    decrypted = load_encrypted_secret(secret_path)
    if decrypted:
        os.environ["GROQ_API_KEY"] = decrypted


def get_settings() -> Settings:
    """Return the validated Settings singleton, creating it on first call."""
    global _settings
    if _settings is None:
        _maybe_load_dpapi_secrets()
        _settings = Settings()
    return _settings


def set_settings(settings: Settings) -> None:
    """Publish the instance eagerly validated by FastAPI lifespan."""
    global _settings
    _settings = settings


def reset_settings() -> None:
    """Reset the singleton — used in tests or when .env changes."""
    global _settings
    _settings = None
