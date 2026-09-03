"""
Watcher agent configuration — pydantic-settings.

All settings are loaded from the .env file (same file the API uses,
kept in the project root) plus environment variables.

Key design decisions from execute.txt:
  - WATCHER_DRY_RUN=true by default. Nothing destructive happens until
    you explicitly flip this to false. This is the single most important
    guardrail for a tool that can kill processes and isolate hosts.
  - Rate limits and retention are configurable but have sane defaults.
"""
from __future__ import annotations

from pydantic_settings import BaseSettings
from pydantic import Field


class WatcherSettings(BaseSettings):
    """Watcher-agent settings — separate from the FastAPI app config."""

    # ── Dry-run safety ────────────────────────────────────────────────
    watcher_dry_run: bool = Field(
        default=True,
        description=(
            "SAFETY: When True (default), destructive actions (kill/isolate) "
            "are logged but NOT executed. Set to false only when you trust "
            "your rules and have watched them in dry-run mode first."
        ),
    )

    # ── Non-admin opt-out ─────────────────────────────────────────────
    watcher_allow_non_admin: bool = Field(
        default=False,
        description=(
            "Allow running in non-admin mode. If False (default), the agent "
            "will prompt for administrative elevation on startup."
        ),
    )

    # ── Collectors to enable ──────────────────────────────────────────
    watcher_collectors: str = Field(
        default="security,system,titan_sensors",
        description=(
            "Comma-separated list of telemetry collectors to enable. "
            "Available: security, system, sysmon, wmi, registry_fim, inventory, "
            "powershell, scheduled_tasks, usb, firewall, defender, titan_sensors. "
            "titan_sensors tails the 5 TITAN ENDPOINT native sensors' own JSONL logs "
            "(see CORRELATOR/correlator_config.txt for their paths) plus the "
            "Correlator's session_timeline output (TITAN_CORRELATOR_LOG_DIR env var); "
            "it cleanly no-ops with a startup warning, not a crash, until those "
            "sensors have actually been run at least once."
        ),
    )

    # ── Backward compatibility channels list ──────────────────────────
    watcher_channels: str = Field(
        default="Microsoft-Windows-Sysmon/Operational,Security,System",
        description="Deprecated. Use WATCHER_COLLECTORS instead.",
    )

    # ── Destructive action rate limit ──────────────────────────────────
    watcher_max_destructive_per_minute: int = Field(
        default=5,
        description=(
            "Agent-wide circuit breaker: max kill/isolate actions per minute. "
            "Prevents a miscalibrated rule from taking down the box in a loop."
        ),
    )

    # ── Evidence retention ────────────────────────────────────────────
    watcher_evidence_retention_days: int = Field(
        default=30,
        description="Delete evidence files older than this many days.",
    )
    watcher_evidence_max_files: int = Field(
        default=10_000,
        ge=100,
        description="Hard cap on retained evidence records after age cleanup.",
    )
    watcher_evidence_max_total_mb: int = Field(
        default=1024,
        ge=10,
        description="Hard cap on total evidence storage after age cleanup.",
    )

    # ── Data directory (relative to project root, or absolute override) ─
    watcher_data_dir: str = Field(
        default="data",
        description="Path to the shared data directory (rules.jsonl lives here).",
    )

    # ── Alert log ─────────────────────────────────────────────────────
    watcher_log_level: str = Field(
        default="INFO",
        description="Logging level for the watcher process (DEBUG/INFO/WARNING/ERROR).",
    )

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
        # Extra fields are allowed so the watcher config can coexist with
        # the FastAPI app's settings in the same .env file.
        "extra": "allow",
    }

    @property
    def collectors_list(self) -> list[str]:
        """Return collectors as a list, mapping old WATCHER_CHANNELS if overridden."""
        val = self.watcher_collectors.strip()
        # Fallback to mapping channels if channels is set to something non-default
        # and collectors is still the default.
        if (
            val == "security,system"
            and self.watcher_channels != "Microsoft-Windows-Sysmon/Operational,Security,System"
        ):
            mapped = []
            for c in self.watcher_channels.split(","):
                c_lower = c.strip().lower()
                if "security" in c_lower:
                    mapped.append("security")
                elif "sysmon" in c_lower:
                    mapped.append("sysmon")
                elif "system" in c_lower:
                    mapped.append("system")
            if mapped:
                return mapped

        return [c.strip() for c in val.split(",") if c.strip()]

    @property
    def channels_list(self) -> list[str]:
        """Deprecated. Maps to collectors_list."""
        return self.collectors_list


# ── Lazy singleton ────────────────────────────────────────────────────

_settings: WatcherSettings | None = None


def get_watcher_settings() -> WatcherSettings:
    """Return the validated WatcherSettings singleton."""
    global _settings
    if _settings is None:
        _settings = WatcherSettings()
    return _settings
