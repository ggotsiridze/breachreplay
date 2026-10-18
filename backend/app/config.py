"""Runtime configuration (environment variables, prefixed ``BREACHREPLAY_`` where noted)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore")

    # Modes
    showcase_mode: bool = Field(default=False, alias="SHOWCASE_MODE")
    public_mode: bool = Field(default=False, alias="PUBLIC_MODE")

    # Analyzer execution: "remote" talks to the analyzer containers over the
    # internal network, "local" runs zeek/suricata binaries found on PATH.
    analyzer_mode: str = Field(default="remote", alias="ANALYZER_MODE", pattern="^(remote|local)$")
    zeek_url: str = Field(default="http://analyzer-zeek:8700", alias="ZEEK_ANALYZER_URL")
    suricata_url: str = Field(default="http://analyzer-suricata:8700", alias="SURICATA_ANALYZER_URL")
    analyzer_timeout_seconds: int = Field(default=180, alias="ANALYZER_TIMEOUT_SECONDS", ge=5, le=3600)

    # Storage
    workspace_root: Path = Field(default=Path("/workspaces"), alias="WORKSPACE_ROOT")
    data_dir: Path = Field(default=REPO_ROOT / "data", alias="DATA_DIR")
    keep_workspaces: bool = Field(default=False, alias="KEEP_WORKSPACES")

    # Uploads
    max_upload_mb: int = Field(default=50, alias="MAX_UPLOAD_MB", ge=1, le=2048)

    # Demo / showcase assets
    demo_pcap_path: Path = Field(default=REPO_ROOT / "demo" / "generated" / "breachreplay-demo.pcap", alias="DEMO_PCAP_PATH")
    demo_rules_path: Path = Field(default=REPO_ROOT / "demo" / "rules" / "breachreplay-demo.rules", alias="DEMO_RULES_PATH")
    demo_context_path: Path = Field(default=REPO_ROOT / "demo" / "asset-context.json", alias="DEMO_CONTEXT_PATH")
    showcase_path: Path = Field(default=REPO_ROOT / "showcase" / "showcase-incident.json", alias="SHOWCASE_PATH")

    cors_origins: str = Field(default="http://localhost:5173,http://127.0.0.1:5173", alias="CORS_ORIGINS")
    max_incidents: int = Field(default=25, alias="MAX_INCIDENTS", ge=1, le=1000)

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    return Settings()
