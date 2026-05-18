import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Sentinel-AI global configuration. Loaded from environment / .env file."""

    # ── Project ──────────────────────────────────────────────
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "Sentinel-AI"
    DATABASE_URL: str = "sqlite:///./sentinel.db"

    # ── LLM / Google ADK ─────────────────────────────────────
    GOOGLE_API_KEY: str = ""          # Gemini API key (required for ADK agents)
    GOOGLE_MODEL: str = "gemini-2.0-flash"

    # ── Vulnerability APIs ───────────────────────────────────
    NVD_API_KEY: str = ""             # optional – raises rate-limit without it
    OSV_API_URL: str = "https://api.osv.dev/v1"
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # ── Registry APIs ────────────────────────────────────────
    NPM_REGISTRY_URL: str = "https://registry.npmjs.org"
    PYPI_API_URL: str = "https://pypi.org"
    CRATES_IO_API_URL: str = "https://crates.io/api/v1"

    # ── One-Week Rule ────────────────────────────────────────
    ONE_WEEK_DAYS: int = 7            # account age threshold (days)

    # ── Lead Warden / LLM Backend ────────────────────────────
    LLM_BACKEND: str = "vllm"                        # "ollama", "vllm", or "aisa"
    OLLAMA_BASE_URL: str = "http://localhost:11434"  # Ollama API
    VLLM_BASE_URL: str = "http://localhost:8000"     # vLLM API (OpenAI compatible)
    VERDICT_MODEL: str = "qwen2.5-coder:7b"          # local verdict model

    # ── AISA.one API Gateway ─────────────────────────────────
    AISA_BASE_URL: str = "https://api.aisa.one/v1"
    AISA_API_KEY: str = ""                           # set via env or per-request

    # ── Sentinel Watcher ─────────────────────────────────────
    SLACK_WEBHOOK_URL: str = ""       # Slack incoming webhook for alerts
    WATCHER_INTERVAL_MINUTES: int = 15  # cron interval for background monitoring

    # ── GitHub App Webhook Integration ───────────────────────
    GITHUB_APP_ID: str = ""
    GITHUB_WEBHOOK_SECRET: str = ""
    GITHUB_PRIVATE_KEY_PATH: str = ""
    BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # ── Pentest module ───────────────────────────────────────
    SENTINEL_PENTEST_ALLOWLIST: str = (
        "localhost,127.0.0.1,*.sandbox.local,*.local,juice-shop.sandbox.local"
    )
    SENTINEL_PENTEST_MAX_DURATION_SECONDS: int = 180

    # ── GitHub Checks API (v2) ───────────────────────────────
    SENTINEL_GH_CHECKS_ENABLED: bool = False    # gate — requires Checks: read&write permission

    # ── GitHub OAuth (v2) ────────────────────────────────────
    GITHUB_OAUTH_CLIENT_ID: str = ""
    GITHUB_OAUTH_CLIENT_SECRET: str = ""
    GITHUB_OAUTH_REDIRECT_URI: str = "http://localhost:8005/api/v1/github/callback"
    SENTINEL_TOKEN_ENC_KEY: str = ""            # Fernet key for github_user_tokens; falls back to SENTINEL_ENCRYPTION_KEY

    # ── Auto-pentest trigger (v2) ────────────────────────────
    SENTINEL_PENTEST_AUTO: bool = False         # gate — disabled by default

    # ── RL Data Collection (v2) ──────────────────────────────
    RL_DATA_DIR: str = "data/rl"                # relative to project root
    RL_REWARD_WEIGHTS: str = "0.6,0.2,0.2"     # human, shannon, mini_verifier
    SENTINEL_RL_TRACE_ENABLED: bool = True      # generate reasoning traces on accept
    SENTINEL_RL_TRACE_DAILY_LIMIT: int = 200    # cap LLM calls for trace generation
    SENTINEL_RL_TRACE_MODEL_AISA: str = "deepseek-r1"
    SENTINEL_RL_TRACE_MODEL_VLLM: str = "Qwen/Qwen2.5-Coder-32B-Instruct"
    SENTINEL_RL_TRACE_MODEL_OLLAMA: str = ""    # empty → falls back to VERDICT_MODEL
    SENTINEL_RL_TRACE_FORCE_BACKEND: str = ""   # "aisa" | "vllm" | "ollama" | "" (auto)

    class Config:
        env_file = ".env"


settings = Settings()

