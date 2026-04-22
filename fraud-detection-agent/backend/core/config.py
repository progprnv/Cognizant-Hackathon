"""
backend/core/config.py
──────────────────────
Centralised application settings loaded from environment variables
or a .env file.  All thresholds used by the fraud detection agents
live here so they can be tuned without touching code.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ── App ───────────────────────────────────────────────────────
    APP_NAME: str = "FraudShield AI"
    APP_ENV: str = "development"
    DEBUG: bool = True
    SECRET_KEY: str = "change-me-in-production"

    # ── Database ──────────────────────────────────────────────────
    DATABASE_URL: str = (
        "postgresql+asyncpg://fraud_user:fraud_pass@localhost:5432/fraud_db"
    )

    # ── Redis ─────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"

    # ── JWT ───────────────────────────────────────────────────────
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # ── Risk Thresholds ───────────────────────────────────────────
    RISK_LOW_THRESHOLD: int = 35    # below → ALLOW
    RISK_HIGH_THRESHOLD: int = 70   # above → BLOCK

    # ── Behavioural Thresholds ────────────────────────────────────
    AUTOFILL_TIME_THRESHOLD_MS: int = 300   # < 300 ms ⟹ autofill suspect
    MIN_HUMAN_TYPING_INTERVAL_MS: int = 50  # keystroke floor

    # ── Geo / Travel ──────────────────────────────────────────────
    IMPOSSIBLE_TRAVEL_SPEED_KMH: float = 900.0  # faster than a plane
    GEOIP_API_URL: str = "http://ip-api.com/json"

    # ── Alerts ────────────────────────────────────────────────────
    ALERT_WEBHOOK_URL: str = ""


settings = Settings()
