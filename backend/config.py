from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from core.crypto import decrypt, encrypt, is_encrypted

SENSITIVE_KEYS = {
    "SPLUNK_PASSWORD",
    "SPLUNK_HEC_TOKEN",
    "PFSENSE_PASSWORD",
    "PFSENSE_CA_CERT_TEXT",
    "ABUSEIPDB_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "JWT_SECRET_KEY",
    "SEED_ADMIN_PASSWORD",
    "SEED_ANALYST_PASSWORD",
    "SEED_VIEWER_PASSWORD",
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    APP_VERSION: str = "1.0.0"
    JWT_SECRET_KEY: str = "change-me-to-a-long-random-hex-string"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 480
    TRUSTED_PROXY_CIDRS: str = "127.0.0.1/32,172.18.0.0/16"
    MFA_DAILY_REQUIRED: bool = True
    SEED_ADMIN_PASSWORD: str = ""
    SEED_ANALYST_PASSWORD: str = ""
    SEED_VIEWER_PASSWORD: str = ""
    DEMO_MODE: bool = False
    DEMO_SEED_ON_START: bool = False
    DEMO_RESET_ON_START: bool = False
    DEMO_USER_AUTOLOGIN: bool = False

    DATABASE_URL: str = "postgresql+asyncpg://zerotrustx:zerotrustx_pw@postgres:5432/zerotrustx"
    DATABASE_URL_SYNC: str = "postgresql+psycopg2://zerotrustx:zerotrustx_pw@postgres:5432/zerotrustx"

    REDIS_URL: str = "redis://redis:6379/0"
    CELERY_BROKER_URL: str = ""
    CELERY_RESULT_BACKEND: str = ""

    SPLUNK_HOST: str = ""
    SPLUNK_PORT: int = 8089
    SPLUNK_SCHEME: str = "https"
    SPLUNK_VERIFY_SSL: bool = False
    SPLUNK_DEFAULT_INDEX: str = "*"
    SPLUNK_DEFAULT_LIMIT: int = 100
    SPLUNK_USERNAME: str = ""
    SPLUNK_PASSWORD: str = ""
    SPLUNK_HEC_TOKEN: str = ""
    SPLUNK_HEC_URL: str = ""

    PFSENSE_HOST: str = ""
    PFSENSE_USERNAME: str = ""
    PFSENSE_PASSWORD: str = ""
    PFSENSE_BLOCK_ALIAS: str = "SOC_BLOCK_TEMP"
    PFSENSE_VERIFY_SSL: bool = False
    PFSENSE_CA_CERT_TEXT: str = ""
    PFSENSE_CA_CERT_PATH: str = ""
    PFSENSE_TIMEOUT: int = 10

    IP_REPUTATION_ENABLED: bool = True
    IP_REPUTATION_AUTO_INCIDENT_ENABLED: bool = True
    IP_REPUTATION_MAX_REQUESTS_PER_MINUTE: int = 50
    IP_REPUTATION_DEFAULT_CACHE_HOURS: int = 24
    ABUSEIPDB_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""

    @field_validator(
        "MFA_DAILY_REQUIRED",
        "DEMO_MODE",
        "DEMO_SEED_ON_START",
        "DEMO_RESET_ON_START",
        "DEMO_USER_AUTOLOGIN",
        "SPLUNK_VERIFY_SSL",
        "PFSENSE_VERIFY_SSL",
        "IP_REPUTATION_ENABLED",
        "IP_REPUTATION_AUTO_INCIDENT_ENABLED",
        mode="before",
    )
    @classmethod
    def _safe_bool(cls, value):
        if value is None:
            return False
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized == "":
                return False
            if normalized in {"true", "1", "yes", "on"}:
                return True
            if normalized in {"false", "0", "no", "off"}:
                return False
            return False
        return bool(value)

    @field_validator("PFSENSE_TIMEOUT", mode="before")
    @classmethod
    def _safe_pfsense_timeout(cls, value):
        if value in (None, ""):
            return 10
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return 10
        return max(1, min(parsed, 120))

    @model_validator(mode="after")
    def _decrypt_sensitive(self):
        # Transparently decrypt enc:-prefixed values so all callers see plaintext.
        for key in SENSITIVE_KEYS:
            val = getattr(self, key, None)
            if isinstance(val, str) and val.startswith("enc:"):
                try:
                    object.__setattr__(self, key, decrypt(val))
                except Exception:
                    pass
        return self


@lru_cache()
def get_settings() -> Settings:
    return Settings()


def get_integration_configured_status() -> dict:
    s = get_settings()
    if s.DEMO_MODE:
        return {
            "splunk": True,
            "pfsense": True,
            "reputation": True,
        }
    return {
        "splunk": all([
            s.SPLUNK_HOST,
            s.SPLUNK_PORT,
            s.SPLUNK_USERNAME,
            s.SPLUNK_PASSWORD,
        ]),
        "pfsense": all([
            s.PFSENSE_HOST,
            s.PFSENSE_USERNAME,
            s.PFSENSE_PASSWORD,
            s.PFSENSE_BLOCK_ALIAS,
        ]),
        "reputation": all([
            s.IP_REPUTATION_ENABLED,
            s.ABUSEIPDB_API_KEY,
            s.VIRUSTOTAL_API_KEY,
        ]),
    }


def get_sensitive_status() -> dict:
    """Inspect raw .env to report which sensitive keys are stored encrypted."""
    env_path = Path(__file__).parent / ".env"
    raw: dict = {}
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if not line.strip() or line.strip().startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                raw[k.strip()] = v.strip()
    return {k: is_encrypted(raw.get(k, "")) for k in SENSITIVE_KEYS}


def update_env_file(values: dict) -> None:
    """Persist values to .env, encrypting any keys that are in SENSITIVE_KEYS.

    Empty strings clear a value (stored as plaintext empty). Non-empty sensitive
    values are encrypted via Fernet before being written so the .env file never
    contains plaintext credentials at rest.
    """
    env_path = Path(__file__).parent / ".env"
    existing: dict = {}
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if not line.strip() or line.strip().startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                existing[k.strip()] = v.strip()

    to_persist: dict = {}
    for k, v in values.items():
        sv = "" if v is None else str(v)
        if k in SENSITIVE_KEYS and sv:
            sv = encrypt(sv)
        to_persist[k] = sv

    existing.update(to_persist)
    lines = [f"{k}={v}" for k, v in existing.items()]
    env_path.write_text("\n".join(lines) + "\n")

    import os
    for k, v in to_persist.items():
        # Decrypt back into os.environ so the running process picks up plaintext
        # without a restart (the validator only runs at Settings instantiation).
        os.environ[k] = decrypt(v) if k in SENSITIVE_KEYS else v
    get_settings.cache_clear()


def write_env_value(key: str, value: str) -> None:
    """Persist one env key and refresh the cached Settings instance."""
    update_env_file({key: value})
