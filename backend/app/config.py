"""CloudShield application configuration."""
import os
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # Core
    secret_key: str = "change-me-to-a-random-32-char-string-minimum"
    fernet_key: str = "change-me-generate-with-python-cryptography-fernet"

    # Admin seed
    admin_email: str = "admin@cloudshield.local"
    admin_password: str = "Admin@12345!"

    # JWT
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    # Database
    database_url: str = "sqlite+aiosqlite:///./cloudshield.db"

    # CORS
    frontend_url: str = "http://localhost:3000"

    # Log monitor
    log_poll_interval_seconds: int = 30

    # Demo mode
    demo_event_interval_min: int = 3
    demo_event_interval_max: int = 8

    # Reports
    report_tool_version: str = "1.0.0"

    # Risk scoring defaults
    default_data_sensitivity: int = 3
    risk_band_critical_min: int = 91
    risk_band_high_min: int = 51
    risk_band_medium_min: int = 21

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


settings = Settings()
