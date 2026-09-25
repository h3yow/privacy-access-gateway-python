"""Configuration for the gateway."""
from __future__ import annotations

import os
from dataclasses import dataclass

# A fixed development default keeps local/test runs reproducible.
# Production deployments must override PRIVACY_GATEWAY_MASTER_KEY.
DEFAULT_MASTER_KEY = "local-dev-master-key-do-not-use-in-prod"
DEFAULT_DATABASE_PATH = "gateway.db"


@dataclass(frozen=True)
class Settings:
    master_key: str                     # derives per-tenant HMAC keys
    database_path: str


def get_settings() -> Settings:
    return Settings(
        master_key=os.environ.get("PRIVACY_GATEWAY_MASTER_KEY", DEFAULT_MASTER_KEY),
        database_path=os.environ.get("PRIVACY_GATEWAY_DATABASE", DEFAULT_DATABASE_PATH),
    )
