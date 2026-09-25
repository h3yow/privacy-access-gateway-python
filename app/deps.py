"""Shared application state / dependency wiring."""
from __future__ import annotations

import os

from app.config import get_settings, Settings
from app.service import GatewayService
from app.storage import Storage

settings: Settings | None = None
storage: Storage | None = None
service: GatewayService | None = None


def init_service(database_path: str | None = None) -> GatewayService:
    """Initialize (or re-initialize) the global service singletons."""
    global settings, storage, service
    if storage is not None:
        storage.close()
    settings = get_settings()
    if database_path is not None:
        from dataclasses import replace

        settings = replace(settings, database_path=database_path)
    storage = Storage(settings.database_path)
    storage.init()
    service = GatewayService(settings, storage)
    return service


def get_service() -> GatewayService:
    global service
    if service is None:
        init_service()
    assert service is not None
    return service


def shutdown_service() -> None:
    global storage, service
    if storage is not None:
        storage.close()
    storage = None
    service = None
