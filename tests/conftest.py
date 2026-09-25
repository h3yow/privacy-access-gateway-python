"""Shared pytest fixtures."""
from __future__ import annotations

import pytest

from app.config import Settings
from app.service import GatewayService
from app.storage import Storage

TEST_MASTER_KEY = "test-master-key-0001"


@pytest.fixture
def service(tmp_path):
    settings = Settings(
        master_key=TEST_MASTER_KEY,
        database_path=str(tmp_path / "test.db"),
    )
    storage = Storage(settings.database_path)
    storage.init()
    svc = GatewayService(settings, storage)
    yield svc
    storage.close()


STANDARD_RULES = [
    {
        "field_name": "phone",
        "strategy": "partial",
        "pattern": r"1\d{10}",
        "keep_prefix": 3,
        "keep_suffix": 4,
        "description": "phone number partial mask",
    },
    {
        "field_name": "id_card",
        "strategy": "token",
        "pattern": r"[0-9X]{15,18}",
        "description": "national id tokenized",
    },
]

STANDARD_ROLES = [
    {
        "name": "admin",
        "fields": {"phone": "masked", "id_card": "masked", "note": "visible"},
        "row_filters": {},
    },
    {
        "name": "auditor",
        "fields": {"phone": "masked", "id_card": "denied", "note": "visible"},
        "row_filters": {"region": "cn-north"},
    },
    {
        "name": "owner",
        "fields": {"phone": "masked", "id_card": "masked"},
        "row_filters": {"owner_id": "$owner_id"},
    },
    {
        "name": "guest",
        "fields": {"phone": "denied", "id_card": "denied"},
        "row_filters": {},
    },
]


@pytest.fixture
def provisioned(service):
    service.provision_tenant(
        "tenant-a",
        sensitive_fields=STANDARD_RULES,
        roles=STANDARD_ROLES,
        default_role="guest",
        retention_days=30,
        retention_action="purge",
    )
    return service
