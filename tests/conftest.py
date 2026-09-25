"""共享夹具：内存存储 + 双版本策略，便于复现历史结论。"""

from __future__ import annotations

import pytest

from app.api import create_app
from app.audit import AuditLog
from app.policy import PolicyStore, load_bundle
from app.service import PrivacyGatewayService
from app.store import GatewayStore

V1_POLICY = {
    "version": "v1",
    "sensitive_rules": [
        {"field": "phone", "pattern": r"^1\d{10}$", "normalizer": "digits",
         "scope": "phone", "mode": "masked"},
        {"field": "email", "pattern": r"^[0-9a-z]+[0-9a-z.]*$", "normalizer": "alnum",
         "scope": "email", "mode": "masked"},
    ],
    "roles": [
        {"role": "admin", "fields": [
            {"field": "phone", "mode": "masked"},
            {"field": "email", "mode": "redacted"},
            {"field": "city", "mode": "masked"},
            {"field": "owner_id", "mode": "masked"},
        ]},
        {"role": "analyst", "fields": [
            {"field": "phone", "mode": "redacted"},
            {"field": "city", "mode": "masked"},
            {"field": "owner_id", "mode": "masked"},
        ]},
        {"role": "owner", "fields": [
            {"field": "phone", "mode": "masked"},
            {"field": "email", "mode": "masked"},
            {"field": "city", "mode": "masked"},
            {"field": "owner_id", "mode": "masked"},
        ], "row_conditions": [
            # 行级 ABAC：owner 只能访问 BJ/SH 的记录
            {"attribute": "city", "operator": "in", "value": ["BJ", "SH"]},
        ]},
    ],
    "retention": [
        {"tenant_id": "t1", "retention_days": 30, "action": "delete"},
        {"tenant_id": "t2", "retention_days": 10, "action": "anonymize"},
    ],
}


@pytest.fixture
def services():
    store, audit = GatewayStore(), AuditLog()
    policies = PolicyStore()
    svc = PrivacyGatewayService(store, policies, audit, secret="unit-test-secret")
    return svc, store, policies, audit


@pytest.fixture
def services_with_v1(services):
    svc, store, policies, audit = services
    policies.put(load_bundle(V1_POLICY))
    return services


@pytest.fixture
def client(services_with_v1):
    svc, *_ = services_with_v1
    from fastapi.testclient import TestClient

    return TestClient(create_app(svc))
