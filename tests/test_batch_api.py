"""HTTP-level tests for batch ingestion, safe resend and audit safety."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import app.deps as deps
from app.config import Settings
from app.storage import Storage
from app.service import GatewayService


@pytest.fixture
def client(tmp_path):
    storage = Storage(str(tmp_path / "batchapi.db"))
    storage.init()
    svc = GatewayService(
        Settings(master_key="batch-api-key",
                 database_path=str(tmp_path / "batchapi.db")),
        storage,
    )
    deps.service = svc
    deps.storage = storage
    from main import app

    with TestClient(app) as c:
        yield c
    storage.close()
    deps.service = None
    deps.storage = None


RULES = [
    {"field_name": "email", "strategy": "token", "pattern": r"[^@]+@[^@]+"},
    {"field_name": "phone", "strategy": "partial", "pattern": r"1\d{10}",
     "keep_prefix": 3, "keep_suffix": 4},
]
ROLES = [
    {"name": "admin", "fields": {"email": "masked", "phone": "masked",
                                 "memo": "visible"}, "row_filters": {}},
]
PROVISION = {
    "sensitive_fields": RULES, "roles": ROLES, "default_role": "admin",
    "retention_days": 30, "retention_action": "purge",
}


def test_batch_http_mixed_results_and_resend(client):
    client.post("/tenants/acme/provision",
                json={"tenant_id": "acme", **PROVISION})
    body = {"records": [
        {"item_id": "a",
         "payload": {"email": "alice@example.com", "phone": "13800001234"}},
        {"item_id": "b", "payload": {"email": "bad", "phone": "13800001234"}},
        {"item_id": "c",
         "payload": {"email": "dave@example.com", "phone": "13700001111",
                     "memo": "same phone shared"}},
        {"item_id": "d",
         "payload": {"email": "erin@example.com", "phone": "13600002222",
                     "memo": "different business content"}},
    ]}
    r1 = client.post("/tenants/acme/records/batch", json=body)
    assert r1.status_code == 200
    data1 = r1.json()
    assert data1["created"] == 3 and data1["rejected"] == 1
    assert data1["results"][1]["reason"] == "value_pattern_mismatch"

    # Resend after an upstream timeout: identical outcomes and record ids.
    r2 = client.post("/tenants/acme/records/batch", json=body)
    data2 = r2.json()
    assert data2["created"] == 0
    assert data2["duplicate"] == 3
    ids1 = {x.get("item_id"): x.get("record_id") for x in data1["results"]}
    ids2 = {x.get("item_id"): x.get("record_id") for x in data2["results"]}
    assert ids1 == ids2
    assert data2["results"][1]["reason"] == "value_pattern_mismatch"

    # Shared email/phone across different business content is NOT a collision:
    # items c and d both stored independently (already asserted created==3).


def test_batch_http_fallback_rejection_and_no_raw_in_response(client):
    client.post("/tenants/acme/provision",
                json={"tenant_id": "acme", **PROVISION})
    secret = "frank@example.com"
    r = client.post("/tenants/acme/records/batch", json={"records": [
        {"item_id": "leak",
         "payload": {"email": "ok@example.com", "phone": "13800001234",
                     "memo": f"ping {secret} please"}},
        {"item_id": "name",
         "payload": {"email": "ok2@example.com", "phone": "13800001234",
                     "passport_no": "E12345678"}},
    ]})
    assert r.status_code == 200
    results = r.json()["results"]
    assert results[0]["reason"] == "undeclared_sensitive_content"
    assert results[1]["reason"] == "undeclared_sensitive_field_name"
    assert secret not in r.text
    assert "E12345678" not in r.text

    audit = client.get("/tenants/acme/audit").text
    assert secret not in audit
    assert "E12345678" not in audit


def test_batch_http_envelope_errors(client):
    client.post("/tenants/acme/provision",
                json={"tenant_id": "acme", **PROVISION})
    assert client.post("/tenants/acme/records/batch",
                       json={"records": []}).status_code == 422
    assert client.post("/tenants/acme/records/batch",
                       json={"records": []}).json()["reason"] == "invalid_batch"
