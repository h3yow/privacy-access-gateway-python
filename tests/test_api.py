"""End-to-end HTTP API tests via FastAPI TestClient."""
from __future__ import annotations

import pytest

from fastapi.testclient import TestClient

import app.deps as deps
from app.config import Settings
from app.storage import Storage
from app.service import GatewayService


@pytest.fixture
def client(tmp_path):
    storage = Storage(str(tmp_path / "api.db"))
    storage.init()
    svc = GatewayService(
        Settings(master_key="api-test-key", database_path=str(tmp_path / "api.db")),
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
    {"name": "auditor", "fields": {"email": "denied", "phone": "masked"},
     "row_filters": {"region": "cn-north"}},
]
PROVISION = {
    "sensitive_fields": RULES,
    "roles": ROLES,
    "default_role": "admin",
    "retention_days": 30,
    "retention_action": "purge",
}


def test_root(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_full_lifecycle_over_http(client):
    r = client.post("/tenants/acme/provision", json={
        "tenant_id": "acme", **PROVISION})
    assert r.status_code == 200, r.text
    assert r.json()["policy_version"] == 1

    # Write sensitive data; response contains masked values only.
    r = client.post("/tenants/acme/records", json={
        "payload": {"email": "alice@example.com", "phone": "13800001234",
                    "memo": "hello"},
        "attributes": {"region": "cn-north", "owner": "alice"},
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "created"
    rid = body["record_id"]
    assert body["masked_payload"]["phone"] == "138****1234"
    assert body["masked_payload"]["email"].startswith("TOK_EMAIL_")
    assert "alice@example.com" not in r.text

    # Repeat identical write is idempotent over HTTP too.
    r2 = client.post("/tenants/acme/records", json={
        "payload": {"email": "alice@example.com", "phone": "13800001234",
                    "memo": "hello"},
        "attributes": {"region": "cn-north", "owner": "alice"},
    })
    assert r2.json()["status"] == "duplicate"
    assert r2.json()["record_id"] == rid

    # Admin read: masked sensitive + visible plain fields.
    r = client.post(f"/tenants/acme/records/{rid}/read", json={
        "role": "admin", "attrs": {}})
    assert r.status_code == 200
    assert r.json()["payload"]["memo"] == "hello"
    assert r.json()["payload"]["phone"] == "138****1234"

    # Auditor row filter passes (cn-north) but email field is denied.
    r = client.post(f"/tenants/acme/records/{rid}/read", json={
        "role": "auditor", "attrs": {}})
    assert r.status_code == 403
    data = r.json()
    assert data["reason"] == "field_access_denied"


def test_rejection_reasons_are_distinguishable_over_http(client):
    client.post("/tenants/acme/provision", json={"tenant_id": "acme", **PROVISION})

    # Unprovisioned tenant.
    r = client.get("/tenants/other/audit")
    assert r.status_code == 422
    assert r.json()["reason"] == "tenant_not_provisioned"

    # Malformed policy at provision time: incomplete partial rule.
    r = client.post("/tenants/bad/provision", json={
        "tenant_id": "bad",
        "sensitive_fields": [
            {"field_name": "phone", "strategy": "partial",
             "keep_prefix": 0, "keep_suffix": 0}],
        "roles": ROLES, "default_role": "admin",
        "retention_days": 30, "retention_action": "purge",
    })
    assert r.status_code == 422
    assert r.json()["reason"] == "rule_incomplete"

    # Bad value at write time.
    r = client.post("/tenants/acme/records", json={
        "payload": {"email": "x", "phone": "13800001234"},
        "attributes": {},
    })
    assert r.status_code == 422
    assert r.json()["reason"] == "value_pattern_mismatch"


def test_audit_endpoint_lists_safe_summaries(client):
    client.post("/tenants/acme/provision", json={"tenant_id": "acme", **PROVISION})
    client.post("/tenants/acme/records", json={
        "payload": {"email": "bob@example.com", "phone": "13700001111"},
        "attributes": {},
    })
    r = client.get("/tenants/acme/audit")
    assert r.status_code == 200
    text = r.text
    assert "bob@example.com" not in text
    assert "13700001111" not in text
    entries = r.json()["entries"]
    assert any(e["event_type"] == "write" for e in entries)
    # Input summary carries a fingerprint — verifiable but not the raw value.
    write_entry = next(e for e in entries if e["event_type"] == "write")
    assert "email" in write_entry["input_summary"]["fingerprints"]


def test_policy_change_and_replay_over_http(client):
    client.post("/tenants/acme/provision", json={"tenant_id": "acme", **PROVISION})
    w = client.post("/tenants/acme/records", json={
        "payload": {"email": "carol@example.com", "phone": "13600002222"},
        "attributes": {"region": "cn-north"},
    }).json()
    rid = w["record_id"]

    # auditor v1: email denied
    r = client.post(f"/tenants/acme/records/{rid}/read",
                    json={"role": "auditor", "attrs": {}})
    assert r.status_code == 403

    audit = client.get("/tenants/acme/audit").json()["entries"]
    deny_id = next(e["audit_id"] for e in audit
                   if e["decision"] == "deny" and e["reason"] == "field_access_denied")

    # Promote auditor to masked email in v2.
    r = client.post("/tenants/acme/policy", json={
        "sensitive_fields": RULES,
        "roles": [
            {"name": "admin", "fields": {"email": "masked", "phone": "masked"},
             "row_filters": {}},
            {"name": "auditor", "fields": {"email": "masked", "phone": "masked"},
             "row_filters": {"region": "cn-north"}},
        ],
        "default_role": "admin",
    })
    assert r.status_code == 200 and r.json()["policy_version"] == 2

    # Historical denial reproduces under v1.
    r = client.get(f"/tenants/acme/audit/{deny_id}/replay")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "match"
    assert body["reproduced_decision"] == "deny"
    assert body["policy_version"] == 1

    # Current read under v2 is allowed.
    r = client.post(f"/tenants/acme/records/{rid}/read",
                    json={"role": "auditor", "attrs": {}})
    assert r.status_code == 200
    assert r.json()["payload"]["email"].startswith("TOK_EMAIL_")


def test_retention_http_idempotent(client):
    client.post("/tenants/acme/provision", json={
        "tenant_id": "acme",
        **{**PROVISION, "retention_days": 30, "retention_action": "anonymize"}})
    w = client.post("/tenants/acme/records", json={
        "payload": {"email": "dave@example.com", "phone": "13500003333"},
        "attributes": {},
    }).json()
    r1 = client.post("/tenants/acme/retention/run?now=2000-01-01T00:00:00Z")
    assert r1.status_code == 200 and r1.json()["anonymized"] == []
    r2 = client.post("/tenants/acme/retention/run?now=2100-01-01T00:00:00Z")
    assert r2.json()["anonymized"] == [w["record_id"]]
    r3 = client.post("/tenants/acme/retention/run?now=2100-01-01T00:00:00Z")
    assert r3.json()["anonymized"] == []
