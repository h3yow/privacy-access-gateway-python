"""HTTP 层：原因码映射、跨租户 404、审计端点。"""

from __future__ import annotations

import copy

from tests.conftest import V1_POLICY


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_write_and_read_flow_and_reason_status(client):
    # 部分成功：200 + 可区分的 rejected reason
    resp = client.post("/tenants/t1/records", json={"records": [
        {"id": "r1", "data": {"phone": "138-0000-1234", "email": "a@b.com", "city": "BJ"}},
        {"id": "r2", "data": {"phone": "1"}},
    ]})
    assert resp.status_code == 200
    body = resp.json()
    assert [x["id"] for x in body["accepted"]] == ["r1"]
    assert body["rejected"][0]["reason"] == "classification_incomplete_rule"

    ok = client.get("/tenants/t1/records/r1", headers={"X-Role": "admin"})
    assert ok.status_code == 200 and ok.json()["data"]["phone"].startswith("tok_")

    # 字段级 403
    deny = client.get("/tenants/t1/records/r1", headers={"X-Role": "analyst"})
    assert deny.status_code == 403
    assert deny.json()["detail"]["reason"] == "access_field_denied"

    # 角色缺失 401；未知角色 403
    assert client.get("/tenants/t1/records/r1").status_code == 401
    ghost = client.get("/tenants/t1/records/r1", headers={"X-Role": "ghost"})
    assert ghost.status_code == 403 and ghost.json()["detail"]["reason"] == "access_unknown_role"

    # 跨租户 404 且不泄露存在性
    cross = client.get("/tenants/t2/records/r1", headers={"X-Role": "admin"})
    assert cross.status_code == 404
    assert cross.json()["detail"]["reason"] == "access_record_not_found"


def test_malformed_policy_http_reason(client):
    bad = copy.deepcopy(V1_POLICY)
    bad["version"] = "v-bad"
    bad["sensitive_rules"][0]["pattern"] = "("
    r = client.post("/admin/policies", json=bad)
    assert r.status_code == 400
    assert r.json()["detail"]["reason"] == "policy_bad_pattern"


def test_retention_sweep_endpoint_idempotent(client):
    client.post("/tenants/t1/records", json={"records": [
        {"id": "old", "created_at": "2026-08-01T00:00:00+00:00",
         "data": {"phone": "13800001234", "city": "BJ"}},
    ]})
    payload = {"now": "2026-09-26T12:00:00+00:00"}
    first = client.post("/admin/retention/sweep", json=payload).json()
    assert first["tenants"]["t1"]["deleted"] == ["old"]
    second = client.post("/admin/retention/sweep", json=payload).json()
    assert second["tenants"]["t1"]["deleted"] == []


def test_audit_endpoint_no_raw_values(client):
    client.post("/tenants/t1/records", json={"records": [
        {"id": "r1", "data": {"phone": "13800001234", "city": "BJ"}},
    ]})
    audit = client.get("/tenants/t1/audit").json()["entries"]
    assert audit, "应有审计记录"
    blob = str(audit)
    assert "13800001234" not in blob
    write_entry = [e for e in audit if e["action"] == "write"][0]
    assert write_entry["summaries"]["phone"]["fingerprint"].startswith("fp_")
    assert write_entry["policy_version"] == "v1"
