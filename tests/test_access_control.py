"""RBAC + ABAC：字段级/行级越权原因可区分，历史结论按旧策略可复现。"""

from __future__ import annotations

import copy

import pytest

from app.errors import AccessDeniedError
from app.policy import load_bundle
from tests.conftest import V1_POLICY


@pytest.fixture
def seeded(services_with_v1):
    svc, *_ = services_with_v1
    svc.put_records("t1", [
        {"id": "r-bj", "data": {"phone": "13800001234", "email": "a@b.com",
                                 "city": "BJ", "owner_id": "u1"}},
        {"id": "r-sh", "data": {"phone": "13900001235", "email": "c@d.com",
                                 "city": "SH", "owner_id": "u2"}},
        {"id": "r-gz", "data": {"phone": "13700001236", "email": "e@f.com",
                                 "city": "GZ", "owner_id": "u3"}},
    ])
    return services_with_v1


def test_field_modes_apply(seeded):
    svc, *_ = seeded
    admin_view = svc.get_record("t1", "r-bj", "admin")
    assert admin_view["data"]["phone"].startswith("tok_")
    assert admin_view["data"]["email"] == "********"  # redacted

    # analyst 对 email 无任何权限 => 字段级拒绝，原因可区分
    with pytest.raises(AccessDeniedError) as ei:
        svc.get_record("t1", "r-bj", "analyst")
    assert ei.value.reason == "access_field_denied"


def test_field_deny_reason(seeded):
    svc, *_ = seeded
    # owner 在 BJ 行上满足行条件，字段可见（masked）
    view = svc.get_record("t1", "r-bj", "owner", {"owner_id": "u1"})
    assert view["data"]["city"] == "BJ"
    assert view["data"]["email"].startswith("tok_")


def test_unknown_role_denied(seeded):
    svc, *_ = seeded
    with pytest.raises(AccessDeniedError) as ei:
        svc.get_record("t1", "r-bj", "ghost")
    assert ei.value.reason == "access_unknown_role"


def test_row_level_abac_deny_is_distinguishable(seeded):
    svc, *_ = seeded
    # owner 行条件 city in [BJ, SH]，GZ 被行级拒绝
    with pytest.raises(AccessDeniedError) as ei:
        svc.get_record("t1", "r-gz", "owner", {"owner_id": "u3"})
    assert ei.value.reason == "access_row_denied"
    # BJ/SH 放行
    assert svc.get_record("t1", "r-bj", "owner", {"owner_id": "u1"})["id"] == "r-bj"
    assert svc.get_record("t1", "r-sh", "owner", {"owner_id": "u2"})["id"] == "r-sh"


def test_list_filters_rows_and_fields_with_reasons(seeded):
    svc, *_ = seeded
    result = svc.list_records("t1", "owner", {"owner_id": "u1"})  # owner 行条件来自记录
    ids = {r["id"] for r in result["records"]}
    assert ids == {"r-bj", "r-sh"}
    # GZ 被行级过滤，原因可查
    assert result["denied_row"] == [{"id": "r-gz", "reason": "access_row_denied"}]
    # owner 看不到 email 之外？owner 有 email 权限；analyst 无 email：
    result2 = svc.list_records("t1", "analyst", {"owner_id": "u1"})
    field_denies = {(d["id"], d["field"]) for d in result2["denied_field"]}
    assert ("r-bj", "email") in field_denies
    for row in result2["records"]:
        assert "email" not in row["data"]


def test_cross_tenant_read_isolated(seeded):
    svc, store, *_ = seeded
    with pytest.raises(AccessDeniedError) as ei:
        svc.get_record("t2", "r-bj", "admin")
    assert ei.value.reason == "access_record_not_found"
    assert store.list_records("t2") == []


def test_history_conclusion_reproduces_under_old_policy(seeded):
    svc, _, policies, audit = seeded
    # v1 下 admin 可见 masked phone；记录一次允许结论
    v1_view = svc.get_record("t1", "r-bj", "admin", policy_version="v1")
    assert v1_view["policy_version"] == "v1"
    assert v1_view["data"]["phone"].startswith("tok_")

    # 发布 v2：admin 的 phone 改为 hidden
    v2 = copy.deepcopy(V1_POLICY)
    v2["version"] = "v2"
    for fp in v2["roles"][0]["fields"]:
        if fp["field"] == "phone":
            fp["mode"] = "hidden"
    policies.put(load_bundle(v2))

    # 新策略下被隐藏
    v2_view = svc.get_record("t1", "r-bj", "admin")
    assert "phone" not in v2_view["data"]

    # 显式按 v1 复现，历史结论仍一致
    replay = svc.get_record("t1", "r-bj", "admin", policy_version="v1")
    assert replay["data"]["phone"] == v1_view["data"]["phone"]

    # 审计中两次结论各自携带当时策略版本
    entries = audit.query(tenant_id="t1", record_id="r-bj")
    versions = {e.policy_version for e in entries if e.action == "read" and e.decision == "allow"}
    assert versions == {"v1", "v2"}
