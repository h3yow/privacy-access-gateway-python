"""保留期边界：到期删除/匿名化、幂等、边界时刻、畸形记录不阻塞。"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.store import ANONYMIZED_SENTINEL

NOW = datetime(2026, 9, 26, 12, 0, 0, tzinfo=timezone.utc)


def _seed(svc):
    # t1 保留 30 天 delete；t2 保留 10 天 anonymize
    svc.put_records("t1", [
        {"id": "expired", "created_at": (NOW - timedelta(days=31)).isoformat(),
         "data": {"phone": "13800001234", "city": "BJ"}},
        {"id": "boundary", "created_at": (NOW - timedelta(days=30)).isoformat(),
         "data": {"phone": "13800001235", "city": "SH"}},
        {"id": "fresh", "created_at": (NOW - timedelta(days=29)).isoformat(),
         "data": {"phone": "13800001236", "city": "GZ"}},
    ])
    svc.put_records("t2", [
        {"id": "old", "created_at": (NOW - timedelta(days=11)).isoformat(),
         "data": {"phone": "13700001237", "city": "BJ", "note": "keep-me"}},
        {"id": "new", "created_at": (NOW - timedelta(days=9)).isoformat(),
         "data": {"phone": "13600001238", "city": "SH"}},
    ])


def test_delete_and_anonymize_at_boundary(services_with_v1):
    svc, store, _, _ = services_with_v1
    _seed(svc)
    result = svc.sweep_retention(now=NOW)
    t1 = result["tenants"]["t1"]
    # <= cutoff：31 天与恰好 30 天的记录都到期
    assert sorted(t1["deleted"]) == ["boundary", "expired"]
    assert t1["anonymized"] == []
    t2 = result["tenants"]["t2"]
    assert t2["anonymized"] == ["old"]

    assert store.get_record("t1", "expired") is None
    assert store.get_record("t1", "boundary") is None
    assert store.get_record("t1", "fresh") is not None

    anon = store.get_record("t2", "old")
    assert anon["anonymized"] is True
    assert anon["data"]["phone"] == ANONYMIZED_SENTINEL
    assert anon["data"]["note"] == "keep-me"  # 非敏感字段保留
    assert store.get_record("t2", "new") is not None


def test_sweep_is_idempotent(services_with_v1):
    svc, store, _, _ = services_with_v1
    _seed(svc)
    first = svc.sweep_retention(now=NOW)
    deleted_first = sum(len(v["deleted"]) for v in first["tenants"].values())
    anon_first = sum(len(v["anonymized"]) for v in first["tenants"].values())
    assert deleted_first == 2 and anon_first == 1

    # 再扫两次：无额外副作用
    for _ in range(2):
        again = svc.sweep_retention(now=NOW)
        assert all(v["deleted"] == [] and v["anonymized"] == []
                   for v in again["tenants"].values())
        assert all(v["errors"] == [] for v in again["tenants"].values())

    # 删除的不复活；匿名化的保持哨兵
    assert store.get_record("t1", "expired") is None
    assert store.get_record("t2", "old")["data"]["phone"] == ANONYMIZED_SENTINEL
    # 物理行数稳定
    n_t1 = store._conn.execute("SELECT COUNT(*) FROM records WHERE tenant_id='t1'").fetchone()[0]
    n_t2 = store._conn.execute("SELECT COUNT(*) FROM records WHERE tenant_id='t2'").fetchone()[0]
    assert (n_t1, n_t2) == (1, 2)


def test_boundary_inclusive_semantics(services_with_v1):
    """created_at 恰好等于 cutoff（now - days）的记录必须被处理。"""
    svc, store, _, _ = services_with_v1
    exact = (NOW - timedelta(days=30)).isoformat()
    svc.put_records("t1", [{"id": "exact", "created_at": exact,
                            "data": {"phone": "13800001234", "city": "BJ"}}])
    result = svc.sweep_retention(now=NOW)
    assert result["tenants"]["t1"]["deleted"] == ["exact"]


def test_token_map_purged_after_anonymize(services_with_v1):
    svc, store, _, _ = services_with_v1
    _seed(svc)
    svc.sweep_retention(now=NOW)
    # t2 的 phone 令牌映射被切断；t1 为 delete 策略但未匿名化，映射可保留用于其他行
    n_t2 = store._conn.execute(
        "SELECT COUNT(*) FROM token_map WHERE tenant_id='t2'"
    ).fetchone()[0]
    assert n_t2 == 0


def test_sweep_continues_after_individual_failure(services_with_v1, monkeypatch):
    svc, store, _, _ = services_with_v1
    _seed(svc)
    calls = {"n": 0}
    orig = store.delete_record

    def flaky(tenant_id, record_id):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("simulated disk error")
        return orig(tenant_id, record_id)

    monkeypatch.setattr(store, "delete_record", flaky)
    result = svc.sweep_retention(now=NOW)
    t1 = result["tenants"]["t1"]
    # 一条失败被记录原因，另一条仍被处理，整体不中断
    assert len(t1["errors"]) == 1
    assert t1["errors"][0] == {"record_id": "boundary",
                               "reason": "retention_record_failed",
                               "error": "RuntimeError"}
    assert t1["deleted"] == ["expired"]  # boundary 首次失败，expired 正常删除
