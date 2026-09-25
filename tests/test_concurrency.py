"""多租户并发：不得串读、不得重复脱敏；单条畸形不阻塞整批。"""

from __future__ import annotations

import concurrent.futures
import threading


def test_concurrent_writes_same_value_same_token(services_with_v1):
    svc, store, _, _ = services_with_v1

    def write(args):
        tenant, rid, phone = args
        return svc.put_records(tenant, [{"id": rid, "data": {"phone": phone, "city": "BJ"}}])

    args_list = [(f"tenant-{i % 5}", f"r{i}", "138-0000-1234") for i in range(50)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(write, args_list))
    assert all(r.accepted for r in results)

    # 每个租户内部：所有相同原值变体共享一个令牌，且 token_map 仅一行
    for t in range(5):
        tenant = f"tenant-{t}"
        tokens = {
            row["data"]["phone"]
            for row in store.list_records(tenant)
        }
        assert tokens == {store.list_records(tenant)[0]["data"]["phone"]}
        n_maps = store._conn.execute(
            "SELECT COUNT(*) FROM token_map WHERE tenant_id=? AND scope='phone'", (tenant,)
        ).fetchone()[0]
        assert n_maps == 1, "重复脱敏：同租户同值应只有一行映射"
        assert len(store.list_records(tenant)) == 10


def test_tokens_differ_across_tenants(services_with_v1):
    svc, store, _, _ = services_with_v1
    svc.put_records("tA", [{"id": "x", "data": {"phone": "13800001234", "city": "BJ"}}])
    svc.put_records("tB", [{"id": "x", "data": {"phone": "13800001234", "city": "BJ"}}])
    tok_a = store.get_record("tA", "x")["data"]["phone"]
    tok_b = store.get_record("tB", "x")["data"]["phone"]
    assert tok_a != tok_b, "跨租户令牌必须隔离"


def test_concurrent_cross_tenant_no_leak(services_with_v1):
    svc, store, _, _ = services_with_v1
    barrier = threading.Barrier(8)

    def worker(tenant):
        barrier.wait()
        for i in range(20):
            svc.put_records(tenant, [{"id": f"{tenant}-{i}",
                                      "data": {"phone": "13800001234", "city": "BJ"}}])
        return {r["id"] for r in store.list_records(tenant)}

    tenants = [f"t{k}" for k in range(8)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        seen = dict(zip(tenants, pool.map(worker, tenants)))

    for tenant in tenants:
        ids = seen[tenant]
        assert ids == {f"{tenant}-{i}" for i in range(20)}
        # 物理层验证：任何租户查询都带 tenant_id
        leak = [rid for rid in ids if not rid.startswith(tenant)]
        assert not leak


def test_concurrent_get_or_create_token_is_linearized(services_with_v1):
    svc, store, _, _ = services_with_v1
    tokens = set()

    def hit(_):
        barrier.wait()
        return store.get_or_create_token("t1", "phone", "fp_abc", "tok_seeded")

    # 预置一次，再并发请求相同 fp，必须全部返回同一个已有令牌
    store.get_or_create_token("t1", "phone", "fp_abc", "tok_seeded")
    barrier = threading.Barrier(16)
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        tokens = set(pool.map(hit, range(64)))
    assert tokens == {"tok_seeded"}
    n = store._conn.execute("SELECT COUNT(*) FROM token_map").fetchone()[0]
    assert n == 1


def test_one_bad_record_does_not_block_batch(services_with_v1):
    svc, _, _, _ = services_with_v1
    records = [
        {"id": "good1", "data": {"phone": "13800001234", "city": "BJ"}},
        {"id": "bad1", "data": {"phone": "0"}},
        {"id": "good2", "data": {"phone": "13900001235", "city": "SH"}},
        42,
        {"id": "good3", "data": {"phone": "13700001236", "city": "GZ"}},
    ]
    result = svc.put_records("t1", records)
    assert [x["id"] for x in result.accepted] == ["good1", "good2", "good3"]
    assert {x["reason"] for x in result.rejected} == {
        "classification_incomplete_rule", "classification_bad_record"
    }
