"""Batch retry idempotency (incl. crash resume) and concurrency guarantees."""
from __future__ import annotations

import json
import threading
import time

import pytest

from app.errors import BatchConflictError

RULES = [
    {"field_name": "phone", "strategy": "partial",
     "pattern": r"1\d{10}", "keep_prefix": 3, "keep_suffix": 4},
]
ROLES = [{"name": "u", "fields": {"phone": "masked", "note": "visible"},
          "row_filters": {}}]


@pytest.fixture
def tenants(service):
    for t in ("ta", "tb"):
        service.provision_tenant(
            t, sensitive_fields=RULES, roles=ROLES, default_role="u",
            retention_days=30, retention_action="purge",
        )
    return service


def _items(n, prefix=138):
    return [
        {"payload": {"phone": f"{prefix}{i:08d}", "note": f"n{i}"},
         "client_item_id": f"c{i}"}
        for i in range(n)
    ]


# ---- idempotent retry -----------------------------------------------------

def test_retry_returns_identical_record_ids_and_statuses(tenants):
    """场景：重推返回的 record_id 与状态与首次完全一致。"""
    svc = tenants
    items = _items(20)
    first = svc.write_records_batch("ta", items, batch_id="R1")
    second = svc.write_records_batch("ta", items, batch_id="R1")
    third = svc.write_records_batch("ta", items, batch_id="R1")
    for i in range(20):
        for res in (second, third):
            assert res["items"][i]["record_id"] == first["items"][i]["record_id"]
            assert res["items"][i]["status"] == first["items"][i]["status"]
    assert len(svc.storage.list_records("ta")) == 20


def test_retry_does_not_duplicate_any_side_effects(tenants):
    """场景：重推不新增记录、不新增逐条审计，仅多一条幂等重放标记。"""
    svc = tenants
    items = _items(10) + [{"payload": {"phone": "bad", "note": "x"}}]
    svc.write_records_batch("ta", items, batch_id="R2")

    def counts():
        audits = svc.list_audit("ta")["entries"]
        return (
            len(svc.storage.list_records("ta")),
            len([a for a in audits if a["event_type"] == "write"]),
            len([a for a in audits if a["event_type"] == "batch_write"]),
        )

    before = counts()
    svc.write_records_batch("ta", items, batch_id="R2")
    after_one = counts()
    svc.write_records_batch("ta", items, batch_id="R2")
    after_two = counts()
    # Records and per-item write audits never multiply on retry...
    assert before[0] == after_one[0] == after_two[0] == 10
    assert before[1] == after_one[1] == after_two[1] == 11
    # ...each retry adds exactly one replay-marker batch audit, nothing else.
    assert after_one[2] == before[2] + 1
    assert after_two[2] == before[2] + 2


def test_resume_after_processing_crash_completes_exactly_once(tenants):
    """场景：处理中途崩溃（批次停留 processing）后重推能断点续跑且只成功一次。"""
    """Simulate a crash mid-batch: run row stays 'processing', some items done."""
    svc = tenants
    items = _items(12)
    # Reserve the batch and mark only the first 5 items as persisted.
    from app.retention import utcnow_iso

    svc.storage.insert_batch_run(
        "ta", "CRASH", item_count=12, policy_version=1, created_at=utcnow_iso()
    )
    from app.masking import request_fingerprint, tenant_key

    key = tenant_key(svc.settings.master_key, "ta")
    for idx, item in enumerate(items):
        svc.storage.insert_batch_item(
            "ta",
            "CRASH",
            idx,
            request_fingerprint(key, item["payload"], item.get("attributes", {})),
            item.get("client_item_id"),
        )
    # Actually store results for indexes 0..4 by processing them one at a time.
    config = svc.storage.get_tenant_config("ta")
    for idx in range(5):
        svc._process_one_for_batch(config, idx, items[idx], "CRASH")

    # Retry resumes the remaining 7 and returns the complete, aligned result.
    result = svc.write_records_batch("ta", items, batch_id="CRASH")
    assert result["summary"] == {
        "total": 12, "created": 12, "duplicate": 0, "rejected": 0
    }
    assert [i["index"] for i in result["items"]] == list(range(12))
    assert len(svc.storage.list_records("ta")) == 12
    # Another retry is now a pure completed replay.
    again = svc.write_records_batch("ta", items, batch_id="CRASH")
    assert again["items"] == result["items"]
    assert len(svc.storage.list_records("ta")) == 12


# ---- concurrency ----------------------------------------------------------

def test_concurrent_resends_store_each_record_once(tenants):
    """场景：8 线程并发重推同一批次，每条记录只存一份，结果一致或明确 409。"""
    svc = tenants
    items = _items(100)
    out: list = []
    conflicts: list[str] = []
    errors: list[Exception] = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        try:
            out.append(svc.write_records_batch("ta", items, batch_id="CONC"))
        except BatchConflictError as exc:
            conflicts.append(exc.reason)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    assert len(svc.storage.list_records("ta")) == 100
    completed = out
    # At least one thread completed; every completed result is identical.
    assert completed
    expected = [(i["status"], i["record_id"]) for i in completed[0]["items"]]
    for res in completed[1:]:
        assert [(i["status"], i["record_id"]) for i in res["items"]] == expected
    # The other threads either shared completion or got a clear 409.
    assert len(completed) + len(conflicts) == 8


def test_concurrent_batches_single_writes_and_reads_never_lose_records(tenants):
    """场景：批量/单条写入与读取并发混跑不丢记录、不出现读不到的中间态。"""
    svc = tenants
    errors: list[str] = []
    stop = threading.Event()

    def reader():
        # Repeatedly list; every observed count must be a stable prefix
        # (no torn intermediate state can throw).
        last = -1
        while not stop.is_set():
            try:
                count = svc.list_records("ta", {"role": "u", "attrs": {}})["count"]
                assert count >= last
                last = count
            except Exception as exc:  # noqa: BLE001
                errors.append(f"read:{exc!r}")
                return

    reader_thread = threading.Thread(target=reader)
    reader_thread.start()

    def singles(n, base):
        for i in range(n):
            try:
                svc.write_record("ta", {"phone": f"139{base+i:08d}", "note": "s"}, {})
            except Exception as exc:  # noqa: BLE001
                errors.append(f"single:{exc!r}")

    def batch_write(n, bid, prefix):
        try:
            svc.write_records_batch(
                "ta",
                [{"payload": {"phone": f"{prefix}{i:08d}", "note": "b"}}
                 for i in range(n)],
                batch_id=bid,
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"batch:{exc!r}")

    workers = [
        threading.Thread(target=singles, args=(100, 1)),       # 13900000001..
        threading.Thread(target=singles, args=(100, 2000)),    # disjoint
        threading.Thread(target=batch_write, args=(150, "B1", 137)),
        threading.Thread(target=batch_write, args=(150, "B2", 136)),
    ]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    stop.set()
    reader_thread.join()

    assert not errors, errors
    # 200 singles + 300 batch records.
    assert len(svc.storage.list_records("ta")) == 500
    # Reads see every committed record.
    assert svc.list_records("ta", {"role": "u", "attrs": {}})["count"] == 500


def test_batches_do_not_cross_tenants(tenants):
    """场景：两租户提交完全相同的一批原值，记录不串、指纹互不相交。"""
    svc = tenants
    shared = _items(50)  # identical raw values submitted to both tenants
    ra = svc.write_records_batch("ta", shared, batch_id="SAME")
    rb = svc.write_records_batch("tb", shared, batch_id="SAME")
    assert len(svc.storage.list_records("ta")) == 50
    assert len(svc.storage.list_records("tb")) == 50
    # Record id sets are disjoint and tokens differ across tenants.
    a_ids = {i["record_id"] for i in ra["items"]}
    b_ids = {i["record_id"] for i in rb["items"]}
    assert a_ids.isdisjoint(b_ids)
    a_tokens = {r.masked_payload["phone"] for r in svc.storage.list_records("ta")}
    b_tokens = {r.masked_payload["phone"] for r in svc.storage.list_records("tb")}
    # partial mask reveals the same head/tail; fingerprints must still differ.
    a_fps = {
        r.sensitive_index["phone"]["fingerprint"]
        for r in svc.storage.list_records("ta")
    }
    b_fps = {
        r.sensitive_index["phone"]["fingerprint"]
        for r in svc.storage.list_records("tb")
    }
    assert a_fps.isdisjoint(b_fps)


def test_batch_concurrent_with_retention_sweep(tenants):
    """场景：批量写入与保留期扫描并发执行互不破坏。"""
    svc = tenants
    errors: list[str] = []

    def batch_write():
        try:
            svc.write_records_batch(
                "ta",
                [{"payload": {"phone": f"138{i:08d}", "note": "x"}}
                 for i in range(100)],
                batch_id="RET",
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(repr(exc))

    def sweeps():
        # Nothing is expired relative to real now, but the sweep must be safe
        # to run concurrently with inserts.
        for _ in range(5):
            try:
                svc.run_retention("ta")
            except Exception as exc:  # noqa: BLE001
                errors.append(repr(exc))

    t1 = threading.Thread(target=batch_write)
    t2 = threading.Thread(target=sweeps)
    t1.start(); t2.start(); t1.join(); t2.join()
    assert not errors, errors
    assert len(svc.storage.list_records("ta")) == 100


# ---- performance ----------------------------------------------------------

def test_batch_of_few_hundred_completes_quickly(tenants):
    """场景：400 条常规批量在秒级内稳定完成，无超时级退化。"""
    svc = tenants
    items = _items(400)
    start = time.perf_counter()
    res = svc.write_records_batch("ta", items, batch_id="PERF")
    elapsed = time.perf_counter() - start
    assert res["summary"]["created"] == 400
    assert elapsed < 5.0, f"batch took {elapsed:.2f}s"
