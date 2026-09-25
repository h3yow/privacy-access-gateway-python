"""Tests for cross-tenant concurrency isolation and write idempotency."""
from __future__ import annotations

import threading

from tests.conftest import STANDARD_ROLES, STANDARD_RULES


def _provision_both(svc):
    rules = [
        {"field_name": "phone", "strategy": "token", "pattern": r"1\d{10}"},
    ]
    roles = [{"name": "user", "fields": {"phone": "masked"}, "row_filters": {}}]
    svc.provision_tenant(
        "tenant-x", sensitive_fields=rules, roles=roles,
        default_role="user", retention_days=30, retention_action="purge",
    )
    svc.provision_tenant(
        "tenant-y", sensitive_fields=rules, roles=roles,
        default_role="user", retention_days=30, retention_action="purge",
    )


def test_same_raw_value_yields_different_tokens_per_tenant(service):
    svc = service
    _provision_both(svc)
    raw = "13800001234"
    rx = svc.write_record("tenant-x", {"phone": raw}, {})
    ry = svc.write_record("tenant-y", {"phone": raw}, {})
    rec_x = svc.storage.get_record("tenant-x", rx["record_id"])
    rec_y = svc.storage.get_record("tenant-y", ry["record_id"])
    assert rec_x.masked_payload["phone"] != rec_y.masked_payload["phone"]
    assert rec_x.sensitive_index["phone"]["fingerprint"] != (
        rec_y.sensitive_index["phone"]["fingerprint"]
    )


def test_no_cross_tenant_reads(service):
    svc = service
    _provision_both(svc)
    rx = svc.write_record("tenant-x", {"phone": "13800001234"}, {})
    # The record id must not resolve under the other tenant.
    assert svc.storage.get_record("tenant-y", rx["record_id"]) is None
    try:
        svc.read_record(
            "tenant-y", rx["record_id"], {"role": "user", "attrs": {}}
        )
        raise AssertionError("cross-tenant read must fail")
    except Exception as e:
        assert e.reason == "record_not_found"


def test_concurrent_identical_writes_deduplicate_to_one_record(service):
    svc = service
    _provision_both(svc)
    results: list[str] = []
    errors: list[Exception] = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        try:
            r = svc.write_record("tenant-x", {"phone": "13800001234"}, {})
            results.append(r["record_id"])
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    assert len(set(results)) == 1, results
    assert len(svc.storage.list_records("tenant-x")) == 1


def test_concurrent_writes_two_tenants_do_not_interleave(service):
    svc = service
    _provision_both(svc)
    out: dict[str, list[str]] = {"x": [], "y": []}
    lock = threading.Lock()

    def worker(tenant, key):
        for i in range(20):
            r = svc.write_record(tenant, {"phone": f"1380000{i:04d}"}, {})
            with lock:
                out[key].append(r["record_id"])

    t1 = threading.Thread(target=worker, args=("tenant-x", "x"))
    t2 = threading.Thread(target=worker, args=("tenant-y", "y"))
    t1.start(); t2.start(); t1.join(); t2.join()

    assert len(out["x"]) == 20
    assert len(out["y"]) == 20
    assert set(out["x"]).isdisjoint(out["y"])
    all_x = svc.storage.list_records("tenant-x")
    all_y = svc.storage.list_records("tenant-y")
    assert {r.record_id for r in all_x} == set(out["x"])
    assert {r.record_id for r in all_y} == set(out["y"])
    x_tokens = {r.masked_payload["phone"] for r in all_x}
    y_tokens = {r.masked_payload["phone"] for r in all_y}
    # Same 20 raw values -> completely disjoint token sets across tenants.
    assert x_tokens.isdisjoint(y_tokens)
