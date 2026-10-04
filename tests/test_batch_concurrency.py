"""Concurrent batch/single writes, reads and retention: no loss, no leakage."""
from __future__ import annotations

import threading

from tests.conftest import STANDARD_ROLES, STANDARD_RULES


RULES = [
    {"field_name": "phone", "strategy": "token", "pattern": r"1\d{10}"},
]
ROLES = [{"name": "user", "fields": {"phone": "masked", "note": "visible"},
          "row_filters": {}}]


def _provision(svc, tenant="tenant-c"):
    svc.provision_tenant(
        tenant, sensitive_fields=RULES, roles=ROLES, default_role="user",
        retention_days=30, retention_action="purge",
    )


def test_concurrent_batch_resends_store_each_record_once(service):
    svc = service
    _provision(svc)
    n = 200
    items = [
        {"item_id": f"i-{i:04d}",
         "payload": {"phone": f"139{i:08d}", "note": f"note-{i}"}}
        for i in range(n)
    ]

    outputs: list[dict] = []
    errors: list[Exception] = []
    barrier = threading.Barrier(4)

    def worker():
        barrier.wait()
        try:
            outputs.append(svc.write_records_batch("tenant-c", items))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    records = svc.storage.list_records("tenant-c")
    assert len(records) == n, len(records)
    # Every resend reports the same n record ids; one created wave, the rest
    # duplicates, but no extra stored records.
    id_sets = [
        {r.get("record_id") for r in out["results"] if r["status"] in
         ("created", "duplicate")}
        for out in outputs
    ]
    assert id_sets.count(id_sets[0]) == len(id_sets)
    stored = {r.record_id for r in records}
    assert id_sets[0] == stored
    created_total = sum(o["created"] for o in outputs)
    assert created_total == n  # exactly one creation per unique record


def test_concurrent_batch_and_single_writes_sharing_value_dont_collide(service):
    svc = service
    _provision(svc)
    shared_phone = "13800001234"
    barrier = threading.Barrier(3)  # noqa
    errors: list[Exception] = []
    single_ids: list[str] = []

    def batch_worker(offset):
        barrier.wait()
        try:
            svc.write_records_batch("tenant-c", [
                {"item_id": f"b{offset}",
                 "payload": {"phone": shared_phone, "note": f"batch-{offset}"}}
            ])
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    def single_worker():
        barrier.wait()
        try:
            r = svc.write_record(
                "tenant-c", {"phone": shared_phone, "note": "single"}, {}
            )
            single_ids.append(r["record_id"])
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = (
        [threading.Thread(target=batch_worker, args=(i,)) for i in range(2)]
        + [threading.Thread(target=single_worker)]
    )
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    # Three genuinely different business contents sharing one sensitive value
    # must all exist independently.
    records = svc.storage.list_records("tenant-c")
    notes = {r.masked_payload["note"] for r in records}
    assert notes == {"batch-0", "batch-1", "single"}
    fps = {r.sensitive_index["phone"]["fingerprint"] for r in records}
    assert len(fps) == 1  # shared sensitive value, deterministic fingerprint
    assert len(records) == 3


def test_batch_concurrent_with_reads_and_retention_loses_nothing(service):
    svc = service
    # Retention purges ancient records; fresh batch records must survive and
    # stay readable while the sweep runs.
    svc.provision_tenant(
        "tenant-d", sensitive_fields=RULES, roles=ROLES, default_role="user",
        retention_days=1, retention_action="purge",
    )
    # Ancient record that retention should remove.
    old = svc.write_record("tenant-d", {"phone": "13800000000", "note": "old"}, {})
    from app.storage import StoredRecord
    with svc.storage.lock():
        rec = svc.storage.get_record("tenant-d", old["record_id"])
        svc.storage._db().execute(
            "UPDATE records SET created_at=? WHERE tenant_id=? AND record_id=?",
            ("1999-01-01T00:00:00Z", "tenant-d", old["record_id"]),
        )
        svc.storage._db().commit()

    n = 100
    items = [
        {"item_id": f"i-{i:04d}",
         "payload": {"phone": f"137{i:08d}", "note": f"fresh-{i}"}}
        for i in range(n)
    ]
    read_seen: list[int] = []
    errors: list[Exception] = []
    barrier = threading.Barrier(3)  # noqa

    def writer():
        barrier.wait()
        try:
            svc.write_records_batch("tenant-d", items)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    def reader():
        barrier.wait()
        try:
            seen = 0
            for r in svc.storage.list_records("tenant-d"):
                # Every row observed must be a fully committed, consistent row.
                assert r.tenant_id == "tenant-d"
                assert "phone" in r.masked_payload
                seen += 1
            read_seen.append(seen)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    def sweeper():
        barrier.wait()
        try:
            svc.run_retention("tenant-d", now="2001-01-01T00:00:00Z")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=writer),
               threading.Thread(target=reader),
               threading.Thread(target=sweeper)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    final = svc.storage.list_records("tenant-d")
    assert len(final) == n
    assert all(r.masked_payload["note"].startswith("fresh-") for r in final)
    assert svc.storage.get_record("tenant-d", old["record_id"]) is None
    # No tenant leakage into other namespaces.
    assert svc.storage.list_records("tenant-c") == []
