"""Batch ingestion: per-item judgement, fault isolation and safe resend."""
from __future__ import annotations

import time

from tests.conftest import STANDARD_ROLES, STANDARD_RULES


def _batch(svc, items):
    return svc.write_records_batch("tenant-a", items)


def _by_id(resp):
    return {r.get("item_id"): r for r in resp["results"]}


def test_batch_mixed_outcomes_are_reported_per_item(provisioned):
    svc = provisioned
    resp = _batch(svc, [
        {"item_id": "good-1",
         "payload": {"phone": "13800001234", "id_card": "11010119900101001X",
                     "note": "first"}},
        {"item_id": "bad-pattern", "payload": {"phone": "nope",
                                               "id_card": "330101200002020022"}},
        {"item_id": "missing", "payload": {"phone": "13800001234"}},
        {"item_id": "non-string",
         "payload": {"phone": 13900000000, "id_card": "330101200002020022"}},
        "this-item-is-not-even-an-object",
        {"item_id": "good-2",
         "payload": {"phone": "13700001111", "id_card": "320101199505050011",
                     "note": "second"}},
    ])
    by = _by_id(resp)
    assert resp["batch_size"] == 6
    assert resp["created"] == 2
    assert resp["duplicate"] == 0
    assert resp["rejected"] == 4

    assert by["good-1"]["status"] == "created"
    assert by["good-2"]["status"] == "created"
    assert by["good-1"]["record_id"] != by["good-2"]["record_id"]

    # Every rejection reason must be distinguishable from the others.
    reasons = {
        1: "value_pattern_mismatch",
        2: "sensitive_field_missing",
        3: "non_string_value",
        4: "invalid_payload",
    }
    for index, reason in reasons.items():
        r = resp["results"][index]
        assert r["status"] == "rejected", index
        assert r["reason"] == reason, (index, r)

    # The two good records were actually persisted despite surrounding failures.
    all_records = svc.storage.list_records("tenant-a")
    assert {r.record_id for r in all_records} == {
        by["good-1"]["record_id"], by["good-2"]["record_id"]
    }


def test_batch_rejected_fallback_reasons_are_distinct(provisioned):
    svc = provisioned
    resp = _batch(svc, [
        {"item_id": "name", "payload": {"passport_no": "G12345678"}},
        {"item_id": "text",
         "payload": {"phone": "13800001234", "id_card": "11010119900101001X",
                     "note": "ping me at bob@example.com"}},
    ])
    by = _by_id(resp)
    assert by["name"]["reason"] == "undeclared_sensitive_field_name"
    assert by["text"]["reason"] == "undeclared_sensitive_content"
    # Neither undeclared value was stored.
    assert svc.storage.list_records("tenant-a") == []


def test_batch_resend_is_idempotent_with_identical_results(provisioned):
    svc = provisioned
    items = [
        {"item_id": "a", "payload": {"phone": "13800001234",
                                      "id_card": "11010119900101001X", "note": "n1"}},
        {"item_id": "b", "payload": {"phone": "bad",
                                      "id_card": "330101200002020022"}},
        {"item_id": "c", "payload": {"phone": "13700001111",
                                      "id_card": "320101199505050011", "note": "n2"}},
    ]
    first = _batch(svc, items)
    ids_after_first = [r.record_id for r in svc.storage.list_records("tenant-a")]

    # Simulate an upstream timeout + full re-push of the same batch.
    second = _batch(svc, items)

    assert first["created"] == 2 and second["created"] == 0
    assert second["duplicate"] == 2
    assert second["rejected"] == first["rejected"] == 1

    def compact(resp):
        return [
            (r["index"], r["status"], r.get("reason"), r.get("record_id"))
            for r in resp["results"]
        ]

    f, s = compact(first), compact(second)
    # Rejected items keep the exact same distinguishable reason on resend;
    # accepted items keep the exact same record id (created -> duplicate).
    assert [(idx, reason) for idx, _status, reason, _rid in s] == [
        (idx, reason) for idx, _status, reason, _rid in f
    ]
    assert s[0][1] == "duplicate" and s[0][3] == f[0][3]
    assert s[2][1] == "duplicate" and s[2][3] == f[2][3]
    assert s[1][:3] == (1, "rejected", "value_pattern_mismatch")

    # No extra records, no duplicate side effects in storage.
    ids_after_second = [r.record_id for r in svc.storage.list_records("tenant-a")]
    assert sorted(ids_after_first) == sorted(ids_after_second)


def test_batch_shared_sensitive_value_different_content_stays_independent(provisioned):
    svc = provisioned
    resp = _batch(svc, [
        {"item_id": "r1", "payload": {"phone": "13800001234",
                                       "id_card": "11010119900101001X",
                                       "note": "business-content-1"}},
        {"item_id": "r2", "payload": {"phone": "13800001234",
                                       "id_card": "11010119900101001X",
                                       "note": "business-content-2"}},
    ])
    by = _by_id(resp)
    # Same sensitive identity, different business content => two real records.
    assert by["r1"]["status"] == "created"
    assert by["r2"]["status"] == "created"
    assert by["r1"]["record_id"] != by["r2"]["record_id"]

    # The same sensitive value is indexed by both records (shared, not blocked).
    recs = svc.storage.list_records("tenant-a")
    fps = {r.sensitive_index["phone"]["fingerprint"] for r in recs}
    assert len(fps) == 1

    # Resending either one alone returns the exact same record (true duplicate).
    again = svc.write_record(
        "tenant-a",
        {"phone": "13800001234", "id_card": "11010119900101001X",
         "note": "business-content-1"},
        {},
    )
    assert again["status"] == "duplicate"
    assert again["record_id"] == by["r1"]["record_id"]


def test_batch_duplicate_raw_value_inside_batch_is_deduplicated(provisioned):
    svc = provisioned
    items = [
        {"item_id": "x1", "payload": {"phone": "13800001234",
                                       "id_card": "11010119900101001X", "note": "same"}},
        {"item_id": "x2", "payload": {"phone": "13800001234",
                                       "id_card": "11010119900101001X", "note": "same"}},
    ]
    resp = _batch(svc, items)
    by = _by_id(resp)
    assert by["x1"]["status"] == "created"
    assert by["x2"]["status"] == "duplicate"
    assert by["x2"]["record_id"] == by["x1"]["record_id"]
    assert len(svc.storage.list_records("tenant-a")) == 1


def test_batch_raw_values_never_persisted_or_audited(provisioned):
    import json

    svc = provisioned
    secret_phone = "13611112222"
    secret_id = "440101199909090099"
    secret_email = "carol@example.com"
    _batch(svc, [
        {"item_id": "keep", "payload": {"phone": secret_phone, "id_card": secret_id,
                                         "note": "ok"}},
        {"item_id": "reject-email",
         "payload": {"phone": "13800001234", "id_card": "11010119900101001X",
                     "note": f"contact {secret_email}"}},
    ])
    # Audit API must expose fingerprints/evidence but never the raw secrets.
    blob = json.dumps(svc.list_audit("tenant-a", limit=100), ensure_ascii=False)
    for secret in (secret_phone, secret_id, secret_email):
        assert secret not in blob


def test_batch_invalid_envelope_reasons(provisioned):
    svc = provisioned
    import pytest

    from app.errors import ClassificationError
    with pytest.raises(ClassificationError) as ei:
        svc.write_records_batch("tenant-a", [])
    assert ei.value.reason == "invalid_batch"
    with pytest.raises(ClassificationError) as ei:
        svc.write_records_batch("tenant-a", {"not": "a list"})
    assert ei.value.reason == "invalid_batch"
    with pytest.raises(ClassificationError) as ei:
        svc.write_records_batch("tenant-a", [{"payload": {}}] * 1001)
    assert ei.value.reason == "batch_too_large"


def test_batch_hundreds_of_records_completes_without_timeout(provisioned):
    svc = provisioned
    n = 500
    items = [
        {"item_id": f"i-{i:04d}",
         "payload": {"phone": f"139{i:08d}",
                     "id_card": f"11010119{850000 + i:06d}X",
                     "note": f"note-{i}"}}
        for i in range(n)
    ]
    start = time.perf_counter()
    resp = _batch(svc, items)
    elapsed = time.perf_counter() - start
    assert resp["created"] == n
    assert resp["rejected"] == 0
    assert len(svc.storage.list_records("tenant-a")) == n
    # Deterministic masking: resend all duplicates, same ids, well within a
    # generous local budget (no timeout-scale degradation).
    again = _batch(svc, items)
    assert again["duplicate"] == n
    assert again["created"] == 0
    assert elapsed < 20.0
