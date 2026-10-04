"""Batch ingestion: per-item independence, distinguishable reasons, idempotent
retry, in-batch dedup, and never crashing the whole batch on one bad item."""
from __future__ import annotations

import json

import pytest

from app.errors import BatchConflictError, BatchError

PHONE_RULE = [
    {
        "field_name": "phone",
        "strategy": "partial",
        "pattern": r"1\d{10}",
        "keep_prefix": 3,
        "keep_suffix": 4,
        "description": "phone",
    }
]
ROLES = [
    {"name": "u", "fields": {"phone": "masked", "note": "visible",
                             "memo": "visible"}, "row_filters": {}}
]


@pytest.fixture
def batch_tenant(service):
    service.provision_tenant(
        "ta",
        sensitive_fields=PHONE_RULE,
        roles=ROLES,
        default_role="u",
        retention_days=30,
        retention_action="purge",
    )
    return service


def _item(phone="13800001111", note="n", **extra):
    payload = {"phone": phone, "note": note}
    payload.update(extra)
    return {"payload": payload}


# ---- per-item independence and result shape ------------------------------

def test_batch_mixed_outcomes_are_reported_per_item(batch_tenant):
    """场景：一批记录成功/重复/拒绝混合，结果可逐条区分且坏数据不带崩整批。"""
    svc = batch_tenant
    batch = [
        {"payload": {"phone": "13800001111", "note": "ok-1"}, "client_item_id": "a"},
        {"payload": {"phone": "bad-phone", "note": "bad-pattern"}},
        {"payload": {"phone": "13800002222",
                     "memo": "write to bob@example.com"}},
        {"payload": {"id_card": "11010119900101001X", "phone": "13800003333"}},
        {"payload": {"phone": "13800001111", "note": "ok-1"}},  # exact duplicate
    ]
    res = svc.write_records_batch("ta", batch, batch_id=None)
    assert res["summary"] == {
        "total": 5, "created": 1, "duplicate": 1, "rejected": 3
    }
    statuses = [(i["index"], i["status"], i.get("reason")) for i in res["items"]]
    assert statuses[0][:2] == (0, "created")
    assert statuses[1] == (1, "rejected", "value_pattern_mismatch")
    assert statuses[2] == (2, "rejected", "undeclared_sensitive_content")
    assert statuses[3] == (3, "rejected", "undeclared_sensitive_content")
    assert statuses[4][:2] == (4, "duplicate")
    # client_item_id echoed back for reconciliation.
    assert res["items"][0]["client_item_id"] == "a"
    # One bad item did not roll back the good one.
    assert len(svc.storage.list_records("ta")) == 1


def test_rejection_reasons_are_pairwise_distinguishable(batch_tenant):
    """场景：缺字段/类型错/取值不匹配/兜底内容/兜底字段名五类拒绝原因彼此可区分。"""
    svc = batch_tenant
    batch = [
        {"payload": {"note": "no-phone-field"}},                       # missing
        {"payload": {"phone": 13800001111, "note": "x"}},              # bad type
        {"payload": {"phone": "bad", "note": "x"}},                    # pattern
        {"payload": {"phone": "13800004444",
                     "memo": "a@b.com"}},                              # fallback value
        {"payload": {"phone": "13800005555", "passport": "P1"}},       # fallback name
        {"payload": {"phone": "13800006666", "note": "fine"}},         # created
    ]
    res = svc.write_records_batch("ta", batch, batch_id=None)
    reasons = {i["reason"] for i in res["items"] if i["status"] == "rejected"}
    assert reasons == {
        "sensitive_field_missing",
        "non_string_value",
        "value_pattern_mismatch",
        "undeclared_sensitive_content",
        "undeclared_sensitive_field_name",
    }
    assert all("message" in i for i in res["items"] if i["status"] == "rejected")


def test_each_item_is_independently_committed(batch_tenant):
    """场景：每条记录独立判定、独立落库，坏条不影响其余条可读性。"""
    """Rejected items never exist; every accepted item is independently readable."""
    svc = batch_tenant
    batch = [_item(phone=f"138{i:08d}", note=f"n{i}") for i in range(20)]
    batch.append({"payload": {"phone": "bad", "note": "x"}})  # last item bad
    res = svc.write_records_batch("ta", batch, batch_id=None)
    assert res["summary"]["created"] == 20
    assert res["summary"]["rejected"] == 1
    assert len(svc.storage.list_records("ta")) == 20
    for i in res["items"][:20]:
        assert svc.storage.get_record("ta", i["record_id"]) is not None


# ---- envelope validation --------------------------------------------------

@pytest.mark.parametrize(
    "batch,batch_id,reason",
    [
        ([], None, "empty_batch"),
        ([{"x": 1}], None, "malformed_batch_item"),
        ([{"payload": {}}], None, "invalid_payload"),
        ([{"payload": {"phone": "13800001111"}, "attributes": "no"}], None,
         "invalid_attributes"),
        ([{"payload": {"phone": "13800001111"}, "client_item_id": 9}], None,
         "invalid_client_item_id"),
        ([_item()], "", "invalid_batch_id"),
    ],
)
def test_malformed_batch_envelope_rejected(batch_tenant, batch, batch_id, reason):
    """场景：批量信封结构错误在入口被整批拒绝且原因可区分。"""
    svc = batch_tenant
    with pytest.raises(BatchError) as ei:
        svc.write_records_batch("ta", batch, batch_id=batch_id)
    assert ei.value.reason == reason


def test_batch_size_limit(batch_tenant):
    """场景：超过 1000 条上限整批拒绝且不产生任何记录。"""
    svc = batch_tenant
    big = [_item(phone=f"138{i:08d}") for i in range(1001)]
    with pytest.raises(BatchError) as ei:
        svc.write_records_batch("ta", big, batch_id=None)
    assert ei.value.reason == "batch_too_large"
    assert svc.storage.list_records("ta") == []


# ---- idempotent retry -----------------------------------------------------

def test_resending_same_batch_id_is_idempotent(batch_tenant):
    """场景：同一 batch_id 重推结果逐字一致、不多存、不多产生逐条副作用。"""
    svc = batch_tenant
    batch = [
        {"payload": {"phone": "13800001111", "note": "a"}, "client_item_id": "i1"},
        {"payload": {"phone": "bad", "note": "b"}, "client_item_id": "i2"},
        {"payload": {"phone": "13800002222", "note": "c"}, "client_item_id": "i3"},
    ]
    first = svc.write_records_batch("ta", batch, batch_id="BATCH-1")
    second = svc.write_records_batch("ta", batch, batch_id="BATCH-1")
    third = svc.write_records_batch("ta", batch, batch_id="BATCH-1")
    # Result is byte-for-byte stable across retries...
    assert second["items"] == first["items"]
    assert third["items"] == first["items"]
    # ...and no extra records or per-item write audits were produced.
    assert len(svc.storage.list_records("ta")) == 2
    write_audits = [
        e for e in svc.list_audit("ta")["entries"] if e["event_type"] == "write"
    ]
    # 2 created + 1 rejected = 3 per-item audits on the first submission only.
    assert len(write_audits) == 3
    batch_audits = [
        e for e in svc.list_audit("ta")["entries"] if e["event_type"] == "batch_write"
    ]
    assert [e["reason"] for e in batch_audits][0] == "batch_idempotent_replay"
    assert batch_audits[0]["input_summary"]["rejected"] is not None  # safe counts
    # Retries are audited as replays with counts only (no raw data).
    replay_audits = [
        e for e in batch_audits if e["reason"] == "batch_idempotent_replay"
    ]
    assert len(replay_audits) == 2


def test_resend_with_different_item_count_is_rejected(batch_tenant):
    """场景：同 batch_id 重推但条目数不一致被拒绝。"""
    svc = batch_tenant
    svc.write_records_batch("ta", [_item(), _item()], batch_id="BX")
    with pytest.raises(BatchError) as ei:
        svc.write_records_batch("ta", [_item()], batch_id="BX")
    assert ei.value.reason == "batch_id_shape_mismatch"


def test_resend_with_different_item_content_is_rejected(batch_tenant):
    """场景：同 batch_id 重推但某条内容不一致被拒绝。"""
    svc = batch_tenant
    svc.write_records_batch(
        "ta", [{"payload": {"phone": "13800001111", "note": "v1"}}], batch_id="BY"
    )
    with pytest.raises(BatchError) as ei:
        svc.write_records_batch(
            "ta", [{"payload": {"phone": "13800009999", "note": "v2"}}], batch_id="BY"
        )
    assert ei.value.reason == "batch_id_content_mismatch"
    # The first submission's records remain untouched.
    assert len(svc.storage.list_records("ta")) == 1


# ---- same sensitive value, different business content --------------------

def test_shared_sensitive_value_different_content_both_stand(batch_tenant):
    """场景：共用同一敏感值但业务内容不同的两条记录各自成立，脱敏结果一致。"""
    svc = batch_tenant
    batch = [
        {"payload": {"phone": "13800007777", "note": "order-alpha"},
         "attributes": {"order": "alpha"}},
        {"payload": {"phone": "13800007777", "note": "order-beta"},
         "attributes": {"order": "beta"}},
    ]
    res = svc.write_records_batch("ta", batch, batch_id="SHARED")
    assert [i["status"] for i in res["items"]] == ["created", "created"]
    rids = {i["record_id"] for i in res["items"]}
    assert len(rids) == 2
    # Deterministic masking stays consistent for the shared value.
    recs = [svc.storage.get_record("ta", rid) for rid in rids]
    assert {r.masked_payload["phone"] for r in recs} == {"138****7777"}


def test_only_identical_whole_content_is_idempotent(batch_tenant):
    """场景：只有整条业务内容（含属性）完全相同才算重复幂等。"""
    svc = batch_tenant
    items = [
        {"payload": {"phone": "13800008888", "note": "same"}, "client_item_id": "x"},
        {"payload": {"phone": "13800008888", "note": "same"},
         "attributes": {"region": "north"}, "client_item_id": "y"},
    ]
    first = svc.write_records_batch("ta", items, batch_id="C1")
    # Same phone, same note, but different attributes => distinct content.
    assert {i["status"] for i in first["items"]} == {"created"}
    # Keyed retry must reproduce the FIRST result verbatim (for reconciliation).
    again = svc.write_records_batch("ta", items, batch_id="C1")
    assert again["items"] == first["items"]
    assert len(svc.storage.list_records("ta")) == 2

    # An unkeyed resubmission observes the records as duplicates via
    # whole-content dedup, proving identity is based on the whole content
    # (payload + attributes), not on the shared sensitive value alone.
    unkeyed = svc.write_records_batch("ta", items, batch_id=None)
    assert [i["status"] for i in unkeyed["items"]] == ["duplicate", "duplicate"]


# ---- cross-batch / single-write interplay --------------------------------

def test_batch_and_single_write_share_dedup(batch_tenant):
    """场景：批量写入与单条写入共享同一套内容级去重。"""
    svc = batch_tenant
    single = svc.write_record("ta", {"phone": "13800001111", "note": "x"}, {})
    res = svc.write_records_batch(
        "ta", [{"payload": {"phone": "13800001111", "note": "x"}}], batch_id=None
    )
    assert res["items"][0]["status"] == "duplicate"
    assert res["items"][0]["record_id"] == single["record_id"]


def test_batch_contains_no_raw_values_in_persisted_results(batch_tenant, tmp_path):
    """场景：批量链路的数据库文件与审计中都不出现原始敏感值。"""
    svc = batch_tenant
    svc.write_records_batch(
        "ta",
        [
            {"payload": {"phone": "13800009001", "note": "ok"}},
            {"payload": {"phone": "13800009002", "memo": "secret x@y.io"}},
        ],
        batch_id="RAW",
    )
    db_bytes = (tmp_path / "test.db").read_bytes()
    # Full raw phone numbers and the free-text secret are never persisted.
    assert b"13800009001" not in db_bytes
    assert b"13800009002" not in db_bytes
    assert b"x@y.io" not in db_bytes
    audit_blob = json.dumps(svc.list_audit("ta"), ensure_ascii=False)
    assert "13800009001" not in audit_blob
    assert "x@y.io" not in audit_blob


def test_unkeyed_batch_has_no_idempotency_state(batch_tenant):
    """场景：不带 batch_id 时不记录幂等状态，重发按内容去重表现为 duplicate。"""
    svc = batch_tenant
    batch = [{"payload": {"phone": f"138{i:08d}", "note": "n"}} for i in range(3)]
    r1 = svc.write_records_batch("ta", batch, batch_id=None)
    r2 = svc.write_records_batch("ta", batch, batch_id=None)
    # Without a batch_id each submission is processed independently; the
    # second run finds the records by content and reports them duplicate.
    assert {i["status"] for i in r1["items"]} == {"created"}
    assert {i["status"] for i in r2["items"]} == {"duplicate"}
    assert r1["batch_id"] is None and r2["batch_id"] is None
