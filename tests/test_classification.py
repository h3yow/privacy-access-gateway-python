"""写入侧：稳定脱敏、拒绝原因可区分、日志不含原始敏感值。"""

from __future__ import annotations

PHONE = "13800001234"
EMAIL = "alice@example.com"


def _put(svc, tenant, records):
    return svc.put_records(tenant, records, request_id="req-test")


def test_same_raw_value_stable_token_across_writes_and_reads(services_with_v1):
    svc, store, _, _ = services_with_v1
    r1 = _put(svc, "t1", [{"id": "a", "data": {"phone": "138-0000-1234", "city": "BJ"}}])
    r2 = _put(svc, "t1", [{"id": "b", "data": {"phone": "138 0000 1234", "city": "SH"}}])
    assert r1.accepted and r2.accepted
    tok1 = store.get_record("t1", "a")["data"]["phone"]
    tok2 = store.get_record("t1", "b")["data"]["phone"]
    assert tok1 == tok2, "相同原值的变体必须得到相同令牌"
    # 再读一次，结果仍然一致
    view = svc.get_record("t1", "a", "admin")
    assert view["data"]["phone"] == tok1


def test_rejected_reasons_are_distinguishable(services_with_v1, caplog):
    svc, _, _, audit = services_with_v1
    result = _put(svc, "t1", [
        {"id": "ok", "data": {"phone": PHONE, "city": "BJ"}},
        {"id": "bad-pattern", "data": {"phone": "911", "city": "BJ"}},          # 规则不完整/值不符
        {"id": "no-rule", "data": {"passport_no": "E12345678"}},                # 未命中规则
        {"id": "bad-type", "data": {"phone": 13800001234}},                     # 值畸形
        "not-even-a-record",                                                    # 记录畸形
    ])
    # 4 条被拒，归因为 3 种可区分原因（bad_record 由值畸形与记录畸形两条触发）
    assert len(result.rejected) == 4
    reason_set = {x["reason"] for x in result.rejected}
    assert reason_set == {
        "classification_bad_record",
        "classification_incomplete_rule",
        "classification_no_rule",
    }, result.rejected
    by_id = {x["record_id"]: x["reason"] for x in result.rejected if x["record_id"]}
    assert by_id == {
        "bad-pattern": "classification_incomplete_rule",
        "no-rule": "classification_no_rule",
        "bad-type": "classification_bad_record",
    }
    assert [x["id"] for x in result.accepted] == ["ok"]

    # 单测日志：打印可核验输入摘要与判定依据（不得打印原值）。
    # 注意：审计 deny 条目不携带任何输入内容，只用字段名/记录号做依据。
    entries = audit.query(tenant_id="t1")
    printed = []
    for e in entries:
        line = (f"[audit] req={e.request_id} action={e.action} decision={e.decision} "
                f"policy={e.policy_version} record={e.record_id} "
                f"basis={e.basis} summaries={e.summaries}")
        printed.append(line)
    print("\n".join(printed))
    blob = "\n".join(printed)
    assert PHONE not in blob, "日志中不得出现原始手机号"
    assert EMAIL not in blob
    # 摘要可核验：包含长度与指纹
    write_allow = [e for e in entries if e.record_id == "ok" and e.decision == "allow"]
    assert write_allow and write_allow[0].summaries["phone"]["len"] == 11
    assert write_allow[0].summaries["phone"]["fingerprint"].startswith("fp_")
    denies = {e.record_id: e for e in entries if e.decision == "deny"}
    assert "bad-pattern" in denies and "no-rule" in denies and "bad-type" in denies


def test_raw_value_never_persisted(services_with_v1):
    svc, store, _, _ = services_with_v1
    _put(svc, "t1", [{"id": "a", "data": {"phone": PHONE, "email": EMAIL, "city": "BJ"}}])
    # 直接查 SQLite 物理内容
    import sqlite3

    row = store._conn.execute("SELECT data_json FROM records").fetchone()
    assert PHONE not in row[0] and EMAIL not in row[0]
    mrows = store._conn.execute("SELECT fp, token FROM token_map").fetchall()
    for fp, token in mrows:
        assert PHONE not in fp and PHONE not in token
        assert EMAIL not in fp and EMAIL not in token


def test_duplicate_write_is_idempotent(services_with_v1):
    svc, store, _, _ = services_with_v1
    rec = {"id": "a", "data": {"phone": PHONE, "city": "BJ"}}
    first = _put(svc, "t1", [rec])
    second = _put(svc, "t1", [rec])
    assert first.accepted[0]["inserted"] is True
    assert second.accepted[0]["inserted"] is False
    assert store._conn.execute("SELECT COUNT(*) FROM records").fetchone()[0] == 1
    assert store._conn.execute("SELECT COUNT(*) FROM token_map").fetchone()[0] == 1
