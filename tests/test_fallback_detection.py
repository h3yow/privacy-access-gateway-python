"""兜底识别：未声明敏感字段的内容/字段名识别与拒绝。

Covers value-shape detection in free text, suspicious field names, the
distinction from declared-rule rejections, the fact that declared fields are
never double-flagged, and the guarantee that matched raw values are never
persisted or logged.
"""
from __future__ import annotations

import json

import pytest

from app.errors import ClassificationError
from tests.conftest import STANDARD_ROLES, STANDARD_RULES

PHONE_RULE = [
    {
        "field_name": "phone",
        "strategy": "partial",
        "pattern": r"1\d{10}",
        "keep_prefix": 3,
        "keep_suffix": 4,
    }
]


def _provision(svc, tenant="ta", rules=None, roles=None):
    svc.provision_tenant(
        tenant,
        sensitive_fields=rules if rules is not None else PHONE_RULE,
        roles=roles
        if roles is not None
        else [
            {"name": "u", "fields": {"phone": "masked", "memo": "visible",
                                     "note": "visible", "comment": "visible",
                                     "email": "visible", "id_card": "visible"},
             "row_filters": {}}
        ],
        default_role="u",
        retention_days=30,
        retention_action="purge",
    )


# ---- value-shape detection in free text ----------------------------------

def test_email_embedded_in_free_text_is_rejected(service):
    """场景：自由文本里混入邮箱，单条写入被兜底拦截。"""
    svc = service
    _provision(svc)
    with pytest.raises(ClassificationError) as ei:
        svc.write_record(
            "ta",
            {"phone": "13800001111", "memo": "ping me at alice@example.com please"},
            {},
        )
    assert ei.value.reason == "undeclared_sensitive_content"


def test_mobile_embedded_in_free_text_is_rejected(service):
    """场景：自由文本里混入手机号，单条写入被兜底拦截。"""
    svc = service
    _provision(svc)
    with pytest.raises(ClassificationError) as ei:
        svc.write_record(
            "ta", {"phone": "13800001111", "note": "备用号 13912345678 随时联系"}, {}
        )
    assert ei.value.reason == "undeclared_sensitive_content"


def test_id_card_shape_embedded_anywhere_is_rejected(service):
    """场景：任意字段值中出现身份证形态被兜底拦截。"""
    svc = service
    _provision(svc)
    with pytest.raises(ClassificationError) as ei:
        svc.write_record(
            "ta",
            {"phone": "13800001111", "comment": "扫描件编号 11010119900101001X 已归档"},
            {},
        )
    assert ei.value.reason == "undeclared_sensitive_content"


def test_detector_does_not_clip_long_number_runs(service):
    """场景：更长的数字串（订单号）不能被截断误判为手机号。"""
    """A longer digit run (order id) must not be clipped into a false phone."""
    from app.fallback import scan_undeclared_sensitive
    from app.masking import tenant_key

    key = tenant_key("m", "ta")
    # 12 digits: no CN-mobile hit, no id-card hit.
    hits = scan_undeclared_sensitive({"note": "order 138000012345"}, {"phone"}, key)
    assert hits == []
    # Exactly 11 well-bounded digits still hits.
    hits = scan_undeclared_sensitive({"note": "call 13800001234 now"}, {"phone"}, key)
    assert len(hits) == 1 and hits[0].detector == "mobile_cn"


# ---- suspicious field-name detection -------------------------------------

def test_sensitive_field_name_with_innocuous_value_is_rejected(service):
    """场景：字段名一看就是证件号、即使值不像也要拦截。"""
    svc = service
    _provision(svc)
    with pytest.raises(ClassificationError) as ei:
        svc.write_record(
            "ta", {"phone": "13800001111", "id_card": "see-envelope-#42"}, {}
        )
    assert ei.value.reason == "undeclared_sensitive_field_name"


def test_bank_card_field_name_is_recognized(service):
    """场景：bank_card_no 这类银行卡字段名被识别。"""
    svc = service
    _provision(svc)
    with pytest.raises(ClassificationError) as ei:
        svc.write_record(
            "ta", {"phone": "13800001111", "bank_card_no": "card held in vault"}, {}
        )
    assert ei.value.reason == "undeclared_sensitive_field_name"


def test_underscore_variants_of_sensitive_names_are_recognized(service):
    """场景：下划线/大小写变体的敏感字段名均可识别。"""
    from app.fallback import scan_undeclared_sensitive
    from app.masking import tenant_key

    key = tenant_key("m", "ta")
    for name in ("email_addr", "passport_no", "card_number"):
        hits = scan_undeclared_sensitive({name: "value"}, set(), key)
        assert hits and hits[0].kind == "field_name", name


def test_generic_id_field_is_not_flagged(service):
    """场景：普通业务字段 id 不被误判。"""
    """A generic business key named ``id`` must not trigger the heuristic."""
    svc = service
    _provision(svc)
    out = svc.write_record("ta", {"phone": "13800001111", "id": "order-001"}, {})
    assert out["status"] == "created"


# ---- interaction with declared rules -------------------------------------

def test_declared_sensitive_field_is_never_double_flagged_by_fallback(service):
    """When the tenant declares id_card, its rule — not the fallback — governs."""
    svc = service
    svc.provision_tenant(
        "tb",
        sensitive_fields=STANDARD_RULES,
        roles=STANDARD_ROLES,
        default_role="guest",
        retention_days=30,
        retention_action="purge",
    )
    out = svc.write_record(
        "tb",
        {"phone": "13800001111", "id_card": "11010119900101001X"},
        {"region": "cn-north"},
    )
    assert out["status"] == "created"


def test_declared_pattern_mismatch_reason_stays_distinct(service):
    """场景：已声明字段取值不匹配仍返回 value_pattern_mismatch。"""
    svc = service
    _provision(svc)
    with pytest.raises(ClassificationError) as ei:
        svc.write_record("ta", {"phone": "not-a-phone", "note": "x"}, {})
    assert ei.value.reason == "value_pattern_mismatch"


def test_missing_declared_field_reason_stays_distinct(service):
    """场景：缺少已声明敏感字段仍返回 sensitive_field_missing。"""
    svc = service
    _provision(svc)
    with pytest.raises(ClassificationError) as ei:
        svc.write_record("ta", {"note": "x"}, {})
    assert ei.value.reason == "sensitive_field_missing"


def test_non_string_declared_value_reason_stays_distinct(service):
    """场景：已声明敏感值类型不对仍返回 non_string_value。"""
    svc = service
    _provision(svc)
    with pytest.raises(ClassificationError) as ei:
        svc.write_record("ta", {"phone": 13800001111}, {})
    assert ei.value.reason == "non_string_value"


def test_clean_free_text_passes_through(service):
    """场景：干净的普通自由文本正常放行。"""
    svc = service
    _provision(svc)
    out = svc.write_record(
        "ta",
        {"phone": "13800001111", "memo": "just a regular business note, nothing secret"},
        {},
    )
    assert out["status"] == "created"


# ---- no raw leakage in storage or audit ----------------------------------

def test_fallback_raw_match_never_persisted_or_logged(service, tmp_path):
    """场景：兜底命中的原值不落库、不入审计，只留指纹与判定依据。"""
    svc = service
    _provision(svc)
    raw_email = "charlie@example.com"
    raw_id = "330101200002020022"
    with pytest.raises(ClassificationError):
        svc.write_record(
            "ta",
            {"phone": "13800001111", "memo": f"contact {raw_email}", "x": raw_id},
            {},
        )
    db_bytes = (tmp_path / "test.db").read_bytes()
    assert raw_email.encode() not in db_bytes
    assert raw_id.encode() not in db_bytes
    audit_blob = json.dumps(svc.list_audit("ta"), ensure_ascii=False)
    assert raw_email not in audit_blob
    assert raw_id not in audit_blob
    # But the rejection is audited with a verifiable fingerprint + detector.
    reject = next(
        e
        for e in svc.list_audit("ta")["entries"]
        if e["reason"] == "undeclared_sensitive_content"
    )
    hit = reject["evidence"]["hits"][0]
    assert hit["value_fingerprint"]
    assert hit["detector"] in {"email", "mobile_cn", "id_card_cn"}
    assert raw_email not in json.dumps(hit)
