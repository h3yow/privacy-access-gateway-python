"""Tests for sensitive-value variants and stable, reversible-nowhere masking."""
from __future__ import annotations

import json

import pytest

from app.masking import fingerprint, partial_mask, stable_token, tenant_key


def test_stable_token_same_value_same_token():
    key = tenant_key("master", "t1")
    t1 = stable_token(key, "phone", "13800001234")
    t2 = stable_token(key, "phone", "13800001234")
    assert t1 == t2
    assert t1.startswith("TOK_PHONE_")


def test_variants_are_distinguished_but_individually_stable():
    """138-0000-1234 / +86... / uppercase IDs are different raw values.

    The gateway performs no fuzzy normalization: each distinct spelling gets a
    distinct token, yet each spelling maps to the same token repeatedly.
    """
    key = tenant_key("master", "t1")
    variants = ["13800001234", "138-0000-1234", "+8613800001234", " 13800001234"]
    tokens = {stable_token(key, "phone", v) for v in variants}
    assert len(tokens) == len(variants)
    for v in variants:
        assert stable_token(key, "phone", v) == stable_token(key, "phone", v)


def test_token_isolation_across_tenants():
    k1 = tenant_key("master", "tenant-a")
    k2 = tenant_key("master", "tenant-b")
    raw = "11010119900101001X"
    assert stable_token(k1, "id_card", raw) != stable_token(k2, "id_card", raw)
    assert fingerprint(k1, "id_card", raw) != fingerprint(k2, "id_card", raw)


def test_partial_mask_keeps_declared_parts_only():
    assert partial_mask("13800001234", 3, 4) == "138****1234"
    # Overly generous keep lengths must never echo the full raw value.
    masked = partial_mask("ab", 1, 1)
    assert masked != "ab"
    assert "*" in masked


def test_id_card_variants_upper_lower_distinguished():
    key = tenant_key("master", "t1")
    upper = stable_token(key, "id_card", "11010119900101001X")
    lower = stable_token(key, "id_card", "11010119900101001x")
    assert upper != lower


def test_write_then_read_returns_consistent_masked_value(provisioned):
    svc = provisioned
    raw = "13800001234"
    r1 = svc.write_record(
        "tenant-a", {"phone": raw, "id_card": "11010119900101001X", "note": "n"}, {}
    )
    r2 = svc.write_record(
        "tenant-a", {"phone": raw, "id_card": "11010119900101001X", "note": "n"}, {}
    )
    assert r1["record_id"] == r2["record_id"]  # identical write dedup
    read = svc.read_record(
        "tenant-a", r1["record_id"], {"role": "admin", "attrs": {}}
    )
    assert read["payload"]["phone"] == "138****1234"
    assert read["payload"]["phone"] == r1["masked_payload"]["phone"]


def test_raw_value_never_persisted(provisioned, tmp_path):
    svc = provisioned
    raw = "13912345678"
    r = svc.write_record(
        "tenant-a",
        {"phone": raw, "id_card": "330101200002020022", "note": "secret-note"},
        {},
    )
    db_bytes = (tmp_path / "test.db").read_bytes()
    assert raw.encode() not in db_bytes
    assert "330101200002020022".encode() not in db_bytes
    # Audit JSON must not contain raw values either.
    audit = svc.list_audit("tenant-a")
    blob = json.dumps(audit, ensure_ascii=False)
    assert raw not in blob
    assert "330101200002020022" not in blob
    # Fingerprints are present and stable though.
    fp = svc.storage.get_record("tenant-a", r["record_id"]).sensitive_index["phone"][
        "fingerprint"
    ]
    assert fp and raw not in fp


def test_bad_pattern_value_rejected_with_distinct_reason(provisioned):
    svc = provisioned
    with pytest.raises(Exception) as ei:
        svc.write_record(
            "tenant-a",
            {"phone": "not-a-phone", "id_card": "330101200002020022"},
            {},
        )
    assert ei.value.reason == "value_pattern_mismatch"


def test_non_string_sensitive_value_rejected(provisioned):
    svc = provisioned
    with pytest.raises(Exception) as ei:
        svc.write_record(
            "tenant-a",
            {"phone": 13800001234, "id_card": "330101200002020022"},
            {},
        )
    assert ei.value.reason == "non_string_value"


def test_missing_sensitive_field_is_not_silently_passed(provisioned):
    svc = provisioned
    with pytest.raises(Exception) as ei:
        svc.write_record("tenant-a", {"phone": "13800001234", "note": "x"}, {})
    assert ei.value.reason == "sensitive_field_missing"
