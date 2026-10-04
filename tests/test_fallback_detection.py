"""Fallback detection: undeclared sensitive names / embedded content.

These tests pin both detection (we must catch what the tenant did not
declare) and boundaries (benign fields must not be false-positived).
"""
from __future__ import annotations

import json

import pytest

from app.fallback import (
    DETECTOR_EMAIL,
    DETECTOR_MOBILE,
    detect_fallback_sensitive,
)
from app.masking import tenant_key
from tests.conftest import STANDARD_ROLES, STANDARD_RULES

_KEY = tenant_key("test-master-key-0001", "tenant-a")


# --------------------------------------------------------------------------
# pure detector
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "field_name",
    ["id_card", "idcard", "id_no", "cert_no", "passport", "passport_no",
     "identity_number", "identity_card", "driver_license", "national_id",
     "resident_id", "ssn", "身份证", "护照号", "证件号码"],
)
def test_identifier_like_field_names_are_flagged(field_name):
    hits = detect_fallback_sensitive(
        {field_name: "whatever"}, declared_fields=set(), key=_KEY
    )
    assert len(hits) == 1
    assert hits[0].reason == "undeclared_sensitive_field_name"
    assert hits[0].field_name == field_name


@pytest.mark.parametrize(
    "field_name",
    ["order_id", "item_id", "product_id", "uid_string", "video_id",
     "build_id", "category_id", "valid", "idempotency_key"],
)
def test_benign_id_suffixed_names_are_not_flagged(field_name):
    assert detect_fallback_sensitive(
        {field_name: "x"}, declared_fields=set(), key=_KEY
    ) == []


def test_embedded_email_and_mobile_in_free_text_are_flagged():
    hits = detect_fallback_sensitive(
        {"note": "reach me at alice@example.com or 13912345678 thanks"},
        declared_fields=set(), key=_KEY,
    )
    detectors = {h.detector for h in hits}
    assert DETECTOR_EMAIL in detectors and DETECTOR_MOBILE in detectors
    assert {h.reason for h in hits} == {"undeclared_sensitive_content"}
    # Positions are evidence, matched substrings are not carried.
    email_hit = next(h for h in hits if h.detector == DETECTOR_EMAIL)
    assert email_hit.match_start is not None and email_hit.match_length
    assert not hasattr(email_hit, "raw")


def test_mobile_boundaries_do_not_partial_match_long_digit_runs():
    # A 12-digit run is not a mobile number: no in-the-middle false positive.
    assert detect_fallback_sensitive(
        {"note": "139123456789"}, declared_fields=set(), key=_KEY
    ) == []
    # ...but a mobile number followed by punctuation is still detected.
    hits = detect_fallback_sensitive(
        {"note": "call 13912345678."}, declared_fields=set(), key=_KEY
    )
    assert len(hits) == 1 and hits[0].detector == DETECTOR_MOBILE


def test_declared_fields_are_never_rescanned():
    # A declared field is governed by its rule even if its name/content would
    # otherwise match a fallback detector.
    hits = detect_fallback_sensitive(
        {"contact_text": "call me at 13912345678"},
        declared_fields={"contact_text"}, key=_KEY,
    )
    assert hits == []


def test_hits_are_deterministically_ordered_and_fingerprinted():
    payload = {"a": "x@y.com", "b": "z@w.io"}
    h1 = detect_fallback_sensitive(payload, declared_fields=set(), key=_KEY)
    h2 = detect_fallback_sensitive(payload, declared_fields=set(), key=_KEY)
    assert h1 == h2
    assert all(h.fingerprint and len(h.fingerprint) == 32 for h in h1)


# --------------------------------------------------------------------------
# service integration (single + batch), reasons distinguishable
# --------------------------------------------------------------------------

def test_single_write_rejects_embedded_content_with_distinct_reason(provisioned):
    svc = provisioned
    with pytest.raises(Exception) as ei:
        svc.write_record(
            "tenant-a",
            {"phone": "13800001234", "id_card": "11010119900101001X",
             "memo": "email alice@example.com"},
            {},
        )
    assert ei.value.reason == "undeclared_sensitive_content"
    assert ei.value.reason not in {
        "sensitive_field_missing", "value_pattern_mismatch", "non_string_value",
        "invalid_payload",
    }


def test_single_write_rejects_suspicious_name_even_with_declared_field_missing(provisioned):
    svc = provisioned
    # Declared 'phone' is missing AND a suspicious field is present; the
    # undeclared-sensitive reason must win so it cannot be hidden.
    with pytest.raises(Exception) as ei:
        svc.write_record(
            "tenant-a", {"id_card": "330101200002020022", "passport_no": "AB123"}, {}
        )
    assert ei.value.reason == "undeclared_sensitive_field_name"


def test_fallback_rejected_writes_persist_nothing_and_log_no_raw(provisioned):
    svc = provisioned
    secret_email = "secret@corp.example"
    with pytest.raises(Exception):
        svc.write_record(
            "tenant-a",
            {"phone": "13800001234", "id_card": "11010119900101001X",
             "memo": f"contact {secret_email}"},
            {},
        )
    assert svc.storage.list_records("tenant-a") == []
    blob = json.dumps(svc.list_audit("tenant-a", limit=100), ensure_ascii=False)
    assert secret_email not in blob
    reject = next(
        e for e in svc.list_audit("tenant-a")["entries"]
        if e["reason"] == "undeclared_sensitive_content"
    )
    hit = reject["evidence"]["hits"][0]
    assert set(hit) == {"field", "detector", "reason", "match_start",
                        "match_length", "fingerprint"}
    assert hit["fingerprint"]


def test_benign_business_text_passes_through(provisioned):
    svc = provisioned
    r = svc.write_record(
        "tenant-a",
        {"phone": "13800001234", "id_card": "11010119900101001X",
         "note": "order shipped, total 42 items, region cn-north"},
        {},
    )
    assert r["status"] == "created"


def test_raw_fallback_value_absent_from_sqlite_bytes(provisioned, tmp_path):
    svc = provisioned
    secret = "550101198808080088"  # looks like an id card inside a free field
    try:
        svc.write_record("tenant-a", {"memo": f"ref {secret} now"}, {})
    except Exception:
        pass
    db_bytes = (tmp_path / "test.db").read_bytes()
    assert secret.encode() not in db_bytes
