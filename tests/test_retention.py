"""Tests for retention boundaries, idempotency and anonymization semantics."""
from __future__ import annotations

import pytest

from app.errors import AccessDeniedError, RetentionError
from tests.conftest import STANDARD_ROLES, STANDARD_RULES

PAYLOAD = {"phone": "13800001234", "id_card": "11010119900101001X"}


def _backdate(svc, tenant_id, record_id, created_at):
    rec = svc.storage.get_record(tenant_id, record_id)
    # Rewrite with an older created_at directly through storage for boundary tests.
    from app.models import StoredRecord

    old = StoredRecord(
        record_id=rec.record_id,
        tenant_id=rec.tenant_id,
        masked_payload=rec.masked_payload,
        sensitive_index=rec.sensitive_index,
        attributes=rec.attributes,
        created_at=created_at,
        status=rec.status,
    )
    svc.storage.delete_record(tenant_id, record_id)
    svc.storage.insert_record(old)


def test_retention_boundary_exclusive(service):
    svc = service
    svc.provision_tenant(
        "ta", sensitive_fields=STANDARD_RULES, roles=STANDARD_ROLES,
        default_role="admin", retention_days=30, retention_action="purge",
    )
    rid = svc.write_record("ta", dict(PAYLOAD), {})["record_id"]
    created = "2026-09-01T00:00:00Z"
    _backdate(svc, "ta", rid, created)

    # Exactly at the cutoff (created + 30d): still active.
    res = svc.run_retention("ta", now="2026-10-01T00:00:00Z")
    assert res["purged"] == []
    assert svc.storage.get_record("ta", rid) is not None

    # One second later: purged.
    res = svc.run_retention("ta", now="2026-10-01T00:00:01Z")
    assert res["purged"] == [rid]
    assert svc.storage.get_record("ta", rid) is None


def test_purge_is_idempotent_no_extra_side_effects(service):
    svc = service
    svc.provision_tenant(
        "ta", sensitive_fields=STANDARD_RULES, roles=STANDARD_ROLES,
        default_role="admin", retention_days=1, retention_action="purge",
    )
    rid = svc.write_record("ta", dict(PAYLOAD), {})["record_id"]
    _backdate(svc, "ta", rid, "2020-01-01T00:00:00Z")

    first = svc.run_retention("ta", now="2020-02-01T00:00:00Z")
    second = svc.run_retention("ta", now="2020-02-01T00:00:00Z")
    third = svc.run_retention("ta", now="2021-01-01T00:00:00Z")
    assert first["purged"] == [rid]
    assert second["purged"] == []
    assert third["purged"] == []
    # Reads of purged records fail with a distinct reason.
    with pytest.raises(AccessDeniedError) as ei:
        svc.read_record("ta", rid, {"role": "admin", "attrs": {}})
    assert ei.value.reason == "record_not_found"


def test_anonymize_is_irreversible_and_idempotent(service):
    svc = service
    svc.provision_tenant(
        "ta", sensitive_fields=STANDARD_RULES, roles=STANDARD_ROLES,
        default_role="admin", retention_days=10, retention_action="anonymize",
    )
    rid = svc.write_record(
        "ta", {**PAYLOAD, "note_keep": "business"}, {}
    )["record_id"]
    _backdate(svc, "ta", rid, "2020-01-01T00:00:00Z")

    res1 = svc.run_retention("ta", now="2020-02-01T00:00:00Z")
    assert res1["anonymized"] == [rid]
    rec = svc.storage.get_record("ta", rid)
    assert rec.status == "anonymized"
    assert rec.sensitive_index == {}  # fingerprints/tokens destroyed
    assert rec.masked_payload["phone"] == "***RETENTION-ANONYMIZED***"
    assert rec.masked_payload["id_card"] == "***RETENTION-ANONYMIZED***"
    # Non-sensitive business data remains.
    assert rec.masked_payload["note_keep"] == "business"

    res2 = svc.run_retention("ta", now="2020-02-01T00:00:00Z")
    assert res2["anonymized"] == []

    with pytest.raises(AccessDeniedError) as ei:
        svc.read_record("ta", rid, {"role": "admin", "attrs": {}})
    assert ei.value.reason == "record_anonymized"


def test_retention_validates_config(service):
    with pytest.raises(RetentionError) as ei:
        service.provision_tenant(
            "bad", sensitive_fields=STANDARD_RULES, roles=STANDARD_ROLES,
            default_role="admin", retention_days=-1, retention_action="purge",
        )
    assert ei.value.reason == "invalid_retention_days"
    with pytest.raises(RetentionError) as ei:
        service.provision_tenant(
            "bad", sensitive_fields=STANDARD_RULES, roles=STANDARD_ROLES,
            default_role="admin", retention_days=1, retention_action="explode",
        )
    assert ei.value.reason == "invalid_retention_action"


def test_one_bad_record_does_not_block_sweep(service, monkeypatch):
    svc = service
    svc.provision_tenant(
        "ta", sensitive_fields=STANDARD_RULES, roles=STANDARD_ROLES,
        default_role="admin", retention_days=1, retention_action="purge",
    )
    r1 = svc.write_record("ta", dict(PAYLOAD), {})["record_id"]
    r2 = svc.write_record(
        "ta", {"phone": "13700001111", "id_card": "330101200002020022"}, {}
    )["record_id"]
    _backdate(svc, "ta", r1, "2020-01-01T00:00:00Z")
    _backdate(svc, "ta", r2, "2020-01-01T00:00:00Z")

    calls = {"n": 0}
    real = svc.storage.delete_record

    def flaky(tenant_id, record_id):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("disk hiccup")
        return real(tenant_id, record_id)

    monkeypatch.setattr(svc.storage, "delete_record", flaky)
    res = svc.run_retention("ta", now="2020-02-01T00:00:00Z")
    assert len(res["errors"]) == 1
    # One of the two records failed, the other was still purged in the sweep.
    assert set(res["purged"]) | {e["record_id"] for e in res["errors"]} == {r1, r2}
    assert len(res["purged"]) == 1

    # Rerun sweeps the previously failing record; final state is clean.
    monkeypatch.undo()
    res2 = svc.run_retention("ta", now="2020-02-01T00:00:00Z")
    assert set(res2["purged"]) == {e["record_id"] for e in res["errors"]}
    assert svc.storage.list_records("ta") == []
