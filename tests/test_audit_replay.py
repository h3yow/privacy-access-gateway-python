"""Historical-decision reproducibility and idempotency replay tests."""
from __future__ import annotations

from tests.conftest import STANDARD_ROLES, STANDARD_RULES


def _find(entries, **criteria):
    for e in entries:
        if all(e.get(k) == v for k, v in criteria.items()):
            return e
    raise KeyError(criteria)


def test_read_denial_replays_against_old_policy_version(service):
    svc = service
    svc.provision_tenant(
        "ta", sensitive_fields=STANDARD_RULES, roles=STANDARD_ROLES,
        default_role="guest", retention_days=365, retention_action="purge",
    )
    rid = svc.write_record(
        "ta",
        {"phone": "13800001234", "id_card": "11010119900101001X"},
        {"region": "cn-north"},
    )["record_id"]

    # v1: guest default -> field denial for an explicit guest read.
    try:
        svc.read_record("ta", rid, {"role": "guest", "attrs": {}})
    except Exception:
        pass
    deny = _find(
        svc.list_audit("ta")["entries"],
        event_type="read", decision="deny", reason="field_access_denied",
    )

    # v2 makes guest see masked phone/id.
    permissive_roles = [
        {"name": "guest",
         "fields": {"phone": "masked", "id_card": "masked"},
         "row_filters": {}},
        {"name": "admin",
         "fields": {"phone": "masked", "id_card": "masked"},
         "row_filters": {}},
    ]
    svc.change_policy(
        "ta", sensitive_fields=STANDARD_RULES, roles=permissive_roles,
        default_role="guest",
    )
    assert svc.read_record("ta", rid, {"role": "guest", "attrs": {}}) is not None

    replay = svc.replay_decision("ta", deny["audit_id"])
    assert replay["original_decision"] == "deny"
    assert replay["reproduced_decision"] == "deny"
    assert replay["policy_version"] == 1
    assert replay["status"] == "match"


def test_row_filter_replay_uses_recorded_subject_attrs(service):
    svc = service
    svc.provision_tenant(
        "ta", sensitive_fields=STANDARD_RULES, roles=STANDARD_ROLES,
        default_role="admin", retention_days=365, retention_action="purge",
    )
    rid = svc.write_record(
        "ta",
        {"phone": "13800001234", "id_card": "11010119900101001X"},
        {"owner_id": "u1"},
    )["record_id"]
    ok_read = svc.read_record(
        "ta", rid, {"role": "owner", "attrs": {"owner_id": "u1"}}
    )
    assert ok_read["record_id"] == rid
    allow = _find(
        svc.list_audit("ta")["entries"],
        event_type="read", decision="allow",
    )
    replay = svc.replay_decision("ta", allow["audit_id"])
    assert replay["status"] == "match"
    assert replay["reproduced_decision"] == "allow"


def test_write_replay_tracks_fingerprint_consistency(service):
    svc = service
    svc.provision_tenant(
        "ta", sensitive_fields=STANDARD_RULES, roles=STANDARD_ROLES,
        default_role="admin", retention_days=365, retention_action="purge",
    )
    svc.write_record(
        "ta",
        {"phone": "13800001234", "id_card": "11010119900101001X"},
        {},
    )
    allow = _find(
        svc.list_audit("ta")["entries"],
        event_type="write", decision="allow", reason="classified_and_stored",
    )
    replay = svc.replay_decision("ta", allow["audit_id"])
    assert replay["status"] == "match"
    assert replay["evidence"]["recorded_fingerprints"]["phone"]
    # The recorded fingerprint must still equal the live persisted index.
    rec = svc.storage.get_record("ta", allow["record_id"])
    assert replay["evidence"]["current_index"]["phone"] == (
        rec.sensitive_index["phone"]["fingerprint"]
    )


def test_rejected_write_replay_stays_rejected(service):
    svc = service
    svc.provision_tenant(
        "ta", sensitive_fields=STANDARD_RULES, roles=STANDARD_ROLES,
        default_role="admin", retention_days=365, retention_action="purge",
    )
    try:
        svc.write_record("ta", {"phone": "bad", "id_card": "x"}, {})
    except Exception:
        pass
    reject = _find(
        svc.list_audit("ta")["entries"],
        event_type="write", decision="reject",
    )
    replay = svc.replay_decision("ta", reject["audit_id"])
    assert replay["status"] == "match"
    assert replay["reproduced_decision"] == "reject"


def test_anonymize_retention_replay_confirms_destruction(service):
    svc = service
    svc.provision_tenant(
        "ta", sensitive_fields=STANDARD_RULES, roles=STANDARD_ROLES,
        default_role="admin", retention_days=1, retention_action="anonymize",
    )
    rid = svc.write_record(
        "ta",
        {"phone": "13800001234", "id_card": "11010119900101001X"},
        {},
    )["record_id"]
    # Backdate.
    from app.models import StoredRecord

    rec = svc.storage.get_record("ta", rid)
    old = StoredRecord(
        record_id=rec.record_id, tenant_id=rec.tenant_id,
        masked_payload=rec.masked_payload, sensitive_index=rec.sensitive_index,
        attributes=rec.attributes, created_at="2020-01-01T00:00:00Z",
        status=rec.status,
    )
    svc.storage.delete_record("ta", rid)
    svc.storage.insert_record(old)

    svc.run_retention("ta", now="2020-02-01T00:00:00Z")
    retention_entry = _find(
        svc.list_audit("ta")["entries"], event_type="retention"
    )
    replay = svc.replay_decision("ta", retention_entry["audit_id"])
    assert replay["status"] == "match"
    assert replay["evidence"]["anonymized_confirmed"] == [rid]
    assert replay["evidence"]["purged_still_present"] == []


def test_purged_record_replay_is_inconclusive_but_audit_preserved(service):
    svc = service
    svc.provision_tenant(
        "ta", sensitive_fields=STANDARD_RULES, roles=STANDARD_ROLES,
        default_role="admin", retention_days=1, retention_action="purge",
    )
    rid = svc.write_record(
        "ta",
        {"phone": "13800001234", "id_card": "11010119900101001X"},
        {"region": "cn-north"},
    )["record_id"]
    svc.read_record("ta", rid, {"role": "admin", "attrs": {}})
    allow = _find(
        svc.list_audit("ta")["entries"],
        event_type="read", decision="allow",
    )
    # Backdate and purge.
    from app.models import StoredRecord

    rec = svc.storage.get_record("ta", rid)
    old = StoredRecord(
        record_id=rec.record_id, tenant_id=rec.tenant_id,
        masked_payload=rec.masked_payload, sensitive_index=rec.sensitive_index,
        attributes=rec.attributes, created_at="2020-01-01T00:00:00Z",
        status=rec.status,
    )
    svc.storage.delete_record("ta", rid)
    svc.storage.insert_record(old)
    svc.run_retention("ta", now="2020-02-01T00:00:00Z")
    assert svc.storage.get_record("ta", rid) is None

    # The historical audit entry still exists and replay marks it inconclusive
    # (record physically gone) rather than fabricating a new denial.
    replay = svc.replay_decision("ta", allow["audit_id"])
    assert replay["original_decision"] == "allow"
    assert replay["status"] == "inconclusive"
    assert replay["policy_version"] == 1


def test_replay_unknown_audit_id(service):
    from app.errors import PolicyError
    import pytest

    svc = service
    svc.provision_tenant(
        "ta", sensitive_fields=STANDARD_RULES, roles=STANDARD_ROLES,
        default_role="admin", retention_days=1, retention_action="purge",
    )
    with pytest.raises(PolicyError) as ei:
        svc.replay_decision("ta", 99999)
    assert ei.value.reason == "audit_not_found"
