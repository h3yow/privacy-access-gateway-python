"""Tests for malformed policies, RBAC/ABAC denials and policy-version replay."""
from __future__ import annotations

import pytest

from app.errors import AccessDeniedError, PolicyError
from tests.conftest import STANDARD_ROLES, STANDARD_RULES


def _provision(service, tenant="tenant-a", **overrides):
    params = dict(
        sensitive_fields=STANDARD_RULES,
        roles=STANDARD_ROLES,
        default_role="guest",
        retention_days=30,
        retention_action="purge",
    )
    params.update(overrides)
    return service.provision_tenant(tenant, **params)


@pytest.mark.parametrize(
    "rules,reason",
    [
        ([{"field_name": "phone", "strategy": "bogus"}], "invalid_strategy"),
        (
            [{"field_name": "phone", "strategy": "partial", "keep_prefix": 0,
              "keep_suffix": 0}],
            "rule_incomplete",
        ),
        (
            [{"field_name": "phone", "strategy": "token", "pattern": "([0-9"}],
            "malformed_pattern",
        ),
        ([{"field_name": "", "strategy": "token"}], "rule_incomplete"),
        (
            [
                {"field_name": "phone", "strategy": "token"},
                {"field_name": "phone", "strategy": "hash"},
            ],
            "duplicate_field_rule",
        ),
    ],
)
def test_malformed_rules_rejected_with_distinct_reasons(service, rules, reason):
    with pytest.raises(PolicyError) as ei:
        _provision(service, sensitive_fields=rules)
    assert ei.value.reason == reason


@pytest.mark.parametrize(
    "roles,default,reason",
    [
        (
            [{"name": "r", "fields": {"phone": "weird"}}],
            "r",
            "invalid_field_visibility",
        ),
        (
            [{"name": "r", "fields": [], "row_filters": {}}],
            "r",
            "malformed_role_fields",
        ),
        ([{"name": "r"}], "missing-role", "default_role_undefined"),
        (
            [
                {"name": "r", "fields": {}},
                {"name": "r", "fields": {}},
            ],
            "r",
            "duplicate_role",
        ),
        (
            [{"name": "", "fields": {}}],
            "",
            "role_name_missing",
        ),
    ],
)
def test_malformed_roles_rejected_with_distinct_reasons(service, roles, default, reason):
    with pytest.raises(PolicyError) as ei:
        _provision(service, roles=roles, default_role=default)
    assert ei.value.reason == reason


def test_unknown_role_denied(provisioned):
    svc = provisioned
    rid = svc.write_record(
        "tenant-a",
        {"phone": "13800001234", "id_card": "11010119900101001X"},
        {"region": "cn-north", "owner_id": "u1"},
    )["record_id"]
    with pytest.raises(AccessDeniedError) as ei:
        svc.read_record("tenant-a", rid, {"role": "root", "attrs": {}})
    assert ei.value.reason == "unknown_role"


def test_row_level_abac_filter_denies_wrong_region(provisioned):
    svc = provisioned
    rid = svc.write_record(
        "tenant-a",
        {"phone": "13800001234", "id_card": "11010119900101001X"},
        {"region": "us-east"},
    )["record_id"]
    with pytest.raises(AccessDeniedError) as ei:
        svc.read_record("tenant-a", rid, {"role": "auditor", "attrs": {}})
    assert ei.value.reason == "row_filter_denied"


def test_row_level_abac_owner_subject_reference(provisioned):
    svc = provisioned
    rid = svc.write_record(
        "tenant-a",
        {"phone": "13800001234", "id_card": "11010119900101001X"},
        {"owner_id": "u-42"},
    )["record_id"]
    with pytest.raises(AccessDeniedError) as ei:
        svc.read_record(
            "tenant-a", rid, {"role": "owner", "attrs": {"owner_id": "u-99"}}
        )
    assert ei.value.reason == "row_filter_denied"
    ok = svc.read_record(
        "tenant-a", rid, {"role": "owner", "attrs": {"owner_id": "u-42"}}
    )
    assert ok["record_id"] == rid


def test_field_level_denial_is_distinct_from_row_denial(provisioned):
    svc = provisioned
    rid = svc.write_record(
        "tenant-a",
        {"phone": "13800001234", "id_card": "11010119900101001X"},
        {"region": "cn-north"},
    )["record_id"]
    # auditor passes the row filter (cn-north) but id_card is denied.
    with pytest.raises(AccessDeniedError) as ei:
        svc.read_record("tenant-a", rid, {"role": "auditor", "attrs": {}})
    assert ei.value.reason == "field_access_denied"


def test_default_role_is_guest_and_denied(provisioned):
    svc = provisioned
    rid = svc.write_record(
        "tenant-a",
        {"phone": "13800001234", "id_card": "11010119900101001X"},
        {},
    )["record_id"]
    with pytest.raises(AccessDeniedError) as ei:
        svc.read_record("tenant-a", rid, {"attrs": {}})
    assert ei.value.reason == "field_access_denied"


def test_policy_change_creates_new_version_and_history_replays(provisioned):
    svc = provisioned
    rid = svc.write_record(
        "tenant-a",
        {"phone": "13800001234", "id_card": "11010119900101001X"},
        {"region": "cn-north"},
    )["record_id"]

    # Under v1, auditor is allowed on the phone but denied on id_card -> deny.
    with pytest.raises(AccessDeniedError) as ei:
        svc.read_record("tenant-a", rid, {"role": "auditor", "attrs": {}})
    assert ei.value.reason == "field_access_denied"
    v1_audit = svc.list_audit("tenant-a")["entries"]
    deny_audit = next(e for e in v1_audit if e["decision"] == "deny")
    assert deny_audit["policy_version"] == 1

    # Policy v2: auditor may now see id_card masked.
    changed = svc.change_policy(
        "tenant-a",
        sensitive_fields=STANDARD_RULES,
        roles=[
            {"name": "admin", "fields": {"phone": "masked", "id_card": "masked"},
             "row_filters": {}},
            {"name": "auditor", "fields": {"phone": "masked", "id_card": "masked"},
             "row_filters": {"region": "cn-north"}},
        ],
        default_role="auditor",
    )
    assert changed["policy_version"] == 2
    read_v2 = svc.read_record("tenant-a", rid, {"role": "auditor", "attrs": {}})
    assert read_v2["policy_version"] == 2
    assert read_v2["payload"]["id_card"].startswith("TOK_ID_CARD_")

    # Replaying the v1 denial against the v1 policy must reproduce the OLD
    # conclusion even though v2 would now allow it.
    replay = svc.replay_decision("tenant-a", deny_audit["audit_id"])
    assert replay["status"] == "match"
    assert replay["reproduced_decision"] == "deny"
    assert replay["original_reason"] == "field_access_denied"
    assert replay["policy_version"] == 1


def test_replay_of_allowed_write_matches_after_policy_change(provisioned):
    svc = provisioned
    r = svc.write_record(
        "tenant-a",
        {"phone": "13800001234", "id_card": "11010119900101001X"},
        {},
    )
    svc.change_policy(
        "tenant-a",
        sensitive_fields=STANDARD_RULES,
        roles=STANDARD_ROLES,
        default_role="guest",
    )
    allow_audit = next(
        e for e in svc.list_audit("tenant-a")["entries"]
        if e["event_type"] == "write" and e["decision"] == "allow"
    )
    replay = svc.replay_decision("tenant-a", allow_audit["audit_id"])
    assert replay["status"] == "match"
    assert replay["reproduced_decision"] == "allow"


def test_list_endpoint_filters_rows_and_counts_denials(service):
    svc = service
    _provision(service)
    svc.write_record(
        "tenant-a",
        {"phone": "13800001111", "id_card": "110101199001010011"},
        {"region": "cn-north"},
    )
    svc.write_record(
        "tenant-a",
        {"phone": "13800002222", "id_card": "110101199001010022"},
        {"region": "us-east"},
    )
    # admin: both rows visible.
    res = svc.list_records("tenant-a", {"role": "admin", "attrs": {}})
    assert res["count"] == 2
    assert res["filtered_rows"] == 0
    # auditor: cn-north row passes the row filter but has id_card denied;
    # us-east row fails the row filter itself.
    res = svc.list_records("tenant-a", {"role": "auditor", "attrs": {}})
    assert res["count"] == 0
    assert res["filtered_rows"] == 1
    assert res["field_denied_rows"] == 1


def test_duplicate_provisioning_rejected(service):
    svc = service
    _provision(service)
    with pytest.raises(PolicyError) as ei:
        _provision(service)
    assert ei.value.reason == "tenant_already_exists"


def test_effective_at_out_of_order_rejected(service):
    svc = service
    _provision(service)
    with pytest.raises(PolicyError) as ei:
        svc.change_policy(
            "tenant-a",
            sensitive_fields=STANDARD_RULES,
            roles=STANDARD_ROLES,
            default_role="guest",
            effective_at="1999-01-01T00:00:00Z",
        )
    assert ei.value.reason == "effective_at_out_of_order"


def test_hash_strategy_policy_is_valid_and_stable(service):
    svc = service
    _provision(
        service,
        tenant="hash-tenant",
        sensitive_fields=[
            {"field_name": "phone", "strategy": "hash", "pattern": r"1\d{10}"}
        ],
        roles=[{"name": "u", "fields": {"phone": "masked"}, "row_filters": {}}],
        default_role="u",
    )
    r = svc.write_record("hash-tenant", {"phone": "13800001234"}, {})
    assert r["masked_payload"]["phone"].startswith("sha256:")
    r2 = svc.write_record("hash-tenant", {"phone": "13800001234"}, {})
    assert r2["status"] == "duplicate"
