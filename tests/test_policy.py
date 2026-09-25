"""畸形策略必须被拒绝且原因可区分；历史版本快照可复现。"""

from __future__ import annotations

import copy

import pytest

from app.errors import PolicyValidationError
from app.policy import PolicyStore, load_bundle
from tests.conftest import V1_POLICY


def test_valid_bundle_loads():
    b = load_bundle(copy.deepcopy(V1_POLICY))
    assert b.version == "v1"
    assert {r.field for r in b.sensitive_rules} == {"phone", "email"}


@pytest.mark.parametrize(
    "mutate, expected_reason",
    [
        (lambda d: d.pop("version"), "policy_missing_version"),
        (lambda d: d.update(version=""), "policy_version_type"),
        (lambda d: d["sensitive_rules"][0].update(mode="weird"), "policy_bad_enum"),
        (lambda d: d["sensitive_rules"][0].update(pattern="("), "policy_bad_pattern"),
        (lambda d: d["sensitive_rules"][0].update(normalizer="bogus"),
         "policy_bad_normalizer"),
        (lambda d: d["sensitive_rules"][0].pop("field"), "policy_missing_field"),
        (lambda d: d["sensitive_rules"].append(dict(d["sensitive_rules"][0])),
         "policy_duplicate_rule"),
        (lambda d: d["roles"][0]["row_conditions"][0].update(operator="~"),
         "policy_bad_operator"),
        (lambda d: d["retention"][0].update(retention_days=-1), "policy_bad_retention_days"),
        (lambda d: d["retention"][0].update(action="burn"), "policy_bad_enum"),
    ],
)
def test_malformed_policy_reasons(mutate, expected_reason):
    data = copy.deepcopy(V1_POLICY)
    # 为 operator 用例补一条行条件
    data["roles"][0]["row_conditions"] = [
        {"attribute": "city", "operator": "eq", "value": "BJ"}
    ]
    mutate(data)
    with pytest.raises(PolicyValidationError) as ei:
        load_bundle(data)
    assert ei.value.reason == expected_reason, (
        f"want {expected_reason}, got {ei.value.reason}"
    )


def test_duplicate_version_put_rejected():
    store = PolicyStore()
    store.put(load_bundle(copy.deepcopy(V1_POLICY)))
    with pytest.raises(PolicyValidationError) as ei:
        store.put(load_bundle(copy.deepcopy(V1_POLICY)))
    assert ei.value.reason == "policy_duplicate_version"


def test_policy_change_creates_new_snapshot_and_old_remains():
    store = PolicyStore()
    store.put(load_bundle(copy.deepcopy(V1_POLICY)))
    v2 = copy.deepcopy(V1_POLICY)
    v2["version"] = "v2"
    v2["roles"][0]["fields"][0]["mode"] = "hidden"  # admin 的 phone 变为不可见
    store.put(load_bundle(v2))
    assert store.get("v1").roles[0].fields[0].mode.value == "masked"
    assert store.get("v2").roles[0].fields[0].mode.value == "hidden"
    assert store.latest().version == "v2"
