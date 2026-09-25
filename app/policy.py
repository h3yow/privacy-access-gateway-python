"""策略加载、校验与版本化管理。

畸形策略必须在加载时被拒绝，并给出可区分的 reason：
policy_missing_version / policy_version_type / policy_duplicate_rule /
policy_bad_enum / policy_bad_pattern / policy_bad_normalizer /
policy_missing_field / policy_bad_condition / policy_bad_retention /
policy_unknown_role / policy_duplicate_version
"""

from __future__ import annotations

import re

from app.errors import PolicyValidationError
from app.masking import normalize_value
from app.models import (
    FieldMode,
    FieldPermission,
    PolicyBundle,
    RetentionAction,
    RetentionPolicy,
    RolePolicy,
    RowCondition,
    SensitiveRule,
)

_VALID_OPERATORS = {"eq", "ne", "in", "notin"}
_REQUIRED_RULE_KEYS = {"field", "pattern", "normalizer", "scope", "mode"}
_REQUIRED_ROLE_KEYS = {"role", "fields"}


def _err(missing: str) -> PolicyValidationError:
    return PolicyValidationError(missing, reason=missing)


def load_bundle(data: object) -> PolicyBundle:
    """从字典加载并严格校验策略包。"""
    if not isinstance(data, dict):
        raise _err("policy_not_object")

    version = data.get("version")
    if version is None:
        raise _err("policy_missing_version")
    if not isinstance(version, str) or not version:
        raise _err("policy_version_type")

    rules_raw = data.get("sensitive_rules", [])
    if not isinstance(rules_raw, list):
        raise _err("policy_rules_not_list")
    rules: list[SensitiveRule] = []
    seen_fields: set[str] = set()
    for i, item in enumerate(rules_raw):
        if not isinstance(item, dict):
            raise _err("policy_rule_not_object")
        missing = _REQUIRED_RULE_KEYS - item.keys()
        if missing:
            raise _err("policy_missing_field")
        field = item["field"]
        if not isinstance(field, str) or not field:
            raise _err("policy_field_name_invalid")
        if field in seen_fields:
            raise _err("policy_duplicate_rule")
        seen_fields.add(field)
        try:
            mode = FieldMode(item["mode"])
        except ValueError:
            raise _err("policy_bad_enum") from None
        normalizer = item["normalizer"]
        # 用空串试跑一次以确认归一化器存在（不接触任何真实敏感值）
        try:
            normalize_value("", normalizer)
        except ValueError:
            raise _err("policy_bad_normalizer") from None
        pattern = item["pattern"]
        if not isinstance(pattern, str) or not pattern:
            raise _err("policy_bad_pattern")
        try:
            re.compile(pattern)
        except re.error:
            raise _err("policy_bad_pattern")
        scope = item["scope"]
        if not isinstance(scope, str) or not scope:
            raise _err("policy_bad_scope")
        rules.append(SensitiveRule(field, pattern, normalizer, scope, mode))

    roles_raw = data.get("roles", [])
    if not isinstance(roles_raw, list):
        raise _err("policy_roles_not_list")
    roles: list[RolePolicy] = []
    seen_roles: set[str] = set()
    for item in roles_raw:
        if not isinstance(item, dict) or _REQUIRED_ROLE_KEYS - item.keys():
            raise _err("policy_role_malformed")
        role = item["role"]
        if not isinstance(role, str) or not role:
            raise _err("policy_role_name_invalid")
        if role in seen_roles:
            raise _err("policy_duplicate_role")
        seen_roles.add(role)
        fields_raw = item["fields"]
        if not isinstance(fields_raw, list):
            raise _err("policy_fields_not_list")
        perms: list[FieldPermission] = []
        seen_perm_fields: set[str] = set()
        for f in fields_raw:
            if not isinstance(f, dict) or "field" not in f or "mode" not in f:
                raise _err("policy_field_perm_malformed")
            if not isinstance(f["field"], str) or not f["field"]:
                raise _err("policy_field_name_invalid")
            if f["field"] in seen_perm_fields:
                raise _err("policy_duplicate_field_perm")
            seen_perm_fields.add(f["field"])
            try:
                fmode = FieldMode(f["mode"])
            except ValueError:
                raise _err("policy_bad_enum") from None
            perms.append(FieldPermission(f["field"], fmode))
        conds_raw = item.get("row_conditions", [])
        if not isinstance(conds_raw, list):
            raise _err("policy_conditions_not_list")
        conds: list[RowCondition] = []
        for c in conds_raw:
            if not isinstance(c, dict) or not {"attribute", "operator", "value"} <= c.keys():
                raise _err("policy_bad_condition")
            if not isinstance(c["attribute"], str) or not c["attribute"]:
                raise _err("policy_bad_condition")
            if c["operator"] not in _VALID_OPERATORS:
                raise _err("policy_bad_operator")
            conds.append(RowCondition(c["attribute"], c["operator"], c["value"]))
        roles.append(RolePolicy(role, tuple(perms), tuple(conds)))

    ret_raw = data.get("retention", [])
    if not isinstance(ret_raw, list):
        raise _err("policy_retention_not_list")
    retentions: list[RetentionPolicy] = []
    seen_tenants: set[str] = set()
    for item in ret_raw:
        if not isinstance(item, dict) or not {"tenant_id", "retention_days", "action"} <= item.keys():
            raise _err("policy_bad_retention")
        tid = item["tenant_id"]
        days = item["retention_days"]
        if not isinstance(tid, str) or not tid:
            raise _err("policy_bad_retention")
        if not isinstance(days, int) or isinstance(days, bool) or days < 0:
            raise _err("policy_bad_retention_days")
        try:
            action = RetentionAction(item["action"])
        except ValueError:
            raise _err("policy_bad_enum") from None
        if tid in seen_tenants:
            raise _err("policy_duplicate_retention")
        seen_tenants.add(tid)
        retentions.append(RetentionPolicy(tid, days, action))

    return PolicyBundle(version, tuple(rules), tuple(roles), tuple(retentions))


class PolicyStore:
    """保存策略的全部历史版本，按版本取不可变快照。"""

    def __init__(self) -> None:
        self._bundles: dict[str, PolicyBundle] = {}
        self._order: list[str] = []

    def put(self, bundle: PolicyBundle) -> None:
        if bundle.version in self._bundles:
            raise _err("policy_duplicate_version")
        self._bundles[bundle.version] = bundle
        self._order.append(bundle.version)

    def get(self, version: str) -> PolicyBundle:
        try:
            return self._bundles[version]
        except KeyError:
            raise _err("policy_version_not_found") from None

    def latest(self) -> PolicyBundle:
        if not self._order:
            raise _err("policy_store_empty")
        return self._bundles[self._order[-1]]

    def versions(self) -> list[str]:
        return list(self._order)
