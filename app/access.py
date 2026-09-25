"""RBAC + ABAC 字段级/行级判定。

默认拒绝（fail-closed）：角色策略中未列出的字段一律不可见；
行级条件全部 AND，不满足即拒绝。拒绝原因通过 reason 区分：
access_unknown_role / access_field_denied / access_row_denied。
"""

from __future__ import annotations

from app.errors import AccessDeniedError
from app.models import FieldMode, RolePolicy, RowCondition


def require_role(bundle, role: str) -> RolePolicy:
    rp = bundle.role_policy(role)
    if rp is None:
        raise AccessDeniedError(
            f"role has no policy: role={role!r}", reason="access_unknown_role"
        )
    return rp


def evaluate_field_access(role_policy: RolePolicy, field_name: str) -> FieldMode:
    """返回该角色对字段的可见模式；未配置则按字段级拒绝处理。"""
    mode = role_policy.field_mode(field_name)
    if mode is None:
        raise AccessDeniedError(
            f"field not permitted for role: field={field_name!r} role={role_policy.role!r}",
            reason="access_field_denied",
        )
    return mode


def _match_condition(cond: RowCondition, record: dict, subject_attrs: dict) -> bool:
    # 属性优先取记录，其次取主体属性（支持 owner_id == subject.id 类判断）
    if cond.attribute in record:
        actual = record[cond.attribute]
    elif cond.attribute in subject_attrs:
        actual = subject_attrs[cond.attribute]
    else:
        actual = None
    op = cond.operator
    if op == "eq":
        return actual == cond.value
    if op == "ne":
        return actual != cond.value
    if op == "in":
        if not isinstance(cond.value, (list, tuple, set)):
            return False
        return actual in cond.value
    if op == "notin":
        if not isinstance(cond.value, (list, tuple, set)):
            return False
        return actual not in cond.value
    raise AccessDeniedError(
        f"unsupported operator: {op!r}", reason="access_bad_operator"
    )


def evaluate_row_access(role_policy: RolePolicy, record: dict, subject_attrs: dict) -> bool:
    """行级条件（AND）。不满足时抛 access_row_denied，返回 True 表示放行。"""
    failed = None
    for cond in role_policy.row_conditions:
        if not _match_condition(cond, record, subject_attrs):
            failed = cond
            break
    if failed is not None:
        raise AccessDeniedError(
            "row condition not satisfied: "
            f"role={role_policy.role!r} attribute={failed.attribute!r} op={failed.operator!r}",
            reason="access_row_denied",
        )
    return True
