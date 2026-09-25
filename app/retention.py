"""保留期扫描。

确定语义：
- 以记录 created_at（ISO8601 UTC）与 now - retention_days 比较，
  created_at <= cutoff 的记录视为到期。
- action=delete     : 物理删除整行。
- action=anonymize  : 行保留，敏感字段改写为匿名哨兵，并切断 scope 的令牌映射。
- 幂等：到期记录处理后再次扫描不会被重复选中（删除即不存在；
  匿名化记录 anonymized=1 被排除），无额外副作用。
- 容错：单条处理失败只记录错误，不中断整租户/整批扫描。
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.models import PolicyBundle, RetentionAction
from app.store import ANONYMIZED_SENTINEL, GatewayStore


def _now_iso(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


def run_retention_sweep(
    store: GatewayStore,
    bundle: PolicyBundle,
    now: datetime | None = None,
) -> dict:
    """对策略中所有租户执行一次保留期扫描，返回按租户的处理结果。"""
    moment = _now_iso(now)
    result: dict = {
        "ran_at": moment.isoformat(),
        "policy_version": bundle.version,
        "tenants": {},
    }

    for rp in bundle.retention:
        cutoff = moment - timedelta(days=rp.retention_days)
        cutoff_iso = cutoff.isoformat()
        deleted: list[str] = []
        anonymized: list[str] = []
        errors: list[dict] = []

        candidates = store.candidates_for_retention(rp.tenant_id, cutoff_iso)
        scopes = {
            rule.scope for rule in bundle.sensitive_rules
        }
        for rec in candidates:
            rid = rec["id"]
            try:
                if rp.action is RetentionAction.DELETE:
                    if store.delete_record(rp.tenant_id, rid):
                        deleted.append(rid)
                else:
                    data = rec["data"]
                    anon_data = {
                        key: (ANONYMIZED_SENTINEL if bundle.rule_for(key) is not None else val)
                        for key, val in data.items()
                    }
                    if store.anonymize_record(rp.tenant_id, rid, anon_data):
                        anonymized.append(rid)
            except Exception as exc:  # 单条失败不阻塞其余记录
                errors.append({"record_id": rid, "reason": "retention_record_failed",
                               "error": type(exc).__name__})

        # 仅当确实发生匿名化时才切断令牌映射；删除/匿名化均不影响映射删除的幂等性
        if anonymized:
            try:
                store.delete_tokens_for_scopes(rp.tenant_id, sorted(scopes))
            except Exception as exc:
                errors.append({"record_id": None, "reason": "retention_token_purge_failed",
                               "error": type(exc).__name__})

        result["tenants"][rp.tenant_id] = {
            "cutoff": cutoff_iso,
            "action": rp.action.value,
            "deleted": deleted,
            "anonymized": anonymized,
            "errors": errors,
        }

    return result
