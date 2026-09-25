"""网关应用服务。

写入（put_records）：
  对每条记录逐字段处理——
  * 命中敏感规则：变体归一化 -> HMAC 确定性令牌（store 保证幂等 get-or-create）
  * 未命中任何规则的疑似敏感字段：拒绝（classification_no_rule），不静默放行
  * 命中但规则不完整/值畸形：拒绝（classification_incomplete_rule / classification_bad_record）
  单条失败不影响同批其他记录。

读取（get_record / list_records）：
  按指定 policy_version（默认最新）取角色策略，字段级模式 + 行级 ABAC 双重判定，
  拒绝原因可区分；所有判定写审计，审计内容只有摘要与依据，无原值。

持久化层与日志中永远不出现原始敏感值。
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from app import access
from app.audit import AuditEntry, AuditLog, value_fingerprint, value_summary
from app.errors import (
    AccessDeniedError,
    ClassificationError,
    GatewayError,
    RecordProcessingError,
)
from app.masking import deterministic_token, normalize_value, redacted_placeholder
from app.models import FieldMode, PolicyBundle
from app.policy import PolicyStore
from app.retention import run_retention_sweep
from app.store import GatewayStore

# 粗粒度"疑似敏感"探测：未配置规则但看起来像手机号/证件/邮箱/带 secret 命名的字段
_SUSPICIOUS_NAME = re.compile(r"(?i)(phone|mobile|email|id.?card|passport|secret|ssn|bank)")
_SUSPICIOUS_LOOKS = [
    re.compile(r"^1\d{10}$"),                      # 手机号
    re.compile(r"^[\w.+-]+@[\w-]+\.[\w.-]+$"),     # 邮箱
    re.compile(r"^\d{15}(\d{2}[0-9Xx])?$"),        # 身份证
]


@dataclass
class BatchResult:
    accepted: list[dict]
    rejected: list[dict]


class PrivacyGatewayService:
    def __init__(
        self,
        store: GatewayStore,
        policies: PolicyStore,
        audit: AuditLog,
        secret: str = "local-dev-secret",
    ) -> None:
        self.store = store
        self.policies = policies
        self.audit = audit
        self.secret = secret

    # ---------- 写入 ----------
    def put_records(
        self,
        tenant_id: str,
        records: list[dict],
        *,
        policy_version: str | None = None,
        request_id: str | None = None,
    ) -> BatchResult:
        bundle = self._bundle(policy_version)
        rid_req = request_id or uuid.uuid4().hex
        accepted: list[dict] = []
        rejected: list[dict] = []

        for index, record in enumerate(records):
            try:
                outcome = self._write_one(tenant_id, record, bundle, rid_req, index)
                accepted.append(outcome)
            except RecordProcessingError as exc:
                rejected.append(
                    {
                        "index": exc.index,
                        "record_id": exc.record_id,
                        "reason": exc.reason,
                        "message": exc.message,
                    }
                )
        return BatchResult(accepted, rejected)

    def _write_one(
        self,
        tenant_id: str,
        record: dict,
        bundle: PolicyBundle,
        request_id: str,
        index: int,
    ) -> dict:
        record_id = record.get("id") if isinstance(record, dict) else None
        try:
            if not isinstance(record, dict):
                raise ClassificationError(
                    "record is not an object", reason="classification_bad_record"
                )
            if not isinstance(record_id, str) or not record_id:
                raise ClassificationError(
                    "record missing string id", reason="classification_bad_record"
                )
            payload = record.get("data")
            if not isinstance(payload, dict):
                raise ClassificationError(
                    "record missing data object", reason="classification_bad_record"
                )

            masked: dict[str, str] = {}
            summaries: dict[str, dict] = {}
            basis_fields: dict[str, dict] = {}

            for field_name, raw in payload.items():
                rule = bundle.rule_for(field_name)
                if rule is None:
                    if not isinstance(raw, str):
                        raise ClassificationError(
                            f"non-sensitive field has unsupported type: field={field_name!r}",
                            reason="classification_bad_record",
                        )
                    if self._looks_sensitive(field_name, raw):
                        raise ClassificationError(
                            f"no sensitive rule matched for field={field_name!r}",
                            reason="classification_no_rule",
                        )
                    # 非敏感字符串字段原样落盘
                    masked[field_name] = raw
                    continue

                if not isinstance(raw, str) or not raw:
                    raise ClassificationError(
                        f"sensitive field value malformed: field={field_name!r}",
                        reason="classification_bad_record",
                    )
                # 先归一化（处理变体），再对归一化结果做形态识别，
                # 保证 "138-0000-1234" 与 "13800001234" 判定一致。
                try:
                    normalized = normalize_value(raw, rule.normalizer)
                    if re.compile(rule.pattern).search(normalized) is None:
                        raise ClassificationError(
                            f"value does not satisfy rule pattern: field={field_name!r}",
                            reason="classification_incomplete_rule",
                        )
                except ClassificationError:
                    raise
                except (ValueError, re.error):
                    raise ClassificationError(
                        f"rule incomplete or unusable: field={field_name!r}",
                        reason="classification_incomplete_rule",
                    ) from None

                wanted = deterministic_token(tenant_id, rule.scope, normalized, self.secret)
                fp = value_fingerprint(tenant_id, normalized, self.secret)
                token = self.store.get_or_create_token(
                    tenant_id, rule.scope, fp, wanted
                )
                masked[field_name] = token
                summaries[field_name] = value_summary(raw)
                summaries[field_name]["fingerprint"] = fp
                basis_fields[field_name] = {
                    "scope": rule.scope,
                    "normalizer": rule.normalizer,
                    "mode": rule.mode.value,
                }

            created_at = record.get("created_at") or datetime.now(timezone.utc).isoformat()
            created = self.store.insert_record(tenant_id, record_id, masked, created_at)
            self.audit.append(
                AuditEntry(
                    ts=datetime.now(timezone.utc).isoformat(),
                    request_id=request_id,
                    tenant_id=tenant_id,
                    action="write",
                    decision="allow",
                    policy_version=bundle.version,
                    subject_role="system",
                    record_id=record_id,
                    basis={"fields": basis_fields, "inserted": created},
                    summaries=summaries,
                )
            )
            return {"id": record_id, "inserted": created, "data": masked}
        except GatewayError as exc:
            self._audit_deny(
                tenant_id=tenant_id,
                bundle=bundle,
                request_id=request_id,
                action="write",
                role="system",
                record_id=record_id if isinstance(record_id, str) else "",
                reason=exc.reason,
                field_basis={"index": index},
                summaries={},
            )
            raise RecordProcessingError(
                exc.message,
                index=index,
                record_id=record_id if isinstance(record_id, str) else None,
                cause=exc,
                reason=exc.reason,
            ) from exc

    # ---------- 读取 ----------
    def get_record(
        self,
        tenant_id: str,
        record_id: str,
        role: str,
        subject_attrs: dict | None = None,
        *,
        policy_version: str | None = None,
        request_id: str | None = None,
    ) -> dict:
        bundle = self._bundle(policy_version)
        rid_req = request_id or uuid.uuid4().hex
        subject_attrs = subject_attrs or {}
        role_pol = access.require_role(bundle, role)

        stored = self.store.get_record(tenant_id, record_id)
        if stored is None:
            self._audit_deny(
                tenant_id=tenant_id, bundle=bundle, request_id=rid_req, action="read",
                role=role, record_id=record_id, reason="access_record_not_found",
                field_basis={}, summaries={},
            )
            raise AccessDeniedError(
                f"record not found or outside tenant: id={record_id!r}",
                reason="access_record_not_found",
            )

        # 行级判定基于非敏感判定元数据（含已脱敏字段不参与关联时可由属性字段决定）
        try:
            access.evaluate_row_access(role_pol, stored["data"], subject_attrs)
            visible = self._project_fields(role_pol, stored["data"])
        except AccessDeniedError as exc:
            self._audit_deny(
                tenant_id=tenant_id, bundle=bundle, request_id=rid_req, action="read",
                role=role, record_id=record_id, reason=exc.reason,
                field_basis={"message": exc.message}, summaries={},
            )
            raise
        self.audit.append(
            AuditEntry(
                ts=datetime.now(timezone.utc).isoformat(),
                request_id=rid_req,
                tenant_id=tenant_id,
                action="read",
                decision="allow",
                policy_version=bundle.version,
                subject_role=role,
                record_id=record_id,
                basis={
                    "fields": {f: m.value for f, m in self._field_modes(role_pol, stored["data"]).items()},
                    "row_conditions": len(role_pol.row_conditions),
                },
                summaries={},
            )
        )
        return {
            "id": stored["id"],
            "tenant_id": tenant_id,
            "created_at": stored["created_at"],
            "anonymized": stored["anonymized"],
            "policy_version": bundle.version,
            "data": visible,
        }

    def list_records(
        self,
        tenant_id: str,
        role: str,
        subject_attrs: dict | None = None,
        *,
        policy_version: str | None = None,
        request_id: str | None = None,
    ) -> dict:
        """列出租户内记录；行级不允许的记录被过滤并计入 denied_row，单条不阻塞整体。"""
        bundle = self._bundle(policy_version)
        rid_req = request_id or uuid.uuid4().hex
        subject_attrs = subject_attrs or {}
        role_pol = access.require_role(bundle, role)

        visible_rows: list[dict] = []
        denied_row: list[dict] = []
        denied_field: list[dict] = []

        for stored in self.store.list_records(tenant_id):
            rid = stored["id"]
            try:
                access.evaluate_row_access(role_pol, stored["data"], subject_attrs)
            except AccessDeniedError as exc:
                denied_row.append({"id": rid, "reason": exc.reason})
                self._audit_deny(
                    tenant_id=tenant_id, bundle=bundle, request_id=rid_req,
                    action="read_list", role=role, record_id=rid,
                    reason=exc.reason, field_basis={"index": len(visible_rows)},
                    summaries={},
                )
                continue
            try:
                projected = self._project_fields(role_pol, stored["data"],
                                                  on_field_error=lambda f: denied_field.append(
                                                      {"id": rid, "field": f,
                                                       "reason": "access_field_denied"}))
            except AccessDeniedError:
                # _project_fields 内部对逐字段模式做容错；整体不抛出
                projected = {}
            visible_rows.append({"id": rid, "data": projected,
                                 "created_at": stored["created_at"],
                                 "anonymized": stored["anonymized"]})
        self.audit.append(
            AuditEntry(
                ts=datetime.now(timezone.utc).isoformat(),
                request_id=rid_req,
                tenant_id=tenant_id,
                action="read_list",
                decision="allow",
                policy_version=bundle.version,
                subject_role=role,
                record_id="*",
                basis={"returned": len(visible_rows), "denied_row": len(denied_row),
                       "denied_field": len(denied_field)},
                summaries={},
            )
        )
        return {"tenant_id": tenant_id, "policy_version": bundle.version,
                "records": visible_rows, "denied_row": denied_row,
                "denied_field": denied_field}

    # ---------- 保留期 ----------
    def sweep_retention(self, *, policy_version: str | None = None, now: datetime | None = None) -> dict:
        bundle = self._bundle(policy_version)
        return run_retention_sweep(self.store, bundle, now=now)

    # ---------- 内部工具 ----------
    def _bundle(self, version: str | None) -> PolicyBundle:
        return self.policies.get(version) if version else self.policies.latest()

    @staticmethod
    def _field_modes(role_pol, data: dict) -> dict:
        return {f: role_pol.field_mode(f) for f in data}

    @staticmethod
    def _project_fields(role_pol, data: dict, *, on_field_error=None) -> dict:
        out: dict = {}
        for key, val in data.items():
            mode = role_pol.field_mode(key)
            if mode is None:
                if on_field_error is not None:
                    on_field_error(key)
                    continue
                raise AccessDeniedError(
                    f"field not permitted: field={key!r}", reason="access_field_denied"
                )
            if mode is FieldMode.MASKED:
                out[key] = val
            elif mode is FieldMode.REDACTED:
                out[key] = redacted_placeholder()
            # HIDDEN: 直接移除
        return out

    def _audit_deny(self, *, tenant_id, bundle, request_id, action, role,
                    record_id, reason, field_basis, summaries) -> None:
        self.audit.append(
            AuditEntry(
                ts=datetime.now(timezone.utc).isoformat(),
                request_id=request_id,
                tenant_id=tenant_id,
                action=action,
                decision="deny",
                policy_version=bundle.version,
                subject_role=role,
                record_id=record_id,
                basis={"reason": reason, **field_basis},
                summaries=summaries,
            )
        )

    @staticmethod
    def _looks_sensitive(field_name: str, value: object) -> bool:
        # 字段名命中敏感命名：无论值是什么类型都视为"疑似敏感但无规则"，
        # 由规则存在性的调用方决定拒绝路径。
        if _SUSPICIOUS_NAME.search(field_name):
            return True
        if isinstance(value, str):
            return any(p.search(value) for p in _SUSPICIOUS_LOOKS)
        return False
