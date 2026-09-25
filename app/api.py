"""FastAPI 路由。

端点：
  GET  /health
  POST /admin/policies              发布新版本策略包
  GET  /admin/policies              列出策略版本
  POST /tenants/{tenant_id}/records 批量写入（识别+脱敏），部分成功
  GET  /tenants/{tenant_id}/records/{record_id}  按角色/属性读取单条
  GET  /tenants/{tenant_id}/records              列出（行级过滤）
  POST /admin/retention/sweep       保留期扫描（幂等）
  GET  /tenants/{tenant_id}/audit   审计查询（可按 record / 版本）

所有错误响应体含可区分 reason 码；响应与日志中均无原始敏感值。
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

from app.errors import GatewayError
from app.policy import load_bundle
from app.service import PrivacyGatewayService

_REASON_STATUS = {
    "classification_no_rule": 422,
    "classification_incomplete_rule": 422,
    "classification_bad_record": 422,
    "policy_not_object": 400,
    "policy_missing_version": 400,
    "policy_version_type": 400,
    "policy_version_not_found": 404,
    "policy_store_empty": 503,
    "policy_duplicate_version": 409,
    "access_unknown_role": 403,
    "access_field_denied": 403,
    "access_row_denied": 403,
    "access_record_not_found": 404,
}


def _raise_http(exc: GatewayError) -> None:
    status = _REASON_STATUS.get(exc.reason, 400)
    raise HTTPException(status_code=status, detail={"reason": exc.reason, "message": exc.message})


class WriteRecordsBody(BaseModel):
    records: list[dict[str, Any]]
    policy_version: str | None = None


class SweepBody(BaseModel):
    policy_version: str | None = None
    now: str | None = None  # ISO8601，测试可注入时间


def create_app(service: PrivacyGatewayService | None = None) -> FastAPI:
    app = FastAPI(title="privacy-access-gateway", version="0.1.0")

    if service is None:  # 允许测试注入；默认使用本地持久化单例
        from app.audit import AuditLog
        from app.policy import PolicyStore
        from app.store import GatewayStore

        db_dir = os.environ.get("PAG_DB_DIR", ".")
        store = GatewayStore(os.path.join(db_dir, "pag_records.db"))
        audit = AuditLog(os.path.join(db_dir, "pag_audit.db"))
        service = PrivacyGatewayService(store, PolicyStore(), audit,
                                        secret=os.environ.get("PAG_SECRET", "local-dev-secret"))
    app.state.service = service

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.post("/admin/policies", status_code=201)
    def publish_policy(payload: dict[str, Any]) -> dict:
        try:
            bundle = load_bundle(payload)
            service.policies.put(bundle)
        except GatewayError as exc:
            _raise_http(exc)
        return {"version": bundle.version, "status": "published"}

    @app.get("/admin/policies")
    def list_policies() -> dict:
        return {"versions": service.policies.versions()}

    @app.post("/tenants/{tenant_id}/records")
    async def write_records(tenant_id: str, body: WriteRecordsBody, request: Request) -> dict:
        result = service.put_records(
            tenant_id, body.records,
            policy_version=body.policy_version,
            request_id=request.headers.get("x-request-id"),
        )
        return {
            "tenant_id": tenant_id,
            "accepted": result.accepted,
            "rejected": result.rejected,
        }

    @app.get("/tenants/{tenant_id}/records/{record_id}")
    async def read_record(
        tenant_id: str,
        record_id: str,
        request: Request,
        x_role: str | None = Header(default=None),
        x_subject_attrs: str | None = Header(default=None),
        policy_version: str | None = None,
    ) -> dict:
        import json

        if not x_role:
            raise HTTPException(status_code=401, detail={"reason": "missing_role",
                                                         "message": "X-Role header required"})
        attrs = {}
        if x_subject_attrs:
            try:
                attrs = json.loads(x_subject_attrs)
            except ValueError:
                raise HTTPException(status_code=400, detail={
                    "reason": "bad_subject_attrs", "message": "X-Subject-Attrs must be JSON"})
        try:
            return service.get_record(
                tenant_id, record_id, x_role, attrs,
                policy_version=policy_version,
                request_id=request.headers.get("x-request-id"),
            )
        except GatewayError as exc:
            _raise_http(exc)

    @app.get("/tenants/{tenant_id}/records")
    async def list_records(
        tenant_id: str,
        request: Request,
        x_role: str | None = Header(default=None),
        x_subject_attrs: str | None = Header(default=None),
        policy_version: str | None = None,
    ) -> dict:
        import json

        if not x_role:
            raise HTTPException(status_code=401, detail={"reason": "missing_role",
                                                         "message": "X-Role header required"})
        attrs = {}
        if x_subject_attrs:
            try:
                attrs = json.loads(x_subject_attrs)
            except ValueError:
                raise HTTPException(status_code=400, detail={
                    "reason": "bad_subject_attrs", "message": "X-Subject-Attrs must be JSON"})
        try:
            return service.list_records(
                tenant_id, x_role, attrs,
                policy_version=policy_version,
                request_id=request.headers.get("x-request-id"),
            )
        except GatewayError as exc:
            _raise_http(exc)

    @app.post("/admin/retention/sweep")
    def retention_sweep(body: SweepBody) -> dict:
        from datetime import datetime

        now = datetime.fromisoformat(body.now) if body.now else None
        return service.sweep_retention(policy_version=body.policy_version, now=now)

    @app.get("/tenants/{tenant_id}/audit")
    def query_audit(
        tenant_id: str,
        record_id: str | None = None,
        policy_version: str | None = None,
    ) -> dict:
        entries = service.audit.query(
            tenant_id=tenant_id, record_id=record_id, policy_version=policy_version
        )
        return {"entries": [e.to_dict() for e in entries]}

    return app
