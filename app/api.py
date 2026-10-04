"""FastAPI route definitions and error mapping."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app.deps import get_service
from app.errors import (
    AccessDeniedError,
    ClassificationError,
    GatewayError,
    PolicyError,
    RetentionError,
)
from app.schemas import (
    BatchWriteIn,
    PolicyChangeIn,
    ProvisionIn,
    SubjectIn,
    WriteIn,
)
from app.service import GatewayService


def register_routes() -> APIRouter:
    router = APIRouter(prefix="/tenants/{tenant_id}")

    @router.post("/provision")
    def provision(tenant_id: str, body: ProvisionIn, svc: GatewayService = Depends(get_service)):
        if body.tenant_id != tenant_id:
            return JSONResponse(
                status_code=400,
                content={"error": "tenant_id_mismatch", "reason": "tenant_id_mismatch"},
            )
        return svc.provision_tenant(
            tenant_id,
            sensitive_fields=[f.model_dump() for f in body.sensitive_fields],
            roles=[r.model_dump() for r in body.roles],
            default_role=body.default_role,
            retention_days=body.retention_days,
            retention_action=body.retention_action,
        )

    @router.post("/policy")
    def change_policy(tenant_id: str, body: PolicyChangeIn, svc: GatewayService = Depends(get_service)):
        return svc.change_policy(
            tenant_id,
            sensitive_fields=[f.model_dump() for f in body.sensitive_fields],
            roles=[r.model_dump() for r in body.roles],
            default_role=body.default_role,
            effective_at=body.effective_at,
        )

    @router.get("/policy")
    def list_policies(tenant_id: str, svc: GatewayService = Depends(get_service)):
        svc._require_tenant(tenant_id)
        versions = svc.storage.list_policy_versions(tenant_id)
        return {
            "versions": [
                {
                    "version": v.version,
                    "effective_at": v.effective_at,
                    "default_role": v.default_role,
                    "sensitive_fields": [
                        {
                            "field_name": r.field_name,
                            "strategy": r.strategy,
                            "pattern": r.pattern,
                            "keep_prefix": r.keep_prefix,
                            "keep_suffix": r.keep_suffix,
                            "description": r.description,
                        }
                        for r in v.rules.values()
                    ],
                    "roles": [
                        {
                            "name": r.name,
                            "fields": r.fields,
                            "row_filters": r.row_filters,
                        }
                        for r in v.roles.values()
                    ],
                }
                for v in versions
            ]
        }

    @router.post("/records")
    def write_record(tenant_id: str, body: WriteIn, svc: GatewayService = Depends(get_service)):
        return svc.write_record(tenant_id, body.payload, body.attributes)

    @router.post("/records/batch")
    def write_records_batch(
        tenant_id: str, body: BatchWriteIn, svc: GatewayService = Depends(get_service)
    ):
        # The batch call itself returns 200 for any processable envelope;
        # per-item created/duplicate/rejected outcomes are in body.results.
        return svc.write_records_batch(tenant_id, body.records)

    @router.get("/records/{record_id}")
    def read_record(
        tenant_id: str,
        record_id: str,
        role: str | None = None,
        svc: GatewayService = Depends(get_service),
    ):
        subject = {"role": role, "attrs": {}} if role else {"attrs": {}}
        return svc.read_record(tenant_id, record_id, subject)

    @router.post("/records/{record_id}/read")
    def read_record_with_subject(
        tenant_id: str,
        record_id: str,
        body: SubjectIn,
        svc: GatewayService = Depends(get_service),
    ):
        return svc.read_record(
            tenant_id, record_id, {"role": body.role, "attrs": body.attrs}
        )

    @router.post("/records/query")
    def list_records(
        tenant_id: str, body: SubjectIn, svc: GatewayService = Depends(get_service)
    ):
        return svc.list_records(
            tenant_id, {"role": body.role, "attrs": body.attrs}
        )

    @router.post("/retention/run")
    def run_retention(
        tenant_id: str,
        now: str | None = None,
        svc: GatewayService = Depends(get_service),
    ):
        return svc.run_retention(tenant_id, now)

    @router.get("/audit")
    def list_audit(
        tenant_id: str, limit: int = 100, svc: GatewayService = Depends(get_service)
    ):
        return svc.list_audit(tenant_id, limit)

    @router.get("/audit/{audit_id}/replay")
    def replay_decision(
        tenant_id: str, audit_id: int, svc: GatewayService = Depends(get_service)
    ):
        return svc.replay_decision(tenant_id, audit_id)

    return router


def register_error_handlers(app) -> None:
    def _handler(exc: GatewayError):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": type(exc).__name__, "reason": exc.reason,
                     "message": str(exc)},
        )

    for etype in (ClassificationError, AccessDeniedError, PolicyError, RetentionError):
        app.add_exception_handler(etype, lambda request, exc: _handler(exc))
