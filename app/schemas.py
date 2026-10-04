"""Pydantic request/response schemas."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class FieldRuleIn(BaseModel):
    field_name: str
    strategy: str = "token"
    pattern: str | None = None
    keep_prefix: int = 0
    keep_suffix: int = 0
    description: str = ""


class RoleIn(BaseModel):
    name: str
    fields: dict[str, str] = Field(default_factory=dict)
    row_filters: dict[str, Any] = Field(default_factory=dict)


class ProvisionIn(BaseModel):
    tenant_id: str
    sensitive_fields: list[FieldRuleIn]
    roles: list[RoleIn]
    default_role: str
    retention_days: int = 365
    retention_action: str = "purge"


class PolicyChangeIn(BaseModel):
    sensitive_fields: list[FieldRuleIn]
    roles: list[RoleIn]
    default_role: str
    effective_at: str | None = None


class WriteIn(BaseModel):
    payload: dict[str, Any]
    attributes: dict[str, Any] = Field(default_factory=dict)


class BatchItemIn(BaseModel):
    payload: dict[str, Any]
    attributes: dict[str, Any] = Field(default_factory=dict)
    # Optional upstream-side per-item key, echoed verbatim in the result.
    client_item_id: str | None = None


class BatchWriteIn(BaseModel):
    items: list[BatchItemIn]
    # Idempotency key: resending the same batch_id must not double-store.
    batch_id: str | None = None


class SubjectIn(BaseModel):
    role: str
    attrs: dict[str, Any] = Field(default_factory=dict)
