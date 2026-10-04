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
    # Kept permissive on purpose: each item is judged independently by the
    # service so one bad item never fails the whole batch. item_id is an
    # upstream-supplied correlation key echoed back in the per-item result.
    payload: dict[str, Any] | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    item_id: str | None = None


class BatchWriteIn(BaseModel):
    # Deliberately untyped element-wise: every item is judged independently by
    # the service, so a malformed item becomes a per-item rejection rather than
    # failing the whole batch at request validation.
    records: list[Any] = Field(default_factory=list)


class SubjectIn(BaseModel):
    role: str
    attrs: dict[str, Any] = Field(default_factory=dict)
