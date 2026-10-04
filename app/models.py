"""Core domain data types."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

# ---- classification / masking ----

MaskStrategy = Literal["token", "partial", "hash"]


@dataclass(frozen=True)
class FieldRule:
    """Rule describing how one sensitive field is recognized and masked."""

    field_name: str
    strategy: MaskStrategy = "token"
    pattern: str | None = None          # regex the original value must match
    keep_prefix: int = 0                # for strategy="partial"
    keep_suffix: int = 0                # for strategy="partial"
    description: str = ""


@dataclass(frozen=True)
class ClassifiedValue:
    field_name: str
    value_fingerprint: str              # HMAC fingerprint of the raw value (safe to store)
    token: str                          # deterministic replacement token
    masked_display: str                 # human-readable masked representation
    rule_description: str


# ---- access control ----

RoleName = str
FieldVisibility = Literal["visible", "masked", "denied"]


@dataclass(frozen=True)
class RolePolicy:
    """Field-level visibility + row-level attribute constraints for one role."""

    name: RoleName
    fields: dict[str, FieldVisibility] = field(default_factory=dict)
    # ABAC row filter: all constraints must hold against record attributes.
    # Example: {"region": "cn-north"} or {"owner_id": "$subject"}
    row_filters: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyVersion:
    """An immutable, numbered policy bundle effective from ``effective_at``."""

    version: int
    rules: dict[str, FieldRule]
    roles: dict[RoleName, RolePolicy]
    default_role: RoleName
    effective_at: str                   # ISO-8601 UTC timestamp


# ---- tenant configuration ----

RetentionAction = Literal["purge", "anonymize"]


@dataclass(frozen=True)
class TenantConfig:
    tenant_id: str
    retention_days: int
    retention_action: RetentionAction
    policy: PolicyVersion


# ---- persisted records ----


@dataclass(frozen=True)
class StoredRecord:
    """A record as stored: only masked/tokenized values, never raw values."""

    record_id: str
    tenant_id: str
    masked_payload: dict[str, Any]
    # field_name -> {"fingerprint": ..., "token": ...}
    sensitive_index: dict[str, dict[str, str]]
    attributes: dict[str, Any]
    created_at: str
    # active | anonymized (purged records are physically deleted)
    status: str = "active"
    # sha256 over the canonical masked payload: identity is the *whole*
    # business content, so records that merely share a sensitive value but
    # differ elsewhere are independent and never collide.
    content_hash: str = ""


# ---- audit ----


@dataclass(frozen=True)
class AuditEntry:
    audit_id: int | None
    tenant_id: str
    event_type: str                     # write | read | policy_change | retention
    decision: str                       # allow | deny | reject
    reason: str
    policy_version: int
    subject: str | None
    record_id: str | None
    # safe input summary: fingerprints, field names, counts — never raw values
    input_summary: dict[str, Any]
    evidence: dict[str, Any]            # matched rules, filters, visibility
    occurred_at: str
