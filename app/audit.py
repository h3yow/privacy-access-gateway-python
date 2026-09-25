"""Audit logging and historical-decision reproducibility."""
from __future__ import annotations

from dataclasses import asdict
from typing import Any

from app.retention import utcnow_iso
from app.models import AuditEntry


def build_entry(
    *,
    tenant_id: str,
    event_type: str,
    decision: str,
    reason: str,
    policy_version: int,
    subject: str | None,
    record_id: str | None,
    input_summary: dict[str, Any],
    evidence: dict[str, Any],
) -> AuditEntry:
    return AuditEntry(
        audit_id=None,
        tenant_id=tenant_id,
        event_type=event_type,
        decision=decision,
        reason=reason,
        policy_version=policy_version,
        subject=subject,
        record_id=record_id,
        input_summary=input_summary,
        evidence=evidence,
        occurred_at=utcnow_iso(),
    )


def entry_to_dict(entry: AuditEntry) -> dict[str, Any]:
    return asdict(entry)
