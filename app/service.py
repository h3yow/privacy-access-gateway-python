"""Application service: orchestrates classification, access control, storage and audit."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from app.access import field_visible, row_visible
from app.audit import build_entry
from app.classifier import classify_payload, validate_rule
from app.config import Settings
from app.errors import (
    AccessDeniedError,
    ClassificationError,
    PolicyError,
    RetentionError,
)
from app.logging_utils import log_decision
from app.masking import tenant_key
from app.models import (
    ClassifiedValue,
    FieldRule,
    PolicyVersion,
    RolePolicy,
    StoredRecord,
    TenantConfig,
)
from app.retention import is_expired, utcnow_iso
from app.storage import Storage

_VALID_VISIBILITY = {"visible", "masked", "denied"}
_VALID_RETENTION = {"purge", "anonymize"}

# Sentinel replacement used when retention action = anonymize.
_ANONYMIZED = "***RETENTION-ANONYMIZED***"


def _parse_ts(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class GatewayService:
    def __init__(self, settings: Settings, storage: Storage) -> None:
        self.settings = settings
        self.storage = storage

    def _key(self, tenant_id: str) -> bytes:
        return tenant_key(self.settings.master_key, tenant_id)

    def _require_tenant(self, tenant_id: str) -> TenantConfig:
        config = self.storage.get_tenant_config(tenant_id)
        if config is None:
            raise PolicyError(
                f"tenant {tenant_id!r} is not provisioned",
                reason="tenant_not_provisioned",
            )
        return config

    # ------------------------------------------------------------------
    # policy model parsing / validation
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_rules(raw_fields: list[dict]) -> dict[str, FieldRule]:
        rules: dict[str, FieldRule] = {}
        for item in raw_fields:
            try:
                strategy = item.get("strategy", "token")
                rule = FieldRule(
                    field_name=item.get("field_name", ""),
                    strategy=strategy,
                    pattern=item.get("pattern"),
                    keep_prefix=int(item.get("keep_prefix", 0)),
                    keep_suffix=int(item.get("keep_suffix", 0)),
                    description=item.get("description", ""),
                )
                # Reject incomplete / malformed rules early, with distinct reasons.
                validate_rule(rule)
            except (ClassificationError, ValueError, TypeError) as exc:
                reason = getattr(exc, "reason", "malformed_field_rule")
                raise PolicyError(str(exc), reason=reason)
            if rule.field_name in rules:
                raise PolicyError(
                    f"duplicate rule for field {rule.field_name!r}",
                    reason="duplicate_field_rule",
                )
            rules[rule.field_name] = rule
        return rules

    @staticmethod
    def _parse_roles(raw_roles: list[dict]) -> dict[str, RolePolicy]:
        roles: dict[str, RolePolicy] = {}
        for item in raw_roles:
            name = item.get("name")
            if not name:
                raise PolicyError("role requires a name", reason="role_name_missing")
            fields = item.get("fields", {})
            if not isinstance(fields, dict):
                raise PolicyError(
                    f"role {name!r} fields must be an object",
                    reason="malformed_role_fields",
                )
            for fname, vis in fields.items():
                if vis not in _VALID_VISIBILITY:
                    raise PolicyError(
                        f"role {name!r} field {fname!r} has invalid visibility {vis!r}",
                        reason="invalid_field_visibility",
                    )
            row_filters = item.get("row_filters", {})
            if not isinstance(row_filters, dict):
                raise PolicyError(
                    f"role {name!r} row_filters must be an object",
                    reason="malformed_row_filters",
                )
            if name in roles:
                raise PolicyError(
                    f"duplicate role definition {name!r}", reason="duplicate_role"
                )
            roles[name] = RolePolicy(
                name=name, fields=dict(fields), row_filters=dict(row_filters)
            )
        return roles

    def _build_policy(
        self,
        version: int,
        sensitive_fields: list[dict],
        roles: list[dict],
        default_role: str,
        effective_at: str,
    ) -> PolicyVersion:
        rules = self._parse_rules(sensitive_fields)
        parsed_roles = self._parse_roles(roles)
        if default_role not in parsed_roles:
            raise PolicyError(
                f"default_role {default_role!r} is not defined",
                reason="default_role_undefined",
            )
        return PolicyVersion(
            version=version,
            rules=rules,
            roles=parsed_roles,
            default_role=default_role,
            effective_at=effective_at,
        )

    # ------------------------------------------------------------------
    # tenant onboarding / policy changes
    # ------------------------------------------------------------------
    def provision_tenant(
        self,
        tenant_id: str,
        *,
        sensitive_fields: list[dict],
        roles: list[dict],
        default_role: str,
        retention_days: int,
        retention_action: str,
    ) -> dict:
        if not tenant_id:
            raise PolicyError("tenant_id is required", reason="tenant_id_missing")
        if retention_days < 0:
            raise RetentionError(
                "retention_days must be non-negative", reason="invalid_retention_days"
            )
        if retention_action not in _VALID_RETENTION:
            raise RetentionError(
                f"retention_action must be one of {sorted(_VALID_RETENTION)}",
                reason="invalid_retention_action",
            )
        existing = self.storage.get_tenant_config(tenant_id)
        if existing is not None:
            raise PolicyError(
                f"tenant {tenant_id!r} already provisioned",
                reason="tenant_already_exists",
            )
        now = utcnow_iso()
        policy = self._build_policy(
            1, sensitive_fields, roles, default_role, now
        )
        config = TenantConfig(
            tenant_id=tenant_id,
            retention_days=retention_days,
            retention_action=retention_action,
            policy=policy,
        )
        self.storage.upsert_tenant_config(config, created_at=now)
        return {
            "tenant_id": tenant_id,
            "policy_version": 1,
            "effective_at": now,
            "retention_days": retention_days,
            "retention_action": retention_action,
        }

    def change_policy(
        self,
        tenant_id: str,
        *,
        sensitive_fields: list[dict],
        roles: list[dict],
        default_role: str,
        effective_at: str | None = None,
    ) -> dict:
        config = self._require_tenant(tenant_id)
        eff = effective_at or utcnow_iso()
        # effective_at must not be earlier than the current version's
        versions = self.storage.list_policy_versions(tenant_id)
        latest = versions[-1]
        if _parse_ts(eff) < _parse_ts(latest.effective_at):
            raise PolicyError(
                "effective_at predates the current policy version",
                reason="effective_at_out_of_order",
            )
        policy = self._build_policy(
            latest.version + 1, sensitive_fields, roles, default_role, eff
        )
        self.storage.insert_policy_version(tenant_id, policy)
        return {
            "tenant_id": tenant_id,
            "policy_version": policy.version,
            "effective_at": eff,
        }

    # ------------------------------------------------------------------
    # audit helper
    # ------------------------------------------------------------------
    def _audit(
        self,
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
    ) -> dict[str, Any]:
        entry = build_entry(
            tenant_id=tenant_id,
            event_type=event_type,
            decision=decision,
            reason=reason,
            policy_version=policy_version,
            subject=subject,
            record_id=record_id,
            input_summary=input_summary,
            evidence=evidence,
        )
        saved = self.storage.insert_audit(entry)
        log_decision(
            tenant_id=tenant_id,
            event_type=event_type,
            decision=decision,
            reason=reason,
            input_summary=input_summary,
            evidence=evidence,
        )
        return {
            "audit_id": saved.audit_id,
            "occurred_at": saved.occurred_at,
        }

    # ------------------------------------------------------------------
    # data plane: write
    # ------------------------------------------------------------------
    def write_record(self, tenant_id: str, payload: dict, attributes: dict) -> dict:
        config = self._require_tenant(tenant_id)
        policy = config.policy
        if not isinstance(payload, dict) or not payload:
            raise ClassificationError(
                "payload must be a non-empty object", reason="invalid_payload"
            )

        summary = self._write_summary(payload, policy)
        try:
            masked_payload, classified = classify_payload(
                payload, policy.rules, self._key(tenant_id)
            )
        except ClassificationError as exc:
            self._audit(
                tenant_id=tenant_id,
                event_type="write",
                decision="reject",
                reason=exc.reason,
                policy_version=policy.version,
                subject=None,
                record_id=None,
                input_summary=summary,
                evidence={"stage": "classification", "message": str(exc)},
            )
            raise

        fingerprints = {f: cv.value_fingerprint for f, cv in classified.items()}
        record_id = uuid.uuid4().hex

        # ---- critical section: dedup + insert under the tenant storage lock ----
        with self.storage.lock():
            existing = self.storage.find_record(tenant_id, fingerprints)
            if existing is not None:
                if existing.masked_payload == masked_payload:
                    self._audit(
                        tenant_id=tenant_id,
                        event_type="write",
                        decision="allow",
                        reason="duplicate_write_idempotent",
                        policy_version=policy.version,
                        subject=None,
                        record_id=existing.record_id,
                        input_summary=self._classified_summary(classified),
                        evidence={"dedup": "identical_masked_payload"},
                    )
                    return {
                        "record_id": existing.record_id,
                        "status": "duplicate",
                        "policy_version": policy.version,
                    }
                self._audit(
                    tenant_id=tenant_id,
                    event_type="write",
                    decision="deny",
                    reason="fingerprint_collision_conflict",
                    policy_version=policy.version,
                    subject=None,
                    record_id=existing.record_id,
                    input_summary=self._classified_summary(classified),
                    evidence={"dedup": "same_fingerprint_different_payload"},
                )
                raise AccessDeniedError(
                    "a different record with the same sensitive values already exists",
                    reason="fingerprint_collision_conflict",
                )

            record = StoredRecord(
                record_id=record_id,
                tenant_id=tenant_id,
                masked_payload=masked_payload,
                sensitive_index={
                    f: {"fingerprint": cv.value_fingerprint, "token": cv.token}
                    for f, cv in classified.items()
                },
                attributes=dict(attributes),
                created_at=utcnow_iso(),
                status="active",
            )
            self.storage.insert_record(record)

        self._audit(
            tenant_id=tenant_id,
            event_type="write",
            decision="allow",
            reason="classified_and_stored",
            policy_version=policy.version,
            subject=None,
            record_id=record_id,
            input_summary=self._classified_summary(classified),
            evidence={
                "rules": {
                    f: cv.rule_description for f, cv in classified.items()
                },
            },
        )
        return {
            "record_id": record_id,
            "status": "created",
            "policy_version": policy.version,
            "masked_payload": masked_payload,
        }

    @staticmethod
    def _write_summary(payload: dict, policy: PolicyVersion) -> dict[str, Any]:
        """Pre-classification summary: field names and lengths only."""
        return {
            "payload_fields": sorted(payload.keys()),
            "declared_sensitive_fields": sorted(policy.rules.keys()),
            "field_lengths": {
                k: len(v) if isinstance(v, str) else None
                for k, v in payload.items()
            },
        }

    @staticmethod
    def _classified_summary(classified: dict[str, ClassifiedValue]) -> dict[str, Any]:
        """Post-classification summary: fingerprints/tokens only, never raw values."""
        return {
            "fields": sorted(classified.keys()),
            "fingerprints": {
                f: cv.value_fingerprint for f, cv in classified.items()
            },
        }

    # ------------------------------------------------------------------
    # data plane: read / list
    # ------------------------------------------------------------------
    def _resolve_role(self, policy: PolicyVersion, subject: dict) -> tuple[RolePolicy, str]:
        role_name = subject.get("role") or policy.default_role
        role = policy.roles.get(role_name)
        if role is None:
            raise AccessDeniedError(
                f"role {role_name!r} is not defined in policy v{policy.version}",
                reason="unknown_role",
            )
        return role, role_name

    def _project_record(
        self,
        record: StoredRecord,
        policy: PolicyVersion,
        role: RolePolicy,
        subject_attrs: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, dict[str, Any]]:
        visible, row_evidence = row_visible(record, role, subject_attrs)
        if not visible:
            return None, {"row": row_evidence}

        sensitive_fields = set(policy.rules.keys())
        projected: dict[str, Any] = {}
        field_evidence: dict[str, Any] = {}
        denied: list[str] = []
        for name, value in record.masked_payload.items():
            vis = field_visible(
                role, name, sensitive=name in sensitive_fields
            )
            field_evidence[name] = vis
            if vis == "denied":
                denied.append(name)
                continue
            if vis == "masked":
                projected[name] = value  # storage value is already masked
            else:  # visible
                if name in sensitive_fields:
                    # Only stored form exists; expose the masked token and mark it.
                    projected[name] = value
                    field_evidence[name] = "visible_as_masked"
                else:
                    projected[name] = value
        evidence = {"row": row_evidence, "fields": field_evidence, "denied": denied}
        return projected, evidence

    def read_record(self, tenant_id: str, record_id: str, subject: dict) -> dict:
        config = self._require_tenant(tenant_id)
        policy = config.policy
        role, role_name = self._resolve_role(policy, subject)
        subject_attrs = subject.get("attrs", {})
        summary = {
            "record_id": record_id,
            "role": role_name,
            "subject_attr_keys": sorted(subject_attrs.keys()),
        }
        record = self.storage.get_record(tenant_id, record_id)
        if record is None:
            self._audit(
                tenant_id=tenant_id,
                event_type="read",
                decision="deny",
                reason="record_not_found",
                policy_version=policy.version,
                subject=role_name,
                record_id=record_id,
                input_summary=summary,
                evidence={},
            )
            raise AccessDeniedError("record not found", reason="record_not_found")
        if record.status != "active":
            self._audit(
                tenant_id=tenant_id,
                event_type="read",
                decision="deny",
                reason=f"record_{record.status}",
                policy_version=policy.version,
                subject=role_name,
                record_id=record_id,
                input_summary=summary,
                evidence={"status": record.status},
            )
            raise AccessDeniedError(
                "record has been anonymized by retention",
                reason=f"record_{record.status}",
            )

        projected, evidence = self._project_record(
            record, policy, role, subject_attrs
        )
        # Subject business attributes are non-sensitive and required to
        # reproduce ABAC row filtering against historical policy versions.
        evidence["subject_attrs"] = subject_attrs
        if projected is None:
            self._audit(
                tenant_id=tenant_id,
                event_type="read",
                decision="deny",
                reason="row_filter_denied",
                policy_version=policy.version,
                subject=role_name,
                record_id=record_id,
                input_summary=summary,
                evidence=evidence,
            )
            raise AccessDeniedError(
                "row-level attribute filter denied access",
                reason="row_filter_denied",
            )
        if evidence["denied"]:
            self._audit(
                tenant_id=tenant_id,
                event_type="read",
                decision="deny",
                reason="field_access_denied",
                policy_version=policy.version,
                subject=role_name,
                record_id=record_id,
                input_summary=summary,
                evidence=evidence,
            )
            raise AccessDeniedError(
                "one or more requested fields are denied for this role",
                reason="field_access_denied",
            )
        self._audit(
            tenant_id=tenant_id,
            event_type="read",
            decision="allow",
            reason="field_and_row_filters_passed",
            policy_version=policy.version,
            subject=role_name,
            record_id=record_id,
            input_summary=summary,
            evidence=evidence,
        )
        return {
            "record_id": record.record_id,
            "payload": projected,
            "attributes": record.attributes,
            "created_at": record.created_at,
            "policy_version": policy.version,
        }

    def list_records(self, tenant_id: str, subject: dict) -> dict:
        config = self._require_tenant(tenant_id)
        policy = config.policy
        role, role_name = self._resolve_role(policy, subject)
        subject_attrs = subject.get("attrs", {})
        items: list[dict[str, Any]] = []
        denied_count = 0
        filtered_count = 0
        for record in self.storage.list_records(tenant_id):
            if record.status != "active":
                filtered_count += 1
                continue
            projected, evidence = self._project_record(
                record, policy, role, subject_attrs
            )
            if projected is None:
                filtered_count += 1
                continue
            if evidence["denied"]:
                # Rows with denied fields are excluded rather than partially leaked.
                denied_count += 1
                continue
            items.append(
                {
                    "record_id": record.record_id,
                    "payload": projected,
                    "attributes": record.attributes,
                    "created_at": record.created_at,
                }
            )
        self._audit(
            tenant_id=tenant_id,
            event_type="list",
            decision="allow",
            reason="row_and_field_filters_applied",
            policy_version=policy.version,
            subject=role_name,
            record_id=None,
            input_summary={
                "role": role_name,
                "subject_attr_keys": sorted(subject_attrs.keys()),
                "matched": len(items),
                "filtered_rows": filtered_count,
                "field_denied_rows": denied_count,
            },
            evidence={},
        )
        return {
            "items": items,
            "count": len(items),
            "filtered_rows": filtered_count,
            "field_denied_rows": denied_count,
            "policy_version": policy.version,
        }

    # ------------------------------------------------------------------
    # retention
    # ------------------------------------------------------------------
    def run_retention(self, tenant_id: str, now: str | None = None) -> dict:
        config = self._require_tenant(tenant_id)
        reference = now or utcnow_iso()
        cutoff_dt = _parse_ts(reference) - timedelta(days=config.retention_days)
        cutoff = cutoff_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        purged: list[str] = []
        anonymized: list[str] = []
        errors: list[dict[str, str]] = []
        # One malformed record must never block the whole sweep.
        for record in self.storage.expired_records(tenant_id, cutoff):
            try:
                if not is_expired(record.created_at, config.retention_days, reference):
                    continue  # defensive boundary re-check
                if config.retention_action == "purge":
                    self.storage.delete_record(tenant_id, record.record_id)
                    purged.append(record.record_id)
                else:
                    self._anonymize_record(record)
                    anonymized.append(record.record_id)
            except Exception as exc:  # noqa: BLE001 - isolate per-record failure
                errors.append({"record_id": record.record_id, "error": type(exc).__name__})

        result = {
            "tenant_id": tenant_id,
            "cutoff": cutoff,
            "action": config.retention_action,
            "purged": purged,
            "anonymized": anonymized,
            "errors": errors,
        }
        self._audit(
            tenant_id=tenant_id,
            event_type="retention",
            decision="allow",
            reason="retention_sweep_complete",
            policy_version=config.policy.version,
            subject=None,
            record_id=None,
            input_summary={
                "cutoff": cutoff,
                "purged_count": len(purged),
                "anonymized_count": len(anonymized),
                "error_count": len(errors),
            },
            evidence={"purged": purged, "anonymized": anonymized, "errors": errors},
        )
        return result

    def _anonymize_record(self, record: StoredRecord) -> None:
        """Irreversibly destroy sensitive material of one record."""
        anon_payload = {
            key: (_ANONYMIZED if key in record.sensitive_index else value)
            for key, value in record.masked_payload.items()
        }
        with self.storage.lock():
            self.storage.update_record_payload(
                record.tenant_id,
                record.record_id,
                anon_payload,
                {},  # destroy fingerprints/tokens: linkage becomes impossible
                status="anonymized",
            )

    # ------------------------------------------------------------------
    # audit / replay
    # ------------------------------------------------------------------
    def list_audit(self, tenant_id: str, limit: int = 100) -> dict:
        self._require_tenant(tenant_id)
        entries = self.storage.list_audit(tenant_id, limit)
        return {
            "entries": [
                {
                    "audit_id": e.audit_id,
                    "event_type": e.event_type,
                    "decision": e.decision,
                    "reason": e.reason,
                    "policy_version": e.policy_version,
                    "subject": e.subject,
                    "record_id": e.record_id,
                    "input_summary": e.input_summary,
                    "evidence": e.evidence,
                    "occurred_at": e.occurred_at,
                }
                for e in entries
            ],
            "count": len(entries),
        }

    def replay_decision(self, tenant_id: str, audit_id: int) -> dict:
        """Reproduce a historical decision using the policy version recorded then."""
        self._require_tenant(tenant_id)
        entry = self.storage.get_audit(tenant_id, audit_id)
        if entry is None:
            raise PolicyError("audit entry not found", reason="audit_not_found")
        policy = self.storage.get_policy_version(tenant_id, entry.policy_version)
        if policy is None:
            raise PolicyError(
                f"policy version {entry.policy_version} no longer available",
                reason="policy_version_missing",
            )

        if entry.event_type == "write":
            return self._replay_write(entry, policy)
        if entry.event_type in ("read", "list"):
            return self._replay_read(entry, policy)
        if entry.event_type == "retention":
            return self._replay_retention(entry, policy)
        raise PolicyError(
            f"cannot replay event type {entry.event_type!r}",
            reason="unsupported_replay_event",
        )

    def _replay_write(self, entry, policy: PolicyVersion) -> dict[str, Any]:
        stored_fps: dict[str, str] = entry.input_summary.get("fingerprints", {})
        if not stored_fps and entry.decision == "allow":
            return self._replay_result(entry, policy, "inconclusive", {})
        # Re-derive expected rule descriptions; fingerprints can only be
        # recomputed from raw values which are never stored, so replay verifies
        # that the recorded fingerprints are still consistent with the current
        # record's persisted index and the policy version's rule set.
        evidence: dict[str, Any] = {
            "rule_fields_at_version": sorted(policy.rules.keys()),
            "recorded_fingerprints": stored_fps,
        }
        consistent: bool
        if entry.record_id is not None:
            record = self.storage.get_record(entry.tenant_id, entry.record_id)
            if record is None:
                consistent = entry.decision == "allow"
                evidence["note"] = "record_purged"
            else:
                now_index = {
                    f: idx.get("fingerprint")
                    for f, idx in record.sensitive_index.items()
                }
                index_matches = all(
                    now_index.get(f) == fp for f, fp in stored_fps.items()
                )
                if entry.decision == "deny" and entry.reason == (
                    "fingerprint_collision_conflict"
                ):
                    # A historical conflict is reproducible iff the conflicting
                    # record still holds the same fingerprints.
                    consistent = index_matches
                else:
                    consistent = index_matches
                evidence["current_index"] = now_index
        else:
            consistent = entry.decision == "reject"
        reproduced = entry.decision if consistent else (
            "reject" if entry.decision == "allow" else "allow"
        )
        return self._replay_result(
            entry,
            policy,
            "match" if reproduced == entry.decision else "mismatch",
            evidence,
            reproduced=reproduced,
        )

    def _replay_read(self, entry, policy: PolicyVersion) -> dict[str, Any]:
        role_name = entry.subject or policy.default_role
        role = policy.roles.get(role_name)
        if role is None:
            return self._replay_result(
                entry, policy, "match", {"note": "unknown_role_at_version"}
            )
        record = (
            self.storage.get_record(entry.tenant_id, entry.record_id)
            if entry.record_id
            else None
        )
        if record is None:
            # Purged records: the recorded denial/allow cannot be re-derived,
            # but the historical evidence itself is preserved.
            return self._replay_result(
                entry, policy, "inconclusive", {"note": "record_purged_or_missing"}
            )
        subject_attrs: dict[str, Any] = dict(
            entry.evidence.get("subject_attrs", {})
        )
        projected, proj_evidence = self._project_record(
            record, policy, role, subject_attrs
        )
        if projected is None:
            reproduced = "deny"
            reproduced_reason = "row_filter_denied"
        elif proj_evidence["denied"]:
            reproduced = "deny"
            reproduced_reason = "field_access_denied"
        else:
            reproduced = "allow"
            reproduced_reason = "field_and_row_filters_passed"
        match = reproduced == entry.decision and (
            reproduced == "allow" or reproduced_reason == entry.reason
        )
        return self._replay_result(
            entry,
            policy,
            "match" if match else "mismatch",
            {
                "projected_at_version": projected,
                "role_at_version": role_name,
                "reproduced_reason": reproduced_reason,
            },
            reproduced=reproduced,
        )

    def _replay_retention(self, entry, policy: PolicyVersion) -> dict[str, Any]:
        # Idempotency evidence: the recorded record ids must no longer be active.
        evidence: dict[str, Any] = {}
        still_active: list[str] = []
        for rid in entry.evidence.get("purged", []):
            rec = self.storage.get_record(entry.tenant_id, rid)
            if rec is not None:
                still_active.append(rid)
        anon_ok: list[str] = []
        for rid in entry.evidence.get("anonymized", []):
            rec = self.storage.get_record(entry.tenant_id, rid)
            if rec is not None and rec.status == "anonymized" and not rec.sensitive_index:
                anon_ok.append(rid)
        evidence["purged_still_present"] = still_active
        evidence["anonymized_confirmed"] = anon_ok
        consistent = not still_active and len(anon_ok) == len(
            entry.evidence.get("anonymized", [])
        )
        return self._replay_result(
            entry,
            policy,
            "match" if consistent else "mismatch",
            evidence,
            reproduced="allow" if consistent else "reject",
        )

    @staticmethod
    def _replay_result(
        entry,
        policy: PolicyVersion,
        status: str,
        evidence: dict[str, Any],
        *,
        reproduced: str | None = None,
    ) -> dict[str, Any]:
        return {
            "audit_id": entry.audit_id,
            "event_type": entry.event_type,
            "original_decision": entry.decision,
            "original_reason": entry.reason,
            "reproduced_decision": reproduced or entry.decision,
            "policy_version": policy.version,
            "policy_effective_at": policy.effective_at,
            "status": status,  # match | mismatch | inconclusive
            "evidence": evidence,
        }
