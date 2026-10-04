"""Application service: orchestrates classification, access control, storage and audit."""
from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from app.access import field_visible, row_visible
from app.audit import build_entry
from app.classifier import classify_payload, validate_rule
from app.config import Settings
from app.errors import (
    AccessDeniedError,
    BatchConflictError,
    BatchError,
    ClassificationError,
    PolicyError,
    RetentionError,
)
from app.fallback import FallbackHit, scan_undeclared_sensitive
from app.logging_utils import log_decision
from app.masking import content_fingerprint, request_fingerprint, tenant_key
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
        # Batch ids whose processing call is alive in this process. Used to
        # distinguish a concurrent live attempt from a crash restart.
        self._live_batches: set[tuple[str, str]] = set()
        self._live_lock = threading.Lock()

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
        if not isinstance(payload, dict) or not payload:
            raise ClassificationError(
                "payload must be a non-empty object", reason="invalid_payload"
            )
        if not isinstance(attributes, dict):
            raise ClassificationError(
                "attributes must be an object", reason="invalid_attributes"
            )
        outcome = self._write_one_item(config, payload, attributes, audit=True)
        if outcome["status"] == "rejected":
            raise ClassificationError(
                outcome.get("message", outcome["reason"]), reason=outcome["reason"]
            )
        return {
            "record_id": outcome["record_id"],
            "status": outcome["status"],
            "policy_version": outcome["policy_version"],
            "masked_payload": outcome["masked_payload"],
        }

    # ------------------------------------------------------------------
    # data plane: batch write
    # ------------------------------------------------------------------
    MAX_BATCH_ITEMS = 1000

    def write_records_batch(
        self, tenant_id: str, batch: list[dict], *, batch_id: str | None
    ) -> dict[str, Any]:
        config = self._require_tenant(tenant_id)
        if not isinstance(batch, list) or not batch:
            raise BatchError(
                "batch must be a non-empty list of items", reason="empty_batch"
            )
        if len(batch) > self.MAX_BATCH_ITEMS:
            raise BatchError(
                f"batch exceeds the maximum of {self.MAX_BATCH_ITEMS} items",
                reason="batch_too_large",
            )
        if batch_id is not None and (
            not isinstance(batch_id, str) or not batch_id.strip()
        ):
            raise BatchError(
                "batch_id must be a non-empty string", reason="invalid_batch_id"
            )

        # Envelope validation is whole-call: every element must carry a usable
        # payload so each result can always be aligned to its upstream index.
        # Per-item content problems are NOT raised here — they are classified
        # independently and reported per item below.
        req_fps: list[str] = []
        client_ids: list[str | None] = []
        for idx, item in enumerate(batch):
            if not isinstance(item, dict) or "payload" not in item:
                raise BatchError(
                    f"item at index {idx} must be an object with a payload",
                    reason="malformed_batch_item",
                )
            payload = item["payload"]
            if not isinstance(payload, dict) or not payload:
                raise BatchError(
                    f"item at index {idx} has an invalid payload",
                    reason="invalid_payload",
                )
            attributes = item.get("attributes", {})
            if not isinstance(attributes, dict):
                raise BatchError(
                    f"item at index {idx} attributes must be an object",
                    reason="invalid_attributes",
                )
            cid = item.get("client_item_id")
            if cid is not None and not isinstance(cid, str):
                raise BatchError(
                    f"item at index {idx} client_item_id must be a string",
                    reason="invalid_client_item_id",
                )
            req_fps.append(
                request_fingerprint(self._key(tenant_id), payload, attributes)
            )
            client_ids.append(cid)

        if batch_id is None:
            return self._process_batch_items(config, batch, batch_id=None)
        return self._run_keyed_batch(config, batch_id, batch, req_fps, client_ids)

    def _run_keyed_batch(
        self,
        config: TenantConfig,
        batch_id: str,
        batch: list[dict],
        req_fps: list[str],
        client_ids: list[str | None],
    ) -> dict[str, Any]:
        tenant_id = config.tenant_id
        with self.storage.lock():
            run = self.storage.get_batch_run(tenant_id, batch_id)
            if run is None:
                self._reserve_batch_run(
                    config, batch_id, len(batch), req_fps, client_ids
                )
            else:
                return self._handle_existing_batch(
                    config, batch_id, run, batch, req_fps, client_ids
                )

        with self._live_lock:
            self._live_batches.add((tenant_id, batch_id))
        try:
            result = self._process_batch_items(config, batch, batch_id=batch_id)
        finally:
            with self._live_lock:
                self._live_batches.discard((tenant_id, batch_id))

        with self.storage.lock():
            run = self.storage.get_batch_run(tenant_id, batch_id)
            if run is not None and run["status"] == "completed" and run["result_json"]:
                # A concurrent resumable attempt finished first.
                return json.loads(run["result_json"])
            self.storage.complete_batch_run(
                tenant_id,
                batch_id,
                json.dumps(result, ensure_ascii=False),
                utcnow_iso(),
            )
        self._audit_batch_summary(tenant_id, batch_id, result, replay=False)
        return result

    def _reserve_batch_run(
        self,
        config: TenantConfig,
        batch_id: str,
        item_count: int,
        req_fps: list[str],
        client_ids: list[str | None],
    ) -> None:
        tenant_id = config.tenant_id
        created = self.storage.insert_batch_run(
            tenant_id,
            batch_id,
            item_count=item_count,
            policy_version=config.policy.version,
            created_at=utcnow_iso(),
        )
        if not created:
            # Lost a race between the get and the insert.
            run = self.storage.get_batch_run(tenant_id, batch_id)
            assert run is not None
            raise BatchConflictError(
                "batch is already registered; retry to obtain its result",
                reason="batch_in_progress",
            )
        for idx, (rfp, cid) in enumerate(zip(req_fps, client_ids)):
            self.storage.insert_batch_item(tenant_id, batch_id, idx, rfp, cid)

    def _handle_existing_batch(
        self,
        config: TenantConfig,
        batch_id: str,
        run,
        batch: list[dict],
        req_fps: list[str],
        client_ids: list[str | None],
    ) -> dict[str, Any]:
        tenant_id = config.tenant_id
        rows = self.storage.list_batch_items(tenant_id, batch_id)
        if len(rows) != len(req_fps):
            raise BatchError(
                "batch_id was already used with a different item count",
                reason="batch_id_shape_mismatch",
            )
        for row, rfp, cid in zip(rows, req_fps, client_ids):
            if row["request_fingerprint"] != rfp:
                raise BatchError(
                    f"item at index {row['item_index']} differs from the first"
                    " submission carrying this batch_id",
                    reason="batch_id_content_mismatch",
                )
            if (row["client_item_id"] is not None or cid is not None) and (
                row["client_item_id"] != cid
            ):
                raise BatchError(
                    f"item at index {row['item_index']} client_item_id differs"
                    " from the first submission carrying this batch_id",
                    reason="batch_id_content_mismatch",
                )

        if run["status"] == "completed" and run["result_json"]:
            stored = json.loads(run["result_json"])
            self._audit_batch_summary(tenant_id, batch_id, stored, replay=True)
            return stored

        # status == 'processing': concurrent live attempt or a crash restart.
        with self._live_lock:
            live = (tenant_id, batch_id) in self._live_batches
        if live:
            raise BatchConflictError(
                "batch is still being processed by another request; retry later",
                reason="batch_in_progress",
            )
        return self._resume_processing(config, batch_id, batch, rows)

    def _resume_processing(
        self,
        config: TenantConfig,
        batch_id: str,
        batch: list[dict],
        rows: list,
    ) -> dict[str, Any]:
        tenant_id = config.tenant_id
        with self._live_lock:
            if (tenant_id, batch_id) in self._live_batches:
                raise BatchConflictError(
                    "batch is still being processed by another request; retry later",
                    reason="batch_in_progress",
                )
            self._live_batches.add((tenant_id, batch_id))
        try:
            items_out: list[dict[str, Any]] = []
            for row in rows:
                stored = row["result_json"]
                if stored is not None:
                    # Already handled before a crash/restart: reuse the stored
                    # outcome exactly and do NOT re-execute (no duplicate audit
                    # side effects, no duplicate writes).
                    items_out.append(json.loads(stored))
                else:
                    item = batch[row["item_index"]]
                    items_out.append(
                        self._process_one_for_batch(
                            config, row["item_index"], item, batch_id
                        )
                    )
            result = self._assemble_batch_result(tenant_id, batch_id, items_out)
        finally:
            with self._live_lock:
                self._live_batches.discard((tenant_id, batch_id))
        with self.storage.lock():
            run = self.storage.get_batch_run(tenant_id, batch_id)
            if run is not None and run["status"] == "completed" and run["result_json"]:
                return json.loads(run["result_json"])
            self.storage.complete_batch_run(
                tenant_id,
                batch_id,
                json.dumps(result, ensure_ascii=False),
                utcnow_iso(),
            )
        self._audit_batch_summary(tenant_id, batch_id, result, replay=False)
        return result

    def _process_batch_items(
        self, config: TenantConfig, batch: list[dict], *, batch_id: str | None
    ) -> dict[str, Any]:
        items_out = [
            self._process_one_for_batch(config, idx, item, batch_id)
            for idx, item in enumerate(batch)
        ]
        return self._assemble_batch_result(config.tenant_id, batch_id, items_out)

    def _assemble_batch_result(
        self, tenant_id: str, batch_id: str | None, items_out: list[dict[str, Any]]
    ) -> dict[str, Any]:
        counts = {"created": 0, "duplicate": 0, "rejected": 0}
        for it in items_out:
            counts[it["status"]] += 1
        policy_version = items_out[0]["policy_version"]
        return {
            "tenant_id": tenant_id,
            "batch_id": batch_id,
            "policy_version": policy_version,
            "items": items_out,
            "summary": {"total": len(items_out), **counts},
        }

    def _process_one_for_batch(
        self,
        config: TenantConfig,
        idx: int,
        item: dict,
        batch_id: str | None,
    ) -> dict[str, Any]:
        """Process one batch item: independent classify/dedup/store decision.

        Item writes emit the same per-item audit trail as single writes (when
        they actually execute), and the outcome is additionally persisted for
        idempotent batch replay. ``masked_payload`` is stripped from the
        persisted per-item result to avoid duplicating stored content.
        """
        payload = item["payload"]
        attributes = item.get("attributes", {})
        client_item_id = item.get("client_item_id")

        outcome = self._write_one_item(config, payload, attributes, audit=True)
        result: dict[str, Any] = {
            "index": idx,
            "client_item_id": client_item_id,
            "status": outcome["status"],
            "policy_version": outcome["policy_version"],
        }
        if outcome["status"] == "rejected":
            result["reason"] = outcome["reason"]
            result["message"] = outcome.get("message", outcome["reason"])
        else:
            result["record_id"] = outcome["record_id"]
            result["reason"] = (
                "duplicate_write_idempotent"
                if outcome["status"] == "duplicate"
                else "classified_and_stored"
            )

        if batch_id is not None:
            self.storage.save_batch_item_result(
                config.tenant_id,
                batch_id,
                idx,
                result_json=json.dumps(result, ensure_ascii=False),
                record_id=result.get("record_id"),
            )
        return result

    def _audit_batch_summary(
        self,
        tenant_id: str,
        batch_id: str,
        result: dict[str, Any],
        *,
        replay: bool,
    ) -> None:
        summary = result["summary"]
        self._audit(
            tenant_id=tenant_id,
            event_type="batch_write",
            decision="allow",
            reason="batch_idempotent_replay" if replay else "batch_accepted",
            policy_version=result["policy_version"],
            subject=None,
            record_id=None,
            input_summary={
                "batch_id": batch_id,
                "total": summary["total"],
                "created": summary["created"],
                "duplicate": summary["duplicate"],
                "rejected": summary["rejected"],
            },
            evidence={"replay": replay},
        )

    @staticmethod
    def _fallback_summary(hits: list[FallbackHit]) -> dict[str, Any]:
        """Safe evidence for fallback detection: names, detectors, fingerprints."""
        return {
            "hits": [
                {
                    "field": h.field_name,
                    "kind": h.kind,
                    "detector": h.detector,
                    "value_fingerprint": h.value_fingerprint,
                    "rule": h.description,
                }
                for h in hits
            ],
        }

    def _reject_item(
        self,
        config: TenantConfig,
        payload: dict,
        reason: str,
        message: str,
        evidence: dict[str, Any],
        *,
        summary: dict[str, Any] | None = None,
        audit: bool,
    ) -> dict[str, Any]:
        policy = config.policy
        if audit:
            self._audit(
                tenant_id=config.tenant_id,
                event_type="write",
                decision="reject",
                reason=reason,
                policy_version=policy.version,
                subject=None,
                record_id=None,
                input_summary=summary
                if summary is not None
                else self._write_summary(payload, policy),
                evidence=evidence,
            )
        return {
            "status": "rejected",
            "reason": reason,
            "message": message,
            "policy_version": policy.version,
        }

    def _write_one_item(
        self,
        config: TenantConfig,
        payload: dict,
        attributes: dict,
        *,
        audit: bool,
    ) -> dict[str, Any]:
        """Classify, fallback-scan, dedup and store one item.

        Never raises for item-level rejections: the outcome dict carries
        ``status`` (created | duplicate | rejected) plus a machine-readable
        ``reason`` so callers can process batches item by item.
        """
        tenant_id = config.tenant_id
        policy = config.policy
        key = self._key(tenant_id)
        summary = self._write_summary(payload, policy)

        # 1) Declared sensitive rules are authoritative and fail closed.
        try:
            masked_payload, classified = classify_payload(
                payload, policy.rules, key
            )
        except ClassificationError as exc:
            return self._reject_item(
                config,
                payload,
                exc.reason,
                str(exc),
                {"stage": "classification", "message": str(exc)},
                summary=summary,
                audit=audit,
            )

        # 2) Fallback detection for fields the tenant did NOT declare.
        hits = scan_undeclared_sensitive(payload, set(policy.rules), key)
        if hits:
            value_hits = [h for h in hits if h.kind == "value"]
            name_hits = [h for h in hits if h.kind == "field_name"]
            if value_hits:
                reason = "undeclared_sensitive_content"
                message = (
                    "obvious sensitive content found in an undeclared field;"
                    " declare a rule for the field before writing"
                )
                stage_hits = value_hits
            else:
                reason = "undeclared_sensitive_field_name"
                message = (
                    "an undeclared field name denotes sensitive data;"
                    " declare a rule for the field before writing"
                )
                stage_hits = name_hits
            evidence: dict[str, Any] = {
                "stage": "fallback_detection",
                **self._fallback_summary(stage_hits),
            }
            if value_hits and name_hits:
                evidence["additional_field_name_hits"] = self._fallback_summary(
                    name_hits
                )["hits"]
            return self._reject_item(
                config,
                payload,
                reason,
                message,
                evidence,
                summary=summary,
                audit=audit,
            )

        content_fp = content_fingerprint(key, masked_payload, attributes)
        record_id = uuid.uuid4().hex

        # 3) Whole-content dedup + insert in the tenant storage critical section.
        with self.storage.lock():
            existing = self.storage.find_active_by_content(tenant_id, content_fp)
            if existing is not None:
                if audit:
                    self._audit(
                        tenant_id=tenant_id,
                        event_type="write",
                        decision="allow",
                        reason="duplicate_write_idempotent",
                        policy_version=policy.version,
                        subject=None,
                        record_id=existing.record_id,
                        input_summary=self._classified_summary(
                            classified, content_fp=content_fp
                        ),
                        evidence={"dedup": "identical_whole_content"},
                    )
                return {
                    "record_id": existing.record_id,
                    "status": "duplicate",
                    "policy_version": policy.version,
                    "masked_payload": existing.masked_payload,
                }

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
                content_fingerprint=content_fp,
            )
            self.storage.insert_record(record)

        if audit:
            self._audit(
                tenant_id=tenant_id,
                event_type="write",
                decision="allow",
                reason="classified_and_stored",
                policy_version=policy.version,
                subject=None,
                record_id=record_id,
                input_summary=self._classified_summary(
                    classified, content_fp=content_fp
                ),
                evidence={
                    "rules": {f: cv.rule_description for f, cv in classified.items()},
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
    def _classified_summary(
        classified: dict[str, ClassifiedValue], *, content_fp: str | None = None
    ) -> dict[str, Any]:
        """Post-classification summary: fingerprints/tokens only, never raw values."""
        summary = {
            "fields": sorted(classified.keys()),
            "fingerprints": {
                f: cv.value_fingerprint for f, cv in classified.items()
            },
        }
        if content_fp is not None:
            summary["content_fingerprint"] = content_fp
        return summary

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
        self.storage.anonymize_record(
            record.tenant_id, record.record_id, anon_payload
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
