"""SQLite-backed persistence. Stores only masked data; never raw values."""
from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any

from app.models import AuditEntry, FieldRule, PolicyVersion, RolePolicy, StoredRecord, TenantConfig

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id        TEXT PRIMARY KEY,
    retention_days   INTEGER NOT NULL,
    retention_action TEXT NOT NULL,
    current_version  INTEGER NOT NULL,
    created_at       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_versions (
    tenant_id     TEXT NOT NULL,
    version       INTEGER NOT NULL,
    rules_json    TEXT NOT NULL,
    roles_json    TEXT NOT NULL,
    default_role  TEXT NOT NULL,
    effective_at  TEXT NOT NULL,
    PRIMARY KEY (tenant_id, version)
);
CREATE TABLE IF NOT EXISTS records (
    record_id       TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active',
    masked_payload  TEXT NOT NULL,
    sensitive_index TEXT NOT NULL,
    attributes      TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    PRIMARY KEY (tenant_id, record_id)
);
CREATE TABLE IF NOT EXISTS dedup_index (
    tenant_id        TEXT NOT NULL,
    field_name       TEXT NOT NULL,
    value_fingerprint TEXT NOT NULL,
    record_id        TEXT NOT NULL,
    PRIMARY KEY (tenant_id, field_name, value_fingerprint)
);
CREATE TABLE IF NOT EXISTS audit_logs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id      TEXT NOT NULL,
    event_type     TEXT NOT NULL,
    decision       TEXT NOT NULL,
    reason         TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    subject        TEXT,
    record_id      TEXT,
    input_summary  TEXT NOT NULL,
    evidence       TEXT NOT NULL,
    occurred_at    TEXT NOT NULL
);
"""


class Storage:
    def __init__(self, database_path: str) -> None:
        self.database_path = database_path
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None

    # ---- lifecycle ----
    def init(self) -> None:
        with self._lock:
            self._conn = sqlite3.connect(
                self.database_path, check_same_thread=False
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL");
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def _db(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("storage not initialized")
        return self._conn

    # ---- serialization ----
    @staticmethod
    def _rule_to_dict(rule: FieldRule) -> dict[str, Any]:
        return {
            "field_name": rule.field_name,
            "strategy": rule.strategy,
            "pattern": rule.pattern,
            "keep_prefix": rule.keep_prefix,
            "keep_suffix": rule.keep_suffix,
            "description": rule.description,
        }

    @staticmethod
    def _rule_from_dict(d: dict[str, Any]) -> FieldRule:
        return FieldRule(
            field_name=d["field_name"],
            strategy=d["strategy"],
            pattern=d.get("pattern"),
            keep_prefix=d.get("keep_prefix", 0),
            keep_suffix=d.get("keep_suffix", 0),
            description=d.get("description", ""),
        )

    @staticmethod
    def _role_to_dict(role: RolePolicy) -> dict[str, Any]:
        return {"name": role.name, "fields": role.fields, "row_filters": role.row_filters}

    @staticmethod
    def _role_from_dict(d: dict[str, Any]) -> RolePolicy:
        return RolePolicy(
            name=d["name"],
            fields=dict(d.get("fields", {})),
            row_filters=dict(d.get("row_filters", {})),
        )

    def _policy_from_row(self, row: sqlite3.Row) -> PolicyVersion:
        rules_raw = json.loads(row["rules_json"])
        roles_raw = json.loads(row["roles_json"])
        rules = {r["field_name"]: self._rule_from_dict(r) for r in rules_raw}
        roles = {r["name"]: self._role_from_dict(r) for r in roles_raw}
        return PolicyVersion(
            version=row["version"],
            rules=rules,
            roles=roles,
            default_role=row["default_role"],
            effective_at=row["effective_at"],
        )

    # ---- tenants / policies ----
    def get_tenant_config(self, tenant_id: str) -> TenantConfig | None:
        with self._lock:
            t = self._db().execute(
                "SELECT * FROM tenants WHERE tenant_id=?", (tenant_id,)
            ).fetchone()
            if t is None:
                return None
            pv = self.get_policy_version(tenant_id, t["current_version"])
            assert pv is not None
            return TenantConfig(
                tenant_id=tenant_id,
                retention_days=t["retention_days"],
                retention_action=t["retention_action"],
                policy=pv,
            )

    def upsert_tenant_config(self, config: TenantConfig, *, created_at: str) -> None:
        """Idempotently create the tenant row and insert a new policy version."""
        with self._lock:
            db = self._db()
            existing = db.execute(
                "SELECT current_version FROM tenants WHERE tenant_id=?",
                (config.tenant_id,),
            ).fetchone()
            version = 1 if existing is None else existing["current_version"] + 1
            pv = PolicyVersion(
                version=version,
                rules=config.policy.rules,
                roles=config.policy.roles,
                default_role=config.policy.default_role,
                effective_at=config.policy.effective_at,
            )
            self._insert_policy_locked(config.tenant_id, pv)
            if existing is None:
                db.execute(
                    "INSERT INTO tenants(tenant_id, retention_days, retention_action,"
                    " current_version, created_at) VALUES (?,?,?,?,?)",
                    (
                        config.tenant_id,
                        config.retention_days,
                        config.retention_action,
                        version,
                        created_at,
                    ),
                )
            else:
                db.execute(
                    "UPDATE tenants SET retention_days=?, retention_action=?,"
                    " current_version=? WHERE tenant_id=?",
                    (
                        config.retention_days,
                        config.retention_action,
                        version,
                        config.tenant_id,
                    ),
                )
            db.commit()

    def _insert_policy_locked(self, tenant_id: str, pv: PolicyVersion) -> None:
        db = self._db()
        rules = [self._rule_to_dict(r) for r in pv.rules.values()]
        roles = [self._role_to_dict(r) for r in pv.roles.values()]
        db.execute(
            "INSERT INTO policy_versions(tenant_id, version, rules_json, roles_json,"
            " default_role, effective_at) VALUES (?,?,?,?,?,?)",
            (
                tenant_id,
                pv.version,
                json.dumps(rules, ensure_ascii=False),
                json.dumps(roles, ensure_ascii=False),
                pv.default_role,
                pv.effective_at,
            ),
        )

    def insert_policy_version(self, tenant_id: str, pv: PolicyVersion) -> None:
        with self._lock:
            db = self._db()
            self._insert_policy_locked(tenant_id, pv)
            db.execute(
                "UPDATE tenants SET current_version=? WHERE tenant_id=?",
                (pv.version, tenant_id),
            )
            db.commit()

    def list_policy_versions(self, tenant_id: str) -> list[PolicyVersion]:
        with self._lock:
            rows = self._db().execute(
                "SELECT * FROM policy_versions WHERE tenant_id=? ORDER BY version",
                (tenant_id,),
            ).fetchall()
            return [self._policy_from_row(r) for r in rows]

    def get_policy_version(self, tenant_id: str, version: int) -> PolicyVersion | None:
        with self._lock:
            row = self._db().execute(
                "SELECT * FROM policy_versions WHERE tenant_id=? AND version=?",
                (tenant_id, version),
            ).fetchone()
            return self._policy_from_row(row) if row is not None else None

    def policy_at(self, tenant_id: str, as_of: str) -> PolicyVersion | None:
        """Latest policy version effective at-or-before ``as_of``."""
        with self._lock:
            row = self._db().execute(
                "SELECT * FROM policy_versions WHERE tenant_id=? AND effective_at<=?"
                " ORDER BY version DESC LIMIT 1",
                (tenant_id, as_of),
            ).fetchone()
            return self._policy_from_row(row) if row is not None else None

    # ---- records ----
    @staticmethod
    def _record_from_row(row: sqlite3.Row) -> StoredRecord:
        return StoredRecord(
            record_id=row["record_id"],
            tenant_id=row["tenant_id"],
            masked_payload=json.loads(row["masked_payload"]),
            sensitive_index=json.loads(row["sensitive_index"]),
            attributes=json.loads(row["attributes"]),
            created_at=row["created_at"],
            status=row["status"],
        )

    def find_record(
        self, tenant_id: str, fingerprints: dict[str, str]
    ) -> StoredRecord | None:
        """Find the active record matching ALL given field fingerprints."""
        if not fingerprints:
            return None
        with self._lock:
            db = self._db()
            for field_name, fp in fingerprints.items():
                row = db.execute(
                    "SELECT r.* FROM records r JOIN dedup_index d"
                    " ON d.tenant_id=r.tenant_id AND d.record_id=r.record_id"
                    " WHERE r.tenant_id=? AND r.status='active'"
                    " AND d.field_name=? AND d.value_fingerprint=?",
                    (tenant_id, field_name, fp),
                ).fetchone()
                if row is None:
                    return None
            candidate = self._record_from_row(row)
            index = candidate.sensitive_index
            if all(index.get(f, {}).get("fingerprint") == fp
                   for f, fp in fingerprints.items()):
                return candidate
            return None

    def get_record(self, tenant_id: str, record_id: str) -> StoredRecord | None:
        with self._lock:
            row = self._db().execute(
                "SELECT * FROM records WHERE tenant_id=? AND record_id=?",
                (tenant_id, record_id),
            ).fetchone()
            return self._record_from_row(row) if row is not None else None

    def list_records(self, tenant_id: str) -> list[StoredRecord]:
        with self._lock:
            rows = self._db().execute(
                "SELECT * FROM records WHERE tenant_id=? ORDER BY created_at, record_id",
                (tenant_id,),
            ).fetchall()
            return [self._record_from_row(r) for r in rows]

    def insert_record(self, record: StoredRecord) -> None:
        with self._lock:
            db = self._db()
            db.execute(
                "INSERT INTO records(record_id, tenant_id, status, masked_payload,"
                " sensitive_index, attributes, created_at) VALUES (?,?,?,?,?,?,?)",
                (
                    record.record_id,
                    record.tenant_id,
                    record.status,
                    json.dumps(record.masked_payload, ensure_ascii=False),
                    json.dumps(record.sensitive_index, ensure_ascii=False),
                    json.dumps(record.attributes, ensure_ascii=False),
                    record.created_at,
                ),
            )
            for field_name, idx in record.sensitive_index.items():
                db.execute(
                    "INSERT INTO dedup_index(tenant_id, field_name, value_fingerprint,"
                    " record_id) VALUES (?,?,?,?)",
                    (record.tenant_id, field_name, idx["fingerprint"], record.record_id),
                )
            db.commit()

    def update_record_payload(
        self,
        tenant_id: str,
        record_id: str,
        masked_payload: dict,
        sensitive_index: dict,
        status: str | None = None,
    ) -> None:
        with self._lock:
            db = self._db()
            if status is None:
                db.execute(
                    "UPDATE records SET masked_payload=?, sensitive_index=?"
                    " WHERE tenant_id=? AND record_id=?",
                    (
                        json.dumps(masked_payload, ensure_ascii=False),
                        json.dumps(sensitive_index, ensure_ascii=False),
                        tenant_id,
                        record_id,
                    ),
                )
            else:
                db.execute(
                    "UPDATE records SET masked_payload=?, sensitive_index=?, status=?"
                    " WHERE tenant_id=? AND record_id=?",
                    (
                        json.dumps(masked_payload, ensure_ascii=False),
                        json.dumps(sensitive_index, ensure_ascii=False),
                        status,
                        tenant_id,
                        record_id,
                    ),
                )
            db.commit()

    def delete_record(self, tenant_id: str, record_id: str) -> None:
        with self._lock:
            db = self._db()
            db.execute(
                "DELETE FROM dedup_index WHERE tenant_id=? AND record_id=?",
                (tenant_id, record_id),
            )
            db.execute(
                "DELETE FROM records WHERE tenant_id=? AND record_id=?",
                (tenant_id, record_id),
            )
            db.commit()

    def expired_records(self, tenant_id: str, cutoff: str) -> list[StoredRecord]:
        """Active records created strictly before ``cutoff``."""
        with self._lock:
            rows = self._db().execute(
                "SELECT * FROM records WHERE tenant_id=? AND status='active'"
                " AND created_at < ? ORDER BY record_id",
                (tenant_id, cutoff),
            ).fetchall()
            return [self._record_from_row(r) for r in rows]

    # ---- audit ----
    def insert_audit(self, entry: AuditEntry) -> AuditEntry:
        with self._lock:
            db = self._db()
            cur = db.execute(
                "INSERT INTO audit_logs(tenant_id, event_type, decision, reason,"
                " policy_version, subject, record_id, input_summary, evidence,"
                " occurred_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    entry.tenant_id,
                    entry.event_type,
                    entry.decision,
                    entry.reason,
                    entry.policy_version,
                    entry.subject,
                    entry.record_id,
                    json.dumps(entry.input_summary, ensure_ascii=False),
                    json.dumps(entry.evidence, ensure_ascii=False),
                    entry.occurred_at,
                ),
            )
            db.commit()
            return AuditEntry(**{**entry.__dict__, "audit_id": cur.lastrowid})

    def get_audit(self, tenant_id: str, audit_id: int) -> AuditEntry | None:
        with self._lock:
            row = self._db().execute(
                "SELECT * FROM audit_logs WHERE tenant_id=? AND id=?",
                (tenant_id, audit_id),
            ).fetchone()
            return self._audit_from_row(row) if row is not None else None

    def list_audit(self, tenant_id: str, limit: int = 100) -> list[AuditEntry]:
        with self._lock:
            rows = self._db().execute(
                "SELECT * FROM audit_logs WHERE tenant_id=? ORDER BY id DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
            return [self._audit_from_row(r) for r in rows]

    @staticmethod
    def _audit_from_row(row: sqlite3.Row) -> AuditEntry:
        return AuditEntry(
            audit_id=row["id"],
            tenant_id=row["tenant_id"],
            event_type=row["event_type"],
            decision=row["decision"],
            reason=row["reason"],
            policy_version=row["policy_version"],
            subject=row["subject"],
            record_id=row["record_id"],
            input_summary=json.loads(row["input_summary"]),
            evidence=json.loads(row["evidence"]),
            occurred_at=row["occurred_at"],
        )

    # ---- locking helpers ----
    def lock(self) -> threading.RLock:
        return self._lock
