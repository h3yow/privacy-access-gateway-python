"""审计日志记录与历史结论复现。

审计记录只保存：
- 输入摘要（字段名、值长度、归一化指纹哈希，绝不保存原值）
- 判定依据（命中规则名、角色、字段模式、行条件、策略版本、结论）
- 时间戳与请求标识
历史结论通过 policy_version 引用当时的 PolicyBundle 快照实现可复现。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass


def value_fingerprint(tenant_id: str, normalized: str, secret: str = "") -> str:
    """对归一化值取不可逆短指纹，用于"同值可关联、原值不可知"的核验。

    使用 HMAC-SHA256（密钥为服务 secret），避免对手机号等低熵值做
    无密钥哈希而被字典反推。
    """
    import hmac as _hmac

    h = _hmac.new(
        secret.encode("utf-8"),
        f"fp:{tenant_id}:{normalized}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"fp_{h[:16]}"


def value_summary(raw: str) -> dict:
    """生成可核验但不泄露原值的输入摘要：仅长度与字符类别统计。"""
    return {
        "len": len(raw),
        "digits": sum(c.isdigit() for c in raw),
        "alpha": sum(c.isalpha() for c in raw),
    }


@dataclass(frozen=True)
class AuditEntry:
    ts: str
    request_id: str
    tenant_id: str
    action: str
    decision: str
    policy_version: str
    subject_role: str
    record_id: str
    basis: dict
    summaries: dict

    def to_dict(self) -> dict:
        return {
            "ts": self.ts,
            "request_id": self.request_id,
            "tenant_id": self.tenant_id,
            "action": self.action,
            "decision": self.decision,
            "policy_version": self.policy_version,
            "subject_role": self.subject_role,
            "record_id": self.record_id,
            "basis": self.basis,
            "summaries": self.summaries,
        }


class AuditLog:
    def __init__(self, path: str = ":memory:") -> None:
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock, self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts             TEXT NOT NULL,
                    request_id     TEXT NOT NULL,
                    tenant_id      TEXT NOT NULL,
                    action         TEXT NOT NULL,
                    decision       TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    subject_role   TEXT NOT NULL,
                    record_id      TEXT NOT NULL,
                    basis_json     TEXT NOT NULL,
                    summaries_json TEXT NOT NULL
                )
                """
            )

    def append(self, entry: AuditEntry) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO audit_log(ts, request_id, tenant_id, action, decision, "
                "policy_version, subject_role, record_id, basis_json, summaries_json) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    entry.ts,
                    entry.request_id,
                    entry.tenant_id,
                    entry.action,
                    entry.decision,
                    entry.policy_version,
                    entry.subject_role,
                    entry.record_id,
                    json.dumps(entry.basis, ensure_ascii=False, sort_keys=True),
                    json.dumps(entry.summaries, ensure_ascii=False, sort_keys=True),
                ),
            )

    def query(
        self,
        tenant_id: str | None = None,
        record_id: str | None = None,
        policy_version: str | None = None,
    ) -> list[AuditEntry]:
        sql = "SELECT * FROM audit_log WHERE 1=1"
        args: list[object] = []
        if tenant_id is not None:
            sql += " AND tenant_id=?"
            args.append(tenant_id)
        if record_id is not None:
            sql += " AND record_id=?"
            args.append(record_id)
        if policy_version is not None:
            sql += " AND policy_version=?"
            args.append(policy_version)
        sql += " ORDER BY seq"
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [self._row_to_entry(r) for r in rows]

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> AuditEntry:
        return AuditEntry(
            ts=row["ts"],
            request_id=row["request_id"],
            tenant_id=row["tenant_id"],
            action=row["action"],
            decision=row["decision"],
            policy_version=row["policy_version"],
            subject_role=row["subject_role"],
            record_id=row["record_id"],
            basis=json.loads(row["basis_json"]),
            summaries=json.loads(row["summaries_json"]),
        )

    def close(self) -> None:
        with self._lock:
            self._conn.close()
