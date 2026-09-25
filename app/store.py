"""记录持久化与确定性脱敏映射（SQLite）。

持久化的 data_json 中，敏感字段在写入前已被替换为令牌/占位符，
原始敏感值永不落盘；token_map 只保存归一化指纹 -> 令牌的映射，
归一化指纹是去除格式后的派生标识，且令牌本身由 HMAC 生成。

并发：单连接 + 进程内互斥锁，所有读写都带 tenant_id 条件，
跨租户无法串读；get_or_create_token 依赖唯一约束保证不重复脱敏。
"""

from __future__ import annotations

import json
import sqlite3
import threading

ANONYMIZED_SENTINEL = "__ANONYMIZED__"


class GatewayStore:
    def __init__(self, path: str = ":memory:") -> None:
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self) -> None:
        with self._lock, self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS records (
                    id          TEXT NOT NULL,
                    tenant_id   TEXT NOT NULL,
                    created_at  TEXT NOT NULL,
                    anonymized  INTEGER NOT NULL DEFAULT 0,
                    data_json   TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, id)
                );
                CREATE TABLE IF NOT EXISTS token_map (
                    tenant_id TEXT NOT NULL,
                    scope     TEXT NOT NULL,
                    fp        TEXT NOT NULL,
                    token     TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, scope, fp),
                    UNIQUE (tenant_id, scope, token)
                );
                """
            )

    # ---- 令牌映射：幂等的 get-or-create ----
    def get_or_create_token(self, tenant_id: str, scope: str, fp: str, token: str) -> str:
        """返回已有令牌或创建新映射。

        fp 为归一化值的不可逆指纹（见 audit.value_fingerprint），
        原始值与归一化值均不落盘；并发/重复调用结果一致，不产生重复行。
        """
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT token FROM token_map WHERE tenant_id=? AND scope=? AND fp=?",
                (tenant_id, scope, fp),
            ).fetchone()
            if row is not None:
                return row["token"]
            # UNIQUE(tenant_id, scope, token) 兜底冲突
            self._conn.execute(
                "INSERT OR IGNORE INTO token_map(tenant_id, scope, fp, token) "
                "VALUES (?,?,?,?)",
                (tenant_id, scope, fp, token),
            )
            row = self._conn.execute(
                "SELECT token FROM token_map WHERE tenant_id=? AND scope=? AND fp=?",
                (tenant_id, scope, fp),
            ).fetchone()
            return row["token"]

    # ---- 记录写入（幂等：同 tenant+id 重复写入不产生副作用）----
    def insert_record(
        self,
        tenant_id: str,
        record_id: str,
        masked_data: dict,
        created_at: str,
    ) -> bool:
        """写入一条已脱敏记录。返回 True 表示新插入，False 表示已存在。"""
        payload = json.dumps(masked_data, ensure_ascii=False, sort_keys=True)
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO records(tenant_id, id, created_at, anonymized, data_json) "
                "VALUES (?,?,?,0,?)",
                (tenant_id, record_id, created_at, payload),
            )
            return cur.rowcount == 1

    def get_record(self, tenant_id: str, record_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, created_at, anonymized, data_json FROM records "
                "WHERE tenant_id=? AND id=?",
                (tenant_id, record_id),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_dict(row)

    def list_records(self, tenant_id: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, created_at, anonymized, data_json FROM records "
                "WHERE tenant_id=? ORDER BY created_at, id",
                (tenant_id,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "created_at": row["created_at"],
            "anonymized": bool(row["anonymized"]),
            "data": json.loads(row["data_json"]),
        }

    # ---- 保留期支持 ----
    def candidates_for_retention(self, tenant_id: str, cutoff_iso: str) -> list[dict]:
        """取该租户 created_at <= cutoff 且尚未匿名化的记录（已删除的自然不在）。"""
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, created_at, anonymized, data_json FROM records "
                "WHERE tenant_id=? AND created_at<=? AND anonymized=0 ORDER BY id",
                (tenant_id, cutoff_iso),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def delete_record(self, tenant_id: str, record_id: str) -> bool:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "DELETE FROM records WHERE tenant_id=? AND id=?", (tenant_id, record_id)
            )
            return cur.rowcount == 1

    def anonymize_record(self, tenant_id: str, record_id: str, data: dict) -> bool:
        """把记录数据改写为匿名哨兵，幂等。"""
        payload = json.dumps(data, ensure_ascii=False, sort_keys=True)
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE records SET data_json=?, anonymized=1 "
                "WHERE tenant_id=? AND id=? AND anonymized=0",
                (payload, tenant_id, record_id),
            )
            return cur.rowcount == 1

    def delete_tokens_for_scopes(self, tenant_id: str, scopes: list[str]) -> int:
        """匿名化后切断 scope 的指纹->令牌关联（不可逆）。"""
        if not scopes:
            return 0
        marks = ",".join("?" for _ in scopes)
        with self._lock, self._conn:
            cur = self._conn.execute(
                f"DELETE FROM token_map WHERE tenant_id=? AND scope IN ({marks})",
                (tenant_id, *scopes),
            )
            return cur.rowcount

    def close(self) -> None:
        with self._lock:
            self._conn.close()
