"""错误类型定义：所有拒绝原因均可区分。

每个错误携带机器可判定的 reason 码；message 面向调用方，
任何错误消息都不得包含原始敏感值（由调用方保证只放摘要/字段名）。
"""

from __future__ import annotations


class GatewayError(Exception):
    """网关错误基类。"""

    reason: str = "gateway_error"

    def __init__(self, message: str = "", *, reason: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        if reason is not None:
            self.reason = reason

    def __str__(self) -> str:  # pragma: no cover - 调试辅助
        return f"[{self.reason}] {self.message}"


class ClassificationError(GatewayError):
    """敏感字段识别失败。

    子原因码通过 reason 区分：
    - classification_no_rule: 原值未命中任何识别规则
    - classification_incomplete_rule: 命中的规则配置不完整
    - classification_bad_record: 记录畸形（字段类型/结构不符）
    """

    reason = "classification_error"


class PolicyValidationError(GatewayError):
    """策略文件畸形或校验失败。

    子原因码示例：
    - policy_missing_field / policy_bad_enum / policy_duplicate_version
    - policy_unknown_role / policy_bad_condition
    """

    reason = "policy_validation_error"


class AccessDeniedError(GatewayError):
    """访问控制拒绝。

    子原因码：
    - access_field_denied: 字段级不可见
    - access_row_denied: 行级 ABAC 条件不满足
    - access_unknown_role: 角色无策略
    """

    reason = "access_denied"


class RetentionError(GatewayError):
    """保留期处理错误。"""

    reason = "retention_error"


class RecordProcessingError(GatewayError):
    """单条记录处理失败（畸形记录），用于批量部分成功的错误汇总。"""

    reason = "record_processing_error"

    def __init__(
        self,
        message: str,
        *,
        index: int | None = None,
        record_id: str | None = None,
        cause: Exception | None = None,
        reason: str | None = None,
    ) -> None:
        super().__init__(message, reason=reason)
        self.index = index
        self.record_id = record_id
        self.cause = cause
