"""领域类型定义。

策略包（PolicyBundle）是不可变快照：每次策略发布产生新版本，
历史审计结论永远引用当时的版本号，从而可按旧策略复现。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class FieldMode(str, Enum):
    """字段可见模式。

    MASKED   : 可见，但只呈现确定性脱敏令牌
    HIDDEN   : 字段整体不可见（读取结果中移除该字段）
    REDACTED : 字段存在但内容整体打码（如 ********）
    """

    MASKED = "masked"
    HIDDEN = "hidden"
    REDACTED = "redacted"


class RetentionAction(str, Enum):
    """保留期到期后的确定性动作。"""

    DELETE = "delete"           # 物理删除整行
    ANONYMIZE = "anonymize"     # 保留行，敏感字段不可逆匿名化


@dataclass(frozen=True)
class SensitiveRule:
    """敏感字段识别与脱敏规则。

    field      : 记录中的字段名
    pattern    : 识别用正则（仅用于判别"是否敏感"，不捕获原值落盘）
    normalizer : 归一化器名称，见 masking.NORMALIZERS（处理变体）
    scope      : 令牌作用域，同 scope 下相同归一化值得到相同令牌
    mode       : 该字段默认呈现模式
    """

    field: str
    pattern: str
    normalizer: str
    scope: str
    mode: FieldMode


@dataclass(frozen=True)
class FieldPermission:
    """字段级权限。"""

    field: str
    mode: FieldMode


@dataclass(frozen=True)
class RowCondition:
    """行级 ABAC 条件：record[attribute] <operator> value。"""

    attribute: str
    operator: str  # eq / ne / in / notin
    value: object


@dataclass(frozen=True)
class RolePolicy:
    """单个角色的策略：字段可见性 + 行级条件（全部 AND）。"""

    role: str
    fields: tuple[FieldPermission, ...]
    row_conditions: tuple[RowCondition, ...] = field(default_factory=tuple)

    def field_mode(self, name: str) -> FieldMode | None:
        for fp in self.fields:
            if fp.field == name:
                return fp.mode
        return None


@dataclass(frozen=True)
class RetentionPolicy:
    """租户级保留期策略。"""

    tenant_id: str
    retention_days: int
    action: RetentionAction


@dataclass(frozen=True)
class PolicyBundle:
    """某一版本的完整策略集合（不可变快照）。"""

    version: str
    sensitive_rules: tuple[SensitiveRule, ...]
    roles: tuple[RolePolicy, ...]
    retention: tuple[RetentionPolicy, ...]

    def rule_for(self, field_name: str) -> SensitiveRule | None:
        for rule in self.sensitive_rules:
            if rule.field == field_name:
                return rule
        return None

    def role_policy(self, role: str) -> RolePolicy | None:
        for rp in self.roles:
            if rp.role == role:
                return rp
        return None

    def retention_for(self, tenant_id: str) -> RetentionPolicy | None:
        for rp in self.retention:
            if rp.tenant_id == tenant_id:
                return rp
        return None
