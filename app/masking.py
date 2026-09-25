"""敏感字段识别、归一化与确定性脱敏。

关键语义：
1. 归一化（normalize_value）把同一语义值的不同写法（空格/连字符/大小写）
   收敛为稳定指纹，保证"变体一致"。
2. 令牌（deterministic_token）基于 HMAC-SHA256，租户 + scope + 归一化值
   三元组决定输出，同租户同 scope 内相同原值永远得到相同替换结果；
   不同租户/scope 相互独立，且由 HMAC 不可逆推出原值。
3. 本模块不做任何持久化与日志输出，原始值仅在函数调用栈内短暂存在。
"""

from __future__ import annotations

import hashlib
import hmac
import re

_DIGITS = re.compile(r"\d")
_KEEP_ALNUM = re.compile(r"[0-9a-z一-鿿]")


def normalize_value(raw: str, normalizer: str) -> str:
    """按规则把原始值变体归一化为稳定指纹输入。

    支持的 normalizer：
    - digits   : 仅保留数字（手机号/证件号去分隔符变体）
    - alnum    : 小写并仅保留字母数字与中日韩文字（邮箱等）
    - exact    : 不去除空白，仅 strip + 原样（区分大小写）
    - lower    : strip + 小写（保留内部结构）
    """
    if not isinstance(raw, str):
        raise TypeError("normalized value must be str")
    if normalizer == "digits":
        return "".join(_DIGITS.findall(raw))
    if normalizer == "alnum":
        return "".join(_KEEP_ALNUM.findall(raw.lower()))
    if normalizer == "lower":
        return raw.strip().lower()
    if normalizer == "exact":
        return raw.strip()
    raise ValueError(f"unknown normalizer: {normalizer}")


def deterministic_token(tenant_id: str, scope: str, normalized: str, secret: str) -> str:
    """生成租户/作用域内稳定一致、不可逆的替换令牌。

    形如 ``tok_<16hex>``。HMAC 密钥由全局 secret 派生（按 scope），
    保证不同 scope 的同一值令牌不同、且无法跨 scope 关联。
    """
    scope_key = hmac.new(
        secret.encode("utf-8"), f"scope:{tenant_id}:{scope}".encode("utf-8"), hashlib.sha256
    ).digest()
    digest = hmac.new(scope_key, normalized.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"tok_{digest[:16]}"


def redacted_placeholder() -> str:
    """REDACTED 模式的固定打码内容（不含任何原值信息）。"""
    return "********"
