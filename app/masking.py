"""Deterministic tokenization / masking primitives.

All replacements are derived from a per-tenant HMAC key so that:

* the same raw value in the same tenant always maps to the same token;
* tokens are uncorrelated across tenants (different derived keys);
* raw values can never be recovered from a token without the key, and
  raw values are never emitted by any helper in this module.
"""
from __future__ import annotations

import hashlib
import hmac

_TOKEN_PREFIX = "TOK"
_FINGERPRINT_LEN = 32
_TOKEN_BYTES = 16


def tenant_key(master_key: str, tenant_id: str) -> bytes:
    """Derive a stable per-tenant key from the configured master key."""
    return hmac.new(
        master_key.encode("utf-8"),
        f"tenant-key\0{tenant_id}".encode("utf-8"),
        hashlib.sha256,
    ).digest()


def _digest(key: bytes, domain: str, field_name: str, raw_value: str) -> bytes:
    msg = f"{domain}\0{field_name}\0{raw_value}".encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).digest()


def fingerprint(key: bytes, field_name: str, raw_value: str) -> str:
    """Stable identity fingerprint for a raw value. Safe to persist."""
    return _digest(key, "fingerprint", field_name, raw_value).hex()[:_FINGERPRINT_LEN]


def stable_token(key: bytes, field_name: str, raw_value: str) -> str:
    """Deterministic opaque replacement token for a raw value."""
    raw = _digest(key, "token", field_name, raw_value)[:_TOKEN_BYTES].hex().upper()
    return f"{_TOKEN_PREFIX}_{field_name.upper()}_{raw}"


def partial_mask(raw_value: str, keep_prefix: int, keep_suffix: int) -> str:
    """Keep a fixed head/tail and replace the middle with ``*``.

    Guarantees at least one masked character, so an overly generous rule can
    never echo the full original value back.
    """
    if keep_prefix < 0 or keep_suffix < 0:
        raise ValueError("keep_prefix/keep_suffix must be non-negative")
    n = len(raw_value)
    if n == 0 or keep_prefix + keep_suffix >= n:
        # Not enough interior to safely reveal: mask everything.
        return "*" * max(n, 1)
    middle = n - keep_prefix - keep_suffix
    return raw_value[:keep_prefix] + ("*" * middle) + raw_value[n - keep_suffix :]
