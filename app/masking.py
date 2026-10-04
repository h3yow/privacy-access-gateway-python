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
import json
from typing import Any

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


def content_fingerprint(
    key: bytes, masked_payload: dict[str, Any], attributes: dict[str, Any]
) -> str:
    """HMAC over the complete business content of a record.

    Inputs are the *masked* payload plus non-sensitive attributes, so the raw
    value is never needed to recompute this fingerprint. Canonical JSON with
    sorted keys makes the digest independent of dict insertion order. Safe to
    persist; used for whole-content idempotency.
    """
    canonical = json.dumps(
        {"p": masked_payload, "a": attributes},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hmac.new(
        key, f"content\0{canonical}".encode("utf-8"), hashlib.sha256
    ).hexdigest()[:_FINGERPRINT_LEN]


def request_fingerprint(key: bytes, payload: dict[str, Any], attributes: dict[str, Any]) -> str:
    """HMAC over the raw inbound item, used to detect mismatched batch retries.

    The digest is one-way and only persisted to compare an identical resend
    against the first submission; it is never logged.
    """
    canonical = json.dumps(
        {"p": payload, "a": attributes},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hmac.new(
        key, f"request\0{canonical}".encode("utf-8"), hashlib.sha256
    ).hexdigest()


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
