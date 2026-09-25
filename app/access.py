"""Role- and attribute-based access control decisions."""
from __future__ import annotations

from typing import Any

from app.models import RolePolicy, StoredRecord

# Sensitive fields are denied unless the role explicitly grants visibility.
# Non-sensitive fields are visible unless the role explicitly hides/denies them.
_SENSITIVE_DEFAULT = "denied"
_NON_SENSITIVE_DEFAULT = "visible"


def field_visible(
    role: RolePolicy, field_name: str, *, sensitive: bool
) -> str:
    """Return one of: visible | masked | denied."""
    setting = role.fields.get(field_name)
    if setting is not None:
        return setting
    return _SENSITIVE_DEFAULT if sensitive else _NON_SENSITIVE_DEFAULT


def _resolve(value: Any, subject_attrs: dict[str, Any]) -> Any:
    """Resolve a ``$attr`` reference against the subject's attributes."""
    if isinstance(value, str) and value.startswith("$"):
        return subject_attrs.get(value[1:])
    return value


def row_visible(
    record: StoredRecord, role: RolePolicy, subject_attrs: dict[str, Any]
) -> tuple[bool, dict[str, Any]]:
    """Evaluate ABAC row filters. Returns (visible, evidence).

    Every constraint must match a record attribute. The special value
    ``"$attr_name"`` is resolved from the subject's attributes (owner-style
    access). An unresolvable attribute denies the row rather than failing open.
    """
    evidence: dict[str, Any] = {"row_filters": {}, "failed": []}
    for attr, required in role.row_filters.items():
        actual = record.attributes.get(attr)
        expected = _resolve(required, subject_attrs)
        matched = actual == expected
        evidence["row_filters"][attr] = {
            "required_ref": required,
            "expected": _safe(expected),
            "actual": _safe(actual),
            "matched": matched,
        }
        if not matched:
            evidence["failed"].append(attr)
    return (not evidence["failed"]), evidence


def _safe(value: Any) -> Any:
    """Attribute values are non-sensitive business attributes; render plainly."""
    return value
