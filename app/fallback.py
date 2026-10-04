"""Fallback sensitive-content detection for fields the tenant did not declare.

Declared policy rules always take precedence. For every *other* top-level
payload field this module applies two conservative heuristics:

1. value scan  – obvious secrets embedded in free text (email / CN mobile /
   CN resident-id shape), even when the field name itself is innocuous;
2. field-name scan – fields whose name unambiguously denotes an identifier
   (id card / passport / bank card / contact channel) regardless of value.

A hit fails the write *closed*: the item is rejected with a reason distinct
from declared-rule failures, instead of silently passing the value through.
Only HMAC fingerprints of matched values ever leave this module — matched raw
text is used transiently and is not returned, logged or persisted.

Scope boundary (intentional): only top-level scalar payload fields are
scanned; nested containers and record ``attributes`` are not scanned.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Literal

from app.masking import fingerprint

# --- value-shape detectors -------------------------------------------------

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# CN mobile: 1[3-9] + 9 digits, with digit boundaries so longer number runs
# (order numbers, timestamps) are not clipped into a false positive.
_MOBILE_CN_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
# CN resident id: 17 digits + digit/X, again bounded against longer runs.
_ID_CARD_CN_RE = re.compile(r"(?<![0-9A-Za-z])\d{17}[0-9Xx](?![0-9A-Za-z])")

_VALUE_DETECTORS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email", _EMAIL_RE),
    ("mobile_cn", _MOBILE_CN_RE),
    ("id_card_cn", _ID_CARD_CN_RE),
)

# --- field-name detectors --------------------------------------------------
# Names compared after lower-casing and stripping underscores.
_FIELD_NAME_HINTS: dict[str, tuple[str, ...]] = {
    "id_document": (
        "idcard",
        "idcardno",
        "idno",
        "idnumber",
        "certno",
        "certificateno",
        "identityno",
        "passport",
        "passportno",
        "licenseno",
    ),
    "contact_info": (
        "email",
        "mail",
        "emailaddr",
        "emailaddress",
        "mobile",
        "mobileno",
        "phone",
        "phoneno",
        "tel",
        "telephone",
        "cellphone",
    ),
    "bank_card": (
        "bankcard",
        "bankcardno",
        "cardno",
        "cardnumber",
        "bankaccount",
        "accountno",
        "creditcard",
    ),
}
_HINT_TO_CATEGORY = {
    hint: category for category, hints in _FIELD_NAME_HINTS.items() for hint in hints
}


@dataclass(frozen=True)
class FallbackHit:
    field_name: str
    kind: Literal["value", "field_name"]
    detector: str                     # matched detector / hint category
    value_fingerprint: str            # HMAC fingerprint, never the raw match
    description: str


def _name_category(field_name: str) -> str | None:
    normalized = field_name.lower().replace("_", "").replace("-", "")
    return _HINT_TO_CATEGORY.get(normalized)


def _fp_of_value(key: bytes, field_name: str, value: Any) -> str:
    if isinstance(value, str):
        raw = value
    else:
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return fingerprint(key, field_name, raw)


def scan_undeclared_sensitive(
    payload: dict[str, Any], declared_fields: set[str], key: bytes
) -> list[FallbackHit]:
    """Return fallback detections for top-level fields not covered by a rule."""
    hits: list[FallbackHit] = []
    for field_name in sorted(k for k in payload if k not in declared_fields):
        value = payload[field_name]
        if not isinstance(value, str):
            # Only free-text values are shape-scanned. Suspicious names on
            # non-string values still fail closed via the field-name heuristic.
            category = _name_category(field_name)
            if category is not None:
                hits.append(
                    FallbackHit(
                        field_name=field_name,
                        kind="field_name",
                        detector=category,
                        value_fingerprint=_fp_of_value(key, field_name, value),
                        description=f"fallback:field_name:{category}",
                    )
                )
            continue

        matched = False
        for detector, pattern in _VALUE_DETECTORS:
            m = pattern.search(value)
            if m is not None:
                matched = True
                hits.append(
                    FallbackHit(
                        field_name=field_name,
                        kind="value",
                        detector=detector,
                        value_fingerprint=fingerprint(key, field_name, m.group(0)),
                        description=f"fallback:value:{detector}",
                    )
                )
        if matched:
            continue
        category = _name_category(field_name)
        if category is not None:
            hits.append(
                FallbackHit(
                    field_name=field_name,
                    kind="field_name",
                    detector=category,
                    value_fingerprint=_fp_of_value(key, field_name, value),
                    description=f"fallback:field_name:{category}",
                )
            )
    return hits
