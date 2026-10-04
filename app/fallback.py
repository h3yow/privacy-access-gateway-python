"""Fallback sensitive-data detection for content that tenant rules never declared.

Declared rules (see ``app/classifier.py``) only cover fields the tenant knows
about. This module is the safety net underneath:

* field *names* that obviously denote an identifier (id_card, cert_no,
  passport, 身份证, 护照 ...) even though the tenant never declared them;
* sensitive content *embedded* in free-text string values of otherwise
  ordinary fields (email addresses, CN mobile numbers, CN national id
  numbers).

The module emits only safe evidence: field names, detector ids, match
position/length and HMAC fingerprints. Raw values and matched substrings are
never returned, logged or persisted.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from app.masking import fingerprint

# Stable machine-readable rejection reasons (kept distinct from the
# declared-field reasons in classifier.py: sensitive_field_missing /
# value_pattern_mismatch / non_string_value / invalid_payload).
REASON_UNDECLARED_FIELD_NAME = "undeclared_sensitive_field_name"
REASON_UNDECLARED_CONTENT = "undeclared_sensitive_content"

# Detector ids used in audit evidence.
DETECTOR_FIELD_NAME = "field_name.identifier"
DETECTOR_EMAIL = "content.email"
DETECTOR_MOBILE = "content.cn_mobile"
DETECTOR_ID_CN = "content.cn_id_card"

# Separate each *kind* of detector so equal raw strings in different
# detection contexts never share an identity.
_FP_DOMAIN = "__fallback__"


@dataclass(frozen=True)
class FallbackHit:
    """One fallback detection; every attribute is safe to log/persist."""

    field_name: str
    detector: str
    reason: str
    match_start: int | None
    match_length: int | None
    fingerprint: str


# ---------------------------------------------------------------------------
# field-name heuristics
# ---------------------------------------------------------------------------

# Identifier-word vocabulary. Names are split into lowercase word tokens so
# that "id_card" cannot match a benign word containing the letter pair "id".
_NAME_TOKEN_WORDS = frozenset(
    {
        "id",
        "identity",
        "identifier",
        "idcard",
        "idno",
        "idnumber",
        "cert",
        "certificate",
        "certno",
        "passport",
        "ssn",
        "sin",
        "drivers",
        "license",
        "licence",
        "identitycard",
        "nationalid",
        "residentid",
        "uid",
        "aem",  # avoid accidental collisions; harmless if unused
    }
)

# Bigrams that only make sense for an identifier-like field.
_NAME_TOKEN_BIGRAMS = frozenset(
    {
        ("id", "card"),
        ("id", "no"),
        ("id", "number"),
        ("identity", "card"),
        ("identity", "number"),
        ("identity", "no"),
        ("cert", "no"),
        ("cert", "number"),
        ("certificate", "no"),
        ("certificate", "number"),
        ("passport", "no"),
        ("passport", "number"),
        ("drivers", "license"),
        ("driver", "license"),
        ("social", "security"),
        ("resident", "id"),
        ("national", "id"),
        ("id", "code"),
        ("identity", "code"),
    }
)

# Chinese identifier vocabulary.
_NAME_ZH_WORDS = ("身份证", "证件号", "护照", "社会保障号", "社保号", "驾驶证")

_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")


def _name_tokens(field_name: str) -> list[str]:
    tokens = [t for t in _TOKEN_SPLIT_RE.split(field_name.lower()) if t]
    # Collapse common concatenations (e.g. "idcard" -> ["idcard", "id", "card"])
    # so bigram matching works without a full tokenizer.
    expanded = list(tokens)
    for joined in ("idcard", "idno", "certno", "identitycard", "nationalid"):
        if joined in tokens:
            head = joined[:2] if joined.startswith("id") else joined
            if joined == "idcard":
                expanded.extend(["id", "card"])
            elif joined == "idno":
                expanded.extend(["id", "no"])
            elif joined == "certno":
                expanded.extend(["cert", "no"])
            elif joined == "identitycard":
                expanded.extend(["identity", "card"])
            elif joined == "nationalid":
                expanded.extend(["national", "id"])
    return expanded


def _suspicious_name(field_name: str) -> bool:
    if any(zh in field_name for zh in _NAME_ZH_WORDS):
        return True
    tokens = _name_tokens(field_name)
    token_set = set(tokens)
    if token_set & {"passport", "ssn", "sin"}:
        return True
    if any(w in tokens for w in ("idcard", "idno", "idnumber", "certno",
                                 "identitycard", "nationalid", "residentid")):
        return True
    if "id" in token_set:
        # A lone "id" is ambiguous (order_id, item_id). Require either another
        # identifier token ("id"+"card") or an identifier-y adjacent word.
        for i, tok in enumerate(tokens):
            if tok != "id":
                continue
            if i > 0 and tuple(tokens[i - 1:i + 1]) in _NAME_TOKEN_BIGRAMS:
                return True
            if i + 1 < len(tokens) and tuple(tokens[i:i + 2]) in _NAME_TOKEN_BIGRAMS:
                return True
    for i in range(len(tokens) - 1):
        if tuple(tokens[i:i + 2]) in _NAME_TOKEN_BIGRAMS:
            return True
    return False


# ---------------------------------------------------------------------------
# embedded-content detectors
# ---------------------------------------------------------------------------

# Local-part/domain kept deliberately simple; matches must not span spaces.
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# 11-digit CN mobile number; must be preceded/followed by a non-digit so that
# digit runs longer than 11 cannot trigger a partial match.
_MOBILE_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")

# 15/18-digit CN national id (18-digit may end with X). Boundaries matter.
_ID_CN_18_RE = re.compile(r"(?<![0-9X])\d{17}[0-9X](?![0-9X])")
_ID_CN_15_RE = re.compile(r"(?<!\d)\d{15}(?!\d)")

_CONTENT_DETECTORS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (DETECTOR_EMAIL, _EMAIL_RE),
    (DETECTOR_MOBILE, _MOBILE_RE),
    (DETECTOR_ID_CN, _ID_CN_18_RE),
    (DETECTOR_ID_CN, _ID_CN_15_RE),
)


def _content_hits(key: bytes, field_name: str, value: str) -> list[FallbackHit]:
    hits: list[FallbackHit] = []
    seen_spans: set[tuple[str, int, int]] = set()
    for detector, pattern in _CONTENT_DETECTORS:
        for match in pattern.finditer(value):
            start, end = match.start(), match.end()
            span = (detector, start, end)
            if span in seen_spans:
                continue
            seen_spans.add(span)
            matched = value[start:end]
            # Fingerprint only — the matched substring itself is never carried.
            fp = fingerprint(key, f"{_FP_DOMAIN}:{detector}", matched)
            hits.append(
                FallbackHit(
                    field_name=field_name,
                    detector=detector,
                    reason=REASON_UNDECLARED_CONTENT,
                    match_start=start,
                    match_length=end - start,
                    fingerprint=fp,
                )
            )
    return hits


def _name_hit(key: bytes, field_name: str) -> FallbackHit:
    fp = fingerprint(key, f"{_FP_DOMAIN}:{DETECTOR_FIELD_NAME}", field_name)
    return FallbackHit(
        field_name=field_name,
        detector=DETECTOR_FIELD_NAME,
        reason=REASON_UNDECLARED_FIELD_NAME,
        match_start=None,
        match_length=None,
        fingerprint=fp,
    )


def detect_fallback_sensitive(
    payload: dict, *, declared_fields: set[str], key: bytes
) -> list[FallbackHit]:
    """Scan undeclared fields for suspicious names or embedded sensitive content.

    Fields declared by the tenant policy are skipped entirely: their values
    are already handled (and pattern-checked) by the declared classifier.
    A hit on the *name* is reported before scanning that field's content.
    Returns a deterministically ordered list (field_name, detector, start).
    """
    hits: list[FallbackHit] = []
    for field_name, value in payload.items():
        if field_name in declared_fields:
            continue
        if not isinstance(field_name, str):
            continue
        if _suspicious_name(field_name):
            hits.append(_name_hit(key, field_name))
            continue
        if isinstance(value, str):
            hits.extend(_content_hits(key, field_name, value))
    hits.sort(
        key=lambda h: (h.field_name, h.detector, h.match_start or -1, h.match_length or -1)
    )
    return hits


def hits_evidence(hits: list[FallbackHit]) -> dict:
    """Render hits into an audit-safe evidence structure (no raw values)."""
    return {
        "stage": "fallback_detection",
        "hits": [
            {
                "field": h.field_name,
                "detector": h.detector,
                "reason": h.reason,
                "match_start": h.match_start,
                "match_length": h.match_length,
                "fingerprint": h.fingerprint,
            }
            for h in hits
        ],
    }
