"""Sensitive-field identification and deterministic masking."""
from __future__ import annotations

import re

from app.errors import ClassificationError
from app.masking import fingerprint, partial_mask, stable_token
from app.models import ClassifiedValue, FieldRule

_VALID_STRATEGIES = {"token", "partial", "hash"}


def validate_rule(rule: FieldRule) -> None:
    """Validate static (value-independent) rule shape."""
    if not rule.field_name:
        raise ClassificationError("field_name is required", reason="rule_incomplete")
    if rule.strategy not in _VALID_STRATEGIES:
        raise ClassificationError(
            f"unknown mask strategy: {rule.strategy!r}", reason="invalid_strategy"
        )
    if rule.pattern is not None:
        try:
            re.compile(rule.pattern)
        except re.error:
            raise ClassificationError(
                f"invalid regex for field {rule.field_name!r}",
                reason="malformed_pattern",
            )
    if rule.strategy == "partial":
        if rule.keep_prefix <= 0 and rule.keep_suffix <= 0:
            raise ClassificationError(
                f"partial rule for {rule.field_name!r} must keep a prefix or suffix",
                reason="rule_incomplete",
            )
        if rule.keep_prefix < 0 or rule.keep_suffix < 0:
            raise ClassificationError(
                f"partial rule for {rule.field_name!r} has negative keep length",
                reason="rule_incomplete",
            )


def classify_value(
    field_name: str, raw_value: str, rule: FieldRule, key: bytes
) -> ClassifiedValue:
    """Classify and mask one value; raise ClassificationError with a reason."""
    validate_rule(rule)
    if not isinstance(raw_value, str):
        raise ClassificationError(
            f"value of {field_name!r} must be a string", reason="non_string_value"
        )
    if rule.pattern is not None and re.fullmatch(rule.pattern, raw_value) is None:
        raise ClassificationError(
            f"value of {field_name!r} does not match required pattern",
            reason="value_pattern_mismatch",
        )

    fp = fingerprint(key, field_name, raw_value)
    token = stable_token(key, field_name, raw_value)
    if rule.strategy == "token":
        masked_display = token
    elif rule.strategy == "hash":
        masked_display = f"sha256:{fp}"
    else:
        masked_display = partial_mask(raw_value, rule.keep_prefix, rule.keep_suffix)

    return ClassifiedValue(
        field_name=field_name,
        value_fingerprint=fp,
        token=token,
        masked_display=masked_display,
        rule_description=rule.description or f"rule:{rule.strategy}:{field_name}",
    )


def classify_payload(
    payload: dict, rules: dict[str, FieldRule], key: bytes
) -> tuple[dict, dict[str, ClassifiedValue]]:
    """Mask every declared sensitive field in ``payload``.

    Every field declared by the policy must be present and valid; the payload
    is rejected otherwise — sensitive data is never silently passed through.
    Non-sensitive fields are copied unchanged.
    """
    masked_payload = dict(payload)
    classified: dict[str, ClassifiedValue] = {}
    for field_name, rule in rules.items():
        if field_name not in payload:
            raise ClassificationError(
                f"declared sensitive field {field_name!r} is missing",
                reason="sensitive_field_missing",
            )
        cv = classify_value(field_name, payload[field_name], rule, key)
        classified[field_name] = cv
        masked_payload[field_name] = cv.masked_display
    return masked_payload, classified
