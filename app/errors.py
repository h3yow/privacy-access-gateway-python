"""Domain error types with distinguishable rejection reasons."""
from __future__ import annotations


class GatewayError(Exception):
    """Base error. ``reason`` is a stable machine-readable code."""

    status_code: int = 400
    reason: str = "gateway_error"

    def __init__(
        self,
        message: str = "",
        *,
        reason: str | None = None,
        summary: dict | None = None,
        evidence: dict | None = None,
    ) -> None:
        super().__init__(message or self.reason)
        if reason is not None:
            self.reason = reason
        # Audit-safe attachments (field names / fingerprints only, never raw
        # sensitive values); populated by the classification layer.
        self.summary = summary
        self.evidence = evidence


class ClassificationError(GatewayError):
    """Raised when a sensitive value cannot be safely classified/masked."""

    status_code = 422


class AccessDeniedError(GatewayError):
    """Raised when a subject is not allowed to access a field or row."""

    status_code = 403


class PolicyError(GatewayError):
    """Raised for malformed policies or missing policy versions."""

    status_code = 422


class RetentionError(GatewayError):
    """Raised when a retention request is invalid."""

    status_code = 422
