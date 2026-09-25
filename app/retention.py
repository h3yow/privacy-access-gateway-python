"""Retention-period evaluation and idempotent expiry actions."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(ts: str) -> datetime:
    # Accept the canonical ``...Z`` form and explicit offsets.
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def is_expired(created_at: str, retention_days: int, now: str | None = None) -> bool:
    """A record expires at the first whole second after ``created + retention_days``.

    Boundary semantics: exactly at the cutoff instant the record is *not*
    expired yet (expiry is ``created_at > cutoff``); a fractional second later
    it is.
    """
    if retention_days < 0:
        raise ValueError("retention_days must be non-negative")
    reference = _parse(now) if now is not None else datetime.now(timezone.utc)
    created = _parse(created_at)
    cutoff = created + timedelta(days=retention_days)
    return reference > cutoff
