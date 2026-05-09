"""Time helpers for token expiration and not-before checks."""

from __future__ import annotations

from datetime import datetime, timezone

DEFAULT_CLOCK_SKEW = 30
MAX_CLOCK_SKEW = 300


def _normalize_skew(clock_skew: int | None) -> int:
    if clock_skew is None:
        return DEFAULT_CLOCK_SKEW
    if clock_skew < 0:
        return 0
    return min(clock_skew, MAX_CLOCK_SKEW)


def _to_datetime(value: datetime | str) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def is_expired(
    expires: datetime | str,
    clock_skew: int | None = None,
    now: datetime | None = None,
) -> bool:
    """Check if a token has expired, accounting for clock skew."""
    expires_dt = _to_datetime(expires)
    skew = _normalize_skew(clock_skew)
    current = now or datetime.now(timezone.utc)
    return current.timestamp() > expires_dt.timestamp() + skew


def is_before_not_before(
    not_before: datetime | str,
    clock_skew: int | None = None,
    now: datetime | None = None,
) -> bool:
    """Check if it's too early to use this token, accounting for clock skew."""
    nb_dt = _to_datetime(not_before)
    skew = _normalize_skew(clock_skew)
    current = now or datetime.now(timezone.utc)
    return current.timestamp() < nb_dt.timestamp() - skew
