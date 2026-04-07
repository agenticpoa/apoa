"""Tests for time utilities."""

from datetime import datetime, timezone, timedelta
from apoa import is_expired, is_before_not_before


class TestIsExpired:
    def test_not_expired(self):
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        assert is_expired(future) is False

    def test_expired(self):
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        assert is_expired(past) is True

    def test_clock_skew_extends_validity(self):
        # Expired 10 seconds ago, but 30s clock skew should still be valid
        just_expired = datetime.now(timezone.utc) - timedelta(seconds=10)
        assert is_expired(just_expired, clock_skew=30) is False

    def test_string_date(self):
        assert is_expired("2020-01-01T00:00:00Z") is True
        assert is_expired("2099-01-01T00:00:00Z") is False

    def test_max_clock_skew(self):
        # Clock skew capped at 300s
        expired_4_min_ago = datetime.now(timezone.utc) - timedelta(seconds=240)
        assert is_expired(expired_4_min_ago, clock_skew=999) is False  # capped at 300


class TestIsBeforeNotBefore:
    def test_after_not_before(self):
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        assert is_before_not_before(past) is False

    def test_before_not_before(self):
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        assert is_before_not_before(future) is True

    def test_clock_skew(self):
        # Not-before is 10 seconds from now, but 30s skew means it's OK
        near_future = datetime.now(timezone.utc) + timedelta(seconds=10)
        assert is_before_not_before(near_future, clock_skew=30) is False
