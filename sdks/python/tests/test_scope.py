"""Tests for scope matching and scope checking."""

from apoa import check_scope, match_scope
from apoa.scope import parse_scope


class TestParseScope:
    def test_simple(self):
        assert parse_scope("appointments:read") == ["appointments", "read"]

    def test_single_segment(self):
        assert parse_scope("read") == ["read"]

    def test_three_segments(self):
        assert parse_scope("docs:read:summary") == ["docs", "read", "summary"]

    def test_empty(self):
        assert parse_scope("") == []


class TestMatchScope:
    def test_root_wildcard(self):
        assert match_scope("*", "anything:at:all") is True

    def test_exact_match(self):
        assert match_scope("appointments:read", "appointments:read") is True

    def test_exact_mismatch(self):
        assert match_scope("appointments:read", "appointments:write") is False

    def test_wildcard_at_level(self):
        assert match_scope("appointments:*", "appointments:read") is True
        assert match_scope("appointments:*", "appointments:write") is True

    def test_wildcard_no_cross_level(self):
        assert match_scope("appointments:*", "appointments:read:summary") is False

    def test_different_segment_count(self):
        assert match_scope("a:b", "a:b:c") is False
        assert match_scope("a:b:c", "a:b") is False

    def test_wildcard_at_first_segment(self):
        assert match_scope("*:read", "appointments:read") is True
        assert match_scope("*:read", "documents:read") is True
        assert match_scope("*:read", "documents:write") is False

    def test_multiple_wildcards(self):
        assert match_scope("*:*", "a:b") is True
        assert match_scope("*:*", "a:b:c") is False

    def test_empty_strings_never_match(self):
        # Regression: parse_scope('') returns [], so a length-0 == length-0
        # comparison plus a never-entered loop silently returned True.
        assert match_scope("", "") is False
        assert match_scope("", "anything") is False
        assert match_scope("anything", "") is False

    def test_empty_segments_never_match(self):
        # "foo::bar" splits to ["foo", "", "bar"]. Empty segments must not
        # wildcard-match — they should be rejected outright.
        assert match_scope("foo::bar", "foo:x:bar") is False
        assert match_scope("foo:x:bar", "foo::bar") is False


class TestCheckScope:
    def test_matching_scope(self, basic_token):
        result = check_scope(basic_token, "nationwidemortgage.com", "rate_lock:read")
        assert result.allowed is True
        assert result.matched_scope == "rate_lock:read"

    def test_no_matching_scope(self, basic_token):
        result = check_scope(basic_token, "nationwidemortgage.com", "payments:send")
        assert result.allowed is False

    def test_unknown_service(self, basic_token):
        result = check_scope(basic_token, "unknown.com", "read")
        assert result.allowed is False
        assert "not found" in result.reason

    def test_wildcard_scope(self, multi_service_token):
        result = check_scope(multi_service_token, "service-b.com", "admin:delete")
        assert result.allowed is True
        assert result.matched_scope == "admin:*"
