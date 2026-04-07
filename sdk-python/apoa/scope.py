"""Scope pattern matching and scope checking against tokens."""

from __future__ import annotations

from .types import APOAToken, ScopeCheckResult


def parse_scope(scope: str) -> list[str]:
    """Parse a scope string into segments. e.g., 'appointments:read' -> ['appointments', 'read']"""
    if not scope:
        return []
    return scope.split(":")


def match_scope(pattern: str, requested: str) -> bool:
    """Check if a scope pattern matches a requested scope.

    Rules:
    1. Root wildcard "*" matches everything
    2. Exact match: "appointments:read" matches "appointments:read"
    3. Wildcard at level: "appointments:*" matches "appointments:read"
       but NOT "appointments:read:summary" (wildcards don't cross levels)
    4. Segment-by-segment matching with wildcard support at each level
    """
    if pattern == "*":
        return True

    pattern_parts = parse_scope(pattern)
    requested_parts = parse_scope(requested)

    # Different number of segments -- no match
    if len(pattern_parts) != len(requested_parts):
        return False

    for pp, rp in zip(pattern_parts, requested_parts):
        if pp == "*":
            continue
        if pp != rp:
            return False

    return True


def check_scope(token: APOAToken, service: str, action: str) -> ScopeCheckResult:
    """Check if an action is allowed under a token's scopes for a given service."""
    service_auth = next((s for s in token.definition.services if s.service == service), None)

    if service_auth is None:
        return ScopeCheckResult(allowed=False, reason=f"service '{service}' not found in token")

    for scope in service_auth.scopes:
        if match_scope(scope, action):
            return ScopeCheckResult(allowed=True, reason=f"matched scope '{scope}'", matched_scope=scope)

    return ScopeCheckResult(allowed=False, reason=f"scope '{action}' not in authorized scopes")
