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
    1. Empty pattern or empty requested string never matches (a vacuous match
       on '' would let a token with scopes=[''] authorize an empty action).
    2. Root wildcard "*" matches everything (non-empty).
    3. Exact match: "appointments:read" matches "appointments:read"
    4. Wildcard at level: "appointments:*" matches "appointments:read"
       but NOT "appointments:read:summary" (wildcards don't cross levels)
    5. Segment-by-segment matching with wildcard support at each level
    """
    if not pattern or not requested:
        return False

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
        if not pp or not rp:
            return False
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
