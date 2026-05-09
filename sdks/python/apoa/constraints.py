"""Constraint checking against tokens."""

from __future__ import annotations

import json

from .types import APOAToken, ScopeCheckResult


def check_constraint(token: APOAToken, service: str, constraint: str) -> ScopeCheckResult:
    """Check a specific constraint on a service.

    Returns allowed=False if the constraint is explicitly set to false.
    Returns allowed=True if the constraint is not set or is truthy.
    Does NOT interpret numeric ranges or enums -- that's the protocol layer's job.
    """
    service_auth = next((s for s in token.definition.services if s.service == service), None)

    if service_auth is None:
        return ScopeCheckResult(allowed=False, reason=f"service '{service}' not found in token")

    if not service_auth.constraints:
        return ScopeCheckResult(allowed=True, reason=f"no constraints defined for service '{service}'")

    value = service_auth.constraints.get(constraint)

    if value is None:
        return ScopeCheckResult(allowed=True, reason=f"constraint '{constraint}' not defined")

    if value is False:
        return ScopeCheckResult(allowed=False, reason=f"constraint '{constraint}' is set to false", constraint=constraint)

    return ScopeCheckResult(allowed=True, reason=f"constraint '{constraint}' is set to {json.dumps(value)}")
