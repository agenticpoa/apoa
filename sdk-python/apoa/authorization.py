"""Full authorization flow: revocation + scope + constraints + rules."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .scope import check_scope
from .types import (
    APOAToken,
    AuditEntry,
    AuthorizationResult,
    RuleViolation,
)


def authorize(
    token: APOAToken,
    service: str,
    action: str,
    revocation_store: Any | None = None,
    audit_store: Any | None = None,
) -> AuthorizationResult:
    """One-stop authorization check: revocation + scope + constraints + rules.

    Enforcement order:
    1. Check revocation (is the token still alive?)
    2. Check scope (is the action in the authorized scope set?)
    3. Check constraints (action segment vs constraint key set to false)
    4. Check hard rules (deny if rule key appears in action)
    5. Check soft rules (log violation + invoke callback + continue)
    """
    # 1. Check revocation
    if revocation_store is not None:
        record = revocation_store.check(token.jti)
        if record:
            return AuthorizationResult(
                authorized=False,
                reason="token has been revoked",
                checks={"revoked": True},
            )

    # 2. Check scope
    scope_result = check_scope(token, service, action)
    if not scope_result.allowed:
        return AuthorizationResult(
            authorized=False,
            reason=scope_result.reason,
            checks={"revoked": False, "scope_allowed": False},
        )

    # 3. Check constraints
    service_auth = next((s for s in token.definition.services if s.service == service), None)
    if service_auth and service_auth.constraints:
        action_segments = action.split(":")
        for key, value in service_auth.constraints.items():
            if value is False and key in action_segments:
                return AuthorizationResult(
                    authorized=False,
                    reason=f"constraint '{key}' is set to false",
                    checks={"revoked": False, "scope_allowed": True, "constraints_passed": False},
                )

    # 4 & 5. Check rules
    rules = token.definition.rules
    violations: list[RuleViolation] = []

    if rules:
        # 4. Hard rules
        for rule in rules:
            if rule.enforcement == "hard":
                rule_key = rule.id[3:] if rule.id.startswith("no-") else rule.id
                if rule_key.lower() in action.lower():
                    return AuthorizationResult(
                        authorized=False,
                        reason=f"hard rule '{rule.id}' violated",
                        checks={
                            "revoked": False,
                            "scope_allowed": True,
                            "constraints_passed": True,
                            "rules_passed": False,
                        },
                    )

        # 5. Soft rules
        for rule in rules:
            if rule.enforcement == "soft":
                violation = RuleViolation(
                    rule_id=rule.id,
                    token_id=token.jti,
                    action=action,
                    service=service,
                    timestamp=datetime.now(timezone.utc),
                    details=rule.description,
                )
                violations.append(violation)

                # Log to audit store if available
                if audit_store is not None:
                    audit_store.append(AuditEntry(
                        token_id=token.jti,
                        timestamp=violation.timestamp,
                        action=action,
                        service=service,
                        result="escalated",
                        details={"ruleId": rule.id, "ruleDescription": rule.description},
                    ))

                # Invoke on_violation callback if provided
                if rule.on_violation:
                    rule.on_violation(violation)

    return AuthorizationResult(
        authorized=True,
        checks={
            "revoked": False,
            "scope_allowed": True,
            "constraints_passed": True,
            "rules_passed": True,
        },
        violations=violations if violations else None,
    )
