"""Delegation chains with capability attenuation."""

from __future__ import annotations

from typing import Any

from .errors import AttenuationViolationError
from .scope import match_scope
from .token import create_token
from .types import (
    APOADefinition,
    APOAToken,
    ChainVerificationResult,
    DelegationDefinition,
    ServiceAuthorization,
    SigningOptions,
)
from .utils import is_expired


def delegate(
    parent_token: APOAToken,
    child_def: DelegationDefinition,
    options: SigningOptions,
) -> APOAToken:
    """Create a delegated (attenuated) token from a parent token.

    - Inherits principal from parent (cannot be overridden)
    - Sets parent_token on child to parent's jti
    - Enforces attenuation rules
    - Additional rules can only be added, not removed
    """
    current_depth = _count_depth(parent_token)
    _verify_attenuation(parent_token, child_def, current_depth)

    parent_def = parent_token.definition

    # Merge rules: parent rules + child-only additions
    parent_rules = parent_def.rules or []
    parent_rule_ids = {r.id for r in parent_rules}
    child_extra_rules = [r for r in (child_def.rules or []) if r.id not in parent_rule_ids]
    merged_rules = [*parent_rules, *child_extra_rules]

    # Track delegation depth
    child_depth = current_depth + 1
    child_metadata = {**(child_def.metadata or {}), "_delegationDepth": child_depth}

    # Inherit parent's false constraints into child services.
    # If parent says { signing: false }, the child MUST carry that constraint
    # even if the delegation definition omits it. Otherwise the child's
    # authorize() would skip the constraint check entirely (privilege escalation).
    inherited_services = []
    for child_svc in child_def.services:
        parent_svc = next((s for s in parent_def.services if s.service == child_svc.service), None)
        if parent_svc and parent_svc.constraints:
            inherited = {k: v for k, v in parent_svc.constraints.items() if v is False}
            if inherited:
                merged_constraints = {**inherited, **(child_svc.constraints or {})}
                inherited_services.append(ServiceAuthorization(
                    service=child_svc.service,
                    scopes=child_svc.scopes,
                    constraints=merged_constraints,
                    access_mode=child_svc.access_mode,
                    browser_config=child_svc.browser_config,
                    api_config=child_svc.api_config,
                ))
            else:
                inherited_services.append(child_svc)
        else:
            inherited_services.append(child_svc)

    full_definition = APOADefinition(
        principal=parent_def.principal,
        agent=child_def.agent,
        agent_provider=parent_def.agent_provider,
        services=inherited_services,
        rules=merged_rules if merged_rules else None,
        expires=child_def.expires or parent_def.expires,
        revocable=parent_def.revocable,
        delegatable=parent_def.delegatable,
        max_delegation_depth=parent_def.max_delegation_depth,
        metadata=child_metadata,
        legal=parent_def.legal,
    )

    # Pass parent_token_id so it's included in the signed JWT payload
    child_token = create_token(full_definition, options, parent_token_id=parent_token.jti)
    return child_token


def verify_chain(
    chain: list[APOAToken],
    revocation_store: Any | None = None,
) -> ChainVerificationResult:
    """Verify a full delegation chain.

    Checks structural integrity (attenuation, expiry, revocation, parent links)
    but does NOT verify cryptographic signatures. Each token MUST be validated
    via validate_token() before passing to verify_chain().
    """
    errors: list[str] = []
    failed_at: int | None = None

    if not chain:
        return ChainVerificationResult(valid=False, depth=0, errors=["Chain is empty"])

    if len(chain) == 1:
        _check_token_validity(chain[0], 0, errors, revocation_store)
        return ChainVerificationResult(
            valid=len(errors) == 0,
            depth=0,
            errors=errors,
            failed_at=0 if errors else None,
            root=chain[0],
            leaf=chain[0],
        )

    for i, token in enumerate(chain):
        errors_before = len(errors)

        _check_token_validity(token, i, errors, revocation_store)

        if i > 0:
            parent = chain[i - 1]
            _check_attenuation(parent, token, i, errors)

            if token.parent_token != parent.jti:
                errors.append(
                    f"Chain link {i}: parentToken '{token.parent_token}' does not match parent jti '{parent.jti}'"
                )

        if failed_at is None and len(errors) > errors_before:
            failed_at = i

    return ChainVerificationResult(
        valid=len(errors) == 0,
        depth=len(chain) - 1,
        errors=errors,
        failed_at=failed_at,
        root=chain[0],
        leaf=chain[-1],
    )


# --- Internal helpers ---


def _count_depth(token: APOAToken) -> int:
    stored = (token.definition.metadata or {}).get("_delegationDepth")
    if isinstance(stored, int):
        return stored
    return 1 if token.parent_token else 0


def _verify_attenuation(
    parent: APOAToken,
    child: DelegationDefinition,
    current_depth: int,
) -> None:
    """Verify attenuation rules. Raises AttenuationViolationError on violation."""
    parent_def = parent.definition
    parent_scopes = [s for svc in parent_def.services for s in svc.scopes]
    child_scopes = [s for svc in child.services for s in svc.scopes]

    # Delegation allowed?
    if parent_def.delegatable is False:
        raise AttenuationViolationError("Parent token does not allow delegation", parent_scopes, child_scopes)

    # Depth limit
    if parent_def.max_delegation_depth is not None:
        if current_depth >= parent_def.max_delegation_depth:
            raise AttenuationViolationError(
                f"Delegation depth {current_depth + 1} exceeds maxDelegationDepth {parent_def.max_delegation_depth}",
                parent_scopes,
                child_scopes,
            )

    # Expiration: child <= parent
    if child.expires is not None:
        from .utils import _to_datetime

        child_exp = _to_datetime(child.expires).timestamp()
        parent_exp = _to_datetime(parent_def.expires).timestamp()
        if child_exp > parent_exp:
            raise AttenuationViolationError("Child token expiration exceeds parent expiration", parent_scopes, child_scopes)

    # Per-service checks
    for child_svc in child.services:
        parent_svc = next((s for s in parent_def.services if s.service == child_svc.service), None)
        if parent_svc is None:
            raise AttenuationViolationError(
                f"Child requests service '{child_svc.service}' not in parent token",
                parent_scopes,
                child_scopes,
            )
        _verify_scope_subset(parent_svc, child_svc)
        _verify_constraints_not_relaxed(parent_svc, child_svc)

    # Rules: child can only add, not remove
    if parent_def.rules:
        parent_rule_ids = [r.id for r in parent_def.rules]
        child_rule_ids = {r.id for r in (child.rules or [])}
        for pid in parent_rule_ids:
            if pid not in child_rule_ids:
                raise AttenuationViolationError(
                    f"Child removes parent rule '{pid}'. Rules can only be added, not removed.",
                    [],
                    [],
                )


def _verify_scope_subset(parent: ServiceAuthorization, child: ServiceAuthorization) -> None:
    parent_scopes = parent.scopes
    for child_scope in child.scopes:
        if not any(match_scope(ps, child_scope) for ps in parent_scopes):
            raise AttenuationViolationError(
                f"Child scope '{child_scope}' on service '{child.service}' is not covered by parent scopes [{', '.join(parent_scopes)}]",
                parent_scopes,
                child.scopes,
            )


def _verify_constraints_not_relaxed(parent: ServiceAuthorization, child: ServiceAuthorization) -> None:
    if not parent.constraints:
        return
    for key, parent_value in parent.constraints.items():
        if parent_value is False:
            child_value = (child.constraints or {}).get(key)
            if child_value is True:
                raise AttenuationViolationError(
                    f"Child relaxes constraint '{key}' on service '{child.service}' (parent: false, child: true)",
                    parent.scopes,
                    child.scopes,
                )


def _check_token_validity(
    token: APOAToken,
    index: int,
    errors: list[str],
    store: Any | None,
) -> None:
    # Expiration (strict, no clock skew)
    if is_expired(token.definition.expires, 0):
        errors.append(f"Chain link {index}: token '{token.jti}' has expired")

    if store is not None:
        record = store.check(token.jti)
        if record:
            errors.append(f"Chain link {index}: token '{token.jti}' has been revoked")


def _check_attenuation(
    parent: APOAToken,
    child: APOAToken,
    index: int,
    errors: list[str],
) -> None:
    for child_svc in child.definition.services:
        parent_svc = next((s for s in parent.definition.services if s.service == child_svc.service), None)
        if parent_svc is None:
            errors.append(f"Chain link {index}: service '{child_svc.service}' not in parent token")
            continue
        for child_scope in child_svc.scopes:
            if not any(match_scope(ps, child_scope) for ps in parent_svc.scopes):
                errors.append(f"Chain link {index}: scope '{child_scope}' on '{child_svc.service}' not covered by parent")

    # Child expiration <= parent
    from .utils import _to_datetime

    child_exp = _to_datetime(child.definition.expires).timestamp()
    parent_exp = _to_datetime(parent.definition.expires).timestamp()
    if child_exp > parent_exp:
        errors.append(f"Chain link {index}: child expiration exceeds parent expiration")
