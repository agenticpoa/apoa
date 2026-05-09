"""APOAClient -- configured facade that wires up stores and keys."""

from __future__ import annotations

from typing import Any

from .audit import MemoryAuditStore, get_audit_trail, get_audit_trail_by_service, log_action
from .authorization import authorize
from .constraints import check_constraint
from .crypto import generate_key_pair
from .delegation import delegate, verify_chain
from .revocation import (
    MemoryRevocationStore,
    cascade_revoke,
    is_revoked,
    revoke,
)
from .scope import check_scope
from .token import create_token, parse_definition, validate_token
from .types import (
    APOADefinition,
    APOAToken,
    AuditEntry,
    AuditQueryOptions,
    AuthorizationResult,
    ChainVerificationResult,
    DelegationDefinition,
    RevocationRecord,
    ScopeCheckResult,
    SigningOptions,
    ValidationOptions,
    ValidationResult,
)


class APOAClient:
    """Configured APOA client with wired-up stores and default signing options."""

    def __init__(
        self,
        revocation_store: Any | None = None,
        audit_store: Any | None = None,
        key_resolver: Any | None = None,
        default_private_key: Any | None = None,
        default_algorithm: str = "EdDSA",
    ) -> None:
        self._revocation_store = revocation_store or MemoryRevocationStore()
        self._audit_store = audit_store or MemoryAuditStore()
        self._key_resolver = key_resolver
        self._default_private_key = default_private_key
        self._default_algorithm = default_algorithm

    def _signing_options(self, options: SigningOptions | None = None) -> SigningOptions:
        if options:
            return options
        if self._default_private_key is None:
            raise ValueError("No signing options provided and no default_private_key configured")
        return SigningOptions(private_key=self._default_private_key, algorithm=self._default_algorithm)

    def create_token(self, definition: APOADefinition, options: SigningOptions | None = None) -> APOAToken:
        return create_token(definition, self._signing_options(options))

    def validate_token(self, token: str | APOAToken, options: ValidationOptions | None = None) -> ValidationResult:
        opts = options or ValidationOptions()
        # Wire up defaults
        if opts.key_resolver is None and self._key_resolver is not None:
            opts.key_resolver = self._key_resolver
        if opts.revocation_store is None:
            opts.revocation_store = self._revocation_store
        if not opts.check_revocation:
            opts.check_revocation = True
        return validate_token(token, opts)

    def check_scope(self, token: APOAToken, service: str, action: str) -> ScopeCheckResult:
        return check_scope(token, service, action)

    def check_constraint(self, token: APOAToken, service: str, constraint: str) -> ScopeCheckResult:
        return check_constraint(token, service, constraint)

    def authorize(self, token: APOAToken, service: str, action: str) -> AuthorizationResult:
        return authorize(token, service, action, self._revocation_store, self._audit_store)

    def delegate(self, parent_token: APOAToken, child_def: DelegationDefinition, options: SigningOptions | None = None) -> APOAToken:
        return delegate(parent_token, child_def, self._signing_options(options))

    def verify_chain(self, chain: list[APOAToken]) -> ChainVerificationResult:
        return verify_chain(chain, self._revocation_store)

    def revoke(self, token_id: str, revoked_by: str, reason: str | None = None) -> RevocationRecord:
        return revoke(token_id, revoked_by, reason, self._revocation_store)

    def is_revoked(self, token_id: str) -> bool:
        return is_revoked(token_id, self._revocation_store)

    def cascade_revoke(self, parent_token_id: str, child_token_ids: list[str], revoked_by: str, reason: str | None = None) -> RevocationRecord:
        return cascade_revoke(parent_token_id, child_token_ids, revoked_by, reason, self._revocation_store)

    def log_action(self, token_id: str, action: str, service: str, result: str, **details: str | int | float | bool | None) -> None:
        log_action(token_id, action, service, result, self._audit_store, **details)

    def get_audit_trail(self, token_id: str, options: AuditQueryOptions | None = None) -> list[AuditEntry]:
        return get_audit_trail(token_id, options, self._audit_store)

    def get_audit_trail_by_service(self, service: str, options: AuditQueryOptions | None = None) -> list[AuditEntry]:
        return get_audit_trail_by_service(service, options, self._audit_store)

    def generate_key_pair(self, algorithm: str | None = None) -> tuple:
        return generate_key_pair(algorithm or self._default_algorithm)

    def parse_definition(self, input_str: str, format: str = "json") -> APOADefinition:
        return parse_definition(input_str, format)


def create_client(
    revocation_store: Any | None = None,
    audit_store: Any | None = None,
    key_resolver: Any | None = None,
    default_private_key: Any | None = None,
    default_algorithm: str = "EdDSA",
) -> APOAClient:
    """Create a configured APOA client.

    Defaults to MemoryRevocationStore + MemoryAuditStore for zero-config dev/testing.
    """
    return APOAClient(
        revocation_store=revocation_store,
        audit_store=audit_store,
        key_resolver=key_resolver,
        default_private_key=default_private_key,
        default_algorithm=default_algorithm,
    )
