"""APOA error hierarchy. Every error carries a `code` string for programmatic handling."""

from __future__ import annotations

from datetime import datetime


class APOAError(Exception):
    """Base error class for all APOA errors."""

    code: str

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


class TokenExpiredError(APOAError):
    expired_at: datetime

    def __init__(self, message: str, expired_at: datetime) -> None:
        super().__init__(message, "TOKEN_EXPIRED")
        self.expired_at = expired_at


class ScopeViolationError(APOAError):
    requested_scope: str
    available_scopes: list[str]

    def __init__(self, message: str, requested_scope: str, available_scopes: list[str]) -> None:
        super().__init__(message, "SCOPE_VIOLATION")
        self.requested_scope = requested_scope
        self.available_scopes = available_scopes


class AttenuationViolationError(APOAError):
    parent_scope: list[str]
    requested_scope: list[str]

    def __init__(self, message: str, parent_scope: list[str], requested_scope: list[str]) -> None:
        super().__init__(message, "ATTENUATION_VIOLATION")
        self.parent_scope = parent_scope
        self.requested_scope = requested_scope


class RevocationError(APOAError):
    revoked_at: datetime
    revoked_by: str

    def __init__(self, message: str, revoked_at: datetime, revoked_by: str) -> None:
        super().__init__(message, "TOKEN_REVOKED")
        self.revoked_at = revoked_at
        self.revoked_by = revoked_by


class ChainVerificationError(APOAError):
    failed_at: int
    reason: str

    def __init__(self, message: str, failed_at: int, reason: str) -> None:
        super().__init__(message, "CHAIN_INVALID")
        self.failed_at = failed_at
        self.reason = reason


class MetadataValidationError(APOAError):
    field: str | None

    def __init__(self, message: str, field: str | None = None) -> None:
        super().__init__(message, "METADATA_INVALID")
        self.field = field


class RuleEnforcementError(APOAError):
    rule_id: str

    def __init__(self, message: str, rule_id: str) -> None:
        super().__init__(message, "RULE_VIOLATED")
        self.rule_id = rule_id


class DefinitionValidationError(APOAError):
    errors: list[str]
    warnings: list[str]

    def __init__(self, message: str, errors: list[str], warnings: list[str] | None = None) -> None:
        super().__init__(message, "DEFINITION_INVALID")
        self.errors = errors
        self.warnings = warnings or []
