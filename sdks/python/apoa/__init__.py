"""APOA SDK -- Agentic Power of Attorney for Python."""

# Client
from .client import APOAClient, create_client

# Token lifecycle
from .token import create_token, parse_definition, validate_token

# Authorization
from .authorization import authorize
from .constraints import check_constraint
from .scope import check_scope, match_scope

# Delegation
from .delegation import delegate, verify_chain

# Revocation
from .revocation import (
    MemoryRevocationStore,
    RevocationStore,
    cascade_revoke,
    is_revoked,
    revoke,
)

# Audit
from .audit import (
    AuditStore,
    MemoryAuditStore,
    get_audit_trail,
    get_audit_trail_by_service,
    log_action,
)

# Crypto
from .crypto import generate_key_pair

# Time utilities
from .utils import is_before_not_before, is_expired

# Types
from .types import (
    APIAccessConfig,
    APOADefinition,
    APOAToken,
    Agent,
    AgentProvider,
    AuditEntry,
    AuditQueryOptions,
    AuthorizationResult,
    BrowserSessionConfig,
    ChainVerificationResult,
    DelegationDefinition,
    LegalFramework,
    Principal,
    RevocationRecord,
    Rule,
    RuleViolation,
    ScopeCheckResult,
    ServiceAuthorization,
    SigningOptions,
    ValidationOptions,
    ValidationResult,
)

# Errors
from .errors import (
    APOAError,
    AttenuationViolationError,
    ChainVerificationError,
    DefinitionValidationError,
    MetadataValidationError,
    RevocationError,
    RuleEnforcementError,
    ScopeViolationError,
    TokenExpiredError,
)

__all__ = [
    # Client
    "APOAClient",
    "create_client",
    # Token lifecycle
    "create_token",
    "validate_token",
    "parse_definition",
    # Authorization
    "authorize",
    "check_scope",
    "match_scope",
    "check_constraint",
    # Delegation
    "delegate",
    "verify_chain",
    # Revocation
    "revoke",
    "is_revoked",
    "cascade_revoke",
    "RevocationStore",
    "MemoryRevocationStore",
    # Audit
    "log_action",
    "get_audit_trail",
    "get_audit_trail_by_service",
    "AuditStore",
    "MemoryAuditStore",
    # Crypto
    "generate_key_pair",
    # Time
    "is_expired",
    "is_before_not_before",
    # Types
    "Principal",
    "Agent",
    "AgentProvider",
    "LegalFramework",
    "BrowserSessionConfig",
    "APIAccessConfig",
    "ServiceAuthorization",
    "Rule",
    "RuleViolation",
    "APOADefinition",
    "APOAToken",
    "ScopeCheckResult",
    "AuthorizationResult",
    "ValidationResult",
    "RevocationRecord",
    "AuditEntry",
    "AuditQueryOptions",
    "DelegationDefinition",
    "ChainVerificationResult",
    "SigningOptions",
    "ValidationOptions",
    # Errors
    "APOAError",
    "TokenExpiredError",
    "ScopeViolationError",
    "AttenuationViolationError",
    "RevocationError",
    "ChainVerificationError",
    "MetadataValidationError",
    "RuleEnforcementError",
    "DefinitionValidationError",
]
