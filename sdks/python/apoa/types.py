"""All APOA types as dataclasses. Mirrors the TypeScript SDK for cross-SDK compatibility."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable


# --- Core identity types ---


@dataclass
class Principal:
    """The human granting authority."""

    id: str
    name: str | None = None


@dataclass
class Agent:
    """The AI agent receiving authority."""

    id: str
    name: str | None = None
    provider: str | None = None


@dataclass
class AgentProvider:
    """The organization operating the AI agent."""

    name: str
    id: str | None = None
    contact: str | None = None


# --- Access configuration types ---


@dataclass
class BrowserSessionConfig:
    """Configuration for browser-based access via secure credential injection."""

    allowed_urls: list[str]
    credential_vault_ref: str
    allow_form_interaction: bool | None = None
    allow_navigation: bool | None = None
    max_session_duration: int | None = None  # seconds, capped at 86400
    capture_screenshots: bool | None = None
    blocked_actions: list[str] | None = None


@dataclass
class APIAccessConfig:
    """Configuration for API-based access."""

    authorization_server: str | None = None
    oauth_scopes: list[str] | None = None
    use_dpop: bool | None = None


@dataclass
class LegalFramework:
    """The legal model under which this authorization operates."""

    model: str  # "provider-as-agent"
    jurisdiction: str | None = None  # ISO 3166 (e.g., "US-CA", "GB")
    legal_basis: list[str] | None = None
    paired_legal_instrument: bool | None = None


# --- Service and rule types ---


ConstraintValue = bool | int | float | str | list[str]
ConstraintMap = dict[str, ConstraintValue]
MetadataValue = str | int | float | bool | None
TokenMetadata = dict[str, MetadataValue]


@dataclass
class ServiceAuthorization:
    """A service the agent is authorized to access."""

    service: str
    scopes: list[str]
    constraints: ConstraintMap | None = None
    access_mode: str | None = None  # "api" | "browser"
    browser_config: BrowserSessionConfig | None = None
    api_config: APIAccessConfig | None = None


@dataclass
class RuleViolation:
    """Logged when a soft rule is violated."""

    rule_id: str
    token_id: str
    action: str
    service: str
    timestamp: datetime
    details: str | None = None


@dataclass
class Rule:
    """Rules that govern agent behavior."""

    id: str
    description: str
    enforcement: str  # "hard" | "soft"
    on_violation: Callable[[RuleViolation], None] | None = None


# --- Definition and token types ---


@dataclass
class APOADefinition:
    """The full APOA authorization definition."""

    principal: Principal
    agent: Agent
    services: list[ServiceAuthorization]
    expires: datetime | str
    agent_provider: AgentProvider | None = None
    rules: list[Rule] | None = None
    not_before: datetime | str | None = None
    revocable: bool = True
    delegatable: bool = False
    max_delegation_depth: int | None = None
    metadata: TokenMetadata | None = None
    legal: LegalFramework | None = None


@dataclass
class APOAToken:
    """A signed, issued APOA token."""

    jti: str
    definition: APOADefinition
    issued_at: datetime
    signature: str
    issuer: str
    audience: list[str] | None = None
    parent_token: str | None = None
    raw: str = ""


# --- Result types ---


@dataclass
class ScopeCheckResult:
    allowed: bool
    reason: str
    matched_scope: str | None = None
    constraint: str | None = None


@dataclass
class AuthorizationResult:
    authorized: bool
    reason: str | None = None
    checks: dict[str, bool] = field(default_factory=dict)
    violations: list[RuleViolation] | None = None


@dataclass
class ValidationResult:
    valid: bool
    errors: list[str] = field(default_factory=list)
    token: APOAToken | None = None
    warnings: list[str] | None = None


@dataclass
class RevocationRecord:
    token_id: str
    revoked_at: datetime
    revoked_by: str
    reason: str | None = None
    cascaded: list[str] = field(default_factory=list)


@dataclass
class AuditEntry:
    token_id: str
    timestamp: datetime
    action: str
    service: str
    result: str  # "allowed" | "denied" | "escalated"
    details: dict[str, str | int | float | bool | None] | None = None
    url: str | None = None
    screenshot_ref: str | None = None
    access_mode: str | None = None


@dataclass
class AuditQueryOptions:
    from_time: datetime | None = None
    to_time: datetime | None = None
    action: str | None = None
    service: str | None = None
    result: str | None = None
    limit: int | None = None
    offset: int | None = None


@dataclass
class DelegationDefinition:
    """Definition for creating a delegated token."""

    agent: Agent
    services: list[ServiceAuthorization]
    rules: list[Rule] | None = None
    expires: datetime | str | None = None
    metadata: TokenMetadata | None = None


@dataclass
class ChainVerificationResult:
    valid: bool
    depth: int
    errors: list[str] = field(default_factory=list)
    failed_at: int | None = None
    root: APOAToken | None = None
    leaf: APOAToken | None = None


@dataclass
class SigningOptions:
    private_key: Any  # Ed25519PrivateKey or EllipticCurvePrivateKey
    algorithm: str = "EdDSA"
    kid: str | None = None


@dataclass
class ValidationOptions:
    public_key: Any | None = None
    key_resolver: Any | None = None  # object with resolve(kid) -> key | None
    public_key_resolver: Callable[[str], Any] | None = None  # issuer -> key
    check_revocation: bool = True
    revocation_store: Any | None = None  # RevocationStore
    clock_skew: int = 30
