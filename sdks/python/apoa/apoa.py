"""Application-facing APOA facade."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

from .client import APOAClient, create_client
from .types import (
    APOADefinition,
    APOAToken,
    Agent,
    AgentProvider,
    APIAccessConfig,
    AuthorizationResult,
    BrowserSessionConfig,
    ConstraintMap,
    LegalFramework,
    Principal,
    Rule,
    ServiceAuthorization,
    SigningOptions,
    ValidationOptions,
    ValidationResult,
)


class APOA:
    """Application-facing APOA facade.

    This keeps the protocol-level client intact while giving app developers a
    smaller first path: configure once, then use namespaced resources.
    """

    def __init__(
        self,
        private_key: Any | None = None,
        algorithm: str = "EdDSA",
        revocation_store: Any | None = None,
        audit_store: Any | None = None,
        key_resolver: Any | None = None,
    ) -> None:
        self._client = create_client(
            revocation_store=revocation_store,
            audit_store=audit_store,
            key_resolver=key_resolver,
            default_private_key=private_key,
            default_algorithm=algorithm,
        )
        self.tokens = TokensResource(self._client)
        self.authorizations = AuthorizationsResource(self._client)

    def generate_key_pair(self, algorithm: str | None = None) -> tuple:
        """Generate a key pair using the configured/default algorithm."""
        return self._client.generate_key_pair(algorithm)


class TokensResource:
    """Token operations exposed from the application-facing facade."""

    def __init__(self, client: APOAClient) -> None:
        self._client = client

    def create(
        self,
        definition: APOADefinition,
        options: SigningOptions | None = None,
    ) -> APOAToken:
        return self._client.create_token(definition, options)

    def create_grant(
        self,
        *,
        principal: str | Principal,
        agent: str | Agent,
        service: str | None = None,
        scopes: list[str] | None = None,
        services: list[ServiceAuthorization] | None = None,
        constraints: ConstraintMap | None = None,
        rules: list[Rule] | None = None,
        expires: datetime | str | None = None,
        expires_in: str | None = None,
        revocable: bool = True,
        delegatable: bool = False,
        max_delegation_depth: int | None = None,
        metadata: dict[str, str | int | float | bool | None] | None = None,
        access_mode: str | None = None,
        browser_config: BrowserSessionConfig | None = None,
        api_config: APIAccessConfig | None = None,
        agent_provider: AgentProvider | None = None,
        legal: LegalFramework | None = None,
        options: SigningOptions | None = None,
    ) -> APOAToken:
        definition = _normalize_grant_input(
            principal=principal,
            agent=agent,
            service=service,
            scopes=scopes,
            services=services,
            constraints=constraints,
            rules=rules,
            expires=expires,
            expires_in=expires_in,
            revocable=revocable,
            delegatable=delegatable,
            max_delegation_depth=max_delegation_depth,
            metadata=metadata,
            access_mode=access_mode,
            browser_config=browser_config,
            api_config=api_config,
            agent_provider=agent_provider,
            legal=legal,
        )
        return self._client.create_token(definition, options)

    def validate(
        self,
        token: str | APOAToken,
        options: ValidationOptions | None = None,
        **kwargs: Any,
    ) -> ValidationResult:
        if options is not None and kwargs:
            raise ValueError("Pass either options or validation keyword arguments, not both")
        return self._client.validate_token(token, options or ValidationOptions(**kwargs))

    def parse(self, input_str: str, format: str = "json") -> APOADefinition:
        return self._client.parse_definition(input_str, format)


class AuthorizationsResource:
    """Authorization operations exposed from the application-facing facade."""

    def __init__(self, client: APOAClient) -> None:
        self._client = client

    def check(self, token: APOAToken, service: str, action: str) -> AuthorizationResult:
        return self._client.authorize(token, service, action)


def _normalize_grant_input(
    *,
    principal: str | Principal,
    agent: str | Agent,
    service: str | None,
    scopes: list[str] | None,
    services: list[ServiceAuthorization] | None,
    constraints: ConstraintMap | None,
    rules: list[Rule] | None,
    expires: datetime | str | None,
    expires_in: str | None,
    revocable: bool,
    delegatable: bool,
    max_delegation_depth: int | None,
    metadata: dict[str, str | int | float | bool | None] | None,
    access_mode: str | None,
    browser_config: BrowserSessionConfig | None,
    api_config: APIAccessConfig | None,
    agent_provider: AgentProvider | None,
    legal: LegalFramework | None,
) -> APOADefinition:
    errors: list[str] = []
    normalized_principal = _normalize_principal(principal, errors)
    normalized_agent = _normalize_agent(agent, errors)
    normalized_services = _normalize_services(
        service=service,
        scopes=scopes,
        services=services,
        constraints=constraints,
        access_mode=access_mode,
        browser_config=browser_config,
        api_config=api_config,
        errors=errors,
    )
    normalized_expires = _normalize_expires(expires, expires_in, errors)

    if errors or normalized_principal is None or normalized_agent is None or normalized_expires is None:
        raise _invalid_grant_input(errors)

    return APOADefinition(
        principal=normalized_principal,
        agent=normalized_agent,
        services=normalized_services,
        expires=normalized_expires,
        agent_provider=agent_provider,
        rules=rules,
        revocable=revocable,
        delegatable=delegatable,
        max_delegation_depth=max_delegation_depth,
        metadata=metadata,
        legal=legal,
    )


def _normalize_principal(principal: str | Principal, errors: list[str]) -> Principal | None:
    if isinstance(principal, str) and principal.strip():
        return Principal(id=principal.strip())
    if isinstance(principal, Principal) and principal.id:
        return principal
    errors.append("principal is required; pass a DID string or Principal(id=...)")
    return None


def _normalize_agent(agent: str | Agent, errors: list[str]) -> Agent | None:
    if isinstance(agent, str) and agent.strip():
        return Agent(id=agent.strip())
    if isinstance(agent, Agent) and agent.id:
        return agent
    errors.append("agent is required; pass a DID string or Agent(id=...)")
    return None


def _normalize_services(
    *,
    service: str | None,
    scopes: list[str] | None,
    services: list[ServiceAuthorization] | None,
    constraints: ConstraintMap | None,
    access_mode: str | None,
    browser_config: BrowserSessionConfig | None,
    api_config: APIAccessConfig | None,
    errors: list[str],
) -> list[ServiceAuthorization]:
    if services is not None:
        if len(services) == 0:
            errors.append("services must be a non-empty list when provided")
            return []
        return services

    if not service:
        errors.append("service is required unless services is provided")
        return []
    if not scopes:
        errors.append("scopes must be a non-empty list unless services is provided")
        return []

    return [
        ServiceAuthorization(
            service=service,
            scopes=scopes,
            constraints=constraints,
            access_mode=access_mode,
            browser_config=browser_config,
            api_config=api_config,
        )
    ]


def _normalize_expires(
    expires: datetime | str | None,
    expires_in: str | None,
    errors: list[str],
) -> datetime | str | None:
    if expires is not None and expires_in is not None:
        errors.append("pass either expires or expires_in, not both")
        return None
    if expires is not None:
        return expires
    if expires_in is not None:
        return _parse_duration_from_now(expires_in)
    errors.append("expires or expires_in is required")
    return None


def _parse_duration_from_now(duration: str) -> datetime:
    match = re.fullmatch(r"(\d+)([smhd])", duration)
    if not match:
        raise _invalid_grant_input([
            "expires_in must use a clear duration like '15m', '2h', or '30d'"
        ])

    amount = int(match.group(1))
    if amount <= 0:
        raise _invalid_grant_input(["expires_in duration must be a positive integer"])

    units = {
        "s": timedelta(seconds=amount),
        "m": timedelta(minutes=amount),
        "h": timedelta(hours=amount),
        "d": timedelta(days=amount),
    }
    return datetime.now(timezone.utc) + units[match.group(2)]


def _invalid_grant_input(errors: list[str]) -> ValueError:
    return ValueError(
        "\n".join(
            [
                "Invalid APOA grant input.",
                *(f"- {error}" for error in errors),
                "Minimal shape: principal, agent, service, scopes, expires_in",
            ]
        )
    )
