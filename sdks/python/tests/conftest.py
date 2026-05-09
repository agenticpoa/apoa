"""Shared test fixtures."""

import pytest
from apoa import (
    APOADefinition,
    APOAToken,
    Agent,
    AgentProvider,
    BrowserSessionConfig,
    LegalFramework,
    Principal,
    Rule,
    ServiceAuthorization,
    SigningOptions,
    create_token,
    generate_key_pair,
)


@pytest.fixture
def ed25519_keys():
    return generate_key_pair("EdDSA")


@pytest.fixture
def es256_keys():
    return generate_key_pair("ES256")


@pytest.fixture
def signing_options(ed25519_keys):
    return SigningOptions(private_key=ed25519_keys[0])


@pytest.fixture
def basic_definition():
    return APOADefinition(
        principal=Principal(id="did:apoa:alice", name="Alice"),
        agent=Agent(id="did:apoa:homebot", name="HomeBot Pro"),
        services=[
            ServiceAuthorization(
                service="nationwidemortgage.com",
                scopes=["rate_lock:read", "documents:read", "timeline:read"],
                constraints={"signing": False, "data_export": False},
                access_mode="browser",
                browser_config=BrowserSessionConfig(
                    allowed_urls=["https://portal.nationwidemortgage.com/*"],
                    credential_vault_ref="1password://vault/mortgage-portal",
                ),
            ),
        ],
        rules=[
            Rule(id="no-signing", description="Never sign anything", enforcement="hard"),
            Rule(id="deadline-alert", description="Alert if deadline within 48 hours", enforcement="soft"),
        ],
        expires="2026-09-01T00:00:00Z",
        agent_provider=AgentProvider(name="HomeBot Inc.", contact="support@homebot.ai"),
        legal=LegalFramework(model="provider-as-agent", jurisdiction="US-CA", legal_basis=["UETA-14"]),
    )


@pytest.fixture
def basic_token(basic_definition, signing_options):
    return create_token(basic_definition, signing_options)


@pytest.fixture
def multi_service_definition():
    return APOADefinition(
        principal=Principal(id="did:apoa:jane"),
        agent=Agent(id="did:apoa:agent1"),
        services=[
            ServiceAuthorization(service="service-a.com", scopes=["read", "write"]),
            ServiceAuthorization(service="service-b.com", scopes=["admin:*"]),
        ],
        expires="2026-12-31T00:00:00Z",
        delegatable=True,
        max_delegation_depth=3,
    )


@pytest.fixture
def multi_service_token(multi_service_definition, signing_options):
    return create_token(multi_service_definition, signing_options)
