# APOA Python SDK

Python SDK for the [Agentic Power of Attorney (APOA)](https://github.com/agenticpoa/apoa) standard -- authorization infrastructure for AI agents.

## Install

```bash
pip install apoa
```

## Quick Start

```python
from apoa import (
    APOADefinition, Agent, BrowserSessionConfig, Principal,
    Rule, ServiceAuthorization, SigningOptions,
    create_client, generate_key_pair,
)

# Generate keys and create a client
private_key, public_key = generate_key_pair()
client = create_client(default_private_key=private_key)

# Create a signed authorization token
token = client.create_token(APOADefinition(
    principal=Principal(id="did:apoa:you"),
    agent=Agent(id="did:apoa:your-agent", name="HomeBot Pro"),
    services=[ServiceAuthorization(
        service="nationwidemortgage.com",
        scopes=["rate_lock:read", "documents:read"],
        constraints={"signing": False},
        access_mode="browser",
        browser_config=BrowserSessionConfig(
            allowed_urls=["https://portal.nationwidemortgage.com/*"],
            credential_vault_ref="1password://vault/mortgage-portal",
        ),
    )],
    rules=[Rule(id="no-signing", description="Never sign anything", enforcement="hard")],
    expires="2026-09-01",
))

# Authorize actions
result = client.authorize(token, "nationwidemortgage.com", "rate_lock:read")
print(result.authorized)  # True

result = client.authorize(token, "nationwidemortgage.com", "documents:sign")
print(result.authorized)  # False
```

## Features

- **Token lifecycle**: create, sign (Ed25519/ES256), validate, parse
- **Scope matching**: hierarchical pattern matching (`appointments:*` matches `appointments:read`)
- **Constraint enforcement**: boolean denial at the SDK level, rich constraints at the protocol level
- **Authorization**: revocation + scope + constraints + hard/soft rules in one call
- **Delegation chains**: parent-to-child with cryptographically enforced attenuation
- **Cascade revocation**: revoke parent, kill all children instantly
- **Audit trail**: append-only action log per token
- **Cross-SDK compatibility**: tokens created by the TypeScript SDK validate in Python and vice versa

## Cross-SDK Compatibility

Tokens are JWTs. A token signed by `@apoa/core` (TypeScript) validates in `apoa` (Python) and vice versa. The serialization layer handles camelCase (JWT payload) to snake_case (Python) mapping automatically.

## API

Two usage styles:

```python
# Style 1: Client instance (recommended)
client = create_client(default_private_key=key)
client.authorize(token, "service.com", "action:read")

# Style 2: Standalone imports
from apoa import authorize, check_scope
check_scope(token, "service.com", "action:read")
```

See the [full spec](https://github.com/agenticpoa/apoa/blob/main/SPEC.md) and [TypeScript SDK](https://github.com/agenticpoa/apoa/tree/main/sdk) for more.

## License

Apache 2.0
