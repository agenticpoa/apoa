# APOA Python SDK

Python SDK for the [Agentic Power of Attorney (APOA)](https://github.com/agenticpoa/apoa) standard -- authorization infrastructure for AI agents.

## Install

```bash
pip install apoa
```

## Quick Start

```python
from apoa import (
    APOA,
    generate_key_pair,
)

private_key, public_key = generate_key_pair()
apoa = APOA(private_key=private_key)

token = apoa.tokens.create_grant(
    principal="did:apoa:alex",
    agent="did:apoa:docs-assistant",
    service="knowledge-base",
    scopes=["articles:search", "articles:summarize"],
    constraints={"external_sharing": False},
    expires_in="24h",
)

valid = apoa.tokens.validate(token.raw, public_key=public_key)
print(valid.valid)  # True

result = apoa.authorizations.check(token, "knowledge-base", "articles:summarize")
print(result.authorized)  # True

result = apoa.authorizations.check(token, "knowledge-base", "articles:delete")
print(result.authorized)  # False
```

## Features

- **Token lifecycle**: create, sign (Ed25519/ES256), validate, parse
- **Scope matching**: hierarchical pattern matching (`articles:*` matches `articles:read`)
- **Constraint enforcement**: boolean denial at the SDK level, rich constraints at the protocol level
- **Authorization**: revocation + scope + constraints + hard/soft rules in one call
- **Delegation chains**: parent-to-child with cryptographically enforced attenuation
- **Cascade revocation**: revoke parent, kill all children instantly
- **Audit trail**: append-only action log per token
- **Cross-SDK compatibility**: tokens created by the TypeScript SDK validate in Python and vice versa

## Cross-SDK Compatibility

Tokens are JWTs. A token signed by `@apoa/core` (TypeScript) validates in `apoa` (Python) and vice versa. The serialization layer handles camelCase (JWT payload) to snake_case (Python) mapping automatically.

## API

Three usage styles:

### Application facade

Recommended for apps. Configure keys once, then use namespaced resources.

```python
from apoa import APOA

apoa = APOA(private_key=key)
token = apoa.tokens.create_grant(
    principal="did:apoa:alex",
    agent="did:apoa:docs-assistant",
    service="knowledge-base",
    scopes=["articles:search"],
    expires_in="24h",
)
apoa.authorizations.check(token, "knowledge-base", "articles:search")
```

### Protocol client

Use this when you want direct access to stores, resolvers, and protocol-level options.

```python
from apoa import create_client

client = create_client(default_private_key=key)
client.authorize(token, "knowledge-base", "articles:search")
```

### Standalone imports

Useful for scripts, tests, adapters, and focused protocol operations.

```python
from apoa import authorize, check_scope

check_scope(token, "knowledge-base", "articles:search")
```

See the [full spec](https://github.com/agenticpoa/apoa/blob/main/SPEC.md) and [TypeScript SDK](https://github.com/agenticpoa/apoa/tree/main/sdks/typescript) for more.

## License

Apache 2.0
