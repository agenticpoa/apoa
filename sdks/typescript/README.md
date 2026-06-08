# @apoa/core

Reference TypeScript SDK for the [Agentic Power of Attorney (APOA)](https://github.com/agenticpoa/apoa) standard -- authorization infrastructure for AI agents.

## Install

```bash
npm install @apoa/core
```

## Quick Start

```typescript
import { APOA, generateKeyPair } from '@apoa/core';

const keys = await generateKeyPair();
const apoa = new APOA({ privateKey: keys.privateKey });

const token = await apoa.tokens.createGrant({
  principal: "did:apoa:alex",
  agent: { id: "did:apoa:docs-assistant", name: "Docs Assistant" },
  service: "knowledge-base",
  scopes: ["articles:search", "articles:summarize"],
  constraints: { externalSharing: false },
  expiresIn: "24h",
});

const valid = await apoa.tokens.validate(token.raw, { publicKey: keys.publicKey });
console.log(valid.valid); // true

const result = await apoa.authorizations.check(
  token,
  "knowledge-base",
  "articles:summarize"
);
// { authorized: true, checks: { revoked: false, scopeAllowed: true, ... } }

const denied = await apoa.authorizations.check(
  token,
  "knowledge-base",
  "articles:delete"
);
// { authorized: false, reason: "scope 'articles:delete' not in authorized scopes" }
```

## Features

- **Token lifecycle**: create, sign (Ed25519/ES256), validate, parse
- **Scope matching**: hierarchical patterns (`articles:*` matches `articles:read`)
- **Constraint enforcement**: boolean denial checks
- **Authorization**: revocation + scope + constraints + hard/soft rules in one call
- **Delegation chains**: capability attenuation (permissions only narrow, never expand)
- **Cascade revocation**: revoke parent, all children die instantly
- **Audit trail**: append-only action log per token
- **Browser mode**: credential vault injection config (the AI never sees passwords)
- **Comprehensive test suite** with cross-SDK fixture verification against the [Python SDK](https://pypi.org/project/apoa/)

## Usage Styles

### Application facade

Recommended for apps. Configure keys once, then use namespaced resources.

```typescript
import { APOA } from '@apoa/core';

const apoa = new APOA({ privateKey: keys.privateKey });
const token = await apoa.tokens.createGrant({
  principal: "did:apoa:alex",
  agent: "did:apoa:docs-assistant",
  service: "knowledge-base",
  scopes: ["articles:search"],
  expiresIn: "24h",
});
await apoa.authorizations.check(token, "knowledge-base", "articles:search");
```

### Protocol client

Use this when you want direct access to stores, resolvers, and protocol-level options.

```typescript
import { createClient, MemoryAuditStore, MemoryRevocationStore } from '@apoa/core';

const client = createClient({
  revocationStore: new MemoryRevocationStore(),
  auditStore: new MemoryAuditStore(),
  defaultSigningOptions: { privateKey: keys.privateKey },
});
await client.authorize(token, "knowledge-base", "articles:search");
```

### Standalone imports

Useful for scripts, tests, adapters, and focused protocol operations.

```typescript
import { checkScope, authorize, createToken } from '@apoa/core';

checkScope(token, "knowledge-base", "articles:search");
```

## Cross-SDK Compatibility

Tokens created by `@apoa/core` validate in the [Python SDK](https://pypi.org/project/apoa/) and vice versa. The camelCase JWT payload round-trips correctly across both SDKs.

## Ecosystem

- [`@apoa/mcp`](https://www.npmjs.com/package/@apoa/mcp) -- APOA authorization for MCP servers
- [`@apoa/a2a`](https://github.com/agenticpoa/apoa-a2a) -- APOA authorization for A2A agent-to-agent communication
- [`apoa`](https://pypi.org/project/apoa/) -- Python SDK

## Links

- [Spec](https://github.com/agenticpoa/apoa/blob/main/SPEC.md)
- [Source](https://github.com/agenticpoa/apoa/tree/main/sdks/typescript)
- [Examples](https://github.com/agenticpoa/apoa/tree/main/sdks/typescript/examples)

## License

Apache-2.0
