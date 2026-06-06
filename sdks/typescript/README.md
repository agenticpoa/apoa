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
  principal: "did:apoa:you",
  agent: { id: "did:apoa:your-agent", name: "HomeBot Pro" },
  service: "nationwidemortgage.com",
  scopes: ["rate_lock:read", "documents:read"],
  constraints: { signing: false },
  expiresIn: "30d",
});

const valid = await apoa.tokens.validate(token.raw, { publicKey: keys.publicKey });
console.log(valid.valid); // true

const result = await apoa.authorizations.check(
  token,
  "nationwidemortgage.com",
  "rate_lock:read"
);
// { authorized: true, checks: { revoked: false, scopeAllowed: true, ... } }

const denied = await apoa.authorizations.check(
  token,
  "nationwidemortgage.com",
  "documents:sign"
);
// { authorized: false, reason: "scope 'documents:sign' not in authorized scopes" }
```

## Features

- **Token lifecycle**: create, sign (Ed25519/ES256), validate, parse
- **Scope matching**: hierarchical patterns (`appointments:*` matches `appointments:read`)
- **Constraint enforcement**: boolean denial checks
- **Authorization**: revocation + scope + constraints + hard/soft rules in one call
- **Delegation chains**: capability attenuation (permissions only narrow, never expand)
- **Cascade revocation**: revoke parent, all children die instantly
- **Audit trail**: append-only action log per token
- **Browser mode**: credential vault injection config (the AI never sees passwords)
- **Comprehensive test suite** with cross-SDK fixture verification against the [Python SDK](https://pypi.org/project/apoa/)

## Two Usage Styles

```typescript
// Style 1: Application facade (recommended for apps)
const apoa = new APOA({ privateKey: keys.privateKey });
const token = await apoa.tokens.createGrant({
  principal: "did:apoa:you",
  agent: "did:apoa:agent",
  service: "service.com",
  scopes: ["action:read"],
  expiresIn: "30d",
});
await apoa.authorizations.check(token, "service.com", "action:read");

// Style 2: Protocol client
const client = createClient({
  revocationStore: new MemoryRevocationStore(),
  auditStore: new MemoryAuditStore(),
  defaultSigningOptions: { privateKey: keys.privateKey },
});
await client.authorize(token, "service.com", "action:read");

// Style 3: Standalone imports (for scripts, tests, and adapters)
import { checkScope, authorize, createToken } from '@apoa/core';
checkScope(token, "service.com", "action:read");
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
