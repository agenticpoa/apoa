# @apoa/core

Reference TypeScript SDK for the [Agentic Power of Attorney (APOA)](https://github.com/agenticpoa/apoa) standard -- authorization infrastructure for AI agents.

## Install

```bash
npm install @apoa/core
```

## Quick Start

```typescript
import { createToken, checkScope, generateKeyPair, createClient } from '@apoa/core';

// Generate keys and create a client
const keys = await generateKeyPair();
const client = createClient({ defaultSigningOptions: { privateKey: keys.privateKey } });

// Create a signed authorization token
const token = await client.createToken({
  principal: { id: "did:apoa:you" },
  agent: { id: "did:apoa:your-agent", name: "HomeBot Pro" },
  services: [{
    service: "nationwidemortgage.com",
    scopes: ["rate_lock:read", "documents:read"],
    constraints: { signing: false },
    accessMode: "browser",
    browserConfig: {
      allowedUrls: ["https://portal.nationwidemortgage.com/*"],
      credentialVaultRef: "1password://vault/mortgage-portal",
    },
  }],
  rules: [{ id: "no-signing", description: "Never sign anything", enforcement: "hard" }],
  expires: "2026-09-01",
});

// Authorize actions
const result = await client.authorize(token, "nationwidemortgage.com", "rate_lock:read");
// { authorized: true, checks: { revoked: false, scopeAllowed: true, ... } }

const denied = await client.authorize(token, "nationwidemortgage.com", "documents:sign");
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
- **263 tests** across 17 test files

## Two Usage Styles

```typescript
// Style 1: Client instance (recommended for apps)
const client = createClient({
  revocationStore: new MemoryRevocationStore(),
  auditStore: new MemoryAuditStore(),
  defaultSigningOptions: { privateKey: keys.privateKey },
});
await client.authorize(token, "service.com", "action:read");

// Style 2: Standalone imports (for scripts and tests)
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
- [Source](https://github.com/agenticpoa/apoa/tree/main/sdk)
- [Examples](https://github.com/agenticpoa/apoa/tree/main/sdk/examples)

## License

Apache-2.0
