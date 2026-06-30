[![APOA: Agentic Power of Attorney](assets/banner.png)](assets/banner.png)

<h1 align="center">🐴 Agentic Power of Attorney (APOA)</h1>

<p align="center"><em>Pronounced "ah-POH-ah" like aloha 🤙</em></p>

<p align="center"><strong>APOA is an open authorization framework for AI agents</strong></p>

<p align="center">
  <a href="https://github.com/agenticpoa/apoa/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/agenticpoa/apoa/ci.yml?branch=main&style=flat-square&label=build&labelColor=f0ece4&color=4a7c59"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-4a7c59?style=flat-square&labelColor=f0ece4"></a>
  <a href="https://www.npmjs.com/package/@apoa/core"><img alt="@apoa/core npm version" src="https://img.shields.io/npm/v/@apoa/core?style=flat-square&label=core&labelColor=f0ece4&color=4a7c59"></a>
  <a href="https://www.npmjs.com/package/@apoa/core"><img alt="@apoa/core npm downloads" src="https://img.shields.io/npm/dm/@apoa/core?style=flat-square&label=npm%2Fmo&labelColor=f0ece4&color=4a7c59"></a>
  <a href="https://pypi.org/project/apoa/"><img alt="apoa PyPI version" src="https://img.shields.io/pypi/v/apoa?style=flat-square&label=python&labelColor=f0ece4&color=4a7c59"></a>
  <a href="https://pepy.tech/project/apoa"><img alt="apoa PyPI downloads" src="https://img.shields.io/pepy/dt/apoa?style=flat-square&label=pypi%20dl&labelColor=f0ece4&color=4a7c59"></a>
</p>

<p align="center">
  <a href="#try-apoa-in-60-seconds">Quickstart</a> ·
  <a href="#what-this-does">What It Does</a> ·
  <a href="#sdk-quickstarts">SDKs</a> ·
  <a href="#protocol-model">Protocol</a> ·
  <a href="#integrations">Integrations</a> ·
  <a href="#the-problem">Problem</a> ·
  <a href="#how-mode-b-actually-works">Mode B</a> ·
  <a href="#why-not-just-use">Compare</a> ·
  <a href="#demos">Demos</a> ·
  <a href="#get-involved">Get Involved</a>
</p>

## Try APOA in 60 Seconds

Install the TypeScript SDK:

```bash
npm install @apoa/core
```

Create a signed grant for a docs assistant, validate it, then check whether the agent can perform a specific action:

```typescript
import { APOA, generateKeyPair } from '@apoa/core';

const keys = await generateKeyPair();
const apoa = new APOA({ privateKey: keys.privateKey });

const token = await apoa.tokens.createGrant({
  principal: "did:apoa:alex",
  agent: { id: "did:apoa:docs-assistant", name: "Docs Assistant" },
  service: "knowledge-base",
  scopes: ["articles:search", "articles:summarize"],
  expiresIn: "24h",
});

const validation = await apoa.tokens.validate(token.raw, {
  publicKey: keys.publicKey,
});
console.log(validation.valid); // true

const allowed = await apoa.authorizations.check(
  token,
  "knowledge-base",
  "articles:summarize"
);
console.log(allowed.authorized); // true

const denied = await apoa.authorizations.check(
  token,
  "knowledge-base",
  "articles:delete"
);
console.log(denied.authorized); // false
```

That is the core APOA loop: create a bounded authorization grant, validate it, and ask whether a proposed action is allowed.

Runnable versions live in [`examples/quickstart-typescript`](examples/quickstart-typescript/) and [`examples/quickstart-python`](examples/quickstart-python/).

---

## What This Does

APOA is an open authorization framework for AI agents. It's an opinionated proposal with working SDKs you can install today, not a ratified standard. Feedback and collaborators welcome.

It answers:

- Who granted authority?
- Which agent received it?
- Which services can the agent use?
- Which actions are allowed?
- What limits, rules, and expiration apply?
- Can the authority be delegated?
- Can it be revoked?
- What happened afterward?

It is inspired by power of attorney: a principal grants an agent bounded authority to act on their behalf. APOA makes that authority machine-readable, signed, scoped, revocable, and auditable.

![APOA Authorization Flow: Principal to Token to Agent to Service](assets/hero-flow.png)

---

## SDK Quickstarts

You already saw the core create → validate → check loop above. These quickstarts go one step further: the TypeScript example shows how hard constraints and behavioral rules ride along on the same grant, and the Python example walks the full loop in Python.

### TypeScript Facade

```bash
npm install @apoa/core
```

```typescript
import { APOA, generateKeyPair } from '@apoa/core';

const keys = await generateKeyPair();
const apoa = new APOA({ privateKey: keys.privateKey });

// Same grant as the quickstart, now with a hard constraint and a behavioral rule.
const token = await apoa.tokens.createGrant({
  principal: "did:apoa:alex",
  agent: { id: "did:apoa:docs-assistant", name: "Docs Assistant" },
  service: "knowledge-base",
  scopes: ["articles:search", "articles:summarize"],
  constraints: { externalSharing: false },
  rules: [
    {
      id: "no-external-sharing",
      description: "Never share internal documents externally",
      enforcement: "hard", // denied at check() time, matched on rule id
    },
  ],
  expiresIn: "24h",
});

const result = await apoa.authorizations.check(
  token,
  "knowledge-base",
  "articles:summarize"
);
console.log(result.authorized); // true — within scope, no rule violated
```

### Python Facade

```bash
pip install apoa
```

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
    expires_in="24h",
)

valid = apoa.tokens.validate(token.raw, public_key=public_key)
print(valid.valid)  # True

result = apoa.authorizations.check(token, "knowledge-base", "articles:summarize")
print(result.authorized)  # True
```

### Three Usage Styles

The SDKs keep protocol-level APIs intact, but the recommended first path is the facade:

| Style | Best For | API Shape |
| --- | --- | --- |
| Facade API | App developers and first integrations | `new APOA(...)`, `apoa.tokens.createGrant(...)`, `apoa.authorizations.check(...)` |
| Protocol client | Stores, resolvers, and advanced options | `createClient(...)`, `client.createToken(...)`, `client.authorize(...)` |
| Standalone functions | Tests, adapters, and protocol utilities | `createToken(...)`, `authorize(...)`, `delegate(...)`, `verifyChain(...)` |

See [`sdks/typescript/`](sdks/typescript/) for TypeScript and [`sdks/python/`](sdks/python/) for Python.

---

## Protocol Model

**The APOA Token** is a signed JWT that contains everything needed to understand the authorization:

| Field | What It Does | Example |
| --- | --- | --- |
| `principal` | Who grants authority | `did:apoa:alex` |
| `agent` | Who receives authority | `did:apoa:docs-assistant` |
| `agentProvider` | The entity operating the agent | `Example Labs` |
| `services[].service` | Where the agent can act | `knowledge-base` |
| `services[].scopes` | What the agent can do there | `["articles:search", "articles:summarize"]` |
| `services[].constraints` | Hard limits | `{externalSharing: false}` |
| `accessMode` | How it connects | `"browser"` or `"api"` |
| `browserConfig` | URL jail + vault reference | `{allowedUrls: [...], credentialVaultRef: "..."}` |
| `rules[]` | Behavioral directives | `"Never share internal documents externally"` |
| `legal` | Jurisdiction + legal basis | `{jurisdiction: "US-CA"}` |
| `expires` | When it dies | `2026-06-15` |

The facade accepts convenient singular `service` / `scopes` input and normalizes it into the protocol-level `services[]` shape.

---

## Integrations

- [`@apoa/mcp`](https://github.com/agenticpoa/apoa-mcp): authorize MCP tool calls with per-tool scopes, revocation, delegation chains, and audit trails.
- [`@apoa/a2a`](https://github.com/agenticpoa/apoa-a2a): attach APOA tokens to A2A messages and verify scoped authority across agent hops.
- [`sshsign`](https://github.com/agenticpoa/sshsign): SSH-based signing service for AI agents with co-sign approval and immutable audit trails.
- [Jean-Claw Van Damme](https://github.com/agenticpoa/jean-claw-van-damme): authorization gatekeeper for OpenClaw agents.

The main SDK teaches the primitive first. The adapters show where it plugs into agent protocols.

---

## The Problem

> In January 2026, a developer [gave an AI agent access to his email, calendar, and browser](https://aaronstuyvenberg.com/posts/clawd-bought-a-car). The agent completed part of the task. It also sent a confidential email to the wrong person, because its entire authorization model was a natural language prompt that said "prompt me before replying to anything consequential."
>
> AI agents are already acting on behalf of humans with little formal authorization, limited auditability, and weak revocation. We think the infrastructure should catch up.

Most authorization frameworks assume your target service has an API. Many important services still do not. APOA is designed for both API-based services and browser-based services, where an agent may need bounded authority inside a web session without seeing the user's credentials.

APOA combines two capabilities:

**1. Natural language rules that actually do something.** Not just scopes and permissions. Rules like "never share internal documents externally" (`enforcement: hard`, denied at `authorize()` time) and rules like "alert me if any document is labeled confidential" (`enforcement: soft`, logged, triggers callbacks). Enforcement is mechanical: the SDK matches on the rule's `id`, not the natural-language description. APOA expresses both at the token level. See [SPEC §7](SPEC.md#7-rules) for the schema and semantics.

**2. Browser-based agent authorization.** Your agent needs to work with a web app that has no API. APOA authorizes a browser session where credentials come from a vault, the AI never sees them, and every action is scoped, audited, and instantly revocable. Browser-session authorization with vault-injected credentials is comparatively underserved today, and APOA treats it as a first-class mode (see [Mode B](#how-mode-b-actually-works) and [`docs/PRIOR_ART.md`](docs/PRIOR_ART.md)).

![APOA Two Access Modes: API-based and Browser-based](assets/two-modes.png)

---

## How Mode B Actually Works

This is the part that gets hand-waved in most authorization discussions, because it's genuinely hard. Here's how APOA approaches it.

![APOA Mode B: Secure Credential Injection via Vault](assets/mode-b-flow.png)

```
1. Agent runtime receives task: "summarize updates in the internal handbook"
2. Runtime calls authorize(token, "knowledge-base", "articles:summarize")
   → authorized: true
3. Runtime reads browserConfig from the token:
   → allowedUrls, credentialVaultRef, blockedActions
4. Runtime requests credential injection from vault
   → Vault injects credentials via encrypted channel
   → AI model NEVER sees the credentials
5. Agent navigates the documentation portal within URL restrictions
6. Runtime logs each action via the SDK audit API
   → optional URL + screenshot metadata
7. Session terminates after maxSessionDuration (30 min)
```

The SDK handles authorization and provides audit APIs. The credential vault handles step 4 (injection). The browser runtime handles steps 3, 5, 6, and 7, including URL and screenshot capture when those fields are logged. Nobody handles the credentials except the vault.

---

## Cross-SDK Compatibility

Tokens are JWTs. A token signed by `@apoa/core` validates in `apoa` (Python) and vice versa. Same algorithm, same payload schema, same scope and rule semantics.

```typescript
// In TypeScript: create a grant, hand off the JWT string.
import { APOA, generateKeyPair } from '@apoa/core';

const keys = await generateKeyPair();
const apoa = new APOA({ privateKey: keys.privateKey });
const token = await apoa.tokens.createGrant({
  principal: "did:apoa:alex",
  agent: "did:apoa:docs-assistant",
  service: "knowledge-base",
  scopes: ["articles:search"],
  expiresIn: "24h",
});

fetch("https://python-service/validate", { method: "POST", body: token.raw });
```

```python
# In Python: validate the same JWT, run authorization checks.
from apoa import APOA

apoa = APOA()
# raw_jwt is token.raw from above; public_key is the issuer's public key.
result = apoa.tokens.validate(raw_jwt, public_key=public_key)
assert result.valid
assert result.token is not None
authz = apoa.authorizations.check(result.token, "knowledge-base", "articles:search")
```

The serialization layer maps the camelCase JWT payload (e.g., `accessMode`, `agentProvider`) to snake_case in Python (`access_mode`, `agent_provider`) automatically. Cross-SDK fixture tests run on every CI build to catch any drift before it ships.

---

## Delegation Chains (They Only Shrink)

When your agent delegates to a sub-agent, permissions can only get *narrower*. That's not a guideline. It's cryptographically enforced.

![APOA Delegation Chains: Permissions Only Shrink](assets/delegation-chain.png)

```
Parent Token (Alex → Docs Assistant)
  scope: [articles:search, articles:summarize, collections:read]

  └── Child Token (Docs Assistant → Citation Checker)
        scope: [articles:search]                   ← subset only
        expires: ≤ parent expiration               ← cannot outlive parent
        rules: parent rules + additional            ← can only add, not remove
        delegation_depth: decremented              ← eventually hits 0
```

Revoke the parent? Every child in the chain dies instantly. That's cascade revocation, and it's the default because leaving orphaned child tokens alive is almost never what you want.

---

## Demos

Working end-to-end demos that exercise the SDK against real services and real signing.

### [`negotiate`](https://github.com/agenticpoa/negotiate): AI agents negotiate a YC SAFE

Two agents, founder-side and investor-side, negotiate a SAFE using the Rubinstein alternating-offers model. Each agent operates inside an APOA token its principal signed: valuation cap floor/ceiling, discount bounds, MFN, pro-rata, signing posture. Every offer is constraint-validated and chained into a Merkle log; the executed PDF includes the full negotiation history.

[![AI Agents Negotiate a YC SAFE](https://img.youtube.com/vi/l_wUpE8daOU/maxresdefault.jpg)](https://youtu.be/l_wUpE8daOU)

```bash
git clone https://github.com/agenticpoa/negotiate.git
cd negotiate && pip install -r requirements.txt
cp .env.example .env  # add ANTHROPIC_API_KEY
python negotiate.py --no-sshsign
```

### [`claw-negotiate`](https://github.com/agenticpoa/claw-negotiate): same negotiation, OpenClaw + Telegram

The same SAFE-negotiation flow packaged as an OpenClaw skill: founder and investor each run their own OpenClaw, the two agents negotiate publicly in a Telegram group, signing happens privately in DMs, and the executed SAFE carries an [`sshsign`](https://github.com/agenticpoa/sshsign) audit trail. Demonstrates APOA across two independently-authorized agents in a real consumer surface.

[![claw-negotiate demo](https://img.youtube.com/vi/T2Y2Tr__g_k/maxresdefault.jpg)](https://www.youtube.com/watch?v=T2Y2Tr__g_k)

---

## Why Not Just Use...

On the API side, the closest work is South et al.'s framework and `agent-passport-system`; APOA's distinct contribution is extending the model to browser-based services and adding legal-alignment metadata. See [`docs/PRIOR_ART.md`](docs/PRIOR_ART.md) for the dated landscape.

---

## Ecosystem

- [`@apoa/mcp`](https://github.com/agenticpoa/apoa-mcp): APOA authorization for MCP servers. Per-tool-call scoping, delegation chains, audit trails. Middleware or proxy mode.
- [`@apoa/a2a`](https://github.com/agenticpoa/apoa-a2a): APOA authorization for A2A agent-to-agent communication. Scoped delegation tokens across agent hops.
- [`sshsign`](https://github.com/agenticpoa/sshsign): SSH-based signing service for AI agents. SSH key as identity, scoped authorization, co-sign approval with handwritten signatures, immutable audit trail. Used by the negotiation demos for cryptographic signing.
- [Jean-Claw Van Damme](https://github.com/agenticpoa/jean-claw-van-damme): authorization gatekeeper for OpenClaw agents ([ClawHub](https://clawhub.ai/juanfiguera/jean-claw-van-damme)).

---

## Prior Art & Related Work

Authorization for AI agents is an active area. APOA was designed independently, and we found much of the related work, including MIT's foundational delegation paper and several parallel implementations, only afterward. Independent convergence on similar primitives is a good sign that the problem is real.

See [`docs/PRIOR_ART.md`](docs/PRIOR_ART.md) for the full landscape, with dated entries and where APOA's contribution (notably Mode B, for services with no API) is distinct.

---

## Technical Foundation

APOA builds on proven standards because the world has enough competing ones:

* **JWT (RFC 7519)**: token format
* **OAuth 2.1**: API-based authorization flows
* **W3C Verifiable Credentials**: portable, signed authorization packaging
* **ZCAP-LD**: capability attenuation model for delegation chains
* **W3C DIDs**: principal and agent identity
* **Web Bot Auth** (emerging): agent identification for browser-based services

See [SPEC.md](SPEC.md) for the full technical specification. It's riveting. Well, it's thorough.

---

## Project Status

- [x] Problem statement and concept definition
- [x] Landscape analysis of existing standards and gaps
- [x] Draft specification v0.1
- [x] Reference implementation (TypeScript SDK, [`@apoa/core`](sdks/typescript/))
- [x] Python SDK, [`apoa`](sdks/python/) (cross-SDK compatible)
- [ ] Community feedback and iteration
- [ ] Consumer product prototype (agent authorization dashboard)
- [ ] Security audit
- [ ] MCP extension proposal, Extensions track (the [`@apoa/mcp`](https://github.com/agenticpoa/apoa-mcp) adapter exists; formal proposal pending)
- [ ] Formal standards body submission

---

## Get Involved

* **Install the SDK**: `npm install @apoa/core` (TypeScript) or `pip install apoa` (Python)
* **Read the spec**: [SPEC.md](SPEC.md) is the working draft
* **Read the FAQ**: [`docs/FAQ.md`](docs/FAQ.md) covers the usual "is this a real POA / how is this different from OAuth / isn't this just X" questions
* **Open an issue**: critiques and "this will never work because..." are welcome
* **Join the discussion**: [Discussions tab](../../discussions) for broader conversations
* **Build with it**: if you're working on AI agents, browser automation, or identity, we want your input

---

## ⚠️ No Tokens. No Coins. No NFTs.

**Agentic POA has no cryptocurrency, no token, no coin, no NFT, and no blockchain-based financial product of any kind.** Not now. Not ever. If someone claims otherwise, **it is a scam.**

---

## License

Apache 2.0. See [LICENSE](LICENSE).

## Origin

Agentic Power of Attorney was created in February 2026 to explore an interoperable way to delegate bounded digital authority from humans to AI agents. Its mascot is Proxy, named for the oldest meaning of the word: one authorized to act on another's behalf.

---

🐴 *Meet **Proxy**, a [Pony of the Americas](https://en.wikipedia.org/wiki/Pony_of_the_Americas). Calm, intelligent, and built to earn your trust. Which is more than we can say for your insurance company's login page.*
