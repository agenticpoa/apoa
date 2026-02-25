# APOA Specification v0.1 (Working Draft)

**Agentic Power of Attorney — Technical Specification**

**Status:** Working Draft
**Version:** 0.1
**Date:** February 2026
**License:** Apache 2.0

---

## 1. Introduction

This document defines the Agentic Power of Attorney (APOA) protocol — a standard for formally delegating bounded authority from a human principal to an AI agent to access and act within digital services on the principal's behalf.

APOA is not a replacement for OAuth, MCP, or any existing authorization protocol. It is an **integration layer** that combines existing standards into a coherent delegation framework purpose-built for AI agents, extending authorization to services that lack APIs, and wrapping everything in a legally meaningful structure.

### 1.1 Design Goals

1. **Universal coverage** — work with API-based services (via OAuth), browser-based services (via secure credential injection and Web Bot Auth), and hybrid environments
2. **Capability attenuation** — every delegation can only reduce, never expand, the scope of authority granted
3. **Audit completeness** — every action taken under an APOA authorization is logged, attributable, and reviewable
4. **Legal alignment** — authorizations are structured to align with existing electronic agency law (UETA, E-SIGN) and emerging AI governance frameworks
5. **Human supremacy** — the principal retains absolute control, including instant revocation, at all times

### 1.2 What APOA Is Not

- **Not a legal power of attorney.** AI systems cannot hold POA under any jurisdiction. APOA is a technical authorization standard that borrows the conceptual framework.
- **Not a credential manager.** APOA never stores or transmits passwords. It delegates authority, not credentials.
- **Not a cryptocurrency, token, or financial instrument.** The word "token" in this document refers exclusively to signed JWT authorization documents.

---

## 2. Terminology

| Term | Definition |
|---|---|
| **Principal** | The human granting authority. The account holder. You. |
| **Agent** | The AI system receiving delegated authority to act on the principal's behalf. |
| **Service** | The digital service the agent will access (e.g., mychart.com, bankofamerica.com). |
| **APOA Token** | A signed, structured authorization instrument — a JWT containing the full scope, constraints, and metadata of the delegation. |
| **Authorization Server** | The entity that issues, validates, and revokes APOA Tokens. |
| **Agent Provider** | The organization operating the AI agent (e.g., Anthropic, OpenAI, a SaaS company). The legal entity responsible for the agent's behavior. |
| **Delegation Chain** | A sequence of delegations where Agent A delegates a subset of its authority to Agent B. Each link can only attenuate (reduce) scope. |
| **Revocation Endpoint** | The URI where a principal can instantly revoke any active APOA Token. |

---

## 3. Architecture Overview

```
┌─────────────┐      ┌──────────────────┐      ┌─────────────┐
│             │      │                  │      │             │
│  Principal  │─(1)──▶  Authorization   │─(2)──▶   Agent     │
│  (Human)    │      │  Server          │      │  (AI)       │
│             │      │                  │      │             │
└─────────────┘      └──────────────────┘      └──────┬──────┘
                              │                        │
                           (3) validates            (4) accesses
                              │                        │
                     ┌────────▼────────┐      ┌───────▼───────┐
                     │                 │      │               │
                     │  Revocation     │      │   Service     │
                     │  Registry       │      │   (Target)    │
                     │                 │      │               │
                     └─────────────────┘      └───────────────┘
```

**Flow:**

1. **Principal creates authorization** — the principal defines scope, constraints, and expiration via the Authorization Server (hosted dashboard, CLI, or API).
2. **APOA Token issued to Agent** — the Authorization Server generates a signed JWT and delivers it to the agent through the Agent Provider's secure channel.
3. **Ongoing validation** — the service (or a verification proxy) checks the token's signature, expiration, and revocation status before granting access.
4. **Agent accesses service** — using the APOA Token, the agent interacts with the service within its authorized scope.

### 3.1 Two Access Modes

APOA supports two fundamentally different modes of service access:

**Mode A: API-Based Access (OAuth Extension)**

For services with APIs, APOA extends standard OAuth 2.1 flows. The APOA Token acts as a "meta-authorization" that constrains the OAuth access token's effective scope. The agent uses standard OAuth token flows; the APOA layer adds agent identity verification, delegation chain tracking, and audit requirements on top.

```
Principal ──▶ APOA Authorization ──▶ OAuth Flow ──▶ API Access
                                         │
                                    APOA constraints
                                    enforced at token
                                    issuance + validation
```

**Mode B: Browser-Based Access (Secure Credential Injection)**

For services without APIs, APOA uses secure credential injection — credentials are retrieved from a credential vault at runtime and injected into a browser context without the AI model ever seeing them. The APOA Token authorizes the credential injection and defines what the agent may do once authenticated.

```
Principal ──▶ APOA Authorization ──▶ Credential Vault ──▶ Browser Session
                                         │                      │
                                    Credentials never      Agent operates
                                    exposed to AI model    within APOA scope
```

This builds on the architecture pioneered by 1Password's Secure Agentic Autofill — an end-to-end encrypted channel where the credential vault injects login details directly into the browser form, and the agent operates within the authenticated session but never has access to the underlying credentials.

---

## 4. APOA Token Format

The APOA Token is a signed JWT (RFC 7519) with the following structure:

### 4.1 Header

```json
{
  "alg": "ES256",
  "typ": "apoa+jwt",
  "kid": "apoa-auth-server-key-2026-01"
}
```

APOA Tokens MUST use asymmetric signing algorithms. Recommended: ES256 (ECDSA with P-256 and SHA-256). RSA (RS256) is acceptable. Symmetric algorithms (HS256) MUST NOT be used.

### 4.2 Payload (Claims)

#### Required Claims

| Claim | Type | Description |
|---|---|---|
| `iss` | string | Issuer — the Authorization Server that created this token |
| `sub` | string | Subject — the Principal's identifier (DID or URI) |
| `agt` | string | Agent — the AI agent's identifier (DID or URI) |
| `agt_provider` | string | Agent Provider — the legal entity operating the agent |
| `svc` | string | Service — the target service identifier (domain or URI) |
| `scope` | string[] | Permitted actions (see Section 5) |
| `iat` | number | Issued at — Unix timestamp |
| `nbf` | number | Not before — Unix timestamp when authorization begins |
| `exp` | number | Expires — Unix timestamp when authorization ends |
| `jti` | string | JWT ID — unique identifier for this token |

#### Conditional Claims

| Claim | Type | Description |
|---|---|---|
| `constraints` | object | Behavioral limits beyond scope (see Section 6) |
| `delegation_depth` | number | Maximum number of re-delegations permitted (0 = no re-delegation) |
| `delegation_chain` | object[] | Array of prior delegations in the chain, each with `from`, `to`, and `scope` |
| `access_mode` | string | `"api"` or `"browser"` — how the agent accesses the service |
| `audit_level` | string | `"all_actions"`, `"mutations_only"`, or `"summary"` |
| `rules` | string[] | Natural language behavioral rules (see Section 7) |
| `co_principal` | string | Additional human with revocation authority |
| `renewal` | string | Renewal policy: `"none"`, `"manual"`, or `"annual_review"` |

#### Optional Claims

| Claim | Type | Description |
|---|---|---|
| `purpose` | string | Human-readable description of the authorization's purpose |
| `apoa_version` | string | Spec version (e.g., `"0.1"`) |
| `revocation_endpoint` | string | URI for real-time revocation checks |
| `notification_uri` | string | Where to send action notifications to the principal |

### 4.3 Example Token Payload

```json
{
  "iss": "https://auth.agenticpoa.com",
  "sub": "did:apoa:principal:juan_abc123",
  "agt": "did:apoa:agent:homebot_pro_xyz",
  "agt_provider": "homebot.ai",
  "svc": "nationwidemortgage.com",
  "scope": ["rate_lock:read", "documents:read", "timeline:read"],
  "constraints": {
    "signing": false,
    "data_export": false
  },
  "rules": [
    "Alert principal if any deadline is within 48 hours",
    "Never sign, submit, or commit to anything"
  ],
  "access_mode": "browser",
  "audit_level": "all_actions",
  "delegation_depth": 0,
  "iat": 1709251200,
  "nbf": 1709251200,
  "exp": 1718409600,
  "jti": "apoa-token-9f8e7d6c-5b4a-3c2d-1e0f",
  "purpose": "Monitor mortgage application during home purchase",
  "apoa_version": "0.1",
  "revocation_endpoint": "https://auth.agenticpoa.com/revoke/apoa-token-9f8e7d6c"
}
```

### 4.4 Signature

The token MUST be signed by the Authorization Server's private key. Verification requires the corresponding public key, available at the Authorization Server's JWKS endpoint (`/.well-known/jwks.json`).

---

## 5. Scope Definitions

Scopes follow the pattern `resource:action` and are hierarchical.

### 5.1 Standard Actions

| Action | Description |
|---|---|
| `read` | View/retrieve information |
| `search` | Search or filter information |
| `create_draft` | Create content in draft state (not published/submitted) |
| `flag_for_review` | Mark items for human review |
| `respond` | Send responses (subject to constraints) |
| `modify` | Change existing data |
| `create` | Create new records |
| `submit` | Submit forms or applications |
| `delete` | Remove data |
| `admin` | Full administrative access |

### 5.2 Scope Hierarchy and Attenuation

Scopes are ordered by privilege level. Higher-privilege scopes include all lower-privilege capabilities:

```
admin > delete > submit > create > modify > respond > create_draft > flag_for_review > search > read
```

**Attenuation rule:** When an agent re-delegates authority (if `delegation_depth > 0`), the delegated token's scope MUST be a subset of the delegating token's scope. A token with `documents:read` cannot delegate `documents:modify`.

### 5.3 Service-Specific Scopes

Services MAY define custom scopes beyond the standard actions. Custom scopes MUST follow the `resource:action` pattern and SHOULD be documented in the service's APOA integration manifest.

Examples:
- `rate_lock:read` — specific to mortgage services
- `prescriptions:refill_status:read` — specific to pharmacy services
- `waitlist:position:read` — specific to queuing services

---

## 6. Constraints

Constraints define behavioral limits that go beyond scope. While scope defines *what* the agent can access, constraints define *how* and *under what conditions*.

### 6.1 Standard Constraint Types

| Constraint | Type | Description | Example |
|---|---|---|---|
| `max_amount` | number | Maximum monetary value per action | `500.00` |
| `max_daily_amount` | number | Maximum monetary value per day | `2000.00` |
| `max_response_length` | number | Maximum character length for responses | `500` |
| `response_policy` | string | Template/policy for outgoing messages | `"approved_templates_only"` |
| `time_window` | object | Hours during which agent may operate | `{"start": "08:00", "end": "22:00", "tz": "America/Los_Angeles"}` |
| `require_confirmation` | string[] | Actions requiring explicit human approval | `["payments", "submissions"]` |
| `rate_limit` | object | Maximum actions per time period | `{"max": 100, "period": "1h"}` |
| `data_export` | boolean | Whether agent may export/download data | `false` |
| `geographic_restriction` | string[] | Allowed geographic regions for access | `["US"]` |

### 6.2 Constraint Enforcement

Constraints are enforced at multiple layers:

1. **Token issuance** — the Authorization Server validates that constraints are logically consistent with scope
2. **Agent runtime** — the Agent Provider's infrastructure enforces constraints during execution
3. **Service-side** (optional) — services that integrate with APOA can independently verify constraints
4. **Audit** — constraint violations are logged and may trigger automatic revocation

---

## 7. Rules (Natural Language Behavioral Directives)

Rules are human-readable behavioral instructions embedded in the APOA Token. They complement structured scope and constraints with intent-level directives that guide agent behavior in ambiguous situations.

### 7.1 Rule Format

Rules are expressed as natural language strings in an array:

```json
"rules": [
  "Alert me if any deadline is within 48 hours",
  "Never sign, submit, or commit to anything",
  "Summarize new activity daily at 8am Pacific"
]
```

### 7.2 Rule Interpretation

Rules are interpreted by the Agent Provider's AI system. Because natural language is inherently ambiguous, rules operate as **behavioral guidance**, not enforceable constraints. Scope and constraint claims are the enforceable boundaries; rules provide intent within those boundaries.

When a rule conflicts with a scope or constraint claim, the scope/constraint takes precedence.

### 7.3 Rule Categories

| Category | Example |
|---|---|
| **Alerting** | "Alert me if any bill is within 5 days of its due date" |
| **Negative** | "Never communicate with providers or approve treatments" |
| **Reporting** | "Generate weekly income summary report" |
| **Escalation** | "If a transaction exceeds $1000, require my explicit approval" |
| **Scheduling** | "Check waitlist position daily at 9am" |

---

## 8. Delegation Chains

APOA supports multi-hop delegation where Agent A delegates a subset of its authority to Agent B (e.g., a coordinator agent delegating to a specialist sub-agent).

### 8.1 Delegation Rules

1. **Attenuation only** — each delegation in the chain MUST reduce or maintain (never expand) the scope and constraints of the parent token
2. **Depth limits** — the `delegation_depth` claim specifies how many further delegations are permitted. A value of `0` means no re-delegation is allowed.
3. **Chain tracking** — each delegated token MUST include the full `delegation_chain` showing all prior delegations, enabling end-to-end audit
4. **Principal visibility** — the original principal MUST be able to view the full delegation chain and revoke at any point

### 8.2 Delegation Chain Example

```json
"delegation_chain": [
  {
    "from": "did:apoa:principal:juan_abc123",
    "to": "did:apoa:agent:coordinator_xyz",
    "scope": ["documents:read", "documents:flag_for_review"],
    "delegated_at": 1709251200
  },
  {
    "from": "did:apoa:agent:coordinator_xyz",
    "to": "did:apoa:agent:doc_reviewer_456",
    "scope": ["documents:read"],
    "delegated_at": 1709337600
  }
]
```

Note how the scope attenuates: the original delegation grants `read` and `flag_for_review`, but the sub-delegation only passes along `read`.

---

## 9. Revocation

Revocation is a first-class operation in APOA, not an afterthought.

### 9.1 Revocation Methods

| Method | Latency | Description |
|---|---|---|
| **Instant (push)** | < 1 second | Principal triggers revocation via dashboard or API; the Authorization Server pushes invalidation to the Agent Provider |
| **Short-lived tokens** | Token lifetime | Tokens are issued with short expiration (e.g., 15 minutes) and refreshed automatically. Revocation takes effect when the token isn't renewed. |
| **Revocation list (pull)** | Polling interval | Agent or service checks a revocation endpoint before each action. Similar to CRL/OCSP in TLS. |

### 9.2 Revocation Cascading

When a token is revoked, all tokens derived from it (via delegation chains) MUST also be revoked. The Authorization Server is responsible for cascading revocation through the delegation chain.

### 9.3 Emergency Revocation

APOA defines a "kill switch" pattern: a single API call or dashboard action that revokes **all** active APOA Tokens for a principal across all services and all agents simultaneously.

```
POST /revoke-all
Authorization: Bearer {principal_auth_token}

Response: 200 OK
{
  "revoked": 12,
  "effective_at": "2026-03-15T14:30:00Z"
}
```

---

## 10. Audit Trail

Every action taken by an agent operating under an APOA Token MUST be logged.

### 10.1 Audit Log Entry Format

```json
{
  "timestamp": "2026-03-15T14:32:00Z",
  "token_id": "apoa-token-9f8e7d6c-5b4a-3c2d-1e0f",
  "agent": "did:apoa:agent:homebot_pro_xyz",
  "service": "nationwidemortgage.com",
  "action": "rate_lock:read",
  "resource": "/account/rate-lock-status",
  "result": "success",
  "data_accessed": "Rate lock status: locked at 6.25% until 2026-04-15",
  "delegation_chain_depth": 0
}
```

### 10.2 Audit Levels

| Level | What's Logged | Use Case |
|---|---|---|
| `all_actions` | Every action, including reads | High-sensitivity contexts (healthcare, financial, legal) |
| `mutations_only` | Only actions that change state | Medium-sensitivity contexts |
| `summary` | Periodic summary of actions taken | Low-sensitivity monitoring |

### 10.3 Audit Access

The principal MUST have access to the complete audit trail for any APOA Token they have issued. Audit logs MUST be retained for the lifetime of the token plus a minimum of 90 days after expiration or revocation.

---

## 11. Agent Identity

Agents are identified using Decentralized Identifiers (DIDs) following the W3C DID Core specification, under a custom `did:apoa` method.

### 11.1 DID Format

```
did:apoa:agent:{provider}:{instance_id}
did:apoa:principal:{user_id}
```

Examples:
- `did:apoa:agent:anthropic:claude-2026-03-abc`
- `did:apoa:principal:juan_abc123`

### 11.2 Agent Identity Document

Each agent DID resolves to a DID Document containing:

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:apoa:agent:anthropic:claude-2026-03-abc",
  "controller": "did:apoa:provider:anthropic",
  "verificationMethod": [{
    "id": "did:apoa:agent:anthropic:claude-2026-03-abc#key-1",
    "type": "JsonWebKey2020",
    "publicKeyJwk": { ... }
  }],
  "service": [{
    "id": "#apoa-profile",
    "type": "APOAAgentProfile",
    "serviceEndpoint": "https://anthropic.com/agents/claude-2026-03-abc/profile"
  }],
  "apoa:agentMetadata": {
    "provider": "Anthropic, PBC",
    "model_family": "Claude",
    "capabilities": ["browser_navigation", "document_analysis", "api_access"],
    "trust_level": "provider_verified"
  }
}
```

### 11.3 Intent Binding (Experimental)

Building on the IETF Agentic JWT draft, APOA supports optional cryptographic binding of agent identity to behavior:

```json
"apoa:intent_binding": {
  "system_prompt_hash": "sha256:a1b2c3d4...",
  "tools_manifest_hash": "sha256:e5f6g7h8...",
  "model_version": "claude-opus-4-5-20250929"
}
```

This allows verification that the agent operating under a token matches the agent that was authorized — preventing token theft or misuse by a different agent or model version.

---

## 12. Verifiable Credential Packaging

For portability across systems, APOA Tokens MAY be packaged as W3C Verifiable Credentials v2.0.

### 12.1 VC Structure

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://agenticpoa.com/ns/v1"
  ],
  "type": ["VerifiableCredential", "APOAAuthorization"],
  "issuer": "did:apoa:auth:agenticpoa-server-1",
  "validFrom": "2026-03-01T00:00:00Z",
  "validUntil": "2026-06-15T00:00:00Z",
  "credentialSubject": {
    "id": "did:apoa:agent:homebot_pro_xyz",
    "principal": "did:apoa:principal:juan_abc123",
    "authorization": {
      "service": "nationwidemortgage.com",
      "scope": ["rate_lock:read", "documents:read", "timeline:read"],
      "constraints": { "signing": false },
      "access_mode": "browser"
    }
  },
  "credentialStatus": {
    "type": "StatusList2021Entry",
    "statusPurpose": "revocation",
    "statusListIndex": "42",
    "statusListCredential": "https://auth.agenticpoa.com/status/1"
  }
}
```

This packaging enables APOA authorizations to be stored in digital wallets, verified by any party, and revoked via standard VC status mechanisms.

---

## 13. Security Considerations

### 13.1 Threat Model

| Threat | Mitigation |
|---|---|
| **Token theft** | Short-lived tokens + proof-of-possession binding. Tokens SHOULD be bound to the agent's key pair using DPoP (RFC 9449). |
| **Agent impersonation** | Intent binding (Section 11.3) cryptographically ties tokens to specific agent configurations. |
| **Scope escalation** | Attenuation rule (Section 5.2) makes it mathematically impossible to gain scope through delegation. |
| **Credential exposure** | Browser-based mode uses secure credential injection; the AI model never sees credentials. |
| **Unauthorized delegation** | `delegation_depth: 0` by default. Multi-hop delegation requires explicit opt-in. |
| **Stale authorization** | Mandatory expiration on all tokens. No indefinite authorizations. |
| **Principal account compromise** | Emergency revocation (Section 9.3) kills all active authorizations in one action. |

### 13.2 Mandatory Security Requirements

1. All APOA Tokens MUST use asymmetric signing (ES256 recommended)
2. All communication MUST use TLS 1.3 or later
3. Tokens MUST have finite expiration (`exp` claim is REQUIRED)
4. Default `delegation_depth` MUST be 0 (no re-delegation)
5. Credential injection endpoints MUST use end-to-end encryption
6. Audit logs MUST be tamper-evident (append-only with integrity verification)

---

## 14. Legal Framework Alignment

APOA is designed to operate within existing legal frameworks while being ready for emerging ones.

### 14.1 Current Legal Basis

- **UETA Section 14** — recognizes contracts formed by electronic agents on behalf of users
- **E-SIGN Act** — validates electronic agent actions when "legally attributable to the person to be bound"
- **Agency law (Restatement Third)** — the Agent Provider (not the AI) is the legal agent; the AI is the provider's tool

### 14.2 APOA Legal Model

APOA adopts the **provider-as-agent** model:

```
Principal (human) ──delegates to──▶ Agent Provider (legal entity) ──operates──▶ AI Agent (software)
```

The principal's legal relationship is with the Agent Provider, which bears fiduciary responsibility. The AI system is an instrument of the provider, not an independent legal agent. This model avoids the unsolved problem of AI legal personhood while maintaining clear liability chains.

### 14.3 Authorization Instrument

The APOA Token is designed to function as a **digital authorization instrument** — analogous to, but distinct from, a legal power of attorney. It documents:

- Who authorized what
- What was authorized (scope + constraints)
- When authorization was granted and expires
- What the agent actually did (audit trail)

This record is intended to be admissible as evidence of authorization under the electronic records provisions of UETA and E-SIGN, though formal legal recognition will require jurisdictional adoption.

---

## 15. Relationship to Existing Standards

| Standard | Relationship to APOA |
|---|---|
| **OAuth 2.1** | APOA uses OAuth for API-based authorization flows. APOA extends OAuth with agent identity, delegation chains, and audit requirements. |
| **GNAP (RFC 9635)** | GNAP's flexible interaction model and token chaining inform APOA's architecture. APOA may adopt GNAP flows in future versions. |
| **MCP** | MCP provides the tool connection layer. APOA provides the authorization layer that sits above MCP. |
| **W3C Verifiable Credentials** | APOA Tokens can be packaged as VCs for portability and cross-system verification. |
| **W3C DIDs** | APOA uses DIDs for principal and agent identity. |
| **ZCAP-LD** | APOA adopts ZCAP-LD's capability attenuation model for delegation chains. |
| **Web Bot Auth** | APOA's browser-based mode integrates with Web Bot Auth for agent identification to websites. |
| **1Password Agentic Autofill** | APOA's secure credential injection model is architecturally aligned with 1Password's approach. |
| **eIDAS 2** | APOA's VC packaging is designed to be compatible with EU Digital Identity Wallet attestations. |

### 15.1 "Isn't This Just a Verifiable Credential?"

No — and this distinction matters enough to warrant its own subsection.

Verifiable Credentials make **assertions about identity** — statements about *what an entity is*. APOA grants **bounded authority** — specifications of *what an agent can do*. These are fundamentally different operations with different security models.

The W3C community has debated this boundary extensively. Kyle Den Hartog, who contributed to both the VC and ZCAP-LD specifications, summarized the consensus: "trying to push square pegs into round holes often times leads to bugs which are elevated to mission critical authentication/authorization bypass vulnerabilities." Using VCs as permission tokens forces developers to implement two completely different behaviors (claims vs. permissions) within a single data model, and they will condition-switch incorrectly.

This is precisely why ZCAP-LD was developed as a separate specification from VCs — and why APOA exists as a protocol layer rather than a VC type.

The ZCAP-LD spec itself recommends the correct pattern: *"Use correlation (Verifiable Credentials) in a reasoning system as a path to make judgements about whether to hand an entity a specific set of initial capabilities. Use capabilities (ZCAP-LD) as the mechanism to grant and exercise authority through computing systems."*

APOA follows this pattern. A VC can **package** an APOA token for portability (see Section 12), but the authorization semantics — scope hierarchy, capability attenuation, delegation chain tracking, constraint enforcement, two access modes, audit trail requirements, and revocation cascading — are what APOA defines and what VCs alone do not provide.

The analogy: OAuth uses HTTP, but "isn't OAuth just HTTP?" is not a useful question. APOA uses VCs (optionally) as a container format, but the authorization protocol is the value.

---

## 16. Conformance

### 16.1 Authorization Server Conformance

An APOA-conformant Authorization Server MUST:
- Issue tokens conforming to the format in Section 4
- Enforce capability attenuation on delegation (Section 5.2)
- Provide a revocation endpoint (Section 9)
- Maintain audit logs per Section 10
- Publish a JWKS endpoint for token verification

### 16.2 Agent Provider Conformance

An APOA-conformant Agent Provider MUST:
- Verify token validity before every action
- Enforce scope and constraint boundaries at runtime
- Log all actions to the audit trail
- Respect revocation within the latency specified by the revocation method
- Never expose credentials to the AI model in browser-based mode

### 16.3 Service Conformance (Optional)

Services MAY integrate with APOA by:
- Accepting APOA Tokens as authorization (alongside or instead of standard OAuth tokens)
- Publishing an APOA integration manifest with supported scopes
- Participating in the revocation checking protocol
- Contributing to the audit trail

Service integration is optional. APOA is designed to work even without service-side adoption — via browser-based access mode.

---

## Appendix A: YAML Authorization Shorthand

For human readability, APOA authorizations can be expressed in YAML. This shorthand maps directly to the JWT claims defined in Section 4.

```yaml
authorization:
  type: "real_estate"                        # → purpose
  principal: "Juan Doe"                      # → sub
  agent: "HomeBot Pro"                       # → agt
  services:
    - service: "nationwidemortgage.com"      # → svc
      scope:                                 # → scope
        - "rate_lock:read"
        - "documents:read"
        - "timeline:read"
    - service: "docusign.com"
      scope:
        - "documents:read"
        - "documents:flag_for_review"
      constraints:                           # → constraints
        signing: false
  rules:                                     # → rules
    - "Alert me if any deadline is within 48 hours"
    - "Never sign, submit, or commit to anything"
  expires: "2026-06-15"                      # → exp
  revocable: true                            # → revocation_endpoint (present)
```

---

## Appendix B: Multi-Service Token Bundles

Real-world delegation often spans multiple services (see README examples). An APOA Token Bundle is a signed container holding multiple individual APOA Tokens — one per service — sharing common principal, agent, and metadata fields.

```json
{
  "type": "apoa-bundle",
  "principal": "did:apoa:principal:juan_abc123",
  "agent": "did:apoa:agent:homebot_pro_xyz",
  "purpose": "Home purchase coordination",
  "tokens": [
    { "svc": "nationwidemortgage.com", "scope": ["rate_lock:read", "documents:read"], ... },
    { "svc": "docusign.com", "scope": ["documents:read", "documents:flag_for_review"], ... },
    { "svc": "acmetitle.com", "scope": ["closing_timeline:read"], ... },
    { "svc": "redfin.com", "scope": ["saved_searches:read"], ... }
  ],
  "exp": 1718409600,
  "bundle_id": "apoa-bundle-home-purchase-2026"
}
```

Bundles enable atomic revocation — revoking the bundle revokes all contained tokens.

---

## Appendix C: Discovery and Metadata

### C.1 Authorization Server Metadata

APOA Authorization Servers SHOULD publish a metadata document at `/.well-known/apoa-configuration`:

```json
{
  "issuer": "https://auth.agenticpoa.com",
  "authorization_endpoint": "https://auth.agenticpoa.com/authorize",
  "token_endpoint": "https://auth.agenticpoa.com/token",
  "revocation_endpoint": "https://auth.agenticpoa.com/revoke",
  "jwks_uri": "https://auth.agenticpoa.com/.well-known/jwks.json",
  "scopes_supported": ["read", "search", "create_draft", "flag_for_review", "respond", "modify", "create", "submit", "delete", "admin"],
  "access_modes_supported": ["api", "browser"],
  "audit_levels_supported": ["all_actions", "mutations_only", "summary"],
  "max_delegation_depth": 3,
  "apoa_version": "0.1"
}
```

### C.2 Service Integration Manifest

Services that integrate with APOA MAY publish a manifest at `/.well-known/apoa-service`:

```json
{
  "service": "nationwidemortgage.com",
  "display_name": "Nationwide Mortgage Portal",
  "apoa_supported": true,
  "access_modes": ["browser"],
  "scopes_available": [
    "rate_lock:read",
    "documents:read",
    "timeline:read",
    "documents:upload"
  ],
  "constraints_supported": ["time_window", "rate_limit"],
  "contact": "security@nationwidemortgage.com"
}
```

---

## Appendix D: Future Work

The following items are identified for future specification versions:

### D.1 High-Authority Delegation

APOA v0.1 defines a monitoring and limited-action authorization layer — scoped read access, alerting, draft creation, and bounded mutations with confirmation requirements. This covers the majority of day-to-day agent delegation needs. However, the full vision of Agentic Power of Attorney requires support for *high-authority delegation*: agents that can negotiate, commit, and transact on behalf of the principal in legally significant contexts.

**Motivating scenario:** A principal instructs their AI agent to purchase a home — searching listings, analyzing comparables, drafting and negotiating offers, coordinating inspections, managing mortgage timelines, and executing closing documents, with the principal intervening only at defined decision points.

This requires several extensions to the APOA framework:

#### D.1.1 Legal POA Pairing

An APOA token alone is a digital authorization instrument, not a legal power of attorney. High-authority delegation requires a **paired legal instrument** — a legally executed POA (filed with the appropriate jurisdiction) that is cryptographically linked to the APOA token.

```
legal_poa_binding:
  instrument_type: "special_power_of_attorney"
  jurisdiction: "State of California"
  filing_reference: "POA-2026-LA-0042891"
  filed_date: "2026-03-15"
  notarization: true
  linked_apoa_token: "jti:uuid:abc123..."
  binding_hash: "sha256:e3b0c44298fc1c14..."
```

The `binding_hash` creates a cryptographic link between the legal document and the APOA token, allowing courts to verify that the digital authorization corresponds to the filed legal instrument. The Agent Provider (as a legal entity) acts as the named attorney-in-fact in the legal POA, with the APOA token constraining the scope of that legal authority.

#### D.1.2 Tiered Confirmation Thresholds

High-authority tokens introduce a `confirmation_tiers` claim that defines escalating approval requirements based on action significance:

```
confirmation_tiers:
  - tier: "autonomous"
    description: "Agent acts without confirmation"
    scope: ["listings:search", "comps:analyze", "documents:read",
            "tours:schedule_virtual", "inspections:read"]
    max_financial_impact: "$0"

  - tier: "notify_and_proceed"
    description: "Agent acts and notifies principal within 1 hour"
    scope: ["tours:schedule_in_person", "inspections:schedule",
            "documents:request"]
    max_financial_impact: "$500"

  - tier: "require_approval"
    description: "Agent drafts, principal approves before execution"
    scope: ["offers:draft", "counteroffers:draft", "rate_lock:request"]
    max_financial_impact: "$10,000"
    timeout: "24h"
    timeout_action: "expire"

  - tier: "require_multi_approval"
    description: "Requires principal + co-principal approval"
    scope: ["offers:submit", "contracts:execute", "closing:authorize"]
    max_financial_impact: "unlimited"
    required_approvers: ["principal", "co_principal:spouse"]
    timeout: "48h"
    timeout_action: "expire"
```

Actions that exceed their tier's `max_financial_impact` automatically escalate to the next tier. No action ever proceeds without the authorization level its tier requires.

#### D.1.3 Licensed Intermediary Integration

Many high-authority domains (real estate, securities, healthcare, law) require licensed professionals. The APOA framework accommodates this through an `intermediary` claim:

```
intermediary:
  type: "licensed_broker"
  entity: "Acme Realty LLC"
  license: "CA-DRE-01234567"
  license_jurisdiction: "State of California"
  role: "executing_broker"
  relationship: "The Agent Provider operates under the
                 supervision of the licensed intermediary
                 for regulated activities"
```

The intermediary bears legal responsibility for regulated actions, while the AI agent handles operational execution within the intermediary's supervisory framework. This maps to existing principal → broker → agent delegation patterns in real estate, securities, and other licensed professions.

#### D.1.4 Decision Audit Trail

High-authority delegation requires an enhanced audit trail that captures not just *actions* but *reasoning*:

```
decision_record:
  action: "counteroffers:draft"
  timestamp: "2026-07-12T14:30:00Z"
  inputs:
    - "Seller listed at $495,000"
    - "Comparable sales: $462K, $478K, $471K (median $471K)"
    - "Principal budget constraint: max $475,000"
    - "Days on market: 34 (above area median of 21)"
  recommendation: "Counteroffer at $458,000"
  reasoning_summary: "Below-median comps and extended DOM suggest
                      negotiating leverage. $458K leaves room for
                      expected counter while staying within budget."
  tier_applied: "require_approval"
  principal_action: "approved_with_modification"
  principal_modification: "Increase to $462,000"
  final_executed: "$462,000"
```

This creates a complete, cryptographically signed record of every decision — what the agent recommended, why, what the principal decided, and what was actually executed. This record serves dual purposes: real-time oversight for the principal and post-hoc verifiability for legal and compliance review.

#### D.1.5 Progressive Authority Escalation

Rather than granting high authority from the start, the specification will support a `trust_escalation` model where agent authority increases based on demonstrated performance:

```
trust_escalation:
  initial_tier: "monitoring_only"
  escalation_path:
    - after: "7d"
      condition: "zero_violations AND principal_satisfaction"
      escalate_to: "autonomous_scheduling"
    - after: "14d"
      condition: "successful_actions >= 10"
      escalate_to: "draft_and_propose"
    - requires: "explicit_principal_upgrade"
      escalate_to: "negotiate_and_commit"
```

This ensures that high-authority delegation is *earned*, not assumed, and gives principals confidence that autonomous actions have been validated through progressively more complex tasks.

#### D.1.6 Legal Framework Requirements

High-authority delegation will require alignment with:

- **UETA Section 14** — electronic agents forming binding contracts, with APOA providing the authorization evidence
- **Agency law (Restatement Third)** — the Agent Provider as agent, the principal as... principal, with APOA token as the written authorization
- **State-specific POA statutes** — APOA legal pairing instruments that satisfy jurisdictional filing requirements (notarization, witness, filing)
- **Regulatory licensing requirements** — intermediary integration satisfying professional licensing mandates
- **Consumer protection** — mandatory cooling-off periods, disclosure requirements, and cancellation rights preserved even in AI-mediated transactions

This is the most legally complex extension of the APOA framework and will require collaboration with legal scholars, regulators, and bar associations. The technical specification will be designed to *enable* legal compliance without *assuming* a specific regulatory outcome.

### D.2 Additional Future Work

2. **Formal IETF Internet-Draft submission** — packaging this specification as an I-D for community review
3. **Multi-principal authorization** — supporting authorizations that require consent from multiple principals (e.g., joint accounts)
4. **Agent reputation and trust scoring** — standardized metrics for agent trustworthiness
5. **Regulatory compliance modules** — jurisdiction-specific extensions (HIPAA for healthcare, SOC 2 for financial services)
6. **Service adoption incentives** — standard for services to advertise APOA support and receive qualified agent traffic
7. **Offline authorization** — supporting delegation in environments with intermittent connectivity
8. **Formal verification** — mathematical proofs of the attenuation and delegation chain properties

---

<p align="center">
  🐴
  <br>
  <em>Spec written by humans. Reviewed by Proxy. All errors are ours.</em>
</p>
