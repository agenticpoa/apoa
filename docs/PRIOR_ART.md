# Prior Art & Related Work

Authorization for AI agents is an active area with credible academic and
implementation work predating and paralleling APOA. APOA was designed
independently; we found much of the work below only afterward. We take that
as a good sign — independent convergence on similar primitives suggests the
problem is real and the shape of a solution is becoming legible. This page
lists related work; the final section describes where APOA's contribution is
distinct. The teams below arrived at overlapping ideas from different
directions, and APOA is glad to be in good company.

## Academic work

**South et al., "Authenticated Delegation and Authorized AI Agents"
(arXiv 2501.09674, 2025-01-16)** — MIT (South, Marro, Hardjono, Mahari,
Whitney, Greenwood, Chan, Pentland). Proposes extending OAuth 2.0 and OpenID
Connect with agent-specific credentials and metadata; a verifiable delegation
credential carrying agent identity, scoped permissions with contextual
restrictions, parent identifiers for chained delegation, and cryptographic
signatures; and a layer for translating natural-language permissions into
auditable access-control rules.

**Google DeepMind, "Intelligent AI Delegation" (arXiv 2602.11865,
2026-02-12)** — Tomašev, Franklin, and Osindero. Frames delegation as transfer
of authority, responsibility, and accountability, with attenuation via
Delegation Capability Tokens built on macaroons/biscuits.

**AIP: Agent Identity Protocol (arXiv 2603.24775, dated 2026-03-25)** —
proposes "Invocation-Bound Capability Tokens" fusing identity, attenuated
authorization, and provenance into an append-only chain, with MCP and A2A
bindings. Caveat: the arXiv identifier is anomalous in format; treat as an
indication the idea is circulating rather than as finalized, peer-reviewed
work.

## IETF drafts

**draft-niyikiza-oauth-attenuating-agent-tokens-00 (2026-03-16)** — JWT-based
attenuating authorization tokens with per-tool-call argument constraints, a
delegation/execution token split, parent-hash chain linkage, and formal
monotonic-attenuation invariants.

**draft-vattaparambil-positioning-of-poa-01 (2023)** — researchers at Luleå
University of Technology applied the Power of Attorney metaphor to IoT device
authorization: principal-agent-delegation for Cyber-Physical Systems.

## Implementations

**aeoess/agent-passport-system (created 2026-02-18)** — a shipping npm
protocol for agent identity, delegation, governance, and commerce: Ed25519
passports, scoped delegation with monotonic narrowing, cascade revocation
through the full chain, signed receipts per action, sub-2ms gateway
enforcement, Zenodo DOI. Engaging the A2A standards process via A2A Issue
#1575 (2026-03-02, open).

**mcp-delegation-gateway / AVCAD (created 2026-01-27)** — a third-party MCP
authorization gateway with delegation chains, verifiable attenuation,
per-tool mapping, and signed audit receipts.

## MCP authorization

MCP's current authorization spec (revision 2025-11-25) is connection-level
OAuth 2.1 — no per-tool-call scoping, delegation, or audit requirement in the
spec itself. The 2026 MCP roadmap (2026-03-09) lists "finer-grained
least-privilege scopes" under its "On the Horizon" section. Open proposals
address pieces of the gap, none accepted: SEP-2385 Tool Authorization
Manifest (2026-03-11), Issue #333 (delegation chains, 2025-04-14, closed),
Issue #214 (On-Behalf-Of token exchange, 2025-03-21, closed).

## Where APOA is differentiated

On API-based, tool-call-scoped delegation, APOA is one of several entrants and
not the first — South et al. framed it, agent-passport-system is a parallel
implementation, and multiple IETF drafts cover the token mechanics. None of
these has emerged as an accepted standard; the solution space is crowded, but
the problem is not solved. APOA can be read as one concrete, protocol-level
operationalization of the framework South et al. described.

APOA's distinct contribution is **Mode B: authorization for services that
have no API** — secure credential injection into a URL-jailed, audited,
revocable browser session where the AI model never sees the credentials. As
of May 2026 no shipping product covers this end-to-end: 1Password's Secure
Agentic Autofill (Early Access since 2025-10-08) provides the
credential-isolation primitive but not the scoping, audit, or revocation
layer; browser-agent platforms reuse the user's full session with no
isolation. The differentiation is real but time-boxed — 1Password has
publicly roadmapped scoped issuance and audit for H2 2026.

## Help us keep this honest

This list is a snapshot of a fast-moving field, and it is certainly
incomplete. If we've overlooked relevant work — yours or anyone else's —
please open an issue or a pull request. We would much rather credit prior
art than miss it.

---

← Back to [README](../README.md)
```
