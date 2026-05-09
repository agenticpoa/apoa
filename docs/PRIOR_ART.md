# Prior Art & Related Work

APOA was designed in February 2026. We later found independent work arriving at similar conclusions from different directions — which is what you want to see when you're working on a standard.

**IETF draft-vattaparambil-positioning-of-poa-01 (October 2023)** — researchers at Lulea University of Technology applied the same Power of Attorney metaphor to IoT device authorization. Their principal-agent-delegation model for Cyber Physical Systems is strikingly parallel, though they target smart devices rather than AI agents. APOA was developed independently; the convergence validates the conceptual model.

**Google DeepMind, "Intelligent AI Delegation" (February 2026)** — Tomašev, Franklin, and Osindero proposed delegation with authority transfer, accountability chains, and capability attenuation via Delegation Capability Tokens. Their paper explicitly flagged MCP's missing policy layer for deep delegation chains — the gap APOA was designed to fill. Developed concurrently and independently.

**MCP 2026 Roadmap (March 2026)** — the official roadmap lists deeper security and authorization as a priority, with active SEPs for DPoP and Workload Identity Federation. APOA is designed as a complementary policy layer above MCP, not a replacement.

**IETF Agent Auth Drafts (2025-2026)** — multiple active Internet-Drafts tackle agent delegation within OAuth. These address API-based authorization. APOA's Mode B addresses the complementary problem: services without APIs.

---

← Back to [README](../README.md)
