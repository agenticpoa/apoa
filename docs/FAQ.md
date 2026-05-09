# FAQ

### Is this a real legal power of attorney?

No. AI systems cannot legally hold power of attorney under any jurisdiction. APOA is a *technical* authorization standard that borrows the *conceptual framework* — scoped delegation, bounded authority, principal-agent relationship. It's designed to align with existing electronic agency law (UETA, E-SIGN) and could serve as the technical foundation for future legal recognition. But we're not lawyers. *Please don't sue us.*

### How is this different from OAuth?

OAuth handles delegated authorization for API-based services. Which is great — if you live in a world where every service has an API. You do not live in that world. APOA extends the model to services without APIs (via browser-based authorization with secure credential injection), adds agent-specific features (delegation chains, natural language rules, intent binding), and wraps everything in a legally meaningful framework. For API-based services, APOA uses OAuth under the hood. It's not a replacement, it's a completion.

### Isn't this just fancy password sharing?

I take personal offense at the suggestion. APOA never shares credentials with the agent. For browser-based services, it uses secure credential injection — architecturally aligned with 1Password's Agentic Autofill — where a vault injects credentials into the browser session through an encrypted channel. The AI model never sees them. The APOA token authorizes the injection and scopes the session. The vault handles the credentials. It's the *opposite* of password sharing. It's password *never-sharing.*

### Why "Power of Attorney"?

Because it's the best existing mental model: one entity formally authorizing another to act on their behalf, within defined boundaries, for a specific purpose and duration. Your grandmother understands what a power of attorney is. That intuition maps directly to what we need for AI agent authorization. We considered "Agentic Delegated Authorization Framework" but we wanted people to actually read the README.

### Isn't this just a Verifiable Credential?

VCs answer "what is this entity?" — assertions about identity. APOA answers "what can this agent DO?" — bounded authority with scoped permissions, capability attenuation, delegation chains, constraint enforcement, audit trails, and revocation cascading. The W3C community debated this boundary extensively; the consensus is clear: using VCs as permission tokens mixes claims with authorization, and developers will implement it wrong. That's why ZCAP-LD exists as a separate spec. A VC can *package* an APOA token for portability, but the authorization semantics are what APOA defines and what VCs alone don't provide.

### Is there an APOA token or cryptocurrency?

No. God, no. There is no coin, no NFT, no blockchain-based financial product, and no airdrop. The word "token" in this project refers exclusively to a signed JWT authorization document. It has the market value of a JSON file, which is zero dollars. If someone is selling you one, they are scamming you. Please [open an issue](../../../issues) so we can make their life difficult.

---

← Back to [README](../README.md)
