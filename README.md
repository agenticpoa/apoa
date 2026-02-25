![APOA — Agentic Power of Attorney](assets/banner.png)

# 🐴 Agentic Power of Attorney (APOA)

*Pronounced "ah-POH-ah" like aloha 🤙*

**The authorization standard for the AI agent economy.**

> In January 2026, a developer named AJ Stuyvenberg [gave an AI agent access to his email, calendar, and browser](https://aaronstuyvenberg.com/posts/clawd-bought-a-car) and told it to buy him a car. The agent searched inventory, contacted dealerships, negotiated a $4,200 discount, and closed the deal. It also sent a confidential email to the wrong person — because its entire authorization model was a natural language prompt that said "prompt me before replying to anything consequential."
>
> This is not a future problem. AI agents are already negotiating, transacting, and acting on behalf of humans — today, right now, with zero formal authorization, no audit trail, and no kill switch.
>
> We think the infrastructure should catch up.

---

## The Vision

Imagine telling your AI agent:

> *"Buy me a house. Budget is $475K. Three bedrooms, good school district, within 30 minutes of the office. I need to be in by August. Handle it."*

The agent searches listings. Analyzes comps. Drafts an offer at $458K. Negotiates with the seller's agent. Coordinates the inspection. Manages the mortgage timeline. Flags exactly three things for your attention: the final offer price, the inspection results, and the closing signature.

Everything else? Handled.

The AI capabilities are here. The authorization infrastructure isn't. That's what APOA fixes.

---

## What Is Agentic POA?

There's a concept that has existed in law for *literally centuries*: power of attorney. You sign a document, you say "this person can do these things on my behalf, within these limits, until this date." Done. It works for real estate. It works for healthcare. It works for finances. Your grandmother has one. It's not complicated.

Agentic Power of Attorney (APOA) is that — but for AI agents operating in the digital world.

It's an open standard that defines how a human (the **Principal**) formally authorizes an AI agent (the **Agent**) to access and act within digital services (the **Services**) on their behalf — with explicit scope, time limits, and a full audit trail.

Think of it as the digital equivalent of that document your grandmother has — but purpose-built for AI, designed for modern digital services, and enforceable at the protocol level.

### Core Principles

- **Scoped by default** — every authorization specifies exactly what the agent can and cannot do. No more "here's my entire digital life, good luck."
- **Time-bounded** — authorizations expire. Because "forever" is not a responsible access policy.
- **Revocable instantly** — changed your mind? One click. Done. Try doing that with a shared password.
- **Auditable** — every action the agent takes is logged and attributable. When the agent sends an email to the wrong person, you know exactly what happened and why.
- **Works everywhere** — API-based services, browser-based services, and everything in between. Even your insurance company's website from 2004.
- **Legally meaningful** — designed to align with existing electronic agency law (UETA, E-SIGN) and emerging AI governance frameworks.

---

## The Problem Today

Here's what "agent authorization" looks like in 2026:

- **Share your password** — hand your entire digital life to an AI. The Clawdbot approach. It works until it doesn't.
- **Use an API** — great, if the service has one. Most don't. Have you *seen* your insurance company's website?
- **Browser automation** — the AI clicks buttons and hopes nothing changes. No scoped access, no audit trail, no way to limit what it touches.
- **Do it yourself** — which is the thing we were trying to *stop doing*

The AI agent that bought a car did it with *all four* of these approaches simultaneously, held together with natural language instructions. That's not an authorization model — that's a prayer.

APOA replaces prayers with infrastructure.

## How It Works

```
┌──────────────┐         ┌──────────────────┐         ┌──────────────┐
│              │         │                  │         │              │
│  Principal   │──issues──▶  APOA Token     │──used by─▶   Agent     │
│  (You)       │         │  (Authorization) │         │  (AI)        │
│              │         │                  │         │              │
└──────────────┘         └──────────────────┘         └──────┬───────┘
                                                             │
                                                          accesses
                                                             │
                                                      ┌──────▼───────┐
                                                      │              │
                                                      │   Service    │
                                                      │  (MyChart,   │
                                                      │   Anthem,    │
                                                      │   MLS, etc.) │
                                                      │              │
                                                      └──────────────┘
```

**The APOA Token** is a signed, structured authorization that contains:

| Field | Description | Example |
|---|---|---|
| `principal` | The human granting authority | `did:apoa:juan_xyz` |
| `agent` | The AI agent receiving authority | `did:apoa:agent_abc` |
| `service` | The target service | `mychart.com` |
| `scope` | What the agent can do | `["messages:read", "calendar:read"]` |
| `constraints` | Limits on the agent's actions | `{"max_response_length": 500}` |
| `not_before` | When authorization begins | `2026-03-01T00:00:00Z` |
| `expires` | When authorization ends | `2026-06-01T00:00:00Z` |
| `audit` | Logging requirements | `"all_actions"` |

## Real-World Scenarios

Agentic POA maps directly to the categories of traditional power of attorney — but for the digital world. And here's the thing: these aren't hypothetical. These are the actual, soul-crushing, portal-logging-into situations that real people deal with *every single day.*

### 🏠 Real Estate Transaction

You're buying a home. Congratulations! Here's your reward: six different web portals, none of which talk to each other, all with time-sensitive deadlines that will absolutely not remind you before they pass.

```yaml
authorization:
  type: "real_estate"
  principal: "Juan Doe"
  agent: "HomeBot Pro"
  services:
    - service: "nationwidemortgage.com"
      scope: ["rate_lock:read", "documents:read", "timeline:read"]
    - service: "docusign.com"
      scope: ["documents:read", "documents:flag_for_review"]
      constraints:
        signing: false  # flag only, never sign
    - service: "acmetitle.com"
      scope: ["closing_timeline:read", "document_status:read"]
    - service: "redfin.com"
      scope: ["saved_searches:read", "listing_updates:read"]
  rules:
    - "Alert me if any deadline is within 48 hours"
    - "Never sign, submit, or commit to anything"
    - "Summarize new activity daily at 8am"
  expires: "2026-06-15"  # closing date
  revocable: true
```

**Today:** You spend hours each week logging into portals, refreshing pages, and lying awake at night wondering if you missed a disclosure deadline.

**With APOA:** Your agent monitors everything, alerts you to what matters, and keeps a complete audit trail — without ever having the authority to commit you to anything. And as the standard evolves toward [high-authority delegation](SPEC.md#appendix-d-future-work), the same agent that monitors your mortgage today negotiates the deal tomorrow.

### 🏥 Healthcare / Medical Coordination

Your parent has a chronic condition. You're now a project manager — except the project is keeping a human being alive, and your tools are four unrelated patient portals that were each apparently designed by someone who has never used a computer.

```yaml
authorization:
  type: "healthcare"
  principal: "Juan Doe"
  agent: "CareCoordinator"
  services:
    - service: "mychart.com"
      scope: ["appointments:read", "test_results:read", "messages:read"]
      constraints:
        modify: false  # read-only, never respond to providers
    - service: "aetna.com"
      scope: ["claims:read", "prior_auth:read", "eob:read"]
    - service: "cvs.com"
      scope: ["prescriptions:read", "refill_status:read"]
    - service: "walgreens.com"
      scope: ["prescriptions:read", "refill_status:read"]
  rules:
    - "Alert me when new test results are posted"
    - "Flag any insurance claim that's been pending more than 14 days"
    - "Notify me 3 days before any prescription refill is due"
    - "Never communicate with providers or approve treatments"
  expires: "2027-02-28"
  revocable: true
```

**Today:** You're logging into four different portals every week, terrified of missing a result or letting a prescription lapse. You've become a full-time unpaid medical secretary. *Nobody trained you for this.*

**With APOA:** Your agent watches everything, connects the dots across providers and pharmacies, and makes sure nothing falls through the cracks — while never having the authority to make a medical decision. It's a healthcare coordinator that actually coordinates.

### 👶 New Parent Logistics

You just had a baby. Mazel tov! Now here's a list of seventeen things you need to do within thirty days, all requiring different websites, none of which you can remember the password to, and you haven't slept since Tuesday.

```yaml
authorization:
  type: "limited_special"
  principal: "Juan Doe"
  agent: "NewParentHelper"
  services:
    - service: "anthem.com"
      scope: ["dependents:read", "enrollment:read", "claims:read"]
      constraints:
        modify_enrollment: false  # track status only
    - service: "brightwheel.com"
      scope: ["waitlist:read", "applications:read", "application_status:read"]
    - service: "zocdoc.com"
      scope: ["appointments:read", "availability:search"]
      constraints:
        booking: false  # find options, human books
    - service: "ssa.gov"
      scope: ["application_status:read"]
  rules:
    - "Alert me if insurance enrollment deadline is within 7 days"
    - "Check daycare waitlist position daily and notify on any movement"
    - "Find available pediatricians accepting our insurance within 10 miles"
    - "Track Social Security card application status"
    - "Never submit applications or make commitments on my behalf"
  expires: "2026-06-01"  # 90 days post-birth
  revocable: true
```

**Today:** You're filling out the same personal information on a dozen different portals at 3am with one hand while holding a baby in the other, praying you don't miss an enrollment window that — and this is the fun part — *nobody told you about.*

**With APOA:** Your agent tracks every deadline, monitors every waitlist, and surfaces exactly what needs your attention — so you can focus on the tiny human who, let's be honest, is not going to focus on any of this themselves.

## Why Existing Solutions Fall Short

Now, you might be thinking: "Don't we already have solutions for this?" And to that I say: *kind of.* In the same way that a horse-drawn carriage is *kind of* a car.

| Approach | Works with APIs? | Works without APIs? | Scoped? | Time-bounded? | Revocable? | Auditable? | Delegation chains? | Legally meaningful? |
|---|---|---|---|---|---|---|---|---|
| OAuth 2.0 / OIDC | ✅ | ❌ | ✅ | ✅ | ✅ | Partial | ❌ | ❌ |
| MCP Auth | ✅ | ❌ | ✅ | ❌ | ❌ | Partial | ❌ | ❌ |
| W3C Verifiable Credentials | ✅ | ❌ | ❌ | ✅ | Partial | ❌ | ❌ | ❌ |
| ZCAP-LD | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ |
| Agent frameworks (Clawdbot, etc.) | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Browser automation | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Password sharing | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| 1Password Agent Autofill | ❌ | ✅ | ❌ | ❌ | ❌ | Partial | ❌ | ❌ |
| **Agentic POA** | **✅** | **✅** | **✅** | **✅** | **✅** | **✅** | **✅** | **✅** |

A few things worth noting: VCs are an *identity* layer — they answer "what is this entity?" not "what can this entity do?" ZCAP-LD is the closest existing standard to APOA and we build on it directly, but it doesn't address browser-based services, audit requirements, or legal alignment. Agent frameworks like Clawdbot are where the actual action is happening right now — and they have essentially zero authorization infrastructure. That's the gap.

## Technical Foundation

Alright, for the engineers in the room who've been patiently waiting for the acronyms — here you go. APOA builds on proven standards rather than reinventing the wheel, because the world has enough competing standards:

- **JWT (RFC 7519)** — token format for authorization instruments
- **OAuth 2.1** — authorization flows for API-based services
- **W3C Verifiable Credentials** — portable, cryptographically signed authorization
- **ZCAP-LD** — capability-based delegation with natural attenuation (each delegation can only reduce, never expand, permissions)
- **W3C DIDs** — decentralized identity for both principals and agents
- **Web Bot Auth** (emerging) — agent identification for browser-based services

See [SPEC.md](SPEC.md) for the full technical specification. It's riveting. Well, it's thorough.

## Where APOA Fits in Your Stack

APOA isn't a replacement for the tools you're already using — it's the authorization layer they're all missing. Here's how it integrates with the current AI ecosystem:

### Consumer AI platforms (ChatGPT, Claude, Gemini)

Today, when you connect Claude to your email via MCP or give ChatGPT a plugin, you grant permissions through OAuth popups — one service at a time, with no unified view of what you've authorized. APOA sits above this as the policy layer. One authorization document governs everything the agent can touch: which services, which scopes, what's off-limits, when it expires. The platform enforces it. You get a single dashboard instead of a trail of forgotten OAuth grants.

### Agentic coding tools (Claude Code, Codex, Cursor agents)

Claude Code can read your files, run commands, and make network requests. The authorization model today is: you launched it, so it can do whatever. APOA would let you scope it — read/write only in this repo, no network access except npm and GitHub, no touching ~/.ssh or ~/.aws. The [confirmation tiers](SPEC.md#appendix-d-future-work) map naturally: autonomous for reading and writing code, require approval for running tests, require explicit confirmation for pushing to main.

### Autonomous agent frameworks (OpenClaw, AutoGPT, CrewAI)

This is where the need is most urgent. These frameworks give AI persistent access to your email, browser, and calendar. The current authorization model is a natural language instruction — literally "ask me before doing anything important." APOA replaces that with machine-enforceable authorization. The framework reads the APOA token on startup and knows exactly what it can access, what requires confirmation, and what's forbidden. Every action is logged. The LLM doesn't self-police — the infrastructure does.

### MCP servers (the connector layer)

MCP is becoming the standard for connecting AI to external services. Each MCP server currently handles its own auth. APOA sits above MCP as the policy language — MCP handles *how* to connect to Gmail, APOA handles *what the agent is allowed to do* in Gmail. An APOA-compliant MCP server checks the token before every tool call, verifies the action is in scope, logs it, and rejects anything that exceeds authorization. This is where integration with agent infrastructure providers like [Arcade.dev](https://arcade.dev) comes in — they build the runtime, APOA provides the policy.

### Agent-to-agent delegation

When your agent needs to delegate a subtask to another agent — say, your real estate agent hands off the inspection scheduling to a specialized service — APOA's delegation chains handle this natively. Each delegation can only *reduce* permissions, never expand them. The chain is cryptographically verifiable end-to-end.

### The adoption path

APOA doesn't need top-down adoption from OpenAI or Anthropic on day one. The realistic path is bottom-up:

1. **Agent frameworks** adopt it first — they have the most urgent need and the least existing auth infrastructure
2. **MCP server providers** integrate it as their policy format — every platform using those servers gets APOA for free
3. **Consumer platforms** adopt it because the ecosystem already speaks APOA — easier to join a standard than invent a new one

## Project Status

🚧 **Early stage — spec in active development**

We're building this in the open, because that's how standards should work. The specification is a working draft and will evolve based on community feedback, security review, and the inevitable "have you considered..." comments that make everything better.

### Roadmap

- [x] Problem statement and concept definition
- [x] Landscape analysis of existing standards and gaps
- [ ] Draft specification v0.1
- [ ] Reference implementation (SDK)
- [ ] Consumer product prototype (agent authorization dashboard)
- [ ] Security audit
- [ ] Formal standards body submission

## Get Involved

This is an open standard. It will only work if actual humans — not just the three of us — help shape it.

- **Read the spec** — [SPEC.md](SPEC.md) is the working draft
- **Open an issue** — questions, critiques, and "this will never work because..." are all welcome
- **Join the discussion** — [Discussions tab](../../discussions) for broader conversations
- **Build with it** — if you're working on AI agents, browser automation, or identity, we genuinely want your input
- **Spread the word** — the more people thinking about this problem, the less likely we end up with twelve competing solutions (see: [XKCD 927](https://xkcd.com/927/))

## FAQ

**Is this a real legal power of attorney?**
No. And this is important, so let me say it clearly: AI systems cannot legally hold power of attorney under any current jurisdiction. APOA is a *technical* authorization standard that borrows the *conceptual framework* of power of attorney — scoped delegation, bounded authority, principal-agent relationship — and applies it to digital agent authorization. That said, it's designed to align with existing electronic agency law (UETA, E-SIGN) and could serve as the technical foundation for future legal recognition. But we're not lawyers. *Please don't sue us.*

**How is this different from OAuth?**
OAuth handles delegated authorization for API-based services. Which is great — if you live in a world where every service has an API. You do not live in that world. APOA extends the model to services without APIs (via browser-based authorization), adds agent-specific features (delegation depth, intent binding, agent identity verification), and wraps everything in a legally meaningful framework. For API-based services, APOA uses OAuth under the hood. It's not a replacement, it's a completion.

**What about security? Isn't this just fancy password sharing?**
No, and I take personal offense at the suggestion. APOA never requires sharing credentials with the agent. For API-based services, it uses standard OAuth token flows. For browser-based services, it leverages secure credential injection (where credentials are injected into browser contexts without the AI model ever seeing them). The principal retains full control, with instant revocation and complete audit trails. It's the *opposite* of password sharing. It's password *never-sharing.*

**Why "Power of Attorney"?**
Because it's the best existing mental model for what this is: one entity formally authorizing another to act on their behalf, within defined boundaries, for a specific purpose and duration. Your grandmother understands what a power of attorney is. That intuition maps directly to what we need for AI agent authorization. We considered calling it "Agentic Delegated Authorization Framework" but we wanted people to actually read the README.

**Is there an APOA token or cryptocurrency?**
No. God, no. There is no coin, no token, no NFT, no blockchain-based financial product, and no airdrop. If someone is selling you one, they are scamming you and we would appreciate you letting us know so we can make their life difficult. The word "token" in this project refers exclusively to a signed JWT authorization document. It has the market value of a JSON file, which is zero dollars.

**Isn't this just a Verifiable Credential?**
This is a great question and we're glad you asked it instead of just posting "skill issue, use VCs" on Hacker News. Verifiable Credentials answer the question *"what is this entity?"* — they make assertions about identity. APOA answers a different question: *"what can this agent DO?"* — it grants bounded authority with scoped permissions, capability attenuation, delegation chains, constraint enforcement, audit trails, and revocation cascading. The W3C community has debated this exact boundary extensively, and the consensus is clear: using VCs as permission tokens is dangerous because it mixes claims with authorization, and developers will implement it wrong. That's why ZCAP-LD exists as a separate spec. APOA follows the same principle — a VC can *package* an APOA token for portability (and we support this in the spec), but the authorization semantics are what APOA defines and what VCs alone don't provide. Think of it this way: "isn't OAuth just HTTP?" Technically yes, but that's not a useful answer.

## ⚠️ No Tokens. No Coins. No NFTs.

Let us be unambiguous about this: **Agentic POA has no cryptocurrency, no token, no coin, no NFT, and no blockchain-based financial product of any kind.** Not now. Not ever.

If someone is selling you an "APOA token," a "Proxy coin," or any financial instrument claiming to be associated with this project — **it is a scam.** We are not affiliated with it. We did not authorize it. We would like it to stop.

APOA is an open technical standard. The only "token" in this project is a signed authorization document — a JWT. It is not tradeable. It is not an investment. It will not "go to the moon." It goes to your mortgage lender's web portal, which is considerably less exciting but *significantly more useful.*

If you see anyone attempting to sell a financial product using the APOA or Proxy name, please [open an issue](../../issues) so we can address it.

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Origin

Agentic Power of Attorney was coined in February 2026 to address the critical gap in AI agent authorization infrastructure — the absence of a universal standard for delegating bounded digital authority from humans to AI agents. Its mascot is Proxy, named for the oldest meaning of the word: one authorized to act on another's behalf.

*Here's your moment of zen.*

---

---

🐴 *Meet **Proxy** — a [Pony of the Americas](https://en.wikipedia.org/wiki/Pony_of_the_Americas). Calm, intelligent, and built to earn your trust. Which is more than we can say for your insurance company's login page.*
