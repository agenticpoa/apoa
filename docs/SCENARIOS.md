# Scenarios

Concrete walk-throughs showing what an APOA token looks like in real consumer flows. The token shape here is the wire format — the same JSON the SDKs emit and consume.

For working code (SAFE negotiation between two agents), see the demo repos linked in the [README](../README.md#demos).

For more scenarios across other domains (healthcare coordination, new parent logistics, etc.), see [`EXAMPLES.md`](../EXAMPLES.md).

---

## Buying a home

You're buying a home. Congratulations! Here's your reward: four different web portals, none of which talk to each other, all with time-sensitive deadlines that will absolutely not remind you before they pass.

```yaml
authorization:
  type: "real_estate"
  principal: "Jane Doe"
  agent: "HomeBot Pro"
  agentProvider:
    name: "HomeBot Inc."
    contact: "support@homebot.ai"
  services:
    - service: "nationwidemortgage.com"           # No API. Browser mode.
      scope: ["rate_lock:read", "documents:read", "timeline:read"]
      accessMode: "browser"
      browserConfig:
        allowedUrls: ["https://portal.nationwidemortgage.com/*"]
        credentialVaultRef: "1password://vault/mortgage-portal"
        captureScreenshots: true
        blockedActions: ["click:*sign*", "click:*submit*", "click:*approve*"]

    - service: "docusign.com"                     # Has an API. API mode.
      scope: ["documents:read", "documents:flag_for_review"]
      accessMode: "api"
      constraints:
        signing: false

    - service: "acmetitle.com"                    # No API. Browser mode.
      scope: ["closing_timeline:read", "title_search:read"]
      accessMode: "browser"
      browserConfig:
        allowedUrls: ["https://portal.acmetitle.com/transaction/*"]
        credentialVaultRef: "1password://vault/title-company"

    - service: "redfin.com"                       # No API. Browser mode.
      scope: ["saved_searches:read", "market_data:read"]
      accessMode: "browser"
      browserConfig:
        allowedUrls: ["https://www.redfin.com/myredfin/*"]
        credentialVaultRef: "1password://vault/redfin"
        blockedActions: ["click:*offer*", "click:*tour*"]
  rules:
    - "Alert me if any deadline is within 48 hours"          # soft — logged + callback
    - "Never sign, submit, or commit to anything"            # hard — machine-enforced
    - "Summarize new activity daily at 8am"                  # soft — logged
  legal:
    model: "provider-as-agent"
    jurisdiction: "US-CA"
    legalBasis: ["UETA-14", "E-SIGN"]
  expires: "2026-06-15"
  revocable: true
```

Four services. Three browser-based, one API. Zero signing authority. Every action logged. Instantly revocable. No passwords shared with any AI model.

**Today:** You spend hours each week logging into portals, refreshing pages, and lying awake at night wondering if you missed a disclosure deadline.

**With APOA:** Your agent monitors everything, alerts you to what matters, and keeps a complete audit trail — without ever having the authority to commit you to anything. And as the standard evolves toward [high-authority delegation](../SPEC.md#appendix-d-future-work), the same agent that monitors your mortgage today negotiates the deal tomorrow.

---

← Back to [README](../README.md)
