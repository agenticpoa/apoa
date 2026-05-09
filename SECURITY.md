# Security Policy

APOA is authorization infrastructure. We treat security reports seriously and ship fixes quickly.

## Supported Versions

| Package | Versions |
| --- | --- |
| `@apoa/core` | latest minor (`0.1.x`) |
| `apoa` (Python) | latest minor (`0.1.x`) |

The project is pre-1.0 and moves fast. Fixes land on the latest version; older patch versions are not backported.

## Reporting a Vulnerability

**Please do not file a public GitHub issue for security reports.**

Use one of the following private channels:

1. **GitHub Security Advisories** (preferred) — go to the repo's [Security tab](../../security/advisories/new) and open a private advisory. This routes directly to maintainers and gives us a place to coordinate a fix.
2. **Email** — `agenticpoa@users.noreply.github.com` if GitHub Advisories isn't an option.

When reporting, please include:

- A clear description of the vulnerability and its impact.
- Affected SDK (`@apoa/core` and/or `apoa`) and version(s).
- Reproduction steps or a minimal proof of concept.
- Any suggested mitigation, if you have one.

## What to Expect

- **Acknowledgement** within 3 business days of report receipt.
- **Initial assessment** (severity + reproducibility) within 7 business days.
- **Coordinated disclosure** — we'll work with you on a timeline. Default target: a patched release within 30 days for high-severity issues.
- **Credit** in the release notes if you want it. We're happy to coordinate a CVE for impactful findings.

## Scope

In scope:

- The TypeScript SDK (`sdk/`) and Python SDK (`sdk-python/`).
- The published packages on npm (`@apoa/core`) and PyPI (`apoa`).
- The APOA specification (`SPEC.md`) — design-level issues that materially weaken the security model.

Out of scope:

- Demo repositories and ecosystem packages — report directly to those repos.
- Vulnerabilities in `jose`, `PyJWT`, or other upstream dependencies — please report upstream first; we'll coordinate updates here.
- Issues that require physical access to a user's machine, a compromised vault, or a malicious browser runtime — APOA is a policy layer and assumes those components are trusted per the architecture in [`SPEC.md`](SPEC.md).

## Defense Notes

For context on how APOA's security model is structured:

- The SDK is a **policy engine**, not an enforcement point. Audit logs and revocation must be honored by the agent runtime; bypassing the SDK is outside the SDK's threat model.
- Keys are managed by the principal/agent infrastructure. The SDK does not store private keys.
- Browser-mode credential injection happens in the vault and the browser runtime — the SDK never sees credentials.

If you're unsure whether something is in scope, report it anyway. We'd rather triage a borderline report than miss a real one.
