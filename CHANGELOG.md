# Changelog

All notable changes to the APOA SDKs are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning](https://semver.org/). The TypeScript SDK (`@apoa/core`) and Python SDK (`apoa`) are released independently but version-aligned where possible.

---

## [Unreleased]

### Added

- `docs/FAQ.md` and `docs/PRIOR_ART.md` — long-form prose moved out of the README to keep the entry point tight.
- `Demos` section in the README pointing to [`negotiate`](https://github.com/agenticpoa/negotiate), [`claw-negotiate`](https://github.com/agenticpoa/claw-negotiate), and [`sshsign`](https://github.com/agenticpoa/sshsign).
- `.github/workflows/ci.yml` — GitHub Actions matrix for the TypeScript SDK (Node 20, 22) and Python SDK (3.11, 3.12, 3.13). The Python job regenerates the cross-SDK fixture from the TS source so `test_cross_sdk.py` exercises real interop on every run.
- `SECURITY.md` — vulnerability disclosure policy.
- `CHANGELOG.md` — this file.
- `sdks/python/examples/` — four worked examples (`quickstart.py`, `delegation_chain.py`, `healthcare.py`, `home_purchase.py`) mirroring the TypeScript SDK's example coverage.

### Changed

- **Repo layout**: SDKs moved from `sdk/` and `sdk-python/` to `sdks/typescript/` and `sdks/python/` so the `sdks/` parent groups all language implementations (matching the plural `docs/` and `assets/` convention). Updates to README, SECURITY, package metadata, CI workflow, and the cross-SDK fixture import path.
- **`@apoa/core`**: `engines.node` raised from `>=18` to `>=20`. `jose@6` uses Web Crypto via `globalThis.crypto`, which isn't a Node global until v19; Node 18 reached end-of-life on 2025-04-30, so the supported-runtime claim now matches reality.
- README ecosystem list now includes `sshsign` (SSH signing service used by the negotiation demos).
- README adds a dedicated Cross-SDK Compatibility section showing TS-to-Python token round-trip; the `@apoa/core` README drops a hardcoded test count that would go stale silently.

---

## `apoa` 0.2.0 — 2026-05-09

### Changed

- **BREAKING**: `log_action` and `client.log_action` now take an `AuditEntryInput` dataclass instead of `(action, service, result, **details)`. This matches the TypeScript SDK's `logAction(tokenId, entry)` signature one-to-one and lets callers populate the typed `url`, `access_mode`, and `screenshot_ref` fields directly. New `AuditEntryInput` type exported from `apoa`.
  - Before: `client.log_action(jti, "read", "svc.com", "allowed", note="x")`
  - After: `client.log_action(jti, AuditEntryInput(action="read", service="svc.com", result="allowed", details={"note": "x"}))`

---

## `@apoa/core` 0.1.2 — 2026-04

### Changed

- npm publishing metadata: package description, keywords, repository, homepage, bugs URL, and a dedicated package README.

---

## `@apoa/core` 0.1.1 / `apoa` 0.1.1 — 2026-04

### Fixed

- Seven findings from the initial security audit, addressed across two patch passes.

---

## `apoa` 0.1.0 — 2026-04

### Added

- Initial Python SDK release with full cross-SDK compatibility against `@apoa/core`.
  Tokens signed by either SDK validate in the other; camelCase JWT payload to snake_case Python mapping handled at the serialization boundary.

---

## `@apoa/core` 0.1.0 — 2026-03

### Added

- Initial reference TypeScript SDK release.
- Token lifecycle: create, sign (Ed25519 / ES256), validate, parse.
- Scope matching with hierarchical patterns.
- Constraint enforcement and hard/soft rule evaluation.
- One-call `authorize()` covering revocation, scope, constraints, and rules.
- Delegation chains with cryptographic capability attenuation.
- Cascade revocation across delegation trees.
- Append-only audit trail per token.
- Browser-mode (`accessMode: "browser"`) configuration for credential-vault injection.
- Pluggable `RevocationStore` and `AuditStore` interfaces with in-memory implementations for development and testing.
