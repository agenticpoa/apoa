# Changelog

All notable changes to the APOA SDKs are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning](https://semver.org/). The TypeScript SDK (`@apoa/core`) and Python SDK (`apoa`) are released independently but version-aligned where possible.

---

## [Unreleased]

### Security

- **Constraint attenuation hardening (both SDKs).** A child delegation that omitted a parent's `false` constraint (e.g. parent `{ signing: false }`, child with no constraints) previously slipped through `verifyAttenuation` / `_verify_attenuation` and caused the child's `authorize()` to skip the constraint check entirely. Both SDKs now treat omission as relaxation and reject it. `delegate()` already inherited parent `false` constraints into the child before signing, so tokens minted via `delegate()` are unaffected — but external callers using `verifyAttenuation` to gate trust on a third-party child token now get the strict semantics they were already documented as receiving.
- **`verifyChain` / `verify_chain` now compare constraints between adjacent tokens.** Previously the chain verifier checked scope subset, expiration, and parent linkage but never inspected `constraints`. A forged child JWT that flipped or omitted a parent's `false` constraint passed chain verification. Both SDKs now flag any constraint relaxation as a chain error.

### Changed

- **BREAKING (`@apoa/core`):** `revoke()`, `isRevoked()`, and `cascadeRevoke()` no longer accept an optional `RevocationStore` — the store argument is required. The previous module-level `defaultStore` singletons silently diverged from the store used by `createClient()` and any caller-supplied store, producing revocations that appeared to succeed but were never enforced. Callers that omitted the store must now pass one explicitly. The Python SDK already required the store at runtime; this aligns the TypeScript surface.

### Added

- `docs/FAQ.md` and `docs/PRIOR_ART.md` — long-form prose moved out of the README to keep the entry point tight.
- `Demos` section in the README pointing to [`negotiate`](https://github.com/agenticpoa/negotiate), [`claw-negotiate`](https://github.com/agenticpoa/claw-negotiate), and [`sshsign`](https://github.com/agenticpoa/sshsign).
- `.github/workflows/ci.yml` — GitHub Actions matrix for the TypeScript SDK (Node 20, 22) and Python SDK (3.11, 3.12, 3.13). The Python job regenerates the cross-SDK fixture from the TS source so `test_cross_sdk.py` exercises real interop on every run.
- `SECURITY.md` — vulnerability disclosure policy.
- `CHANGELOG.md` — this file.
- `sdks/python/examples/` — four worked examples (`quickstart.py`, `delegation_chain.py`, `healthcare.py`, `home_purchase.py`) mirroring the TypeScript SDK's example coverage.
- **JWKS publish + resolve helpers** in both SDKs:
  - `publicKeyToJWK` / `public_key_to_jwk` — convert an Ed25519 or P-256 public key to a JWK with `kid`, `use`, and `alg` set.
  - `buildJWKS` / `build_jwks` — wrap JWKs in the standard `{ keys: [...] }` envelope for serving at `/.well-known/jwks.json`.
  - `createJWKSResolver` / `create_jwks_resolver` — fetch + cache a remote JWKS, plug into `validateToken` via the existing `keyResolver` interface. Includes stale-while-failing fallback so validation survives brief upstream blips.
  - Full publish + resolve walkthrough in [`docs/JWKS.md`](docs/JWKS.md).
- `docs/STORES.md` — concrete Redis revocation + Postgres audit adapter recipes for both SDKs.

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
