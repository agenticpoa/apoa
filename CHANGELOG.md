# Changelog

All notable changes to the APOA SDKs are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning](https://semver.org/). The TypeScript SDK (`@apoa/core`) and Python SDK (`apoa`) are released independently but version-aligned where possible.

---

## [Unreleased]

---

## `@apoa/core` 0.2.4 / `apoa` 0.3.3 — 2026-06-08

### Changed

- Refresh the main README and SDK package READMEs around a simpler docs-assistant quickstart that uses the `APOA` facade first.
- Add runnable top-level TypeScript and Python quickstart examples under `examples/`.
- Update SDK quickstart scripts to use the same neutral knowledge-base authorization flow.

---

## `@apoa/core` 0.2.3 — 2026-06-06

### Changed

- Refresh npm package README to show the new `APOA` facade quickstart and split the three usage styles into separate sections.

---

## `@apoa/core` 0.2.2 / `apoa` 0.3.2 — 2026-06-06

### Added

- Application-facing `APOA` facade in both SDKs. App developers can now configure keys once and use namespaced resources:
  - TypeScript: `new APOA({ privateKey })`, `apoa.tokens.createGrant(...)`, `apoa.tokens.validate(...)`, and `apoa.authorizations.check(...)`.
  - Python: `APOA(private_key=...)`, `apoa.tokens.create_grant(...)`, `apoa.tokens.validate(...)`, and `apoa.authorizations.check(...)`.
- Quickstart examples and SDK READMEs now lead with the simpler app-facing facade while keeping the protocol client and standalone helpers available for advanced usage.

### Changed

- Missing signing-key errors now point callers toward the new facade and existing protocol-client configuration options.

---

## `apoa` 0.3.1 — 2026-05-19

### Added

- `get_delegation_ancestor_ids()` in the Python SDK. Mirrors `getDelegationAncestorIds()` from `@apoa/core` 0.2.1: normalizes a canonical `APOAToken.parent_token` and any transport-level `delegationChain` / `delegation_chain` array (with string or `{"parentTokenId": "..."}` entries) into a de-duplicated, order-preserving ancestor token ID list. Restores cross-SDK parity for the helper that was TS-only after 0.2.1.

---

## `@apoa/core` 0.2.1 — 2026-05-16

### Added

- `getDelegationAncestorIds()` in the TypeScript SDK. The helper normalizes canonical `parentToken` links and transport-level `delegationChain` references into a de-duplicated ancestor token ID list for revocation checks.

### Changed

- `SPEC.md` now documents the nested signed JWT `definition` payload profile used by the SDKs, replacing the older flat-claim draft example.
- README project status now distinguishes the shipped `@apoa/mcp` adapter from the still-pending formal MCP standards proposal.

---

## `@apoa/core` 0.2.0 / `apoa` 0.3.0 — 2026-05-09

This release closes all 11 findings from the 2026-04-12 self-audit and pulls forward a backlog of additive features (JWKS helpers, Python lockfile, examples, doc reorg).

### Security

- **Constraint attenuation hardening (both SDKs).** A child delegation that omitted a parent's `false` constraint (e.g. parent `{ signing: false }`, child with no constraints) previously slipped through `verifyAttenuation` / `_verify_attenuation` and caused the child's `authorize()` to skip the constraint check entirely. Both SDKs now treat omission as relaxation and reject it. `delegate()` already inherited parent `false` constraints into the child before signing, so tokens minted via `delegate()` are unaffected — but external callers using `verifyAttenuation` to gate trust on a third-party child token now get the strict semantics they were already documented as receiving.
- **`verifyChain` / `verify_chain` now compare constraints between adjacent tokens.** Previously the chain verifier checked scope subset, expiration, and parent linkage but never inspected `constraints`. A forged child JWT that flipped or omitted a parent's `false` constraint passed chain verification. Both SDKs now flag any constraint relaxation as a chain error.
- **Empty scope no longer matches empty scope (both SDKs).** `matchScope('', '')` previously returned `true` because `parseScope('')` produced an empty array on both sides and the segment-comparison loop was never entered. A token with `scopes: ['']` could authorize an empty action string, or vice versa. Both SDKs now reject empty patterns, empty requested strings, and empty segments (`'foo::bar'`). `parseDefinition` also rejects empty scope strings at definition time.
- **`ValidationOptions.algorithms` lets callers pin the accepted JWS algorithm (both SDKs).** Previously the Python SDK passed `["EdDSA", "ES256"]` to PyJWT unconditionally, with no caller override. The TS SDK silently inherited `jose`'s default acceptance. An organization that mandates EdDSA-only had no way to enforce it. The new option defaults to `["EdDSA", "ES256"]` (the APOA conformance baseline) and can be narrowed to a single value to enforce policy.
- **JWKS resolver hardening (both SDKs).** Resolvers now reject non-`https://` URLs by default (escape hatch via `allowInsecure` / `allow_insecure` or a custom HTTP fetcher). The Python resolver's `alg` whitelist is tightened to EdDSA + ES256 only, matching the SPEC §4.1 conformance baseline; previously it silently accepted ES384/ES512 keys.

### Changed

- **BREAKING (`@apoa/core`):** `revoke()`, `isRevoked()`, and `cascadeRevoke()` no longer accept an optional `RevocationStore` — the store argument is required. The previous module-level `defaultStore` singletons silently diverged from the store used by `createClient()` and any caller-supplied store, producing revocations that appeared to succeed but were never enforced. Callers that omitted the store must now pass one explicitly. The Python SDK already required the store at runtime; this aligns the TypeScript surface.
- **Repo layout**: SDKs moved from `sdk/` and `sdk-python/` to `sdks/typescript/` and `sdks/python/` so the `sdks/` parent groups all language implementations.
- **`@apoa/core`**: `engines.node` raised from `>=18` to `>=20`. `jose@6` uses Web Crypto via `globalThis.crypto`, which isn't a Node global until v19; Node 18 reached end-of-life on 2025-04-30.
- **`SPEC.md`**: §4.1 and §13.2 now recommend EdDSA primary, ES256 acceptable. Aligns the spec with what both SDKs already default to and what TLS 1.3 / OpenSSH / RFC 8410 prefer.

### Added

- **JWKS publish + resolve helpers** in both SDKs:
  - `publicKeyToJWK` / `public_key_to_jwk` — convert an Ed25519 or P-256 public key to a JWK with `kid`, `use`, and `alg` set.
  - `buildJWKS` / `build_jwks` — wrap JWKs in the standard `{ keys: [...] }` envelope for serving at `/.well-known/jwks.json`.
  - `createJWKSResolver` / `create_jwks_resolver` — fetch + cache a remote JWKS, plug into `validateToken` via the existing `keyResolver` interface. Includes stale-while-failing fallback so validation survives brief upstream blips.
  - Full publish + resolve walkthrough in [`docs/JWKS.md`](docs/JWKS.md).
- **`sdks/python/uv.lock`** — Python SDK now ships a [uv](https://docs.astral.sh/uv/) lockfile pinning every transitive dependency at exact versions. CI installs from the lock with `uv sync --locked`, so builds are reproducible across machines and time.
- `sdks/python/examples/` — four worked examples (`quickstart.py`, `delegation_chain.py`, `healthcare.py`, `home_purchase.py`) mirroring the TypeScript SDK's example coverage.
- `docs/STORES.md` — concrete Redis revocation + Postgres audit adapter recipes for both SDKs.
- `docs/FAQ.md` and `docs/PRIOR_ART.md` — long-form prose moved out of the README to keep the entry point tight.
- `Demos` section in the README pointing to [`negotiate`](https://github.com/agenticpoa/negotiate), [`claw-negotiate`](https://github.com/agenticpoa/claw-negotiate), and [`sshsign`](https://github.com/agenticpoa/sshsign).
- `.github/workflows/ci.yml` — GitHub Actions matrix for the TypeScript SDK (Node 20, 22) and Python SDK (3.11, 3.12, 3.13). The Python job regenerates the cross-SDK fixture from the TS source so `test_cross_sdk.py` exercises real interop on every run.
- `SECURITY.md` — vulnerability disclosure policy.
- `CHANGELOG.md` — this file.

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
