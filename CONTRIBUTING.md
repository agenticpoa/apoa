# Contributing to Agentic POA

Thanks for your interest in contributing to APOA. This is an open standard, and it'll only work if people beyond the original authors help shape it.

## Ways to contribute

**Review the spec.** Read [SPEC.md](SPEC.md) and tell us what's missing, what's wrong, or what won't work in practice. The most valuable contributions at this stage are critical feedback, not code.

**Open an issue.** Questions, critiques, edge cases, "have you considered..." — all welcome. The best issues are specific: "Section 7.2 doesn't account for X" is more useful than "this needs work."

**Join the discussion.** Use the [Discussions tab](../../discussions) for broader conversations about direction, use cases, and design philosophy.

**Propose a scenario.** If you have a real-world delegation use case that isn't covered in [EXAMPLES.md](EXAMPLES.md), open an issue describing it. The more concrete, the better.

**Improve the spec.** If you want to propose changes to the specification itself, open a pull request with a clear description of what you're changing and why. For significant changes, open an issue first to discuss the approach.

## What we're looking for right now

The spec is in working draft. The highest-value contributions at this stage are:

- **Security review** — identify vulnerabilities, attack vectors, and edge cases in the authorization model
- **Standards expertise** — if you've worked on OAuth, ZCAP-LD, VCs, or related specs, your perspective on interoperability and design decisions is invaluable
- **Real-world validation** — if you're building AI agents or agent infrastructure, tell us whether this spec would actually work for your use case
- **Legal review** — if you have expertise in agency law, UETA, E-SIGN, or AI governance, we'd love your input on the legal alignment sections

## Working on the SDKs

The reference SDKs live under [`sdks/typescript/`](sdks/typescript/) and [`sdks/python/`](sdks/python/). Run the test suite for each before opening a PR:

```bash
# TypeScript
cd sdks/typescript
npm install
npm run typecheck
npm test

# Python
cd sdks/python
pip install -e ".[dev]"
pytest
```

Cross-SDK fixture: the Python suite includes `test_cross_sdk.py`, which validates a JWT signed by the TypeScript SDK. To regenerate the fixture before running it locally:

```bash
cd sdks/typescript
npx tsx ../python/tests/generate_ts_fixture.mjs
```

CI runs both suites on every push and PR. The Python job regenerates the fixture automatically so cross-SDK drift is caught before merge.

## Releasing

Releases are tag-driven. Pushing an `apoa-v*` tag publishes the Python SDK to PyPI; pushing a `core-v*` tag publishes `@apoa/core` to npm. The [release workflow](.github/workflows/release.yml) verifies the tag matches the package metadata version, runs the full test suite, publishes, and creates a GitHub Release with notes pulled from the matching `CHANGELOG.md` section.

To cut a release:

1. Bump the version in `sdks/python/pyproject.toml` or `sdks/typescript/package.json`.
2. Update `CHANGELOG.md`: move items from `[Unreleased]` into a dated `## \`apoa\` <version> — <date>` (or `## \`@apoa/core\` <version> — <date>`) section.
3. Commit on `main`.
4. Tag and push: `git tag apoa-v<version> && git push origin main apoa-v<version>` (or `core-v<version>`).

The workflow handles the rest. Pre-1.0 releases follow the convention that breaking changes bump the minor version (`0.1.x` → `0.2.0`).

## Guidelines

- Be specific and constructive
- Assume good faith
- If you disagree with a design decision, explain the tradeoff you'd make instead
- No cryptocurrency, token, or blockchain proposals — see the [FAQ](docs/FAQ.md)

## License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](LICENSE).
