# JWKS — Key Distribution and Resolution

APOA tokens are signed JWTs. Anyone validating a token needs the issuing principal's public key. Without a discovery mechanism, key distribution is manual: emailing PEM files, hardcoding keys, hand-rolling rotation.

The standard answer is [JWKS](https://datatracker.ietf.org/doc/html/rfc7517) (JSON Web Key Set) — the same mechanism Auth0, Cognito, Okta, Google, and GitHub use to publish their signing keys. The convention: principals serve their public keys at `https://<principal>/.well-known/jwks.json`, and validators fetch + cache the JWKS to verify tokens.

The SDK ships helpers for both sides.

---

## Publishing keys (the principal)

A principal converts each public key to a JWK, wraps the JWKs in a JWKS envelope, and serves the envelope at a stable URL. The SDK gives you the conversion; serving the bytes is your job (use whatever HTTP framework you already have).

### TypeScript

```typescript
import { generateKeyPair, publicKeyToJWK, buildJWKS } from '@apoa/core';

const current = await generateKeyPair();
const previous = await generateKeyPair(); // kept around during a key rotation

const jwks = buildJWKS([
  await publicKeyToJWK(current.publicKey, { kid: '2026-05' }),
  await publicKeyToJWK(previous.publicKey, { kid: '2026-04' }),
]);

// Serve at /.well-known/jwks.json with whichever framework you use.
// Express:
app.get('/.well-known/jwks.json', (_req, res) => {
  res.set('content-type', 'application/jwk-set+json');
  res.set('cache-control', 'public, max-age=3600');
  res.json(jwks);
});

// Bun / fetch-style:
//   if (url.pathname === '/.well-known/jwks.json') {
//     return new Response(JSON.stringify(jwks), {
//       headers: {
//         'content-type': 'application/jwk-set+json',
//         'cache-control': 'public, max-age=3600',
//       },
//     });
//   }
```

When you sign a token, set the matching `kid` in the JWS header so validators know which key to look up:

```typescript
const token = await createToken(definition, {
  privateKey: current.privateKey,
  kid: '2026-05',
});
```

### Python

```python
from apoa import generate_key_pair, public_key_to_jwk, build_jwks

_, current_public = generate_key_pair()
_, previous_public = generate_key_pair()  # kept during rotation

jwks = build_jwks([
    public_key_to_jwk(current_public, kid="2026-05"),
    public_key_to_jwk(previous_public, kid="2026-04"),
])

# FastAPI:
@app.get("/.well-known/jwks.json")
def jwks_endpoint():
    return JSONResponse(
        jwks,
        media_type="application/jwk-set+json",
        headers={"cache-control": "public, max-age=3600"},
    )

# Flask:
# @app.get("/.well-known/jwks.json")
# def jwks_endpoint():
#     return jsonify(jwks), 200, {
#         "Content-Type": "application/jwk-set+json",
#         "Cache-Control": "public, max-age=3600",
#     }
```

When you sign a token, pass `kid` so the JWS header carries it:

```python
from apoa import SigningOptions, create_token
token = create_token(
    definition,
    SigningOptions(private_key=current_private, kid="2026-05"),
)
```

### Notes on rotation

- Keep both keys (current + previous) in the JWKS for at least the longest token lifetime your principals issue. A token signed with key `2026-04` will still be in the wild after you've rotated to `2026-05`; validators need both keys available until the old tokens have all expired.
- Don't reuse `kid` values across rotations. New rotation = new `kid`.
- The `Cache-Control` header above sets a 1-hour cache. Lower it if your rotation cadence is faster than that; raise it if your JWKS endpoint is on the critical path for high-volume validation.

---

## Resolving keys (the relying party)

A relying party — an agent runtime, a downstream service, anyone validating an incoming APOA token — fetches the JWKS, picks the key matching the JWT's `kid`, and verifies the signature. The SDK ships a resolver that does the fetch + cache for you and plugs straight into `validateToken`.

### TypeScript

```typescript
import { createJWKSResolver, validateToken } from '@apoa/core';

const resolver = createJWKSResolver(
  'https://principal.example/.well-known/jwks.json',
  { cacheMaxAgeMs: 60 * 60 * 1000 } // 1 hour, the default
);

// validateToken handles the kid lookup + cryptographic verification.
const result = await validateToken(rawJWT, { keyResolver: resolver });
if (!result.valid) {
  throw new Error(`invalid token: ${result.errors.join('; ')}`);
}
```

### Python

```python
from apoa import create_jwks_resolver, validate_token, ValidationOptions

resolver = create_jwks_resolver(
    "https://principal.example/.well-known/jwks.json",
    cache_max_age=3600.0,
)

result = validate_token(raw_jwt, ValidationOptions(key_resolver=resolver))
if not result.valid:
    raise ValueError(f"invalid token: {result.errors}")
```

### How the cache behaves

Both resolvers cache the fetched JWKS in process memory:

- `cacheMaxAgeMs` / `cache_max_age` — how long a successful fetch is reused before refetching. Default: 1 hour.
- `cooldownMs` / `cooldown` — if a refetch fails (network blip, upstream 5xx, etc.) and the cached value is younger than this, the resolver returns the cached value instead of raising. Default: 24 hours. Stale-while-failing keeps validation working through brief upstream issues.

If you need a tighter cache window (e.g., key rotations every few minutes for testing), pass a smaller `cacheMaxAgeMs`. If you're behind a corporate proxy and the SDK's default fetch doesn't work, both SDKs let you inject a custom fetcher via the `fetch` (TS) or `http_get` (Python) option.

---

## How this fits into the bigger picture

- **Identity** of the principal lives in a [DID](https://www.w3.org/TR/did-core/) (`did:apoa:...`) — separate from key material.
- **Key material** lives in JWKS — published by the principal, fetched by validators, rotated as needed.
- **Authorization** is what the APOA token expresses — signed by a key in the JWKS, verified against it, and then consulted for scope, constraints, rules, delegation, and revocation.

This is the same separation OAuth/OIDC providers use; APOA borrows the pattern verbatim and adds the agent-specific authorization semantics on top.

---

← Back to [README](../README.md)
