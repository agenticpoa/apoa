import { describe, it, expect } from 'vitest';
import {
  buildJWKS,
  createJWKSResolver,
  createToken,
  generateKeyPair,
  publicKeyToJWK,
  validateToken,
} from '../src/index.js';
import type { JWKS } from '../src/index.js';

describe('publicKeyToJWK', () => {
  it('exports an Ed25519 public key as a JWK with kid, use, and alg', async () => {
    const { publicKey } = await generateKeyPair('EdDSA');
    const jwk = await publicKeyToJWK(publicKey, { kid: '2026-05' });
    expect(jwk.kid).toBe('2026-05');
    expect(jwk.use).toBe('sig');
    expect(jwk.alg).toBe('EdDSA');
    expect(jwk.kty).toBe('OKP');
    expect(jwk.crv).toBe('Ed25519');
    expect(typeof jwk.x).toBe('string');
  });

  it('exports an ES256 public key with the right algorithm', async () => {
    const { publicKey } = await generateKeyPair('ES256');
    const jwk = await publicKeyToJWK(publicKey, { kid: 'p256-key' });
    expect(jwk.alg).toBe('ES256');
    expect(jwk.kty).toBe('EC');
    expect(jwk.crv).toBe('P-256');
  });

  it('honors explicit alg and use overrides', async () => {
    const { publicKey } = await generateKeyPair('EdDSA');
    const jwk = await publicKeyToJWK(publicKey, {
      kid: 'k',
      alg: 'EdDSA',
      use: 'sig',
    });
    expect(jwk.alg).toBe('EdDSA');
    expect(jwk.use).toBe('sig');
  });
});

describe('buildJWKS', () => {
  it('wraps keys in a JWKS envelope', async () => {
    const { publicKey } = await generateKeyPair('EdDSA');
    const jwk = await publicKeyToJWK(publicKey, { kid: 'a' });
    const jwks = buildJWKS([jwk]);
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0].kid).toBe('a');
  });
});

describe('createJWKSResolver', () => {
  it('fetches the JWKS and resolves the matching key by kid', async () => {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA');
    const jwk = await publicKeyToJWK(publicKey, { kid: 'rotation-1' });
    const jwks = buildJWKS([jwk]);

    let fetchCount = 0;
    const fakeFetch = async (): Promise<Response> => {
      fetchCount++;
      return new Response(JSON.stringify(jwks), {
        status: 200,
        headers: { 'content-type': 'application/jwk-set+json' },
      });
    };

    const resolver = createJWKSResolver('https://example.invalid/.well-known/jwks.json', {
      fetch: fakeFetch as unknown as typeof fetch,
    });

    const resolved = await resolver.resolve('rotation-1');
    expect(resolved).not.toBeNull();
    expect(fetchCount).toBe(1);

    // Token signed with kid header validates through the resolver.
    const token = await createToken(
      {
        principal: { id: 'did:apoa:alice' },
        agent: { id: 'did:apoa:agent' },
        services: [{ service: 'svc.com', scopes: ['read'] }],
        expires: '2099-01-01',
      },
      { privateKey, kid: 'rotation-1' }
    );

    const result = await validateToken(token.raw, { keyResolver: resolver });
    expect(result.valid).toBe(true);
  });

  it('returns null for an unknown kid', async () => {
    const { publicKey } = await generateKeyPair('EdDSA');
    const jwk = await publicKeyToJWK(publicKey, { kid: 'known' });
    const jwks: JWKS = { keys: [jwk] };

    const fakeFetch = async (): Promise<Response> =>
      new Response(JSON.stringify(jwks), { status: 200 });

    const resolver = createJWKSResolver('https://example.invalid/jwks.json', {
      fetch: fakeFetch as unknown as typeof fetch,
    });

    expect(await resolver.resolve('does-not-exist')).toBeNull();
  });

  it('caches the JWKS for the lifetime of the cache window', async () => {
    const { publicKey } = await generateKeyPair('EdDSA');
    const jwk = await publicKeyToJWK(publicKey, { kid: 'cached' });
    const jwks = buildJWKS([jwk]);

    let fetchCount = 0;
    const fakeFetch = async (): Promise<Response> => {
      fetchCount++;
      return new Response(JSON.stringify(jwks), { status: 200 });
    };

    const resolver = createJWKSResolver('https://example.invalid/jwks.json', {
      fetch: fakeFetch as unknown as typeof fetch,
      cacheMaxAgeMs: 60_000,
    });

    await resolver.resolve('cached');
    await resolver.resolve('cached');
    await resolver.resolve('cached');
    expect(fetchCount).toBe(1);
  });

  it('throws when the JWKS endpoint returns a non-2xx status', async () => {
    const fakeFetch = async (): Promise<Response> =>
      new Response('boom', { status: 503, statusText: 'Service Unavailable' });

    const resolver = createJWKSResolver('https://example.invalid/jwks.json', {
      fetch: fakeFetch as unknown as typeof fetch,
    });

    await expect(resolver.resolve('any')).rejects.toThrow(/JWKS fetch failed/);
  });

  it('rejects http:// URLs by default', () => {
    expect(() =>
      createJWKSResolver('http://example.invalid/jwks.json')
    ).toThrow(/https:\/\//);
  });

  it('accepts http:// URLs when allowInsecure is true', () => {
    expect(() =>
      createJWKSResolver('http://localhost:3000/jwks.json', {
        allowInsecure: true,
      })
    ).not.toThrow();
  });

  it('accepts http:// URLs when a custom fetch is supplied', () => {
    const fakeFetch = (async () => new Response('{}', { status: 200 })) as unknown as typeof fetch;
    expect(() =>
      createJWKSResolver('http://example.invalid/jwks.json', { fetch: fakeFetch })
    ).not.toThrow();
  });
});
