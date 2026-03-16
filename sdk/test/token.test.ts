import { describe, it, expect, beforeAll } from 'vitest';
import { createToken } from '../src/token/create.js';
import { signToken, decodeHeader, verifySignature } from '../src/token/sign.js';
import { validateToken } from '../src/token/validate.js';
import { cascadeRevoke } from '../src/revocation/cascade.js';
import { generateKeyPair } from '../src/utils/crypto.js';
import { MemoryRevocationStore } from '../src/revocation/store.js';
import type {
  APOADefinition,
  APOAToken,
  SigningOptions,
  KeyResolver,
} from '../src/types.js';

// Shared keys and definition for tests
let edKeys: CryptoKeyPair;
let esKeys: CryptoKeyPair;

const baseDef: APOADefinition = {
  principal: { id: 'did:apoa:juan', name: 'Juan' },
  agent: { id: 'did:apoa:homebot', name: 'HomeBot Pro' },
  services: [
    {
      service: 'mychart.com',
      scopes: ['appointments:read', 'prescriptions:read'],
      constraints: { signing: false },
    },
  ],
  rules: [
    { id: 'no-messaging', description: 'Never send messages', enforcement: 'hard' },
  ],
  expires: '2099-09-01',
  revocable: true,
};

beforeAll(async () => {
  edKeys = await generateKeyPair('EdDSA');
  esKeys = await generateKeyPair('ES256');
});

// ── signToken ──────────────────────────────────────────────────

describe('signToken', () => {
  it('produces a compact JWS with 3 parts', async () => {
    const jws = await signToken(
      { sub: 'test' },
      { privateKey: edKeys.privateKey }
    );
    expect(jws.split('.')).toHaveLength(3);
  });

  it('embeds kid in the header when provided', async () => {
    const jws = await signToken(
      { sub: 'test' },
      { privateKey: edKeys.privateKey, kid: 'key-v1' }
    );
    const header = decodeHeader(jws);
    expect(header.kid).toBe('key-v1');
    expect(header.alg).toBe('EdDSA');
  });

  it('supports ES256 algorithm', async () => {
    const jws = await signToken(
      { sub: 'test' },
      { privateKey: esKeys.privateKey, algorithm: 'ES256' }
    );
    const header = decodeHeader(jws);
    expect(header.alg).toBe('ES256');
  });
});

// ── decodeHeader ───────────────────────────────────────────────

describe('decodeHeader', () => {
  it('decodes the protected header', async () => {
    const jws = await signToken(
      { sub: 'test' },
      { privateKey: edKeys.privateKey, kid: 'my-key' }
    );
    const header = decodeHeader(jws);
    expect(header.alg).toBe('EdDSA');
    expect(header.kid).toBe('my-key');
  });

  it('throws on invalid JWS', () => {
    expect(() => decodeHeader('')).toThrow();
  });
});

// ── verifySignature ────────────────────────────────────────────

describe('verifySignature', () => {
  it('verifies and returns payload', async () => {
    const jws = await signToken(
      { sub: 'test', num: 42 },
      { privateKey: edKeys.privateKey }
    );
    const payload = await verifySignature(jws, edKeys.publicKey);
    expect(payload.sub).toBe('test');
    expect(payload.num).toBe(42);
  });

  it('rejects with wrong key', async () => {
    const jws = await signToken(
      { sub: 'test' },
      { privateKey: edKeys.privateKey }
    );
    await expect(verifySignature(jws, esKeys.publicKey)).rejects.toThrow();
  });
});

// ── createToken ────────────────────────────────────────────────

describe('createToken', () => {
  it('creates a token with a UUID jti', async () => {
    const token = await createToken(baseDef, { privateKey: edKeys.privateKey });
    expect(token.jti).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
    );
  });

  it('sets issuedAt to current time', async () => {
    const before = Date.now();
    const token = await createToken(baseDef, { privateKey: edKeys.privateKey });
    const after = Date.now();
    expect(token.issuedAt.getTime()).toBeGreaterThanOrEqual(before);
    expect(token.issuedAt.getTime()).toBeLessThanOrEqual(after);
  });

  it('derives audience from services', async () => {
    const token = await createToken(baseDef, { privateKey: edKeys.privateKey });
    expect(token.audience).toEqual(['mychart.com']);
  });

  it('derives audience from multiple services', async () => {
    const multiDef: APOADefinition = {
      ...baseDef,
      services: [
        { service: 'mychart.com', scopes: ['read'] },
        { service: 'stripe.com', scopes: ['charges:read'] },
      ],
    };
    const token = await createToken(multiDef, { privateKey: edKeys.privateKey });
    expect(token.audience).toEqual(['mychart.com', 'stripe.com']);
  });

  it('sets issuer to principal.id', async () => {
    const token = await createToken(baseDef, { privateKey: edKeys.privateKey });
    expect(token.issuer).toBe('did:apoa:juan');
  });

  it('produces a verifiable raw JWT', async () => {
    const token = await createToken(baseDef, { privateKey: edKeys.privateKey });
    const payload = await verifySignature(token.raw, edKeys.publicKey);
    expect(payload.jti).toBe(token.jti);
    expect(payload.iss).toBe('did:apoa:juan');
  });

  it('preserves the full definition', async () => {
    const token = await createToken(baseDef, { privateKey: edKeys.privateKey });
    expect(token.definition.principal.id).toBe('did:apoa:juan');
    expect(token.definition.services).toHaveLength(1);
    expect(token.definition.services[0].scopes).toContain('appointments:read');
  });

  it('works with ES256', async () => {
    const token = await createToken(baseDef, {
      privateKey: esKeys.privateKey,
      algorithm: 'ES256',
    });
    const payload = await verifySignature(token.raw, esKeys.publicKey);
    expect(payload.jti).toBe(token.jti);
  });

  it('embeds kid when provided', async () => {
    const token = await createToken(baseDef, {
      privateKey: edKeys.privateKey,
      kid: 'apoa-key-2026',
    });
    const header = decodeHeader(token.raw);
    expect(header.kid).toBe('apoa-key-2026');
  });

  it('rejects metadata with too many keys', async () => {
    const metadata: Record<string, string> = {};
    for (let i = 0; i < 25; i++) metadata[`k${i}`] = 'v';
    const def = { ...baseDef, metadata };
    await expect(
      createToken(def, { privateKey: edKeys.privateKey })
    ).rejects.toThrow(/max 20/);
  });

  it('rejects metadata exceeding 1KB', async () => {
    const def = { ...baseDef, metadata: { big: 'x'.repeat(1100) } };
    await expect(
      createToken(def, { privateKey: edKeys.privateKey })
    ).rejects.toThrow(/max 1024/);
  });

  it('handles Date objects for expires', async () => {
    const def = { ...baseDef, expires: new Date('2099-01-01') };
    const token = await createToken(def, { privateKey: edKeys.privateKey });
    expect(token.jti).toBeTruthy();
  });

  it('handles notBefore as Date', async () => {
    const def = { ...baseDef, notBefore: new Date('2020-01-01') };
    const token = await createToken(def, { privateKey: edKeys.privateKey });
    const payload = await verifySignature(token.raw, edKeys.publicKey);
    expect(payload.nbf).toBeDefined();
  });
});

// ── validateToken ──────────────────────────────────────────────

describe('validateToken', () => {
  let validToken: APOAToken;

  beforeAll(async () => {
    validToken = await createToken(baseDef, { privateKey: edKeys.privateKey });
  });

  it('validates a good token with publicKey', async () => {
    const result = await validateToken(validToken.raw, {
      publicKey: edKeys.publicKey,
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
    expect(result.token).toBeDefined();
    expect(result.token?.jti).toBe(validToken.jti);
  });

  it('validates an APOAToken object', async () => {
    const result = await validateToken(validToken, {
      publicKey: edKeys.publicKey,
    });
    expect(result.valid).toBe(true);
  });

  it('fails on wrong public key', async () => {
    const otherKeys = await generateKeyPair('EdDSA');
    const result = await validateToken(validToken.raw, {
      publicKey: otherKeys.publicKey,
    });
    expect(result.valid).toBe(false);
    expect(result.errors).toContainEqual(
      expect.stringContaining('Signature verification failed')
    );
  });

  it('fails when no key is provided', async () => {
    const result = await validateToken(validToken.raw, {});
    expect(result.valid).toBe(false);
    expect(result.errors).toContainEqual(
      expect.stringContaining('No key provided')
    );
  });

  it('detects expired tokens', async () => {
    const expiredDef = { ...baseDef, expires: '2020-01-01' };
    const expired = await createToken(expiredDef, {
      privateKey: edKeys.privateKey,
    });
    const result = await validateToken(expired.raw, {
      publicKey: edKeys.publicKey,
    });
    expect(result.valid).toBe(false);
    expect(result.errors).toContainEqual(
      expect.stringContaining('expired')
    );
  });

  it('detects not-yet-active tokens', async () => {
    const futureDef = { ...baseDef, notBefore: '2099-01-01' };
    const future = await createToken(futureDef, {
      privateKey: edKeys.privateKey,
    });
    const result = await validateToken(future.raw, {
      publicKey: edKeys.publicKey,
    });
    expect(result.valid).toBe(false);
    expect(result.errors).toContainEqual(
      expect.stringContaining('not valid before')
    );
  });

  it('respects clock skew tolerance', async () => {
    // Create a token that expired 20 seconds ago
    const recentExpiry = new Date(Date.now() - 20_000).toISOString();
    const recentDef = { ...baseDef, expires: recentExpiry };
    const recent = await createToken(recentDef, {
      privateKey: edKeys.privateKey,
    });

    // With default 30s skew — should still be valid
    const result = await validateToken(recent.raw, {
      publicKey: edKeys.publicKey,
    });
    expect(result.valid).toBe(true);

    // With 0s skew — should be expired
    const strict = await validateToken(recent.raw, {
      publicKey: edKeys.publicKey,
      clockSkew: 0,
    });
    expect(strict.valid).toBe(false);
  });

  it('checks revocation when store is provided', async () => {
    const store = new MemoryRevocationStore();
    await store.add({
      tokenId: validToken.jti,
      revokedAt: new Date(),
      revokedBy: 'did:apoa:juan',
      cascaded: [],
    });

    const result = await validateToken(validToken.raw, {
      publicKey: edKeys.publicKey,
      revocationStore: store,
      checkRevocation: true,
    });
    expect(result.valid).toBe(false);
    expect(result.errors).toContainEqual(
      expect.stringContaining('revoked')
    );
  });

  it('skips revocation check when checkRevocation is false', async () => {
    const store = new MemoryRevocationStore();
    await store.add({
      tokenId: validToken.jti,
      revokedAt: new Date(),
      revokedBy: 'did:apoa:juan',
      cascaded: [],
    });

    const result = await validateToken(validToken.raw, {
      publicKey: edKeys.publicKey,
      revocationStore: store,
      checkRevocation: false,
    });
    expect(result.valid).toBe(true);
  });

  it('resolves key via keyResolver', async () => {
    const token = await createToken(baseDef, {
      privateKey: edKeys.privateKey,
      kid: 'test-kid',
    });

    const resolver: KeyResolver = {
      resolve: async (kid: string) => {
        if (kid === 'test-kid') return edKeys.publicKey;
        return null;
      },
    };

    const result = await validateToken(token.raw, { keyResolver: resolver });
    expect(result.valid).toBe(true);
  });

  it('fails when keyResolver returns null', async () => {
    const token = await createToken(baseDef, {
      privateKey: edKeys.privateKey,
      kid: 'unknown-kid',
    });

    const resolver: KeyResolver = {
      resolve: async () => null,
    };

    const result = await validateToken(token.raw, { keyResolver: resolver });
    expect(result.valid).toBe(false);
    expect(result.errors).toContainEqual(
      expect.stringContaining("returned null for kid 'unknown-kid'")
    );
  });

  it('resolves key via publicKeyResolver', async () => {
    const token = await createToken(baseDef, {
      privateKey: edKeys.privateKey,
    });

    const result = await validateToken(token.raw, {
      publicKeyResolver: async (issuer: string) => {
        if (issuer === 'did:apoa:juan') return edKeys.publicKey;
        throw new Error('Unknown issuer');
      },
    });
    expect(result.valid).toBe(true);
  });

  it('returns all errors, not just the first', async () => {
    const badDef = {
      ...baseDef,
      expires: '2020-01-01',
      notBefore: '2099-01-01',
    };
    const badToken = await createToken(badDef, {
      privateKey: edKeys.privateKey,
    });

    const otherKeys = await generateKeyPair('EdDSA');
    const result = await validateToken(badToken.raw, {
      publicKey: otherKeys.publicKey,
    });
    expect(result.valid).toBe(false);
    // Should have at least signature + expiry + notBefore errors
    expect(result.errors.length).toBeGreaterThanOrEqual(3);
  });

  it('includes parsed token when structurally valid', async () => {
    const result = await validateToken(validToken.raw, {
      publicKey: edKeys.publicKey,
    });
    expect(result.token).toBeDefined();
    expect(result.token?.issuer).toBe('did:apoa:juan');
    expect(result.token?.audience).toEqual(['mychart.com']);
  });
});

// ── cascadeRevoke ──────────────────────────────────────────────

describe('cascadeRevoke', () => {
  it('revokes parent and all children', async () => {
    const store = new MemoryRevocationStore();

    const record = await cascadeRevoke(
      'parent-token',
      ['child-1', 'child-2', 'child-3'],
      { revokedBy: 'did:apoa:juan', reason: 'compromised' },
      store
    );

    expect(record.tokenId).toBe('parent-token');
    expect(record.cascaded).toEqual(['child-1', 'child-2', 'child-3']);
    expect(record.reason).toBe('compromised');

    // All children should be revoked
    expect(await store.check('child-1')).not.toBeNull();
    expect(await store.check('child-2')).not.toBeNull();
    expect(await store.check('child-3')).not.toBeNull();

    // Parent should be revoked
    expect(await store.check('parent-token')).not.toBeNull();
  });

  it('child records have cascade reason', async () => {
    const store = new MemoryRevocationStore();
    await cascadeRevoke(
      'parent',
      ['child-1'],
      { revokedBy: 'did:apoa:juan', reason: 'nope' },
      store
    );

    const childRecord = await store.check('child-1');
    expect(childRecord?.reason).toContain('Cascade');
  });

  it('handles empty children array', async () => {
    const store = new MemoryRevocationStore();
    const record = await cascadeRevoke(
      'parent',
      [],
      { revokedBy: 'did:apoa:juan' },
      store
    );
    expect(record.cascaded).toEqual([]);
    expect(await store.check('parent')).not.toBeNull();
  });
});

// ── Full lifecycle ─────────────────────────────────────────────

describe('token lifecycle', () => {
  it('create → validate → revoke → confirm revoked', async () => {
    const store = new MemoryRevocationStore();
    const keys = await generateKeyPair('EdDSA');

    // Create
    const token = await createToken(baseDef, { privateKey: keys.privateKey });
    expect(token.jti).toBeTruthy();

    // Validate (should pass)
    const valid = await validateToken(token.raw, {
      publicKey: keys.publicKey,
      revocationStore: store,
    });
    expect(valid.valid).toBe(true);

    // Revoke
    await store.add({
      tokenId: token.jti,
      revokedAt: new Date(),
      revokedBy: 'did:apoa:juan',
      cascaded: [],
    });

    // Validate again (should fail — revoked)
    const revoked = await validateToken(token.raw, {
      publicKey: keys.publicKey,
      revocationStore: store,
    });
    expect(revoked.valid).toBe(false);
    expect(revoked.errors).toContainEqual(
      expect.stringContaining('revoked')
    );
  });

  it('create with EdDSA, validate with ES256 key fails', async () => {
    const edKey = await generateKeyPair('EdDSA');
    const esKey = await generateKeyPair('ES256');

    const token = await createToken(baseDef, { privateKey: edKey.privateKey });
    const result = await validateToken(token.raw, {
      publicKey: esKey.publicKey,
    });
    expect(result.valid).toBe(false);
  });

  it('create with kid, validate via keyResolver', async () => {
    const keys = await generateKeyPair('EdDSA');

    const token = await createToken(baseDef, {
      privateKey: keys.privateKey,
      kid: 'rotation-key-v2',
    });

    const resolver: KeyResolver = {
      resolve: async (kid) => {
        if (kid === 'rotation-key-v2') return keys.publicKey;
        return null;
      },
    };

    const result = await validateToken(token.raw, { keyResolver: resolver });
    expect(result.valid).toBe(true);
    expect(result.token?.jti).toBe(token.jti);
  });
});
