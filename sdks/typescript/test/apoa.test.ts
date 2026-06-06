import { describe, expect, it } from 'vitest';
import {
  APOA,
  generateKeyPair,
  type APOADefinition,
} from '../src/index.js';

describe('APOA facade', () => {
  it('creates a simple grant from string inputs', async () => {
    const keys = await generateKeyPair();
    const apoa = new APOA({ privateKey: keys.privateKey });

    const before = Date.now();
    const token = await apoa.tokens.createGrant({
      principal: 'did:apoa:you',
      agent: 'did:apoa:agent',
      service: 'mychart.com',
      scopes: ['appointments:read'],
      constraints: { signing: false },
      expiresIn: '30d',
    });

    expect(token.definition.principal).toEqual({ id: 'did:apoa:you' });
    expect(token.definition.agent).toEqual({ id: 'did:apoa:agent' });
    expect(token.definition.services).toEqual([{
      service: 'mychart.com',
      scopes: ['appointments:read'],
      constraints: { signing: false },
    }]);
    expect(new Date(token.definition.expires).getTime()).toBeGreaterThan(before);
  });

  it('authorizes through the application-facing namespace', async () => {
    const keys = await generateKeyPair();
    const apoa = new APOA({ privateKey: keys.privateKey });

    const token = await apoa.tokens.createGrant({
      principal: 'did:apoa:you',
      agent: { id: 'did:apoa:agent', name: 'My Agent' },
      service: 'mychart.com',
      scopes: ['appointments:read'],
      expiresIn: '1h',
    });

    const allowed = await apoa.authorizations.check(
      token,
      'mychart.com',
      'appointments:read'
    );
    const denied = await apoa.authorizations.check(
      token,
      'mychart.com',
      'messages:send'
    );

    expect(allowed.authorized).toBe(true);
    expect(denied.authorized).toBe(false);
  });

  it('validates tokens through the application-facing namespace', async () => {
    const keys = await generateKeyPair();
    const apoa = new APOA({ privateKey: keys.privateKey });

    const token = await apoa.tokens.createGrant({
      principal: 'did:apoa:you',
      agent: 'did:apoa:agent',
      service: 'mychart.com',
      scopes: ['appointments:read'],
      expiresIn: '1h',
    });

    const result = await apoa.tokens.validate(token.raw, {
      publicKey: keys.publicKey,
    });

    expect(result.valid).toBe(true);
    expect(result.token?.jti).toBe(token.jti);
  });

  it('keeps canonical token creation available as tokens.create', async () => {
    const keys = await generateKeyPair();
    const apoa = new APOA({ privateKey: keys.privateKey });
    const definition: APOADefinition = {
      principal: { id: 'did:apoa:you' },
      agent: { id: 'did:apoa:agent' },
      services: [{
        service: 'mychart.com',
        scopes: ['appointments:read'],
      }],
      expires: '2099-09-01',
    };

    const token = await apoa.tokens.create(definition);

    expect(token.definition).toEqual(definition);
  });

  it('accepts advanced multi-service grant input', async () => {
    const keys = await generateKeyPair();
    const apoa = new APOA({ privateKey: keys.privateKey });

    const token = await apoa.tokens.createGrant({
      principal: { id: 'did:apoa:you', name: 'You' },
      agent: { id: 'did:apoa:agent', name: 'Agent' },
      services: [
        { service: 'mychart.com', scopes: ['appointments:read'] },
        { service: 'docusign.com', scopes: ['documents:read'] },
      ],
      expires: '2099-09-01',
      metadata: { source: 'test' },
    });

    expect(token.definition.services).toHaveLength(2);
    expect(token.definition.metadata).toEqual({ source: 'test' });
  });

  it('throws a helpful error for missing private keys', async () => {
    const apoa = new APOA();

    await expect(apoa.tokens.createGrant({
      principal: 'did:apoa:you',
      agent: 'did:apoa:agent',
      service: 'mychart.com',
      scopes: ['appointments:read'],
      expiresIn: '1h',
    })).rejects.toThrow('APOA needs a private key to create tokens');
  });

  it('throws a helpful error for invalid grant input', async () => {
    const keys = await generateKeyPair();
    const apoa = new APOA({ privateKey: keys.privateKey });

    await expect(apoa.tokens.createGrant({
      principal: 'did:apoa:you',
      agent: 'did:apoa:agent',
      service: 'mychart.com',
      expiresIn: '1h',
    })).rejects.toThrow('scopes must be a non-empty array');
  });

  it('rejects ambiguous duration strings', async () => {
    const keys = await generateKeyPair();
    const apoa = new APOA({ privateKey: keys.privateKey });

    await expect(apoa.tokens.createGrant({
      principal: 'did:apoa:you',
      agent: 'did:apoa:agent',
      service: 'mychart.com',
      scopes: ['appointments:read'],
      // @ts-expect-error testing runtime validation for JavaScript callers
      expiresIn: '1mo',
    })).rejects.toThrow("expiresIn must use a clear duration");
  });
});
