import { describe, it, expect, beforeAll } from 'vitest';
import { createClient } from '../src/client.js';
import { generateKeyPair } from '../src/utils/crypto.js';
import { MemoryRevocationStore } from '../src/revocation/store.js';
import { MemoryAuditStore } from '../src/audit/store.js';
import type { APOADefinition } from '../src/types.js';

let keys: CryptoKeyPair;

const baseDef: APOADefinition = {
  principal: { id: 'did:apoa:juan' },
  agent: { id: 'did:apoa:bot', name: 'TestBot' },
  services: [
    { service: 'mychart.com', scopes: ['appointments:read', 'prescriptions:read'] },
  ],
  expires: '2099-09-01',
};

beforeAll(async () => {
  keys = await generateKeyPair('EdDSA');
});

describe('createClient', () => {
  it('creates a client with default in-memory stores', () => {
    const client = createClient();
    expect(client).toBeDefined();
    expect(client.createToken).toBeTypeOf('function');
    expect(client.validateToken).toBeTypeOf('function');
    expect(client.authorize).toBeTypeOf('function');
    expect(client.revoke).toBeTypeOf('function');
  });

  it('creates a client with custom stores', () => {
    const revocationStore = new MemoryRevocationStore();
    const auditStore = new MemoryAuditStore();
    const client = createClient({ revocationStore, auditStore });
    expect(client).toBeDefined();
  });

  it('creates a client with defaultSigningOptions', async () => {
    const client = createClient({
      defaultSigningOptions: { privateKey: keys.privateKey },
    });
    // Can create token without passing signing options
    const token = await client.createToken(baseDef);
    expect(token.jti).toBeTruthy();
  });
});

describe('client methods', () => {
  it('createToken + validateToken round-trip', async () => {
    const client = createClient({
      defaultSigningOptions: { privateKey: keys.privateKey },
    });

    const token = await client.createToken(baseDef);
    const result = await client.validateToken(token, {
      publicKey: keys.publicKey,
    });
    expect(result.valid).toBe(true);
    expect(result.token?.jti).toBe(token.jti);
  });

  it('checkScope works through client', async () => {
    const client = createClient({
      defaultSigningOptions: { privateKey: keys.privateKey },
    });

    const token = await client.createToken(baseDef);
    const allowed = client.checkScope(token, 'mychart.com', 'appointments:read');
    expect(allowed.allowed).toBe(true);

    const denied = client.checkScope(token, 'mychart.com', 'messages:send');
    expect(denied.allowed).toBe(false);
  });

  it('checkConstraint works through client', async () => {
    const client = createClient({
      defaultSigningOptions: { privateKey: keys.privateKey },
    });

    const def: APOADefinition = {
      ...baseDef,
      services: [
        {
          service: 'mychart.com',
          scopes: ['appointments:read'],
          constraints: { signing: false },
        },
      ],
    };
    const token = await client.createToken(def);
    const result = client.checkConstraint(token, 'mychart.com', 'signing');
    expect(result.allowed).toBe(false);
  });

  it('revoke + isRevoked use the configured store', async () => {
    const client = createClient({
      defaultSigningOptions: { privateKey: keys.privateKey },
    });

    const token = await client.createToken(baseDef);
    expect(await client.isRevoked(token.jti)).toBe(false);

    await client.revoke(token.jti, { revokedBy: 'did:apoa:juan' });
    expect(await client.isRevoked(token.jti)).toBe(true);
  });

  it('validateToken checks revocation via configured store', async () => {
    const client = createClient({
      defaultSigningOptions: { privateKey: keys.privateKey },
    });

    const token = await client.createToken(baseDef);
    await client.revoke(token.jti, { revokedBy: 'did:apoa:juan' });

    const result = await client.validateToken(token, {
      publicKey: keys.publicKey,
    });
    expect(result.valid).toBe(false);
    expect(result.errors).toContainEqual(expect.stringContaining('revoked'));
  });

  it('authorize uses configured stores', async () => {
    const client = createClient({
      defaultSigningOptions: { privateKey: keys.privateKey },
    });

    const token = await client.createToken(baseDef);

    const allowed = await client.authorize(token, 'mychart.com', 'appointments:read');
    expect(allowed.authorized).toBe(true);

    await client.revoke(token.jti, { revokedBy: 'did:apoa:juan' });
    const denied = await client.authorize(token, 'mychart.com', 'appointments:read');
    expect(denied.authorized).toBe(false);
    expect(denied.checks.revoked).toBe(true);
  });

  it('logAction + getAuditTrail use configured store', async () => {
    const client = createClient({
      defaultSigningOptions: { privateKey: keys.privateKey },
    });

    const token = await client.createToken(baseDef);
    await client.logAction(token.jti, {
      action: 'appointments:read',
      service: 'mychart.com',
      result: 'allowed',
    });

    const trail = await client.getAuditTrail(token.jti);
    expect(trail).toHaveLength(1);
    expect(trail[0].action).toBe('appointments:read');
  });

  it('getAuditTrailByService uses configured store', async () => {
    const client = createClient({
      defaultSigningOptions: { privateKey: keys.privateKey },
    });

    const token = await client.createToken(baseDef);
    await client.logAction(token.jti, {
      action: 'appointments:read',
      service: 'mychart.com',
      result: 'allowed',
    });

    const trail = await client.getAuditTrailByService('mychart.com');
    expect(trail).toHaveLength(1);
  });

  it('delegate works through client', async () => {
    const client = createClient({
      defaultSigningOptions: { privateKey: keys.privateKey },
    });

    const parentDef: APOADefinition = {
      ...baseDef,
      delegatable: true,
      maxDelegationDepth: 3,
    };
    const parent = await client.createToken(parentDef);

    const child = await client.delegate(parent, {
      agent: { id: 'did:apoa:sub-bot' },
      services: [{ service: 'mychart.com', scopes: ['appointments:read'] }],
    });

    expect(child.parentToken).toBe(parent.jti);
    expect(child.definition.principal.id).toBe('did:apoa:juan');
  });

  it('verifyChain uses configured revocation store', async () => {
    const client = createClient({
      defaultSigningOptions: { privateKey: keys.privateKey },
    });

    const parentDef: APOADefinition = {
      ...baseDef,
      delegatable: true,
      maxDelegationDepth: 3,
    };
    const parent = await client.createToken(parentDef);
    const child = await client.delegate(parent, {
      agent: { id: 'did:apoa:sub-bot' },
      services: [{ service: 'mychart.com', scopes: ['appointments:read'] }],
    });

    const valid = await client.verifyChain([parent, child]);
    expect(valid.valid).toBe(true);

    await client.revoke(parent.jti, { revokedBy: 'did:apoa:juan' });
    const invalid = await client.verifyChain([parent, child]);
    expect(invalid.valid).toBe(false);
  });

  it('parseDefinition works through client', () => {
    const client = createClient();
    const def = client.parseDefinition(JSON.stringify(baseDef));
    expect(def.principal.id).toBe('did:apoa:juan');
  });

  it('generateKeyPair works through client', async () => {
    const client = createClient();
    const kp = await client.generateKeyPair();
    expect(kp.publicKey).toBeDefined();
    expect(kp.privateKey).toBeDefined();
  });
});
