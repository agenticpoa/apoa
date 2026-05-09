import { describe, it, expect, beforeAll } from 'vitest';
import { createClient } from '../src/client.js';
import { createToken } from '../src/token/create.js';
import { validateToken } from '../src/token/validate.js';
import { checkScope } from '../src/scope/check.js';
import { generateKeyPair } from '../src/utils/crypto.js';
import { revoke, isRevoked } from '../src/revocation/revoke.js';
import { logAction } from '../src/audit/log.js';
import { getAuditTrail } from '../src/audit/trail.js';
import { delegate } from '../src/delegation/chain.js';
import { verifyChain } from '../src/delegation/verify.js';
import { cascadeRevoke } from '../src/revocation/cascade.js';
import { MemoryRevocationStore } from '../src/revocation/store.js';
import { MemoryAuditStore } from '../src/audit/store.js';
import type { APOADefinition } from '../src/types.js';

let keys: CryptoKeyPair;

beforeAll(async () => {
  keys = await generateKeyPair('EdDSA');
});

// ── Full token lifecycle ───────────────────────────────────────

describe('integration: full token lifecycle', () => {
  it('create → validate → use → revoke → confirm revoked', async () => {
    const store = new MemoryRevocationStore();
    const auditStore = new MemoryAuditStore();

    // Create
    const token = await createToken(
      {
        principal: { id: 'did:apoa:juan' },
        agent: { id: 'did:apoa:bot', name: 'TestBot' },
        services: [
          { service: 'mychart.com', scopes: ['appointments:read', 'prescriptions:read'] },
        ],
        expires: '2099-09-01',
      },
      { privateKey: keys.privateKey }
    );

    // Validate
    const valid = await validateToken(token.raw, {
      publicKey: keys.publicKey,
      revocationStore: store,
    });
    expect(valid.valid).toBe(true);

    // Use (scope check + audit)
    const scopeResult = checkScope(token, 'mychart.com', 'appointments:read');
    expect(scopeResult.allowed).toBe(true);

    await logAction(
      token.jti,
      { action: 'appointments:read', service: 'mychart.com', result: 'allowed' },
      auditStore
    );

    // Revoke
    await revoke(token.jti, { revokedBy: 'did:apoa:juan', reason: 'done' }, store);
    expect(await isRevoked(token.jti, store)).toBe(true);

    // Confirm revoked via validation
    const revoked = await validateToken(token.raw, {
      publicKey: keys.publicKey,
      revocationStore: store,
    });
    expect(revoked.valid).toBe(false);
    expect(revoked.errors).toContainEqual(expect.stringContaining('revoked'));

    // Audit trail has the action
    const trail = await getAuditTrail(token.jti, undefined, auditStore);
    expect(trail).toHaveLength(1);
    expect(trail[0].action).toBe('appointments:read');
  });
});

// ── Delegation chain lifecycle ─────────────────────────────────

describe('integration: delegation chain', () => {
  it('create parent → delegate → verify chain → cascade revoke', async () => {
    const store = new MemoryRevocationStore();

    const parent = await createToken(
      {
        principal: { id: 'did:apoa:juan' },
        agent: { id: 'did:apoa:homebot', name: 'HomeBot' },
        services: [
          { service: 'mychart.com', scopes: ['appointments:read', 'appointments:write'] },
          { service: 'stripe.com', scopes: ['charges:read'] },
        ],
        expires: '2099-09-01',
        delegatable: true,
        maxDelegationDepth: 3,
      },
      { privateKey: keys.privateKey }
    );

    // Delegate with attenuation
    const child = await delegate(
      parent,
      {
        agent: { id: 'did:apoa:sub-bot', name: 'SubBot' },
        services: [
          { service: 'mychart.com', scopes: ['appointments:read'] },
        ],
        expires: '2098-01-01',
      },
      { privateKey: keys.privateKey }
    );

    expect(child.parentToken).toBe(parent.jti);
    expect(child.definition.principal.id).toBe('did:apoa:juan');

    // Verify chain
    const chainResult = await verifyChain([parent, child], store);
    expect(chainResult.valid).toBe(true);
    expect(chainResult.depth).toBe(1);

    // Cascade revoke
    const record = await cascadeRevoke(
      parent.jti,
      [child.jti],
      { revokedBy: 'did:apoa:juan', reason: 'compromised' },
      store
    );
    expect(record.cascaded).toEqual([child.jti]);

    // Both should be revoked
    expect(await isRevoked(parent.jti, store)).toBe(true);
    expect(await isRevoked(child.jti, store)).toBe(true);

    // Chain should now fail verification
    const invalidChain = await verifyChain([parent, child], store);
    expect(invalidChain.valid).toBe(false);
  });
});

// ── Multi-service with rules and audit ─────────────────────────

describe('integration: multi-service authorization with rules', () => {
  it('authorizes across services with soft rules and audit logging', async () => {
    const client = createClient({
      defaultSigningOptions: { privateKey: keys.privateKey },
    });

    const token = await client.createToken({
      principal: { id: 'did:apoa:juan' },
      agent: { id: 'did:apoa:bot' },
      services: [
        { service: 'mychart.com', scopes: ['appointments:read'] },
        { service: 'stripe.com', scopes: ['charges:read', 'balance:read'] },
      ],
      rules: [
        { id: 'frequency-alert', description: 'Track high-frequency access', enforcement: 'soft' },
      ],
      expires: '2099-09-01',
    });

    // Authorize on mychart
    const r1 = await client.authorize(token, 'mychart.com', 'appointments:read');
    expect(r1.authorized).toBe(true);
    expect(r1.violations).toHaveLength(1);
    expect(r1.violations![0].ruleId).toBe('frequency-alert');

    // Authorize on stripe
    const r2 = await client.authorize(token, 'stripe.com', 'charges:read');
    expect(r2.authorized).toBe(true);

    // Log actions
    await client.logAction(token.jti, {
      action: 'appointments:read',
      service: 'mychart.com',
      result: 'allowed',
    });
    await client.logAction(token.jti, {
      action: 'charges:read',
      service: 'stripe.com',
      result: 'allowed',
    });

    // Audit trail
    const trail = await client.getAuditTrail(token.jti);
    // 2 soft rule violations (from authorize) + 2 logAction calls = 4
    expect(trail.length).toBeGreaterThanOrEqual(4);

    // Filter by service
    const stripeTrail = await client.getAuditTrailByService('stripe.com');
    expect(stripeTrail.length).toBeGreaterThanOrEqual(1);
  });
});

// ── Mixed-mode token ───────────────────────────────────────────

describe('integration: mixed-mode token', () => {
  it('browser and API services produce different audit trail shapes', async () => {
    const client = createClient({
      defaultSigningOptions: { privateKey: keys.privateKey },
    });

    const token = await client.createToken({
      principal: { id: 'did:apoa:juan' },
      agent: { id: 'did:apoa:homebot', name: 'HomeBot' },
      services: [
        {
          service: 'mortgage.com',
          scopes: ['rate_lock:read', 'documents:read'],
          accessMode: 'browser',
          browserConfig: {
            allowedUrls: ['https://portal.mortgage.com/*'],
            credentialVaultRef: '1password://vault/mortgage',
            maxSessionDuration: 1800,
          },
        },
        {
          service: 'api.redfin.com',
          scopes: ['listings:read', 'offers:read'],
          accessMode: 'api',
        },
      ],
      expires: '2099-06-15',
    });

    // Browser-mode action
    await client.logAction(token.jti, {
      action: 'rate_lock:read',
      service: 'mortgage.com',
      result: 'allowed',
      url: 'https://portal.mortgage.com/rate-lock',
      accessMode: 'browser',
      screenshotRef: 's3://bucket/shot1.png',
    });

    // API-mode action
    await client.logAction(token.jti, {
      action: 'listings:read',
      service: 'api.redfin.com',
      result: 'allowed',
      accessMode: 'api',
    });

    const trail = await client.getAuditTrail(token.jti);
    expect(trail).toHaveLength(2);

    const browserEntry = trail.find((e) => e.accessMode === 'browser');
    expect(browserEntry?.url).toBe('https://portal.mortgage.com/rate-lock');
    expect(browserEntry?.screenshotRef).toBe('s3://bucket/shot1.png');

    const apiEntry = trail.find((e) => e.accessMode === 'api');
    expect(apiEntry?.url).toBeUndefined();
    expect(apiEntry?.screenshotRef).toBeUndefined();
  });
});

// ── Legal framework round-trip ─────────────────────────────────

describe('integration: legal framework', () => {
  it('create with legal fields → validate → fields persist', async () => {
    const client = createClient({
      defaultSigningOptions: { privateKey: keys.privateKey },
    });

    const token = await client.createToken({
      principal: { id: 'did:apoa:jane', name: 'Jane Doe' },
      agent: { id: 'did:apoa:homebot', name: 'HomeBot Pro' },
      agentProvider: {
        name: 'HomeBot Inc.',
        id: 'did:apoa:provider:homebot',
        contact: 'legal@homebot.ai',
      },
      services: [
        {
          service: 'mortgage.com',
          scopes: ['rate_lock:read', 'documents:read'],
          accessMode: 'browser',
          browserConfig: {
            allowedUrls: ['https://portal.mortgage.com/*'],
            credentialVaultRef: '1password://vault/mortgage',
          },
        },
      ],
      legal: {
        model: 'provider-as-agent',
        jurisdiction: 'US-CA',
        legalBasis: ['UETA-14', 'E-SIGN'],
        pairedLegalInstrument: false,
      },
      expires: '2099-06-15',
    });

    // Verify legal fields persist on the token object
    expect(token.definition.legal?.model).toBe('provider-as-agent');
    expect(token.definition.legal?.jurisdiction).toBe('US-CA');
    expect(token.definition.legal?.legalBasis).toEqual(['UETA-14', 'E-SIGN']);
    expect(token.definition.legal?.pairedLegalInstrument).toBe(false);
    expect(token.definition.agentProvider?.name).toBe('HomeBot Inc.');

    // Validate and check parsed token preserves legal fields
    const result = await client.validateToken(token, {
      publicKey: keys.publicKey,
    });
    expect(result.valid).toBe(true);
    expect(result.token?.definition.legal?.jurisdiction).toBe('US-CA');
    expect(result.token?.definition.agentProvider?.name).toBe('HomeBot Inc.');
  });
});

// ── Client vs standalone parity ────────────────────────────────

describe('integration: client vs standalone parity', () => {
  it('client and standalone functions produce equivalent results', async () => {
    const store = new MemoryRevocationStore();
    const auditStore = new MemoryAuditStore();

    const client = createClient({
      revocationStore: store,
      auditStore,
      defaultSigningOptions: { privateKey: keys.privateKey },
    });

    const def: APOADefinition = {
      principal: { id: 'did:apoa:juan' },
      agent: { id: 'did:apoa:bot' },
      services: [
        { service: 'mychart.com', scopes: ['appointments:read'] },
      ],
      expires: '2099-09-01',
    };

    // Create via both paths
    const clientToken = await client.createToken(def);
    const standaloneToken = await createToken(def, { privateKey: keys.privateKey });

    // Both should have valid structure
    expect(clientToken.jti).toBeTruthy();
    expect(standaloneToken.jti).toBeTruthy();
    expect(clientToken.issuer).toBe(standaloneToken.issuer);

    // Scope check parity
    const clientScope = client.checkScope(clientToken, 'mychart.com', 'appointments:read');
    const standaloneScope = checkScope(standaloneToken, 'mychart.com', 'appointments:read');
    expect(clientScope.allowed).toBe(standaloneScope.allowed);

    // Validate parity
    const clientValid = await client.validateToken(clientToken, {
      publicKey: keys.publicKey,
    });
    const standaloneValid = await validateToken(standaloneToken.raw, {
      publicKey: keys.publicKey,
      revocationStore: store,
    });
    expect(clientValid.valid).toBe(standaloneValid.valid);
  });
});
