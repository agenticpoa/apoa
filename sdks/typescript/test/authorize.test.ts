import { describe, it, expect, beforeAll, vi } from 'vitest';
import { authorize } from '../src/scope/check.js';
import { createToken } from '../src/token/create.js';
import { generateKeyPair } from '../src/utils/crypto.js';
import { MemoryRevocationStore } from '../src/revocation/store.js';
import { MemoryAuditStore } from '../src/audit/store.js';
import type { APOADefinition, APOAToken, RuleViolation } from '../src/types.js';

let keys: CryptoKeyPair;

beforeAll(async () => {
  keys = await generateKeyPair('EdDSA');
});

function makeDef(overrides: Partial<APOADefinition> = {}): APOADefinition {
  return {
    principal: { id: 'did:apoa:juan' },
    agent: { id: 'did:apoa:bot' },
    services: [
      {
        service: 'mychart.com',
        scopes: ['appointments:read', 'prescriptions:read'],
        constraints: { signing: false, data_export: false },
      },
    ],
    expires: '2099-09-01',
    ...overrides,
  };
}

// ── Basic authorization ────────────────────────────────────────

describe('authorize — basic', () => {
  let token: APOAToken;
  let constrainedToken: APOAToken;

  beforeAll(async () => {
    // Token with NO rules and NO false constraints
    token = await createToken(
      makeDef({
        services: [
          { service: 'mychart.com', scopes: ['appointments:read', 'prescriptions:read'] },
        ],
      }),
      { privateKey: keys.privateKey }
    );
    // Token WITH false constraints AND matching scopes
    constrainedToken = await createToken(
      makeDef({
        services: [
          {
            service: 'mychart.com',
            scopes: ['appointments:read', 'signing:submit', 'data_export:run'],
            constraints: { signing: false, data_export: false },
          },
        ],
      }),
      { privateKey: keys.privateKey }
    );
  });

  it('authorizes an allowed action', async () => {
    const result = await authorize(token, 'mychart.com', 'appointments:read');
    expect(result.authorized).toBe(true);
    expect(result.checks.revoked).toBe(false);
    expect(result.checks.scopeAllowed).toBe(true);
    expect(result.checks.constraintsPassed).toBe(true);
    expect(result.checks.rulesPassed).toBe(true);
  });

  it('denies an out-of-scope action', async () => {
    const result = await authorize(token, 'mychart.com', 'messages:send');
    expect(result.authorized).toBe(false);
    expect(result.reason).toContain("scope 'messages:send' not in authorized scopes");
    expect(result.checks.scopeAllowed).toBe(false);
  });

  it('denies when service is not in token', async () => {
    const result = await authorize(token, 'unknown.com', 'read');
    expect(result.authorized).toBe(false);
    expect(result.reason).toContain("service 'unknown.com' not found");
  });

  it('denies when action matches a false constraint', async () => {
    // constrainedToken has { signing: false, data_export: false }
    // "signing:submit" should be denied because "signing" matches the constraint key
    const denied = await authorize(constrainedToken, 'mychart.com', 'signing:submit');
    expect(denied.authorized).toBe(false);
    expect(denied.checks.constraintsPassed).toBe(false);
    expect(denied.reason).toContain('constraint');
  });

  it('allows when action does NOT match any false constraint', async () => {
    // "appointments:read" has nothing to do with "signing" or "data_export"
    const allowed = await authorize(constrainedToken, 'mychart.com', 'appointments:read');
    expect(allowed.authorized).toBe(true);
    expect(allowed.checks.constraintsPassed).toBe(true);
  });
});

// ── Authorization with no constraints ──────────────────────────

describe('authorize — no constraints', () => {
  let token: APOAToken;

  beforeAll(async () => {
    token = await createToken(
      makeDef({
        services: [
          { service: 'mychart.com', scopes: ['appointments:read', 'prescriptions:read'] },
        ],
      }),
      { privateKey: keys.privateKey }
    );
  });

  it('authorizes when no constraints are set', async () => {
    const result = await authorize(token, 'mychart.com', 'appointments:read');
    expect(result.authorized).toBe(true);
    expect(result.checks.constraintsPassed).toBe(true);
  });
});

// ── Revocation ─────────────────────────────────────────────────

describe('authorize — revocation', () => {
  let token: APOAToken;

  beforeAll(async () => {
    token = await createToken(
      makeDef({
        services: [{ service: 'mychart.com', scopes: ['appointments:read'] }],
      }),
      { privateKey: keys.privateKey }
    );
  });

  it('denies a revoked token', async () => {
    const store = new MemoryRevocationStore();
    await store.add({
      tokenId: token.jti,
      revokedAt: new Date(),
      revokedBy: 'did:apoa:juan',
      cascaded: [],
    });

    const result = await authorize(token, 'mychart.com', 'appointments:read', {
      revocationStore: store,
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toBe('token has been revoked');
    expect(result.checks.revoked).toBe(true);
  });

  it('allows when not revoked', async () => {
    const store = new MemoryRevocationStore();
    const result = await authorize(token, 'mychart.com', 'appointments:read', {
      revocationStore: store,
    });
    expect(result.authorized).toBe(true);
    expect(result.checks.revoked).toBe(false);
  });

  it('skips revocation check when no store provided', async () => {
    const result = await authorize(token, 'mychart.com', 'appointments:read');
    expect(result.authorized).toBe(true);
  });

  it('revocation is checked before scope', async () => {
    const store = new MemoryRevocationStore();
    await store.add({
      tokenId: token.jti,
      revokedAt: new Date(),
      revokedBy: 'did:apoa:juan',
      cascaded: [],
    });

    // Even for an allowed scope, revocation takes precedence
    const result = await authorize(token, 'mychart.com', 'appointments:read', {
      revocationStore: store,
    });
    expect(result.authorized).toBe(false);
    expect(result.checks.revoked).toBe(true);
    // scopeAllowed should not be set — we short-circuited at revocation
    expect(result.checks.scopeAllowed).toBeUndefined();
  });
});

// ── Hard rules ─────────────────────────────────────────────────

describe('authorize — hard rules', () => {
  let token: APOAToken;

  beforeAll(async () => {
    token = await createToken(
      makeDef({
        services: [{ service: 'mychart.com', scopes: ['appointments:read', 'signing:submit'] }],
        rules: [
          { id: 'no-signing', description: 'Never sign anything', enforcement: 'hard' },
        ],
      }),
      { privateKey: keys.privateKey }
    );
  });

  it('denies when action matches a hard rule', async () => {
    // "no-signing" extracts "signing", which matches "signing:submit"
    const result = await authorize(token, 'mychart.com', 'signing:submit');
    expect(result.authorized).toBe(false);
    expect(result.checks.rulesPassed).toBe(false);
    expect(result.reason).toContain('no-signing');
  });

  it('allows when action does NOT match hard rule', async () => {
    // "appointments:read" has nothing to do with "signing"
    const result = await authorize(token, 'mychart.com', 'appointments:read');
    expect(result.authorized).toBe(true);
    expect(result.checks.rulesPassed).toBe(true);
  });

  it('hard rule denial includes rule id in reason', async () => {
    const result = await authorize(token, 'mychart.com', 'signing:submit');
    expect(result.reason).toContain('no-signing');
  });

  it('hard rule check happens after scope check', async () => {
    // Out-of-scope action — should fail on scope, not rules
    const result = await authorize(token, 'mychart.com', 'admin:write');
    expect(result.authorized).toBe(false);
    expect(result.checks.scopeAllowed).toBe(false);
    // rulesPassed should not be set — we short-circuited at scope
    expect(result.checks.rulesPassed).toBeUndefined();
  });
});

// ── Soft rules ─────────────────────────────────────────────────

describe('authorize — soft rules', () => {
  let token: APOAToken;

  beforeAll(async () => {
    token = await createToken(
      makeDef({
        services: [{ service: 'mychart.com', scopes: ['appointments:read'] }],
        rules: [
          {
            id: 'business-hours',
            description: 'Alert when accessed outside business hours',
            enforcement: 'soft',
          },
          {
            id: 'frequency-monitor',
            description: 'Track access frequency',
            enforcement: 'soft',
          },
        ],
      }),
      { privateKey: keys.privateKey }
    );
  });

  it('allows the action despite soft rule violations', async () => {
    const result = await authorize(token, 'mychart.com', 'appointments:read');
    expect(result.authorized).toBe(true);
    expect(result.checks.rulesPassed).toBe(true);
  });

  it('returns violations for all soft rules', async () => {
    const result = await authorize(token, 'mychart.com', 'appointments:read');
    expect(result.violations).toHaveLength(2);
    expect(result.violations![0].ruleId).toBe('business-hours');
    expect(result.violations![1].ruleId).toBe('frequency-monitor');
  });

  it('violations have correct fields', async () => {
    const result = await authorize(token, 'mychart.com', 'appointments:read');
    const v = result.violations![0];
    expect(v.tokenId).toBe(token.jti);
    expect(v.action).toBe('appointments:read');
    expect(v.service).toBe('mychart.com');
    expect(v.timestamp).toBeInstanceOf(Date);
    expect(v.details).toBe('Alert when accessed outside business hours');
  });

  it('logs violations to audit store when provided', async () => {
    const auditStore = new MemoryAuditStore();

    await authorize(token, 'mychart.com', 'appointments:read', { auditStore });

    const entries = await auditStore.query(token.jti);
    expect(entries).toHaveLength(2);
    expect(entries[0].result).toBe('escalated');
    expect(entries[0].details?.ruleId).toBe('business-hours');
    expect(entries[1].details?.ruleId).toBe('frequency-monitor');
  });

  it('invokes onViolation callbacks', async () => {
    const violations: RuleViolation[] = [];
    const callbackToken = await createToken(
      makeDef({
        services: [{ service: 'mychart.com', scopes: ['appointments:read'] }],
        rules: [
          {
            id: 'tracked-rule',
            description: 'Track this',
            enforcement: 'soft',
            onViolation: (v) => { violations.push(v); },
          },
        ],
      }),
      { privateKey: keys.privateKey }
    );

    await authorize(callbackToken, 'mychart.com', 'appointments:read');
    expect(violations).toHaveLength(1);
    expect(violations[0].ruleId).toBe('tracked-rule');
  });
});

// ── Mixed rules ────────────────────────────────────────────────

describe('authorize — mixed hard and soft rules', () => {
  it('hard rule denies matching action, soft rules don\'t fire', async () => {
    const token = await createToken(
      makeDef({
        services: [{ service: 'mychart.com', scopes: ['access:read', 'appointments:read'] }],
        rules: [
          { id: 'monitor', description: 'Track access', enforcement: 'soft' },
          { id: 'no-access', description: 'Block access actions', enforcement: 'hard' },
        ],
      }),
      { privateKey: keys.privateKey }
    );

    // "access:read" matches hard rule "no-access" (contains "access")
    const result = await authorize(token, 'mychart.com', 'access:read');
    expect(result.authorized).toBe(false);
    expect(result.checks.rulesPassed).toBe(false);
    // Soft rule violations should NOT be present — hard rule short-circuits
    expect(result.violations).toBeUndefined();
  });

  it('non-matching hard rule allows action, soft rules still fire', async () => {
    const token = await createToken(
      makeDef({
        services: [{ service: 'mychart.com', scopes: ['appointments:read'] }],
        rules: [
          { id: 'monitor', description: 'Track access', enforcement: 'soft' },
          { id: 'no-signing', description: 'Block signing', enforcement: 'hard' },
        ],
      }),
      { privateKey: keys.privateKey }
    );

    // "appointments:read" doesn't match "signing" — hard rule doesn't fire
    const result = await authorize(token, 'mychart.com', 'appointments:read');
    expect(result.authorized).toBe(true);
    expect(result.checks.rulesPassed).toBe(true);
    // Soft rule still fires
    expect(result.violations).toHaveLength(1);
    expect(result.violations![0].ruleId).toBe('monitor');
  });
});

// ── No rules ───────────────────────────────────────────────────

describe('authorize — no rules', () => {
  it('returns rulesPassed: true with no violations', async () => {
    const token = await createToken(
      makeDef({
        services: [{ service: 'mychart.com', scopes: ['appointments:read'] }],
        // No rules
      }),
      { privateKey: keys.privateKey }
    );

    const result = await authorize(token, 'mychart.com', 'appointments:read');
    expect(result.authorized).toBe(true);
    expect(result.checks.rulesPassed).toBe(true);
    expect(result.violations).toBeUndefined();
  });

  it('returns rulesPassed: true with empty rules array', async () => {
    const token = await createToken(
      makeDef({
        services: [{ service: 'mychart.com', scopes: ['appointments:read'] }],
        rules: [],
      }),
      { privateKey: keys.privateKey }
    );

    const result = await authorize(token, 'mychart.com', 'appointments:read');
    expect(result.authorized).toBe(true);
    expect(result.checks.rulesPassed).toBe(true);
    expect(result.violations).toBeUndefined();
  });
});

// ── Enforcement order ──────────────────────────────────────────

describe('authorize — enforcement order', () => {
  it('revocation is checked first', async () => {
    const store = new MemoryRevocationStore();
    const token = await createToken(
      makeDef({
        services: [{ service: 'mychart.com', scopes: ['appointments:read'] }],
        rules: [
          { id: 'hard-rule', description: 'Block', enforcement: 'hard' },
        ],
      }),
      { privateKey: keys.privateKey }
    );

    await store.add({
      tokenId: token.jti,
      revokedAt: new Date(),
      revokedBy: 'did:apoa:juan',
      cascaded: [],
    });

    const result = await authorize(token, 'mychart.com', 'appointments:read', {
      revocationStore: store,
    });

    // Should fail on revocation, not on hard rule
    expect(result.authorized).toBe(false);
    expect(result.checks.revoked).toBe(true);
    expect(result.checks.rulesPassed).toBeUndefined();
  });

  it('scope is checked before rules', async () => {
    const token = await createToken(
      makeDef({
        services: [{ service: 'mychart.com', scopes: ['appointments:read'] }],
        rules: [
          { id: 'soft-rule', description: 'Monitor', enforcement: 'soft' },
        ],
      }),
      { privateKey: keys.privateKey }
    );

    // Bad scope — should fail on scope, not produce violations
    const result = await authorize(token, 'mychart.com', 'admin:delete');
    expect(result.authorized).toBe(false);
    expect(result.checks.scopeAllowed).toBe(false);
    expect(result.violations).toBeUndefined();
  });

  it('constraints are checked before rules', async () => {
    const token = await createToken(
      makeDef({
        services: [
          {
            service: 'mychart.com',
            scopes: ['signing:submit'],
            constraints: { signing: false },
          },
        ],
        rules: [
          { id: 'soft-rule', description: 'Monitor', enforcement: 'soft' },
        ],
      }),
      { privateKey: keys.privateKey }
    );

    // "signing:submit" matches constraint { signing: false } — denied at constraint step
    const result = await authorize(token, 'mychart.com', 'signing:submit');
    expect(result.authorized).toBe(false);
    expect(result.checks.constraintsPassed).toBe(false);
    // Soft rules should NOT fire — constraint check short-circuits first
    expect(result.violations).toBeUndefined();
  });
});

// ── Multi-service ──────────────────────────────────────────────

describe('authorize — multi-service', () => {
  it('checks the correct service', async () => {
    const token = await createToken(
      makeDef({
        services: [
          { service: 'mychart.com', scopes: ['appointments:read'] },
          { service: 'stripe.com', scopes: ['charges:read'] },
        ],
      }),
      { privateKey: keys.privateKey }
    );

    const r1 = await authorize(token, 'mychart.com', 'appointments:read');
    expect(r1.authorized).toBe(true);

    const r2 = await authorize(token, 'stripe.com', 'charges:read');
    expect(r2.authorized).toBe(true);

    const r3 = await authorize(token, 'mychart.com', 'charges:read');
    expect(r3.authorized).toBe(false);
  });
});
