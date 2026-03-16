import { describe, it, expect } from 'vitest';
import { checkScope, checkConstraint } from '../src/scope/check.js';
import type { APOAToken } from '../src/types.js';

function makeToken(services: APOAToken['definition']['services']): APOAToken {
  return {
    jti: 'test-token',
    definition: {
      principal: { id: 'did:apoa:user' },
      agent: { id: 'did:apoa:bot' },
      services,
      expires: '2099-01-01',
    },
    issuedAt: new Date(),
    signature: 'test-sig',
    issuer: 'did:apoa:user',
    raw: 'raw-jwt',
  };
}

describe('checkScope', () => {
  it('allows an exact scope match', () => {
    const token = makeToken([
      { service: 'mychart.com', scopes: ['appointments:read'] },
    ]);
    const result = checkScope(token, 'mychart.com', 'appointments:read');
    expect(result.allowed).toBe(true);
    expect(result.reason).toContain("matched scope 'appointments:read'");
    expect(result.matchedScope).toBe('appointments:read');
  });

  it('denies an action not in scopes', () => {
    const token = makeToken([
      { service: 'mychart.com', scopes: ['appointments:read'] },
    ]);
    const result = checkScope(token, 'mychart.com', 'messages:send');
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("scope 'messages:send' not in authorized scopes");
  });

  it('allows wildcard scope match', () => {
    const token = makeToken([
      { service: 'mychart.com', scopes: ['appointments:*'] },
    ]);
    const result = checkScope(token, 'mychart.com', 'appointments:read');
    expect(result.allowed).toBe(true);
    expect(result.matchedScope).toBe('appointments:*');
  });

  it('wildcard does not match across levels', () => {
    const token = makeToken([
      { service: 'mychart.com', scopes: ['appointments:*'] },
    ]);
    const result = checkScope(token, 'mychart.com', 'appointments:read:summary');
    expect(result.allowed).toBe(false);
  });

  it('root wildcard matches everything', () => {
    const token = makeToken([{ service: 'mychart.com', scopes: ['*'] }]);
    const result = checkScope(token, 'mychart.com', 'anything:at:all');
    expect(result.allowed).toBe(true);
    expect(result.matchedScope).toBe('*');
  });

  it('returns service not found for unknown service', () => {
    const token = makeToken([
      { service: 'mychart.com', scopes: ['appointments:read'] },
    ]);
    const result = checkScope(token, 'stripe.com', 'charges:read');
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("service 'stripe.com' not found");
  });

  it('checks the correct service in multi-service token', () => {
    const token = makeToken([
      { service: 'mychart.com', scopes: ['appointments:read'] },
      { service: 'stripe.com', scopes: ['charges:read'] },
    ]);
    expect(checkScope(token, 'mychart.com', 'appointments:read').allowed).toBe(true);
    expect(checkScope(token, 'stripe.com', 'charges:read').allowed).toBe(true);
    expect(checkScope(token, 'mychart.com', 'charges:read').allowed).toBe(false);
    expect(checkScope(token, 'stripe.com', 'appointments:read').allowed).toBe(false);
  });

  it('matches first matching scope when multiple scopes exist', () => {
    const token = makeToken([
      {
        service: 'mychart.com',
        scopes: ['appointments:read', 'appointments:*', 'prescriptions:read'],
      },
    ]);
    const result = checkScope(token, 'mychart.com', 'appointments:read');
    expect(result.allowed).toBe(true);
    expect(result.matchedScope).toBe('appointments:read');
  });
});

describe('checkConstraint', () => {
  it('returns allowed: false when constraint is false', () => {
    const token = makeToken([
      {
        service: 'mychart.com',
        scopes: ['appointments:read'],
        constraints: { signing: false, data_export: false },
      },
    ]);
    const result = checkConstraint(token, 'mychart.com', 'signing');
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("constraint 'signing' is set to false");
    expect(result.constraint).toBe('signing');
  });

  it('returns allowed: true when constraint is true', () => {
    const token = makeToken([
      {
        service: 'mychart.com',
        scopes: ['appointments:read'],
        constraints: { form_fill: true },
      },
    ]);
    const result = checkConstraint(token, 'mychart.com', 'form_fill');
    expect(result.allowed).toBe(true);
  });

  it('returns allowed: true when constraint is not defined', () => {
    const token = makeToken([
      {
        service: 'mychart.com',
        scopes: ['appointments:read'],
        constraints: { signing: false },
      },
    ]);
    const result = checkConstraint(token, 'mychart.com', 'nonexistent');
    expect(result.allowed).toBe(true);
    expect(result.reason).toContain("constraint 'nonexistent' not defined");
  });

  it('returns allowed: true when no constraints on service', () => {
    const token = makeToken([
      { service: 'mychart.com', scopes: ['appointments:read'] },
    ]);
    const result = checkConstraint(token, 'mychart.com', 'signing');
    expect(result.allowed).toBe(true);
    expect(result.reason).toContain('no constraints defined');
  });

  it('returns service not found for unknown service', () => {
    const token = makeToken([
      { service: 'mychart.com', scopes: ['read'] },
    ]);
    const result = checkConstraint(token, 'unknown.com', 'signing');
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("service 'unknown.com' not found");
  });

  it('handles string constraint values', () => {
    const token = makeToken([
      {
        service: 'mychart.com',
        scopes: ['read'],
        constraints: { region: 'US' },
      },
    ]);
    const result = checkConstraint(token, 'mychart.com', 'region');
    expect(result.allowed).toBe(true);
    expect(result.reason).toContain('"US"');
  });

  it('handles numeric constraint values', () => {
    const token = makeToken([
      {
        service: 'mychart.com',
        scopes: ['read'],
        constraints: { max_results: 100 },
      },
    ]);
    const result = checkConstraint(token, 'mychart.com', 'max_results');
    expect(result.allowed).toBe(true);
    expect(result.reason).toContain('100');
  });
});
