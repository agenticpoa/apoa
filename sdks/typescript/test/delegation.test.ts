import { describe, it, expect, beforeAll } from 'vitest';
import { delegate } from '../src/delegation/chain.js';
import { verifyChain } from '../src/delegation/verify.js';
import { verifyAttenuation } from '../src/scope/attenuate.js';
import { createToken } from '../src/token/create.js';
import { generateKeyPair } from '../src/utils/crypto.js';
import { MemoryRevocationStore } from '../src/revocation/store.js';
import { AttenuationViolationError } from '../src/utils/errors.js';
import type {
  APOAToken,
  APOADefinition,
  DelegationDefinition,
} from '../src/types.js';

let keys: CryptoKeyPair;
let parentToken: APOAToken;

const parentDef: APOADefinition = {
  principal: { id: 'did:apoa:juan', name: 'Juan' },
  agent: { id: 'did:apoa:homebot', name: 'HomeBot Pro' },
  services: [
    {
      service: 'mychart.com',
      scopes: ['appointments:read', 'appointments:write', 'prescriptions:read'],
      constraints: { signing: false, data_export: false },
    },
    {
      service: 'stripe.com',
      scopes: ['charges:read', 'balance:read'],
    },
  ],
  rules: [
    { id: 'no-messaging', description: 'Never send messages', enforcement: 'hard' },
  ],
  expires: '2099-09-01',
  delegatable: true,
  maxDelegationDepth: 3,
  revocable: true,
};

beforeAll(async () => {
  keys = await generateKeyPair('EdDSA');
  parentToken = await createToken(parentDef, { privateKey: keys.privateKey });
});

// ── verifyAttenuation ──────────────────────────────────────────

describe('verifyAttenuation', () => {
  it('accepts valid attenuation (subset of scopes)', () => {
    const child: DelegationDefinition = {
      agent: { id: 'did:apoa:sub-bot' },
      services: [
        { service: 'mychart.com', scopes: ['appointments:read'] },
      ],
      rules: [
        { id: 'no-messaging', description: 'Never send messages', enforcement: 'hard' },
      ],
    };
    expect(() => verifyAttenuation(parentToken, child)).not.toThrow();
  });

  it('rejects scope expansion', () => {
    const child: DelegationDefinition = {
      agent: { id: 'did:apoa:sub-bot' },
      services: [
        { service: 'mychart.com', scopes: ['appointments:read', 'messages:send'] },
      ],
      rules: [
        { id: 'no-messaging', description: 'Never send messages', enforcement: 'hard' },
      ],
    };
    expect(() => verifyAttenuation(parentToken, child)).toThrow(
      AttenuationViolationError
    );
  });

  it('rejects service not in parent', () => {
    const child: DelegationDefinition = {
      agent: { id: 'did:apoa:sub-bot' },
      services: [
        { service: 'unknown.com', scopes: ['read'] },
      ],
      rules: [
        { id: 'no-messaging', description: 'Never send messages', enforcement: 'hard' },
      ],
    };
    expect(() => verifyAttenuation(parentToken, child)).toThrow(
      AttenuationViolationError
    );
  });

  it('rejects child expiration after parent', () => {
    const child: DelegationDefinition = {
      agent: { id: 'did:apoa:sub-bot' },
      services: [
        { service: 'mychart.com', scopes: ['appointments:read'] },
      ],
      expires: '2199-01-01',
      rules: [
        { id: 'no-messaging', description: 'Never send messages', enforcement: 'hard' },
      ],
    };
    expect(() => verifyAttenuation(parentToken, child)).toThrow(
      AttenuationViolationError
    );
  });

  it('accepts child expiration before parent', () => {
    const child: DelegationDefinition = {
      agent: { id: 'did:apoa:sub-bot' },
      services: [
        { service: 'mychart.com', scopes: ['appointments:read'] },
      ],
      expires: '2098-01-01',
      rules: [
        { id: 'no-messaging', description: 'Never send messages', enforcement: 'hard' },
      ],
    };
    expect(() => verifyAttenuation(parentToken, child)).not.toThrow();
  });

  it('rejects constraint relaxation (false → true)', () => {
    const child: DelegationDefinition = {
      agent: { id: 'did:apoa:sub-bot' },
      services: [
        {
          service: 'mychart.com',
          scopes: ['appointments:read'],
          constraints: { signing: true }, // parent has signing: false
        },
      ],
      rules: [
        { id: 'no-messaging', description: 'Never send messages', enforcement: 'hard' },
      ],
    };
    expect(() => verifyAttenuation(parentToken, child)).toThrow(
      AttenuationViolationError
    );
  });

  it('accepts adding new constraints', () => {
    const child: DelegationDefinition = {
      agent: { id: 'did:apoa:sub-bot' },
      services: [
        {
          service: 'mychart.com',
          scopes: ['appointments:read'],
          constraints: { signing: false, data_export: false, new_constraint: false },
        },
      ],
      rules: [
        { id: 'no-messaging', description: 'Never send messages', enforcement: 'hard' },
      ],
    };
    expect(() => verifyAttenuation(parentToken, child)).not.toThrow();
  });

  it('rejects removing parent rules', () => {
    const child: DelegationDefinition = {
      agent: { id: 'did:apoa:sub-bot' },
      services: [
        { service: 'mychart.com', scopes: ['appointments:read'] },
      ],
      // Missing 'no-messaging' rule from parent
    };
    expect(() => verifyAttenuation(parentToken, child)).toThrow(
      AttenuationViolationError
    );
  });

  it('accepts adding new rules', () => {
    const child: DelegationDefinition = {
      agent: { id: 'did:apoa:sub-bot' },
      services: [
        { service: 'mychart.com', scopes: ['appointments:read'] },
      ],
      rules: [
        { id: 'no-messaging', description: 'Never send messages', enforcement: 'hard' },
        { id: 'business-hours', description: 'Only during business hours', enforcement: 'soft' },
      ],
    };
    expect(() => verifyAttenuation(parentToken, child)).not.toThrow();
  });

  it('rejects when delegation is not allowed', async () => {
    const noDelegateDef = { ...parentDef, delegatable: false };
    const noDelegateToken = await createToken(noDelegateDef, {
      privateKey: keys.privateKey,
    });
    const child: DelegationDefinition = {
      agent: { id: 'did:apoa:sub-bot' },
      services: [
        { service: 'mychart.com', scopes: ['appointments:read'] },
      ],
    };
    expect(() => verifyAttenuation(noDelegateToken, child)).toThrow(
      AttenuationViolationError
    );
  });

  it('rejects when maxDelegationDepth is exceeded', async () => {
    const shallowDef = { ...parentDef, maxDelegationDepth: 1 };
    const shallowToken = await createToken(shallowDef, {
      privateKey: keys.privateKey,
    });
    // Simulate depth 1 (already delegated once)
    const child: DelegationDefinition = {
      agent: { id: 'did:apoa:sub-bot' },
      services: [
        { service: 'mychart.com', scopes: ['appointments:read'] },
      ],
      rules: [
        { id: 'no-messaging', description: 'Never send messages', enforcement: 'hard' },
      ],
    };
    expect(() => verifyAttenuation(shallowToken, child, 1)).toThrow(
      AttenuationViolationError
    );
  });
});

// ── delegate ───────────────────────────────────────────────────

describe('delegate', () => {
  it('creates a child token with subset of parent scopes', async () => {
    const child = await delegate(
      parentToken,
      {
        agent: { id: 'did:apoa:sub-bot', name: 'SubBot' },
        services: [
          { service: 'mychart.com', scopes: ['appointments:read'] },
        ],
        rules: [
          { id: 'no-messaging', description: 'Never send messages', enforcement: 'hard' },
        ],
      },
      { privateKey: keys.privateKey }
    );

    expect(child.jti).toBeTruthy();
    expect(child.parentToken).toBe(parentToken.jti);
    expect(child.definition.agent.id).toBe('did:apoa:sub-bot');
    expect(child.definition.principal.id).toBe('did:apoa:juan');
  });

  it('inherits principal from parent', async () => {
    const child = await delegate(
      parentToken,
      {
        agent: { id: 'did:apoa:other-bot' },
        services: [{ service: 'mychart.com', scopes: ['appointments:read'] }],
        rules: [
          { id: 'no-messaging', description: 'Never send messages', enforcement: 'hard' },
        ],
      },
      { privateKey: keys.privateKey }
    );

    // Principal must be inherited, not overridable
    expect(child.definition.principal).toEqual(parentToken.definition.principal);
  });

  it('sets parentToken to parent jti', async () => {
    const child = await delegate(
      parentToken,
      {
        agent: { id: 'did:apoa:sub-bot' },
        services: [{ service: 'mychart.com', scopes: ['appointments:read'] }],
        rules: [
          { id: 'no-messaging', description: 'Never send messages', enforcement: 'hard' },
        ],
      },
      { privateKey: keys.privateKey }
    );
    expect(child.parentToken).toBe(parentToken.jti);
  });

  it('inherits parent expiration when child omits it', async () => {
    const child = await delegate(
      parentToken,
      {
        agent: { id: 'did:apoa:sub-bot' },
        services: [{ service: 'mychart.com', scopes: ['appointments:read'] }],
        rules: [
          { id: 'no-messaging', description: 'Never send messages', enforcement: 'hard' },
        ],
        // no expires — inherits from parent
      },
      { privateKey: keys.privateKey }
    );
    expect(child.definition.expires).toBe(parentDef.expires);
  });

  it('merges rules (parent + child additions)', async () => {
    const child = await delegate(
      parentToken,
      {
        agent: { id: 'did:apoa:sub-bot' },
        services: [{ service: 'mychart.com', scopes: ['appointments:read'] }],
        rules: [
          { id: 'no-messaging', description: 'Never send messages', enforcement: 'hard' },
          { id: 'biz-hours', description: 'Business hours only', enforcement: 'soft' },
        ],
      },
      { privateKey: keys.privateKey }
    );

    const ruleIds = child.definition.rules?.map((r) => r.id) ?? [];
    expect(ruleIds).toContain('no-messaging');
    expect(ruleIds).toContain('biz-hours');
  });

  it('throws on scope expansion', async () => {
    await expect(
      delegate(
        parentToken,
        {
          agent: { id: 'did:apoa:sub-bot' },
          services: [
            { service: 'mychart.com', scopes: ['appointments:read', 'admin:write'] },
          ],
          rules: [
            { id: 'no-messaging', description: 'Never send messages', enforcement: 'hard' },
          ],
        },
        { privateKey: keys.privateKey }
      )
    ).rejects.toThrow(AttenuationViolationError);
  });

  it('allows delegation to multiple services (all subsets)', async () => {
    const child = await delegate(
      parentToken,
      {
        agent: { id: 'did:apoa:sub-bot' },
        services: [
          { service: 'mychart.com', scopes: ['appointments:read'] },
          { service: 'stripe.com', scopes: ['charges:read'] },
        ],
        rules: [
          { id: 'no-messaging', description: 'Never send messages', enforcement: 'hard' },
        ],
      },
      { privateKey: keys.privateKey }
    );
    expect(child.definition.services).toHaveLength(2);
  });
});

// ── verifyChain ────────────────────────────────────────────────

describe('verifyChain', () => {
  it('validates a 2-link chain (parent → child)', async () => {
    const child = await delegate(
      parentToken,
      {
        agent: { id: 'did:apoa:sub-bot' },
        services: [{ service: 'mychart.com', scopes: ['appointments:read'] }],
        rules: [
          { id: 'no-messaging', description: 'Never send messages', enforcement: 'hard' },
        ],
      },
      { privateKey: keys.privateKey }
    );

    const result = await verifyChain([parentToken, child]);
    expect(result.valid).toBe(true);
    expect(result.depth).toBe(1);
    expect(result.root.jti).toBe(parentToken.jti);
    expect(result.leaf.jti).toBe(child.jti);
    expect(result.errors).toHaveLength(0);
  });

  it('validates a 3-link chain (parent → child → grandchild)', async () => {
    const child = await delegate(
      parentToken,
      {
        agent: { id: 'did:apoa:sub-bot' },
        services: [
          { service: 'mychart.com', scopes: ['appointments:read', 'appointments:write'] },
        ],
        rules: [
          { id: 'no-messaging', description: 'Never send messages', enforcement: 'hard' },
        ],
      },
      { privateKey: keys.privateKey }
    );

    const grandchild = await delegate(
      child,
      {
        agent: { id: 'did:apoa:tiny-bot' },
        services: [
          { service: 'mychart.com', scopes: ['appointments:read'] },
        ],
        rules: [
          { id: 'no-messaging', description: 'Never send messages', enforcement: 'hard' },
        ],
      },
      { privateKey: keys.privateKey }
    );

    const result = await verifyChain([parentToken, child, grandchild]);
    expect(result.valid).toBe(true);
    expect(result.depth).toBe(2);
  });

  it('fails when a chain link has an expanded scope', async () => {
    // Create a "rogue" child that claims wider scopes
    const rogueDef: APOADefinition = {
      principal: parentDef.principal,
      agent: { id: 'did:apoa:rogue' },
      services: [
        { service: 'mychart.com', scopes: ['admin:write'] }, // not in parent
      ],
      expires: '2099-01-01',
    };
    const rogueToken = await createToken(rogueDef, {
      privateKey: keys.privateKey,
    });
    rogueToken.parentToken = parentToken.jti;

    const result = await verifyChain([parentToken, rogueToken]);
    expect(result.valid).toBe(false);
    expect(result.errors).toContainEqual(
      expect.stringContaining("scope 'admin:write'")
    );
    expect(result.failedAt).toBe(1);
  });

  it('fails when a chain link is expired', async () => {
    const expiredDef: APOADefinition = {
      principal: parentDef.principal,
      agent: { id: 'did:apoa:expired-bot' },
      services: [{ service: 'mychart.com', scopes: ['appointments:read'] }],
      expires: '2020-01-01', // expired
    };
    const expiredToken = await createToken(expiredDef, {
      privateKey: keys.privateKey,
    });
    expiredToken.parentToken = parentToken.jti;

    const result = await verifyChain([parentToken, expiredToken]);
    expect(result.valid).toBe(false);
    expect(result.errors).toContainEqual(
      expect.stringContaining('expired')
    );
  });

  it('fails when parent in chain is expired', async () => {
    const expiredParentDef: APOADefinition = {
      ...parentDef,
      expires: '2020-01-01',
    };
    const expiredParent = await createToken(expiredParentDef, {
      privateKey: keys.privateKey,
    });

    const childDef: APOADefinition = {
      principal: parentDef.principal,
      agent: { id: 'did:apoa:child-bot' },
      services: [{ service: 'mychart.com', scopes: ['appointments:read'] }],
      expires: '2020-01-01',
    };
    const childToken = await createToken(childDef, {
      privateKey: keys.privateKey,
    });
    childToken.parentToken = expiredParent.jti;

    const result = await verifyChain([expiredParent, childToken]);
    expect(result.valid).toBe(false);
    expect(result.failedAt).toBe(0);
  });

  it('checks revocation when store is provided', async () => {
    const store = new MemoryRevocationStore();

    const child = await delegate(
      parentToken,
      {
        agent: { id: 'did:apoa:sub-bot' },
        services: [{ service: 'mychart.com', scopes: ['appointments:read'] }],
        rules: [
          { id: 'no-messaging', description: 'Never send messages', enforcement: 'hard' },
        ],
      },
      { privateKey: keys.privateKey }
    );

    // Revoke the child
    await store.add({
      tokenId: child.jti,
      revokedAt: new Date(),
      revokedBy: 'did:apoa:juan',
      cascaded: [],
    });

    const result = await verifyChain([parentToken, child], store);
    expect(result.valid).toBe(false);
    expect(result.errors).toContainEqual(
      expect.stringContaining('revoked')
    );
  });

  it('fails when parentToken reference is wrong', async () => {
    const childDef: APOADefinition = {
      principal: parentDef.principal,
      agent: { id: 'did:apoa:orphan' },
      services: [{ service: 'mychart.com', scopes: ['appointments:read'] }],
      expires: '2099-01-01',
    };
    const orphan = await createToken(childDef, {
      privateKey: keys.privateKey,
    });
    orphan.parentToken = 'wrong-parent-id';

    const result = await verifyChain([parentToken, orphan]);
    expect(result.valid).toBe(false);
    expect(result.errors).toContainEqual(
      expect.stringContaining('does not match parent jti')
    );
  });

  it('validates a single-token chain', async () => {
    const result = await verifyChain([parentToken]);
    expect(result.valid).toBe(true);
    expect(result.depth).toBe(0);
    expect(result.root.jti).toBe(parentToken.jti);
    expect(result.leaf.jti).toBe(parentToken.jti);
  });

  it('reports all errors, not just the first', async () => {
    // Create a rogue token: expired + wrong scope + wrong parentToken
    const rogueDef: APOADefinition = {
      principal: parentDef.principal,
      agent: { id: 'did:apoa:rogue' },
      services: [{ service: 'mychart.com', scopes: ['admin:delete'] }],
      expires: '2020-01-01',
    };
    const rogue = await createToken(rogueDef, {
      privateKey: keys.privateKey,
    });
    rogue.parentToken = 'bogus';

    const result = await verifyChain([parentToken, rogue]);
    expect(result.valid).toBe(false);
    // Should have at least: expired + scope violation + parentToken mismatch
    expect(result.errors.length).toBeGreaterThanOrEqual(3);
  });

  it('handles empty chain', async () => {
    const result = await verifyChain([]);
    expect(result.valid).toBe(false);
    expect(result.errors).toContainEqual(
      expect.stringContaining('empty')
    );
  });

  it('fails when child expiration exceeds parent', async () => {
    // Manually create a child with later expiration
    const longChildDef: APOADefinition = {
      principal: parentDef.principal,
      agent: { id: 'did:apoa:long-child' },
      services: [{ service: 'mychart.com', scopes: ['appointments:read'] }],
      expires: '2199-01-01', // after parent's 2099
    };
    const longChild = await createToken(longChildDef, {
      privateKey: keys.privateKey,
    });
    longChild.parentToken = parentToken.jti;

    const result = await verifyChain([parentToken, longChild]);
    expect(result.valid).toBe(false);
    expect(result.errors).toContainEqual(
      expect.stringContaining('child expiration exceeds parent')
    );
  });
});
