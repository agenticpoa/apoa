import { describe, it, expect } from 'vitest';
import { parseDefinition } from '../src/token/parse.js';
import { checkScope } from '../src/scope/check.js';
import { DefinitionValidationError } from '../src/utils/errors.js';
import type { APOAToken } from '../src/types.js';

const baseDef = {
  principal: { id: 'did:apoa:user' },
  agent: { id: 'did:apoa:bot' },
  expires: '2026-09-01',
};

describe('browser mode validation', () => {
  it('browser mode requires browserConfig', () => {
    const def = {
      ...baseDef,
      services: [
        {
          service: 'mortgage.com',
          scopes: ['rate_lock:read'],
          accessMode: 'browser',
          // no browserConfig
        },
      ],
    };
    try {
      parseDefinition(JSON.stringify(def));
      expect.fail('should have thrown');
    } catch (e) {
      const err = e as DefinitionValidationError;
      expect(err.errors).toContainEqual(
        expect.stringContaining("accessMode 'browser' but no browserConfig")
      );
    }
  });

  it('browser mode requires allowedUrls', () => {
    const def = {
      ...baseDef,
      services: [
        {
          service: 'mortgage.com',
          scopes: ['rate_lock:read'],
          accessMode: 'browser',
          browserConfig: {
            allowedUrls: [],
            credentialVaultRef: '1password://vault/test',
          },
        },
      ],
    };
    try {
      parseDefinition(JSON.stringify(def));
      expect.fail('should have thrown');
    } catch (e) {
      const err = e as DefinitionValidationError;
      expect(err.errors).toContainEqual(
        expect.stringContaining('allowedUrls must be a non-empty array')
      );
    }
  });

  it('browser mode requires credentialVaultRef', () => {
    const def = {
      ...baseDef,
      services: [
        {
          service: 'mortgage.com',
          scopes: ['rate_lock:read'],
          accessMode: 'browser',
          browserConfig: {
            allowedUrls: ['https://portal.mortgage.com/*'],
            // no credentialVaultRef
          },
        },
      ],
    };
    try {
      parseDefinition(JSON.stringify(def));
      expect.fail('should have thrown');
    } catch (e) {
      const err = e as DefinitionValidationError;
      expect(err.errors).toContainEqual(
        expect.stringContaining('credentialVaultRef must be a non-empty string')
      );
    }
  });

  it('maxSessionDuration rejects values over 86400', () => {
    const def = {
      ...baseDef,
      services: [
        {
          service: 'mortgage.com',
          scopes: ['rate_lock:read'],
          accessMode: 'browser',
          browserConfig: {
            allowedUrls: ['https://portal.mortgage.com/*'],
            credentialVaultRef: '1password://vault/test',
            maxSessionDuration: 100000,
          },
        },
      ],
    };
    try {
      parseDefinition(JSON.stringify(def));
      expect.fail('should have thrown');
    } catch (e) {
      const err = e as DefinitionValidationError;
      expect(err.errors).toContainEqual(
        expect.stringContaining('maxSessionDuration must be <= 86400')
      );
    }
  });

  it('api mode ignores browserConfig with warning', () => {
    const def = {
      ...baseDef,
      services: [
        {
          service: 'api.stripe.com',
          scopes: ['charges:read'],
          accessMode: 'api',
          browserConfig: {
            allowedUrls: ['https://stripe.com/*'],
            credentialVaultRef: '1password://vault/test',
          },
        },
      ],
    };
    // Should not throw — just warns
    const result = parseDefinition(JSON.stringify(def));
    expect(result).toBeDefined();
  });

  it('accepts valid browser mode config', () => {
    const def = {
      ...baseDef,
      services: [
        {
          service: 'mortgage.com',
          scopes: ['rate_lock:read', 'documents:read'],
          accessMode: 'browser',
          browserConfig: {
            allowedUrls: ['https://portal.mortgage.com/*'],
            credentialVaultRef: '1password://vault/mortgage',
            allowFormInteraction: false,
            maxSessionDuration: 1800,
            captureScreenshots: true,
            blockedActions: ['click:*sign*'],
          },
        },
      ],
    };
    const result = parseDefinition(JSON.stringify(def));
    expect(result.services[0].accessMode).toBe('browser');
    expect(result.services[0].browserConfig?.maxSessionDuration).toBe(1800);
  });

  it('multi-service token can mix api and browser modes', () => {
    const def = {
      ...baseDef,
      services: [
        {
          service: 'mortgage.com',
          scopes: ['rate_lock:read'],
          accessMode: 'browser',
          browserConfig: {
            allowedUrls: ['https://portal.mortgage.com/*'],
            credentialVaultRef: '1password://vault/mortgage',
          },
        },
        {
          service: 'api.stripe.com',
          scopes: ['charges:read'],
          accessMode: 'api',
        },
        {
          service: 'docusign.com',
          scopes: ['documents:read'],
          accessMode: 'browser',
          browserConfig: {
            allowedUrls: ['https://app.docusign.com/*'],
            credentialVaultRef: '1password://vault/docusign',
          },
        },
      ],
    };
    const result = parseDefinition(JSON.stringify(def));
    expect(result.services).toHaveLength(3);
    expect(result.services[0].accessMode).toBe('browser');
    expect(result.services[1].accessMode).toBe('api');
    expect(result.services[2].accessMode).toBe('browser');
  });

  it('scope checking works the same for both access modes', () => {
    const token: APOAToken = {
      jti: 'test',
      definition: {
        principal: { id: 'did:apoa:user' },
        agent: { id: 'did:apoa:bot' },
        services: [
          {
            service: 'mortgage.com',
            scopes: ['rate_lock:read'],
            accessMode: 'browser',
            browserConfig: {
              allowedUrls: ['https://portal.mortgage.com/*'],
              credentialVaultRef: '1password://vault/test',
            },
          },
          {
            service: 'api.stripe.com',
            scopes: ['charges:read'],
            accessMode: 'api',
          },
        ],
        expires: '2099-01-01',
      },
      issuedAt: new Date(),
      signature: 'sig',
      issuer: 'did:apoa:user',
      raw: 'jwt',
    };

    expect(checkScope(token, 'mortgage.com', 'rate_lock:read').allowed).toBe(true);
    expect(checkScope(token, 'api.stripe.com', 'charges:read').allowed).toBe(true);
    expect(checkScope(token, 'mortgage.com', 'rate_lock:write').allowed).toBe(false);
  });

  it('maxSessionDuration at exactly 86400 is valid', () => {
    const def = {
      ...baseDef,
      services: [
        {
          service: 'mortgage.com',
          scopes: ['read'],
          accessMode: 'browser',
          browserConfig: {
            allowedUrls: ['https://portal.mortgage.com/*'],
            credentialVaultRef: '1password://vault/test',
            maxSessionDuration: 86400,
          },
        },
      ],
    };
    const result = parseDefinition(JSON.stringify(def));
    expect(result.services[0].browserConfig?.maxSessionDuration).toBe(86400);
  });
});
