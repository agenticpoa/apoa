import { describe, it, expect } from 'vitest';
import { parseDefinition } from '../src/token/parse.js';
import { DefinitionValidationError } from '../src/utils/errors.js';

const baseDef = {
  principal: { id: 'did:apoa:user' },
  agent: { id: 'did:apoa:bot' },
  services: [{ service: 'mychart.com', scopes: ['appointments:read'] }],
  expires: '2026-09-01',
};

describe('legal framework validation', () => {
  it('accepts valid legal framework', () => {
    const def = {
      ...baseDef,
      legal: {
        model: 'provider-as-agent',
        jurisdiction: 'US-CA',
        legalBasis: ['UETA-14', 'E-SIGN'],
        pairedLegalInstrument: false,
      },
    };
    const result = parseDefinition(JSON.stringify(def));
    expect(result.legal?.model).toBe('provider-as-agent');
    expect(result.legal?.jurisdiction).toBe('US-CA');
    expect(result.legal?.legalBasis).toEqual(['UETA-14', 'E-SIGN']);
  });

  it('validates jurisdiction format — rejects lowercase', () => {
    const def = {
      ...baseDef,
      legal: { model: 'provider-as-agent', jurisdiction: 'us-ca' },
    };
    try {
      parseDefinition(JSON.stringify(def));
      expect.fail('should have thrown');
    } catch (e) {
      const err = e as DefinitionValidationError;
      expect(err.errors).toContainEqual(
        expect.stringContaining('ISO 3166 format')
      );
    }
  });

  it('validates jurisdiction format — rejects invalid strings', () => {
    const invalid = ['USA', 'U', '123', 'US-', 'US-CALIF', ''];
    for (const j of invalid) {
      const def = {
        ...baseDef,
        legal: { model: 'provider-as-agent', jurisdiction: j },
      };
      expect(
        () => parseDefinition(JSON.stringify(def)),
        `should reject jurisdiction '${j}'`
      ).toThrow(DefinitionValidationError);
    }
  });

  it('accepts valid jurisdiction formats', () => {
    const valid = ['US', 'US-CA', 'GB', 'DE', 'JP', 'AU-NSW', 'CA-ON'];
    for (const j of valid) {
      const def = {
        ...baseDef,
        legal: { model: 'provider-as-agent', jurisdiction: j },
      };
      const result = parseDefinition(JSON.stringify(def));
      expect(result.legal?.jurisdiction).toBe(j);
    }
  });

  it('rejects invalid legal model', () => {
    const def = {
      ...baseDef,
      legal: { model: 'some-other-model' },
    };
    try {
      parseDefinition(JSON.stringify(def));
      expect.fail('should have thrown');
    } catch (e) {
      const err = e as DefinitionValidationError;
      expect(err.errors).toContainEqual(
        expect.stringContaining("'provider-as-agent'")
      );
    }
  });

  it('accepts legal framework with only model', () => {
    const def = {
      ...baseDef,
      legal: { model: 'provider-as-agent' },
    };
    const result = parseDefinition(JSON.stringify(def));
    expect(result.legal?.model).toBe('provider-as-agent');
    expect(result.legal?.jurisdiction).toBeUndefined();
  });
});

describe('agentProvider validation', () => {
  it('accepts valid agentProvider', () => {
    const def = {
      ...baseDef,
      agentProvider: {
        name: 'HomeBot Inc.',
        id: 'did:apoa:provider:homebot',
        contact: 'legal@homebot.ai',
      },
    };
    const result = parseDefinition(JSON.stringify(def));
    expect(result.agentProvider?.name).toBe('HomeBot Inc.');
  });

  it('agentProvider.name is required', () => {
    const def = {
      ...baseDef,
      agentProvider: { id: 'did:apoa:provider:homebot' },
    };
    try {
      parseDefinition(JSON.stringify(def));
      expect.fail('should have thrown');
    } catch (e) {
      const err = e as DefinitionValidationError;
      expect(err.errors).toContainEqual(
        expect.stringContaining('agentProvider.name')
      );
    }
  });

  it('agentProvider as empty object fails', () => {
    const def = {
      ...baseDef,
      agentProvider: {},
    };
    expect(() => parseDefinition(JSON.stringify(def))).toThrow(
      DefinitionValidationError
    );
  });
});
