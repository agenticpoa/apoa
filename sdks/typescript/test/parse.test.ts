import { describe, it, expect } from 'vitest';
import { parseDefinition } from '../src/token/parse.js';
import { DefinitionValidationError } from '../src/utils/errors.js';

const validDef = {
  principal: { id: 'did:apoa:user', name: 'Test User' },
  agent: { id: 'did:apoa:bot', name: 'TestBot' },
  services: [
    {
      service: 'mychart.com',
      scopes: ['appointments:read', 'prescriptions:read'],
      constraints: { signing: false },
    },
  ],
  expires: '2026-09-01',
};

describe('parseDefinition', () => {
  it('parses a valid JSON definition', () => {
    const def = parseDefinition(JSON.stringify(validDef));
    expect(def.principal.id).toBe('did:apoa:user');
    expect(def.agent.name).toBe('TestBot');
    expect(def.services).toHaveLength(1);
    expect(def.expires).toBe('2026-09-01');
  });

  it('auto-detects JSON format', () => {
    const def = parseDefinition(JSON.stringify(validDef));
    expect(def.principal.id).toBe('did:apoa:user');
  });

  it('respects explicit format parameter', () => {
    const def = parseDefinition(JSON.stringify(validDef), 'json');
    expect(def.principal.id).toBe('did:apoa:user');
  });

  it('throws on invalid JSON', () => {
    expect(() => parseDefinition('{bad json}')).toThrow(DefinitionValidationError);
  });

  it('throws on YAML input without yaml package', () => {
    expect(() => parseDefinition('principal:\n  id: test')).toThrow(
      /YAML parsing requires/
    );
  });

  describe('required field validation', () => {
    it('throws when principal is missing', () => {
      const def = { ...validDef, principal: undefined };
      expect(() => parseDefinition(JSON.stringify(def))).toThrow(
        DefinitionValidationError
      );
      try {
        parseDefinition(JSON.stringify(def));
      } catch (e) {
        expect((e as DefinitionValidationError).errors).toContainEqual(
          expect.stringContaining('principal')
        );
      }
    });

    it('throws when principal.id is missing', () => {
      const def = { ...validDef, principal: { name: 'No ID' } };
      expect(() => parseDefinition(JSON.stringify(def))).toThrow(
        DefinitionValidationError
      );
    });

    it('throws when agent is missing', () => {
      const def = { ...validDef, agent: undefined };
      expect(() => parseDefinition(JSON.stringify(def))).toThrow(
        DefinitionValidationError
      );
    });

    it('throws when agent.id is missing', () => {
      const def = { ...validDef, agent: { name: 'No ID' } };
      expect(() => parseDefinition(JSON.stringify(def))).toThrow(
        DefinitionValidationError
      );
    });

    it('throws when services is missing', () => {
      const def = { ...validDef, services: undefined };
      expect(() => parseDefinition(JSON.stringify(def))).toThrow(
        DefinitionValidationError
      );
    });

    it('throws when services is empty', () => {
      const def = { ...validDef, services: [] };
      expect(() => parseDefinition(JSON.stringify(def))).toThrow(
        DefinitionValidationError
      );
    });

    it('throws when expires is missing', () => {
      const def = { ...validDef, expires: undefined };
      expect(() => parseDefinition(JSON.stringify(def))).toThrow(
        DefinitionValidationError
      );
    });

    it('reports all validation errors at once', () => {
      const def = {};
      try {
        parseDefinition(JSON.stringify(def));
        expect.fail('should have thrown');
      } catch (e) {
        const err = e as DefinitionValidationError;
        expect(err.errors.length).toBeGreaterThanOrEqual(4);
      }
    });
  });

  describe('service validation', () => {
    it('throws when service name is missing', () => {
      const def = {
        ...validDef,
        services: [{ scopes: ['read'] }],
      };
      try {
        parseDefinition(JSON.stringify(def));
        expect.fail('should have thrown');
      } catch (e) {
        expect((e as DefinitionValidationError).errors).toContainEqual(
          expect.stringContaining('services[0].service')
        );
      }
    });

    it('throws when scopes is empty', () => {
      const def = {
        ...validDef,
        services: [{ service: 'mychart.com', scopes: [] }],
      };
      try {
        parseDefinition(JSON.stringify(def));
        expect.fail('should have thrown');
      } catch (e) {
        expect((e as DefinitionValidationError).errors).toContainEqual(
          expect.stringContaining('services[0].scopes')
        );
      }
    });
  });

  describe('metadata validation', () => {
    it('accepts valid metadata', () => {
      const def = {
        ...validDef,
        metadata: { key: 'value', count: 5, active: true, gone: null },
      };
      const result = parseDefinition(JSON.stringify(def));
      expect(result.metadata).toBeDefined();
    });

    it('rejects metadata with more than 20 keys', () => {
      const metadata: Record<string, string> = {};
      for (let i = 0; i < 25; i++) {
        metadata[`key${i}`] = 'value';
      }
      const def = { ...validDef, metadata };
      try {
        parseDefinition(JSON.stringify(def));
        expect.fail('should have thrown');
      } catch (e) {
        expect((e as DefinitionValidationError).errors).toContainEqual(
          expect.stringContaining('max 20')
        );
      }
    });

    it('rejects metadata exceeding 1KB serialized', () => {
      const metadata = { big: 'x'.repeat(1100) };
      const def = { ...validDef, metadata };
      try {
        parseDefinition(JSON.stringify(def));
        expect.fail('should have thrown');
      } catch (e) {
        expect((e as DefinitionValidationError).errors).toContainEqual(
          expect.stringContaining('max 1024')
        );
      }
    });

    it('rejects metadata with non-primitive values', () => {
      const def = { ...validDef, metadata: { nested: { a: 1 } } };
      try {
        parseDefinition(JSON.stringify(def));
        expect.fail('should have thrown');
      } catch (e) {
        expect((e as DefinitionValidationError).errors).toContainEqual(
          expect.stringContaining("metadata['nested']")
        );
      }
    });
  });

  it('accepts a definition with all optional fields', () => {
    const full = {
      ...validDef,
      agentProvider: { name: 'BotCorp', id: 'did:apoa:botcorp', contact: 'bot@corp.com' },
      rules: [{ id: 'r1', description: 'No signing', enforcement: 'hard' }],
      notBefore: '2026-01-01',
      revocable: true,
      delegatable: true,
      maxDelegationDepth: 3,
      metadata: { env: 'test' },
      legal: {
        model: 'provider-as-agent',
        jurisdiction: 'US-CA',
        legalBasis: ['UETA-14'],
        pairedLegalInstrument: false,
      },
    };
    const result = parseDefinition(JSON.stringify(full));
    expect(result.agentProvider?.name).toBe('BotCorp');
    expect(result.legal?.jurisdiction).toBe('US-CA');
  });
});
