import { describe, it, expect } from 'vitest';
import type {
  Principal,
  Agent,
  ConstraintValue,
  ConstraintMap,
  AccessMode,
  BrowserSessionConfig,
  APIAccessConfig,
  AgentProvider,
  LegalFramework,
  ServiceAuthorization,
  Rule,
  RuleViolation,
  MetadataValue,
  TokenMetadata,
  APOADefinition,
  APOAToken,
  AuditDetailValue,
  AuditEntry,
  ScopeCheckResult,
  RevocationRecord,
  RevocationOptions,
  AuditQueryOptions,
  ChainVerificationResult,
  DelegationChain,
  DelegationDefinition,
  SigningOptions,
  ValidationOptions,
  ValidationResult,
  KeyResolver,
  AuthorizeOptions,
  AuthorizationResult,
  RevocationStore,
  AuditStore,
  APOAClientOptions,
  APOAClient,
} from '../src/types.js';

describe('types', () => {
  it('Principal compiles with required and optional fields', () => {
    const minimal: Principal = { id: 'did:apoa:test' };
    const full: Principal = { id: 'did:apoa:test', name: 'Test User' };
    expect(minimal.id).toBe('did:apoa:test');
    expect(full.name).toBe('Test User');
  });

  it('Agent compiles with required and optional fields', () => {
    const minimal: Agent = { id: 'did:apoa:agent' };
    const full: Agent = { id: 'did:apoa:agent', name: 'Bot', provider: 'Anthropic' };
    expect(minimal.id).toBe('did:apoa:agent');
    expect(full.provider).toBe('Anthropic');
  });

  it('ConstraintValue accepts all valid types', () => {
    const bool: ConstraintValue = true;
    const num: ConstraintValue = 42;
    const str: ConstraintValue = 'hello';
    const arr: ConstraintValue = ['a', 'b'];
    expect(bool).toBe(true);
    expect(num).toBe(42);
    expect(str).toBe('hello');
    expect(arr).toEqual(['a', 'b']);
  });

  it('AccessMode is api or browser', () => {
    const api: AccessMode = 'api';
    const browser: AccessMode = 'browser';
    expect(api).toBe('api');
    expect(browser).toBe('browser');
  });

  it('BrowserSessionConfig compiles with required and optional fields', () => {
    const config: BrowserSessionConfig = {
      allowedUrls: ['https://example.com/*'],
      credentialVaultRef: '1password://vault/test',
    };
    expect(config.allowedUrls).toHaveLength(1);
    expect(config.allowFormInteraction).toBeUndefined();
  });

  it('ServiceAuthorization supports both access modes', () => {
    const apiService: ServiceAuthorization = {
      service: 'api.stripe.com',
      scopes: ['charges:read'],
      accessMode: 'api',
      apiConfig: { oauthScopes: ['read_only'] },
    };
    const browserService: ServiceAuthorization = {
      service: 'portal.example.com',
      scopes: ['documents:read'],
      accessMode: 'browser',
      browserConfig: {
        allowedUrls: ['https://portal.example.com/*'],
        credentialVaultRef: '1password://vault/portal',
      },
    };
    expect(apiService.accessMode).toBe('api');
    expect(browserService.browserConfig?.credentialVaultRef).toBeTruthy();
  });

  it('Rule supports hard and soft enforcement', () => {
    const hard: Rule = { id: 'no-sign', description: 'No signing', enforcement: 'hard' };
    const soft: Rule = {
      id: 'alert',
      description: 'Alert on access',
      enforcement: 'soft',
      onViolation: () => {},
    };
    expect(hard.enforcement).toBe('hard');
    expect(soft.onViolation).toBeDefined();
  });

  it('APOADefinition compiles with all fields', () => {
    const def: APOADefinition = {
      principal: { id: 'did:apoa:user' },
      agent: { id: 'did:apoa:bot' },
      agentProvider: { name: 'BotCorp' },
      services: [{ service: 'example.com', scopes: ['read'] }],
      rules: [{ id: 'r1', description: 'test', enforcement: 'hard' }],
      notBefore: new Date(),
      expires: '2026-12-31',
      revocable: true,
      delegatable: true,
      maxDelegationDepth: 3,
      metadata: { key: 'value' },
      legal: { model: 'provider-as-agent', jurisdiction: 'US-CA' },
    };
    expect(def.principal.id).toBe('did:apoa:user');
    expect(def.legal?.model).toBe('provider-as-agent');
  });

  it('APOAToken compiles with all fields', () => {
    const token: APOAToken = {
      jti: 'uuid-123',
      definition: {
        principal: { id: 'did:apoa:user' },
        agent: { id: 'did:apoa:bot' },
        services: [{ service: 'example.com', scopes: ['read'] }],
        expires: '2026-12-31',
      },
      issuedAt: new Date(),
      signature: 'sig',
      issuer: 'did:apoa:user',
      audience: ['example.com'],
      parentToken: undefined,
      raw: 'jwt-string',
    };
    expect(token.jti).toBe('uuid-123');
  });

  it('AuditEntry compiles with browser-mode fields', () => {
    const entry: AuditEntry = {
      tokenId: 'token-1',
      timestamp: new Date(),
      action: 'read',
      service: 'example.com',
      result: 'allowed',
      url: 'https://example.com/page',
      screenshotRef: 's3://bucket/shot.png',
      accessMode: 'browser',
    };
    expect(entry.result).toBe('allowed');
    expect(entry.accessMode).toBe('browser');
  });

  it('ScopeCheckResult compiles', () => {
    const allowed: ScopeCheckResult = { allowed: true, reason: 'matched', matchedScope: 'read' };
    const denied: ScopeCheckResult = { allowed: false, reason: 'no match', constraint: 'signing' };
    expect(allowed.allowed).toBe(true);
    expect(denied.constraint).toBe('signing');
  });

  it('RevocationRecord compiles', () => {
    const record: RevocationRecord = {
      tokenId: 't1',
      revokedAt: new Date(),
      revokedBy: 'did:apoa:user',
      reason: 'compromised',
      cascaded: ['t2', 't3'],
    };
    expect(record.cascaded).toHaveLength(2);
  });

  it('DelegationDefinition compiles', () => {
    const del: DelegationDefinition = {
      agent: { id: 'did:apoa:sub-agent' },
      services: [{ service: 'example.com', scopes: ['read'] }],
      expires: '2026-06-01',
    };
    expect(del.agent.id).toBe('did:apoa:sub-agent');
  });

  it('MetadataValue accepts all valid types', () => {
    const str: MetadataValue = 'hello';
    const num: MetadataValue = 42;
    const bool: MetadataValue = true;
    const nul: MetadataValue = null;
    expect(str).toBe('hello');
    expect(nul).toBeNull();
  });

  it('TokenMetadata is a record of MetadataValue', () => {
    const meta: TokenMetadata = { key: 'val', count: 5, active: true, gone: null };
    expect(Object.keys(meta)).toHaveLength(4);
  });

  it('AuthorizationResult compiles with violations', () => {
    const result: AuthorizationResult = {
      authorized: true,
      checks: { revoked: false, scopeAllowed: true, constraintsPassed: true, rulesPassed: true },
      violations: [
        {
          ruleId: 'r1',
          tokenId: 't1',
          action: 'read',
          service: 'example.com',
          timestamp: new Date(),
        },
      ],
    };
    expect(result.violations).toHaveLength(1);
  });

  it('ValidationResult compiles with warnings', () => {
    const result: ValidationResult = {
      valid: true,
      errors: [],
      warnings: ['Token is large'],
    };
    expect(result.warnings).toHaveLength(1);
  });
});
