import { describe, it, expect } from 'vitest';
import {
  APOAError,
  TokenExpiredError,
  ScopeViolationError,
  AttenuationViolationError,
  RevocationError,
  ChainVerificationError,
  MetadataValidationError,
  RuleEnforcementError,
  DefinitionValidationError,
} from '../src/utils/errors.js';

describe('error classes', () => {
  it('APOAError has code and message', () => {
    const err = new APOAError('test error', 'TEST_CODE');
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(APOAError);
    expect(err.message).toBe('test error');
    expect(err.code).toBe('TEST_CODE');
    expect(err.name).toBe('APOAError');
  });

  it('TokenExpiredError has expiredAt', () => {
    const date = new Date('2026-01-01');
    const err = new TokenExpiredError('Token expired', date);
    expect(err).toBeInstanceOf(APOAError);
    expect(err.code).toBe('TOKEN_EXPIRED');
    expect(err.expiredAt).toBe(date);
    expect(err.name).toBe('TokenExpiredError');
  });

  it('ScopeViolationError has requestedScope and availableScopes', () => {
    const err = new ScopeViolationError(
      'Scope violation',
      'messages:send',
      ['appointments:read', 'prescriptions:read']
    );
    expect(err).toBeInstanceOf(APOAError);
    expect(err.code).toBe('SCOPE_VIOLATION');
    expect(err.requestedScope).toBe('messages:send');
    expect(err.availableScopes).toEqual(['appointments:read', 'prescriptions:read']);
    expect(err.name).toBe('ScopeViolationError');
  });

  it('AttenuationViolationError has parentScope and requestedScope', () => {
    const err = new AttenuationViolationError(
      'Cannot expand scope',
      ['appointments:read'],
      ['appointments:*']
    );
    expect(err).toBeInstanceOf(APOAError);
    expect(err.code).toBe('ATTENUATION_VIOLATION');
    expect(err.parentScope).toEqual(['appointments:read']);
    expect(err.requestedScope).toEqual(['appointments:*']);
    expect(err.name).toBe('AttenuationViolationError');
  });

  it('RevocationError has revokedAt and revokedBy', () => {
    const date = new Date();
    const err = new RevocationError('Token revoked', date, 'did:apoa:juan');
    expect(err).toBeInstanceOf(APOAError);
    expect(err.code).toBe('TOKEN_REVOKED');
    expect(err.revokedAt).toBe(date);
    expect(err.revokedBy).toBe('did:apoa:juan');
    expect(err.name).toBe('RevocationError');
  });

  it('ChainVerificationError has failedAt and reason', () => {
    const err = new ChainVerificationError('Chain invalid', 2, 'signature mismatch');
    expect(err).toBeInstanceOf(APOAError);
    expect(err.code).toBe('CHAIN_INVALID');
    expect(err.failedAt).toBe(2);
    expect(err.reason).toBe('signature mismatch');
    expect(err.name).toBe('ChainVerificationError');
  });

  it('MetadataValidationError has optional field', () => {
    const err1 = new MetadataValidationError('Too many keys');
    expect(err1.code).toBe('METADATA_INVALID');
    expect(err1.field).toBeUndefined();

    const err2 = new MetadataValidationError('Invalid value', 'badKey');
    expect(err2.field).toBe('badKey');
    expect(err2.name).toBe('MetadataValidationError');
  });

  it('RuleEnforcementError has ruleId and enforcement is always hard', () => {
    const err = new RuleEnforcementError('Rule violated', 'no-messaging');
    expect(err).toBeInstanceOf(APOAError);
    expect(err.code).toBe('RULE_VIOLATED');
    expect(err.ruleId).toBe('no-messaging');
    expect(err.enforcement).toBe('hard');
    expect(err.name).toBe('RuleEnforcementError');
  });

  it('DefinitionValidationError has errors array', () => {
    const err = new DefinitionValidationError('Invalid definition', [
      'Missing principal.id',
      'Missing expires',
    ]);
    expect(err).toBeInstanceOf(APOAError);
    expect(err.code).toBe('DEFINITION_INVALID');
    expect(err.errors).toEqual(['Missing principal.id', 'Missing expires']);
    expect(err.name).toBe('DefinitionValidationError');
  });

  it('all errors are catchable as APOAError', () => {
    const errors = [
      new TokenExpiredError('expired', new Date()),
      new ScopeViolationError('scope', 'x', []),
      new AttenuationViolationError('attenuation', [], []),
      new RevocationError('revoked', new Date(), 'user'),
      new ChainVerificationError('chain', 0, 'reason'),
      new MetadataValidationError('metadata'),
      new RuleEnforcementError('rule', 'r1'),
      new DefinitionValidationError('definition', []),
    ];
    for (const err of errors) {
      expect(err).toBeInstanceOf(APOAError);
      expect(err).toBeInstanceOf(Error);
    }
  });
});
