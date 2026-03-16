import { describe, it, expect } from 'vitest';
import { parseScope, matchScope } from '../src/scope/patterns.js';

describe('scope patterns', () => {
  describe('parseScope', () => {
    it('parses a simple scope', () => {
      expect(parseScope('appointments:read')).toEqual(['appointments', 'read']);
    });

    it('parses a nested scope', () => {
      expect(parseScope('appointments:read:summary')).toEqual([
        'appointments',
        'read',
        'summary',
      ]);
    });

    it('parses a single-segment scope', () => {
      expect(parseScope('appointments')).toEqual(['appointments']);
    });

    it('parses a wildcard scope', () => {
      expect(parseScope('appointments:*')).toEqual(['appointments', '*']);
    });

    it('parses root wildcard', () => {
      expect(parseScope('*')).toEqual(['*']);
    });

    it('returns empty array for empty string', () => {
      expect(parseScope('')).toEqual([]);
    });
  });

  describe('matchScope', () => {
    it('exact match works', () => {
      expect(matchScope('appointments:read', 'appointments:read')).toBe(true);
    });

    it('exact match fails on different scopes', () => {
      expect(matchScope('appointments:read', 'appointments:write')).toBe(false);
    });

    it('wildcard matches any action at same level', () => {
      expect(matchScope('appointments:*', 'appointments:read')).toBe(true);
      expect(matchScope('appointments:*', 'appointments:write')).toBe(true);
    });

    it('wildcard does NOT match across levels', () => {
      expect(matchScope('appointments:*', 'appointments:read:summary')).toBe(false);
    });

    it('root wildcard matches everything', () => {
      expect(matchScope('*', 'appointments:read')).toBe(true);
      expect(matchScope('*', 'documents:write:all')).toBe(true);
      expect(matchScope('*', 'anything')).toBe(true);
    });

    it('nested exact match works', () => {
      expect(
        matchScope('appointments:read:summary', 'appointments:read:summary')
      ).toBe(true);
    });

    it('nested exact match fails on mismatch', () => {
      expect(
        matchScope('appointments:read:summary', 'appointments:read:detail')
      ).toBe(false);
    });

    it('wildcard in middle segment works', () => {
      expect(matchScope('appointments:*:summary', 'appointments:read:summary')).toBe(
        true
      );
      expect(
        matchScope('appointments:*:summary', 'appointments:write:summary')
      ).toBe(true);
      expect(matchScope('appointments:*:summary', 'appointments:read:detail')).toBe(
        false
      );
    });

    it('different segment counts do not match', () => {
      expect(matchScope('appointments', 'appointments:read')).toBe(false);
      expect(matchScope('appointments:read', 'appointments')).toBe(false);
    });

    it('different resource names do not match', () => {
      expect(matchScope('appointments:read', 'documents:read')).toBe(false);
    });

    it('empty pattern does not match non-empty scope', () => {
      expect(matchScope('', 'appointments:read')).toBe(false);
    });
  });
});
