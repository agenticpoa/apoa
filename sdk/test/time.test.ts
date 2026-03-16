import { describe, it, expect } from 'vitest';
import { isExpired, isBeforeNotBefore } from '../src/utils/time.js';

describe('time utilities', () => {
  describe('isExpired', () => {
    it('returns false for a future expiration', () => {
      const future = new Date(Date.now() + 3600_000);
      expect(isExpired(future)).toBe(false);
    });

    it('returns true for a past expiration', () => {
      const past = new Date(Date.now() - 3600_000);
      expect(isExpired(past)).toBe(true);
    });

    it('accepts ISO string dates', () => {
      const future = new Date(Date.now() + 3600_000).toISOString();
      expect(isExpired(future)).toBe(false);
    });

    it('accounts for default clock skew (30s)', () => {
      // Expired 20 seconds ago — within 30s default skew, so NOT expired
      const recent = new Date(Date.now() - 20_000);
      expect(isExpired(recent)).toBe(false);

      // Expired 40 seconds ago — beyond 30s skew, so IS expired
      const older = new Date(Date.now() - 40_000);
      expect(isExpired(older)).toBe(true);
    });

    it('uses custom clock skew', () => {
      // Expired 50 seconds ago, with 60s skew — NOT expired
      const recent = new Date(Date.now() - 50_000);
      expect(isExpired(recent, 60)).toBe(false);

      // Expired 50 seconds ago, with 10s skew — IS expired
      expect(isExpired(recent, 10)).toBe(true);
    });

    it('caps clock skew at 300 seconds', () => {
      // Expired 310 seconds ago, with 999s requested skew (capped to 300)
      const old = new Date(Date.now() - 310_000);
      expect(isExpired(old, 999)).toBe(true);

      // Expired 290 seconds ago, with 999s requested skew (capped to 300) — NOT expired
      const newer = new Date(Date.now() - 290_000);
      expect(isExpired(newer, 999)).toBe(false);
    });

    it('uses zero skew when negative is provided', () => {
      // Expired 1 second ago, with negative skew (treated as 0)
      const recent = new Date(Date.now() - 1_000);
      expect(isExpired(recent, -10)).toBe(true);
    });

    it('accepts a custom now parameter', () => {
      const expires = new Date('2026-06-01T00:00:00Z');
      const before = new Date('2026-05-01T00:00:00Z');
      const after = new Date('2026-07-01T00:00:00Z');
      expect(isExpired(expires, 0, before)).toBe(false);
      expect(isExpired(expires, 0, after)).toBe(true);
    });
  });

  describe('isBeforeNotBefore', () => {
    it('returns true when current time is before notBefore', () => {
      const future = new Date(Date.now() + 3600_000);
      expect(isBeforeNotBefore(future)).toBe(true);
    });

    it('returns false when current time is after notBefore', () => {
      const past = new Date(Date.now() - 3600_000);
      expect(isBeforeNotBefore(past)).toBe(false);
    });

    it('accepts ISO string dates', () => {
      const past = new Date(Date.now() - 3600_000).toISOString();
      expect(isBeforeNotBefore(past)).toBe(false);
    });

    it('accounts for default clock skew (30s)', () => {
      // notBefore is 20 seconds in the future — within 30s skew, so NOT before
      const soon = new Date(Date.now() + 20_000);
      expect(isBeforeNotBefore(soon)).toBe(false);

      // notBefore is 40 seconds in the future — beyond 30s skew, so IS before
      const later = new Date(Date.now() + 40_000);
      expect(isBeforeNotBefore(later)).toBe(true);
    });

    it('uses custom clock skew', () => {
      // notBefore is 50 seconds in the future, with 60s skew — NOT before
      const soon = new Date(Date.now() + 50_000);
      expect(isBeforeNotBefore(soon, 60)).toBe(false);

      // notBefore is 50 seconds in the future, with 10s skew — IS before
      expect(isBeforeNotBefore(soon, 10)).toBe(true);
    });

    it('accepts a custom now parameter', () => {
      const notBefore = new Date('2026-06-01T00:00:00Z');
      const before = new Date('2026-05-01T00:00:00Z');
      const after = new Date('2026-07-01T00:00:00Z');
      expect(isBeforeNotBefore(notBefore, 0, before)).toBe(true);
      expect(isBeforeNotBefore(notBefore, 0, after)).toBe(false);
    });
  });
});
