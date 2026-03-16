import { describe, it, expect, beforeEach } from 'vitest';
import { revoke, isRevoked } from '../src/revocation/revoke.js';
import { MemoryRevocationStore } from '../src/revocation/store.js';

describe('revocation', () => {
  let store: MemoryRevocationStore;

  beforeEach(() => {
    store = new MemoryRevocationStore();
  });

  describe('revoke', () => {
    it('creates a revocation record', async () => {
      const record = await revoke(
        'token-1',
        { revokedBy: 'did:apoa:juan', reason: 'compromised' },
        store
      );
      expect(record.tokenId).toBe('token-1');
      expect(record.revokedBy).toBe('did:apoa:juan');
      expect(record.reason).toBe('compromised');
      expect(record.revokedAt).toBeInstanceOf(Date);
      expect(record.cascaded).toEqual([]);
    });

    it('stores the record in the store', async () => {
      await revoke(
        'token-1',
        { revokedBy: 'did:apoa:juan' },
        store
      );
      const check = await store.check('token-1');
      expect(check).not.toBeNull();
      expect(check?.revokedBy).toBe('did:apoa:juan');
    });

    it('revocation without reason is allowed', async () => {
      const record = await revoke(
        'token-1',
        { revokedBy: 'did:apoa:juan' },
        store
      );
      expect(record.reason).toBeUndefined();
    });
  });

  describe('isRevoked', () => {
    it('returns false for non-revoked token', async () => {
      expect(await isRevoked('token-1', store)).toBe(false);
    });

    it('returns true for revoked token', async () => {
      await revoke('token-1', { revokedBy: 'did:apoa:juan' }, store);
      expect(await isRevoked('token-1', store)).toBe(true);
    });

    it('different tokens have independent revocation status', async () => {
      await revoke('token-1', { revokedBy: 'did:apoa:juan' }, store);
      expect(await isRevoked('token-1', store)).toBe(true);
      expect(await isRevoked('token-2', store)).toBe(false);
    });
  });
});
