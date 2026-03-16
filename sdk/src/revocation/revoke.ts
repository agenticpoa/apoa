import type {
  RevocationOptions,
  RevocationRecord,
  RevocationStore,
} from '../types.js';
import { MemoryRevocationStore } from './store.js';

const defaultStore = new MemoryRevocationStore();

/**
 * Revoke a token. No cascade logic — that's Phase 3.
 */
export async function revoke(
  tokenId: string,
  options: RevocationOptions,
  store?: RevocationStore
): Promise<RevocationRecord> {
  const s = store ?? defaultStore;

  const record: RevocationRecord = {
    tokenId,
    revokedAt: new Date(),
    revokedBy: options.revokedBy,
    reason: options.reason,
    cascaded: [],
  };

  await s.add(record);
  return record;
}

/**
 * Check if a token has been revoked.
 */
export async function isRevoked(
  tokenId: string,
  store?: RevocationStore
): Promise<boolean> {
  const s = store ?? defaultStore;
  const record = await s.check(tokenId);
  return record !== null;
}
