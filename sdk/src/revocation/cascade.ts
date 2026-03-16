import type {
  DelegationChain,
  RevocationOptions,
  RevocationRecord,
  RevocationStore,
} from '../types.js';
import { MemoryRevocationStore } from './store.js';

const defaultStore = new MemoryRevocationStore();

/**
 * Cascade revoke: revoke a parent token and all child tokens in a delegation chain.
 * Populates RevocationRecord.cascaded with child token IDs.
 *
 * @param parentTokenId - The parent token's jti to revoke
 * @param childTokenIds - Array of child token jti values to cascade-revoke
 * @param options - Revocation options (revokedBy, reason)
 * @param store - Optional revocation store
 */
export async function cascadeRevoke(
  parentTokenId: string,
  childTokenIds: string[],
  options: RevocationOptions,
  store?: RevocationStore
): Promise<RevocationRecord> {
  const s = store ?? defaultStore;
  const revokedAt = new Date();

  // Revoke all children
  for (const childId of childTokenIds) {
    const childRecord: RevocationRecord = {
      tokenId: childId,
      revokedAt,
      revokedBy: options.revokedBy,
      reason: options.reason
        ? `Cascade: ${options.reason}`
        : `Cascade revocation from parent ${parentTokenId}`,
      cascaded: [],
    };
    await s.add(childRecord);
  }

  // Revoke parent with cascaded list
  const parentRecord: RevocationRecord = {
    tokenId: parentTokenId,
    revokedAt,
    revokedBy: options.revokedBy,
    reason: options.reason,
    cascaded: childTokenIds,
  };
  await s.add(parentRecord);

  return parentRecord;
}
