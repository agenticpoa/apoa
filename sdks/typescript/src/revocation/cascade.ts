import type {
  DelegationChain,
  RevocationOptions,
  RevocationRecord,
  RevocationStore,
} from '../types.js';

/**
 * Cascade revoke: revoke a parent token and all child tokens in a delegation
 * chain. Populates RevocationRecord.cascaded with child token IDs.
 *
 * The caller MUST supply a RevocationStore. There is no default store: a
 * process-shared singleton would silently diverge from the store used by
 * `createClient()` and any caller-supplied store.
 *
 * @param parentTokenId - The parent token's jti to revoke
 * @param childTokenIds - Array of child token jti values to cascade-revoke
 * @param options - Revocation options (revokedBy, reason)
 * @param store - The revocation store to write to
 */
export async function cascadeRevoke(
  parentTokenId: string,
  childTokenIds: string[],
  options: RevocationOptions,
  store: RevocationStore
): Promise<RevocationRecord> {
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
    await store.add(childRecord);
  }

  // Revoke parent with cascaded list
  const parentRecord: RevocationRecord = {
    tokenId: parentTokenId,
    revokedAt,
    revokedBy: options.revokedBy,
    reason: options.reason,
    cascaded: childTokenIds,
  };
  await store.add(parentRecord);

  return parentRecord;
}
