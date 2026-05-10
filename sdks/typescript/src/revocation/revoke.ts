import type {
  RevocationOptions,
  RevocationRecord,
  RevocationStore,
} from '../types.js';

/**
 * Revoke a token. The caller MUST supply a RevocationStore so the revocation
 * is durable and visible to other parts of the system. There is no default
 * store: a process-shared singleton would silently diverge from the store
 * used by `createClient()` and any caller-supplied store, producing
 * "succeeded but never enforced" revocations.
 */
export async function revoke(
  tokenId: string,
  options: RevocationOptions,
  store: RevocationStore
): Promise<RevocationRecord> {
  const record: RevocationRecord = {
    tokenId,
    revokedAt: new Date(),
    revokedBy: options.revokedBy,
    reason: options.reason,
    cascaded: [],
  };

  await store.add(record);
  return record;
}

/**
 * Check if a token has been revoked. Caller must supply the same
 * RevocationStore that revoke() wrote to.
 */
export async function isRevoked(
  tokenId: string,
  store: RevocationStore
): Promise<boolean> {
  const record = await store.check(tokenId);
  return record !== null;
}
