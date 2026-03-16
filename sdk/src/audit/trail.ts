import type { AuditEntry, AuditQueryOptions, AuditStore } from '../types.js';
import { MemoryAuditStore } from './store.js';

const defaultStore = new MemoryAuditStore();

/**
 * Get the audit trail for a token.
 */
export async function getAuditTrail(
  tokenId: string,
  options?: AuditQueryOptions,
  store?: AuditStore
): Promise<AuditEntry[]> {
  const s = store ?? defaultStore;
  return s.query(tokenId, options);
}

/**
 * Get the audit trail for a service — across all tokens.
 */
export async function getAuditTrailByService(
  service: string,
  options?: AuditQueryOptions,
  store?: AuditStore
): Promise<AuditEntry[]> {
  const s = store ?? defaultStore;
  return s.queryByService(service, options);
}
