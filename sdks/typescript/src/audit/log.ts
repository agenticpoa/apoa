import type { AuditEntry, AuditStore } from '../types.js';
import { MemoryAuditStore } from './store.js';

const defaultStore = new MemoryAuditStore();

/**
 * Log an action against a token.
 */
export async function logAction(
  tokenId: string,
  entry: Omit<AuditEntry, 'tokenId' | 'timestamp'>,
  store?: AuditStore
): Promise<void> {
  const s = store ?? defaultStore;

  const fullEntry: AuditEntry = {
    ...entry,
    tokenId,
    timestamp: new Date(),
  };

  await s.append(fullEntry);
}
