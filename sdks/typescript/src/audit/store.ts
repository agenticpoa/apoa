import type { AuditEntry, AuditQueryOptions, AuditStore } from '../types.js';

/**
 * In-memory audit store for dev/testing.
 * Data is lost when the process exits.
 */
export class MemoryAuditStore implements AuditStore {
  private entries: AuditEntry[] = [];

  async append(entry: AuditEntry): Promise<void> {
    this.entries.push(entry);
  }

  async query(tokenId: string, options?: AuditQueryOptions): Promise<AuditEntry[]> {
    const results = this.entries.filter((e) => e.tokenId === tokenId);
    return applyFilters(results, options);
  }

  async queryByService(
    service: string,
    options?: AuditQueryOptions
  ): Promise<AuditEntry[]> {
    const results = this.entries.filter((e) => e.service === service);
    return applyFilters(results, options);
  }
}

function applyFilters(
  entries: AuditEntry[],
  options?: AuditQueryOptions
): AuditEntry[] {

  let results = entries;

  if (options?.from) {
    const from = options.from.getTime();
    results = results.filter((e) => e.timestamp.getTime() >= from);
  }
  if (options?.to) {
    const to = options.to.getTime();
    results = results.filter((e) => e.timestamp.getTime() <= to);
  }
  if (options?.action) {
    results = results.filter((e) => e.action === options.action);
  }
  if (options?.service) {
    results = results.filter((e) => e.service === options.service);
  }
  if (options?.result) {
    results = results.filter((e) => e.result === options.result);
  }

  const offset = options?.offset ?? 0;
  const limit = options?.limit ?? 100;
  results = results.slice(offset, offset + limit);

  return results;
}
