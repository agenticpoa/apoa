import type { RevocationRecord, RevocationStore } from '../types.js';

/**
 * In-memory revocation store for dev/testing.
 * Data is lost when the process exits.
 */
export class MemoryRevocationStore implements RevocationStore {
  private records: Map<string, RevocationRecord> = new Map();

  async add(record: RevocationRecord): Promise<void> {
    this.records.set(record.tokenId, record);
  }

  async check(tokenId: string): Promise<RevocationRecord | null> {
    return this.records.get(tokenId) ?? null;
  }

  async list(principalId: string): Promise<RevocationRecord[]> {
    const results: RevocationRecord[] = [];
    for (const record of this.records.values()) {
      if (record.revokedBy === principalId) {
        results.push(record);
      }
    }
    return results;
  }
}
