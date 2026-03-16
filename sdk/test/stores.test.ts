import { describe, it, expect, beforeEach } from 'vitest';
import { MemoryRevocationStore } from '../src/revocation/store.js';
import { MemoryAuditStore } from '../src/audit/store.js';
import type { RevocationRecord, AuditEntry } from '../src/types.js';

describe('MemoryRevocationStore', () => {
  let store: MemoryRevocationStore;

  beforeEach(() => {
    store = new MemoryRevocationStore();
  });

  it('returns null for unknown token', async () => {
    expect(await store.check('unknown')).toBeNull();
  });

  it('adds and retrieves a revocation record', async () => {
    const record: RevocationRecord = {
      tokenId: 'token-1',
      revokedAt: new Date(),
      revokedBy: 'did:apoa:juan',
      reason: 'compromised',
      cascaded: [],
    };
    await store.add(record);
    const result = await store.check('token-1');
    expect(result).toEqual(record);
  });

  it('lists records by principal', async () => {
    const r1: RevocationRecord = {
      tokenId: 't1',
      revokedAt: new Date(),
      revokedBy: 'did:apoa:juan',
      cascaded: [],
    };
    const r2: RevocationRecord = {
      tokenId: 't2',
      revokedAt: new Date(),
      revokedBy: 'did:apoa:juan',
      cascaded: [],
    };
    const r3: RevocationRecord = {
      tokenId: 't3',
      revokedAt: new Date(),
      revokedBy: 'did:apoa:other',
      cascaded: [],
    };
    await store.add(r1);
    await store.add(r2);
    await store.add(r3);

    const juanRecords = await store.list('did:apoa:juan');
    expect(juanRecords).toHaveLength(2);

    const otherRecords = await store.list('did:apoa:other');
    expect(otherRecords).toHaveLength(1);

    const noneRecords = await store.list('did:apoa:nobody');
    expect(noneRecords).toHaveLength(0);
  });

  it('overwrites a record for the same token', async () => {
    const r1: RevocationRecord = {
      tokenId: 't1',
      revokedAt: new Date('2026-01-01'),
      revokedBy: 'did:apoa:juan',
      reason: 'first',
      cascaded: [],
    };
    const r2: RevocationRecord = {
      tokenId: 't1',
      revokedAt: new Date('2026-02-01'),
      revokedBy: 'did:apoa:juan',
      reason: 'second',
      cascaded: [],
    };
    await store.add(r1);
    await store.add(r2);
    const result = await store.check('t1');
    expect(result?.reason).toBe('second');
  });
});

describe('MemoryAuditStore', () => {
  let store: MemoryAuditStore;

  beforeEach(() => {
    store = new MemoryAuditStore();
  });

  function makeEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
    return {
      tokenId: 'token-1',
      timestamp: new Date(),
      action: 'appointments:read',
      service: 'mychart.com',
      result: 'allowed',
      ...overrides,
    };
  }

  it('returns empty array for unknown token', async () => {
    expect(await store.query('unknown')).toEqual([]);
  });

  it('appends and queries entries by tokenId', async () => {
    await store.append(makeEntry());
    await store.append(makeEntry({ tokenId: 'token-2' }));

    const results = await store.query('token-1');
    expect(results).toHaveLength(1);
  });

  it('queries entries by service', async () => {
    await store.append(makeEntry({ service: 'mychart.com' }));
    await store.append(makeEntry({ service: 'stripe.com' }));
    await store.append(makeEntry({ service: 'mychart.com' }));

    const results = await store.queryByService('mychart.com');
    expect(results).toHaveLength(2);
  });

  it('filters by date range', async () => {
    await store.append(
      makeEntry({ timestamp: new Date('2026-01-01') })
    );
    await store.append(
      makeEntry({ timestamp: new Date('2026-06-01') })
    );
    await store.append(
      makeEntry({ timestamp: new Date('2026-12-01') })
    );

    const results = await store.query('token-1', {
      from: new Date('2026-03-01'),
      to: new Date('2026-09-01'),
    });
    expect(results).toHaveLength(1);
  });

  it('filters by action', async () => {
    await store.append(makeEntry({ action: 'appointments:read' }));
    await store.append(makeEntry({ action: 'prescriptions:read' }));

    const results = await store.query('token-1', { action: 'appointments:read' });
    expect(results).toHaveLength(1);
  });

  it('filters by result', async () => {
    await store.append(makeEntry({ result: 'allowed' }));
    await store.append(makeEntry({ result: 'denied' }));
    await store.append(makeEntry({ result: 'allowed' }));

    const results = await store.query('token-1', { result: 'denied' });
    expect(results).toHaveLength(1);
  });

  it('applies limit and offset', async () => {
    for (let i = 0; i < 10; i++) {
      await store.append(makeEntry());
    }

    const limited = await store.query('token-1', { limit: 3 });
    expect(limited).toHaveLength(3);

    const offset = await store.query('token-1', { limit: 3, offset: 8 });
    expect(offset).toHaveLength(2);
  });

  it('defaults to limit 100', async () => {
    for (let i = 0; i < 150; i++) {
      await store.append(makeEntry());
    }
    const results = await store.query('token-1');
    expect(results).toHaveLength(100);
  });

  it('handles browser-mode audit entries', async () => {
    await store.append(
      makeEntry({
        url: 'https://portal.example.com/page',
        screenshotRef: 's3://bucket/shot.png',
        accessMode: 'browser',
      })
    );

    const results = await store.query('token-1');
    expect(results[0].url).toBe('https://portal.example.com/page');
    expect(results[0].accessMode).toBe('browser');
  });
});
