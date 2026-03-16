import { describe, it, expect, beforeEach } from 'vitest';
import { logAction } from '../src/audit/log.js';
import { getAuditTrail, getAuditTrailByService } from '../src/audit/trail.js';
import { MemoryAuditStore } from '../src/audit/store.js';

describe('audit', () => {
  let store: MemoryAuditStore;

  beforeEach(() => {
    store = new MemoryAuditStore();
  });

  describe('logAction', () => {
    it('logs an action with timestamp', async () => {
      await logAction(
        'token-1',
        {
          action: 'appointments:read',
          service: 'mychart.com',
          result: 'allowed',
        },
        store
      );

      const entries = await store.query('token-1');
      expect(entries).toHaveLength(1);
      expect(entries[0].tokenId).toBe('token-1');
      expect(entries[0].action).toBe('appointments:read');
      expect(entries[0].service).toBe('mychart.com');
      expect(entries[0].result).toBe('allowed');
      expect(entries[0].timestamp).toBeInstanceOf(Date);
    });

    it('logs an action with details', async () => {
      await logAction(
        'token-1',
        {
          action: 'rate_lock:read',
          service: 'mortgage.com',
          result: 'allowed',
          details: { rate: '6.25%', locked: true },
        },
        store
      );

      const entries = await store.query('token-1');
      expect(entries[0].details).toEqual({ rate: '6.25%', locked: true });
    });

    it('logs a denied action', async () => {
      await logAction(
        'token-1',
        {
          action: 'messages:send',
          service: 'mychart.com',
          result: 'denied',
        },
        store
      );

      const entries = await store.query('token-1');
      expect(entries[0].result).toBe('denied');
    });

    it('logs browser-mode fields', async () => {
      await logAction(
        'token-1',
        {
          action: 'rate_lock:read',
          service: 'mortgage.com',
          result: 'allowed',
          url: 'https://portal.mortgage.com/rate-lock',
          accessMode: 'browser',
          screenshotRef: 's3://bucket/shot.png',
        },
        store
      );

      const entries = await store.query('token-1');
      expect(entries[0].url).toBe('https://portal.mortgage.com/rate-lock');
      expect(entries[0].accessMode).toBe('browser');
      expect(entries[0].screenshotRef).toBe('s3://bucket/shot.png');
    });
  });

  describe('getAuditTrail', () => {
    it('returns entries for a specific token', async () => {
      await logAction('token-1', { action: 'read', service: 'a.com', result: 'allowed' }, store);
      await logAction('token-2', { action: 'read', service: 'a.com', result: 'allowed' }, store);
      await logAction('token-1', { action: 'write', service: 'a.com', result: 'denied' }, store);

      const trail = await getAuditTrail('token-1', undefined, store);
      expect(trail).toHaveLength(2);
    });

    it('returns empty array for unknown token', async () => {
      const trail = await getAuditTrail('unknown', undefined, store);
      expect(trail).toEqual([]);
    });

    it('supports query options', async () => {
      await logAction('token-1', { action: 'read', service: 'a.com', result: 'allowed' }, store);
      await logAction('token-1', { action: 'write', service: 'a.com', result: 'denied' }, store);

      const trail = await getAuditTrail('token-1', { result: 'denied' }, store);
      expect(trail).toHaveLength(1);
      expect(trail[0].action).toBe('write');
    });
  });

  describe('getAuditTrailByService', () => {
    it('returns entries across all tokens for a service', async () => {
      await logAction('token-1', { action: 'read', service: 'mychart.com', result: 'allowed' }, store);
      await logAction('token-2', { action: 'write', service: 'mychart.com', result: 'allowed' }, store);
      await logAction('token-1', { action: 'read', service: 'stripe.com', result: 'allowed' }, store);

      const trail = await getAuditTrailByService('mychart.com', undefined, store);
      expect(trail).toHaveLength(2);
    });

    it('returns empty for unknown service', async () => {
      const trail = await getAuditTrailByService('unknown.com', undefined, store);
      expect(trail).toEqual([]);
    });
  });
});
