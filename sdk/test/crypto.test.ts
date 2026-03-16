import { describe, it, expect } from 'vitest';
import { generateKeyPair, sign, verify } from '../src/utils/crypto.js';

describe('crypto', () => {
  describe('generateKeyPair', () => {
    it('generates an EdDSA key pair by default', async () => {
      const keys = await generateKeyPair();
      expect(keys.publicKey).toBeDefined();
      expect(keys.privateKey).toBeDefined();
    });

    it('generates an ES256 key pair', async () => {
      const keys = await generateKeyPair('ES256');
      expect(keys.publicKey).toBeDefined();
      expect(keys.privateKey).toBeDefined();
    });
  });

  describe('sign and verify', () => {
    it('signs and verifies a payload with EdDSA', async () => {
      const keys = await generateKeyPair('EdDSA');
      const payload = { sub: 'did:apoa:test', action: 'read' };

      const jws = await sign(payload, { privateKey: keys.privateKey });
      expect(typeof jws).toBe('string');
      expect(jws.split('.')).toHaveLength(3);

      const decoded = await verify(jws, keys.publicKey);
      expect(decoded.sub).toBe('did:apoa:test');
      expect(decoded.action).toBe('read');
    });

    it('signs and verifies a payload with ES256', async () => {
      const keys = await generateKeyPair('ES256');
      const payload = { sub: 'did:apoa:test', num: 42 };

      const jws = await sign(payload, {
        privateKey: keys.privateKey,
        algorithm: 'ES256',
      });
      const decoded = await verify(jws, keys.publicKey);
      expect(decoded.sub).toBe('did:apoa:test');
      expect(decoded.num).toBe(42);
    });

    it('includes kid in the header when provided', async () => {
      const keys = await generateKeyPair('EdDSA');
      const payload = { sub: 'test' };

      const jws = await sign(payload, {
        privateKey: keys.privateKey,
        kid: 'key-2026-01',
      });

      // Decode the protected header to verify kid
      const [headerB64] = jws.split('.');
      const header = JSON.parse(
        Buffer.from(headerB64, 'base64url').toString('utf-8')
      );
      expect(header.kid).toBe('key-2026-01');
      expect(header.alg).toBe('EdDSA');
    });

    it('rejects a tampered token', async () => {
      const keys = await generateKeyPair('EdDSA');
      const jws = await sign({ sub: 'test' }, { privateKey: keys.privateKey });

      // Tamper with the payload
      const parts = jws.split('.');
      parts[1] = Buffer.from(JSON.stringify({ sub: 'hacked' })).toString(
        'base64url'
      );
      const tampered = parts.join('.');

      await expect(verify(tampered, keys.publicKey)).rejects.toThrow();
    });

    it('rejects verification with wrong key', async () => {
      const keys1 = await generateKeyPair('EdDSA');
      const keys2 = await generateKeyPair('EdDSA');

      const jws = await sign({ sub: 'test' }, { privateKey: keys1.privateKey });

      await expect(verify(jws, keys2.publicKey)).rejects.toThrow();
    });
  });
});
