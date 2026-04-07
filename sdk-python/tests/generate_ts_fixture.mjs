/**
 * Generate a fixture JWT from the TypeScript SDK for cross-SDK compatibility testing.
 * Run: node tests/generate_ts_fixture.mjs
 */
import { createToken, generateKeyPair } from '../../sdk/src/index.ts';
import { writeFileSync } from 'fs';

const keys = await generateKeyPair();

const token = await createToken(
  {
    principal: { id: 'did:apoa:alice', name: 'Alice' },
    agent: { id: 'did:apoa:homebot', name: 'HomeBot Pro' },
    agentProvider: { name: 'HomeBot Inc.', contact: 'support@homebot.ai' },
    services: [
      {
        service: 'nationwidemortgage.com',
        scopes: ['rate_lock:read', 'documents:read'],
        constraints: { signing: false, data_export: false },
        accessMode: 'browser',
        browserConfig: {
          allowedUrls: ['https://portal.nationwidemortgage.com/*'],
          credentialVaultRef: '1password://vault/mortgage-portal',
          maxSessionDuration: 1800,
          captureScreenshots: true,
        },
      },
      {
        service: 'docusign.com',
        scopes: ['documents:read'],
        accessMode: 'api',
      },
    ],
    rules: [
      { id: 'no-signing', description: 'Never sign anything', enforcement: 'hard' },
      { id: 'deadline-alert', description: 'Alert if deadline within 48 hours', enforcement: 'soft' },
    ],
    expires: '2026-09-01T00:00:00Z',
    legal: { model: 'provider-as-agent', jurisdiction: 'US-CA', legalBasis: ['UETA-14'] },
    metadata: { source: 'ts-sdk-fixture', version: 1 },
  },
  { privateKey: keys.privateKey }
);

// Export the public key as JWK for Python to use
const pubJwk = await crypto.subtle.exportKey('jwk', keys.publicKey);

const fixture = {
  jwt: token.raw,
  publicKeyJwk: pubJwk,
  expected: {
    principalId: 'did:apoa:alice',
    agentName: 'HomeBot Pro',
    services: ['nationwidemortgage.com', 'docusign.com'],
    agentProviderName: 'HomeBot Inc.',
    jurisdiction: 'US-CA',
    constraintSigning: false,
    browserConfigVaultRef: '1password://vault/mortgage-portal',
  },
};

import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
const __dirname = dirname(fileURLToPath(import.meta.url));
writeFileSync(join(__dirname, 'fixtures', 'ts_token.json'), JSON.stringify(fixture, null, 2));
console.log('Fixture written to tests/fixtures/ts_token.json');
