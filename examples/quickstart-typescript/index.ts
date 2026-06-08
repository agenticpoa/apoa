import { APOA, generateKeyPair } from '@apoa/core';

const keys = await generateKeyPair();
const apoa = new APOA({ privateKey: keys.privateKey });

const token = await apoa.tokens.createGrant({
  principal: 'did:apoa:alex',
  agent: { id: 'did:apoa:docs-assistant', name: 'Docs Assistant' },
  service: 'knowledge-base',
  scopes: ['articles:search', 'articles:summarize'],
  expiresIn: '24h',
});

const validation = await apoa.tokens.validate(token.raw, {
  publicKey: keys.publicKey,
});

const allowed = await apoa.authorizations.check(
  token,
  'knowledge-base',
  'articles:summarize',
);

const denied = await apoa.authorizations.check(
  token,
  'knowledge-base',
  'articles:delete',
);

console.log({
  valid: validation.valid,
  summarize: allowed.authorized,
  delete: denied.authorized,
  deniedReason: denied.reason,
});

