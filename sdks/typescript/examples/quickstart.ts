import { APOA, generateKeyPair } from '../src/index.js';

const keys = await generateKeyPair();
const apoa = new APOA({ privateKey: keys.privateKey });

const token = await apoa.tokens.createGrant({
  principal: "did:apoa:alex",
  agent: { id: "did:apoa:docs-assistant", name: "Docs Assistant" },
  service: "knowledge-base",
  scopes: ["articles:search", "articles:summarize"],
  constraints: { externalSharing: false },
  expiresIn: "24h",
});

const validation = await apoa.tokens.validate(token.raw, {
  publicKey: keys.publicKey,
});
console.log("token valid →", validation.valid);

// Can the agent summarize articles? Yes.
const allowed = await apoa.authorizations.check(token, "knowledge-base", "articles:summarize");
console.log("articles:summarize →", allowed);
// { authorized: true, checks: { revoked: false, scopeAllowed: true, ... } }

// Can the agent delete articles? Absolutely not.
const denied = await apoa.authorizations.check(token, "knowledge-base", "articles:delete");
console.log("articles:delete →", denied);
// { authorized: false, reason: "scope 'articles:delete' not in authorized scopes" }
