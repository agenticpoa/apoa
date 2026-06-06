import { APOA, generateKeyPair } from '../src/index.js';

const keys = await generateKeyPair();
const apoa = new APOA({ privateKey: keys.privateKey });

const token = await apoa.tokens.createGrant({
  principal: "did:apoa:you",
  agent: { id: "did:apoa:your-agent", name: "My Agent" },
  service: "mychart.com",
  scopes: ["appointments:read", "prescriptions:read"],
  constraints: { signing: false, data_export: false },
  expiresIn: "30d",
});

const validation = await apoa.tokens.validate(token.raw, {
  publicKey: keys.publicKey,
});
console.log("token valid →", validation.valid);

// Can the agent read appointments? Yes.
const allowed = await apoa.authorizations.check(token, "mychart.com", "appointments:read");
console.log("appointments:read →", allowed);
// { authorized: true, checks: { revoked: false, scopeAllowed: true, ... } }

// Can the agent send messages? Absolutely not.
const denied = await apoa.authorizations.check(token, "mychart.com", "messages:send");
console.log("messages:send →", denied);
// { authorized: false, reason: "scope 'messages:send' not in authorized scopes" }
