import { createToken, checkScope, generateKeyPair } from '../src/index.js';

const keys = await generateKeyPair();

const token = await createToken({
  principal: { id: "did:apoa:you" },
  agent: { id: "did:apoa:your-agent", name: "My Agent" },
  services: [{
    service: "mychart.com",
    scopes: ["appointments:read", "prescriptions:read"],
    constraints: { signing: false, data_export: false }
  }],
  expires: "2026-09-01"
}, { privateKey: keys.privateKey });

// Can the agent read appointments? Yes.
const allowed = checkScope(token, "mychart.com", "appointments:read");
console.log("appointments:read →", allowed);
// { allowed: true, reason: "matched scope 'appointments:read'", matchedScope: "appointments:read" }

// Can the agent send messages? Absolutely not.
const denied = checkScope(token, "mychart.com", "messages:send");
console.log("messages:send →", denied);
// { allowed: false, reason: "scope 'messages:send' not in authorized scopes" }
