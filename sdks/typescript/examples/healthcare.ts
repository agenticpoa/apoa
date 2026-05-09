import { createClient, generateKeyPair } from '../src/index.js';

const keys = await generateKeyPair();

const apoa = createClient({
  defaultSigningOptions: { privateKey: keys.privateKey },
});

// Create a multi-service healthcare monitoring token
const token = await apoa.createToken({
  principal: { id: 'did:apoa:juan', name: 'Juan Figuera' },
  agent: { id: 'did:apoa:healthbot', name: 'HealthBot Pro' },
  agentProvider: { name: 'HealthBot Inc.' },
  services: [
    {
      service: 'mychart.com',
      scopes: ['appointments:read', 'prescriptions:refill_status:read', 'lab_results:read'],
      constraints: { signing: false, data_export: false },
    },
    {
      service: 'aetna.com',
      scopes: ['claims:read', 'benefits:read', 'coverage:read'],
      constraints: { data_export: false },
    },
    {
      service: 'cvs.com',
      scopes: ['prescriptions:status:read', 'prescriptions:refill:request'],
      constraints: { payment: false },
    },
  ],
  rules: [
    { id: 'no-messaging', description: 'Never respond to messages on my behalf', enforcement: 'hard' },
    { id: 'notify-refill', description: 'Alert me when requesting any refill', enforcement: 'soft' },
  ],
  expires: '2026-09-01',
  revocable: true,
});

console.log(`Token created: ${token.jti}`);
console.log(`Issuer: ${token.issuer}`);
console.log(`Audience: ${token.audience?.join(', ')}`);

// Check various scopes
console.log('\n--- Scope Checks ---');
console.log('mychart appointments:read →', apoa.checkScope(token, 'mychart.com', 'appointments:read'));
console.log('mychart messages:send →', apoa.checkScope(token, 'mychart.com', 'messages:send'));
console.log('aetna claims:read →', apoa.checkScope(token, 'aetna.com', 'claims:read'));
console.log('cvs prescriptions:status:read →', apoa.checkScope(token, 'cvs.com', 'prescriptions:status:read'));

// Check constraints
console.log('\n--- Constraint Checks ---');
console.log('mychart signing →', apoa.checkConstraint(token, 'mychart.com', 'signing'));
console.log('cvs payment →', apoa.checkConstraint(token, 'cvs.com', 'payment'));

// Log actions
await apoa.logAction(token.jti, {
  action: 'appointments:read',
  service: 'mychart.com',
  result: 'allowed',
  details: { appointmentCount: 3 },
});

await apoa.logAction(token.jti, {
  action: 'claims:read',
  service: 'aetna.com',
  result: 'allowed',
  details: { claimsReturned: 12 },
});

await apoa.logAction(token.jti, {
  action: 'prescriptions:refill:request',
  service: 'cvs.com',
  result: 'allowed',
  details: { medication: 'Lisinopril', pharmacy: 'CVS #4521' },
});

// Query audit trail
console.log('\n--- Audit Trail ---');
const trail = await apoa.getAuditTrail(token.jti);
for (const entry of trail) {
  console.log(`  [${entry.service}] ${entry.action} → ${entry.result}`);
}

// Query by service
const aetnaTrail = await apoa.getAuditTrailByService('aetna.com');
console.log(`\nAetna audit entries: ${aetnaTrail.length}`);
