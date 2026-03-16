import { createClient, generateKeyPair } from '../src/index.js';

const keys = await generateKeyPair();

const apoa = createClient({
  defaultSigningOptions: { privateKey: keys.privateKey },
});

// The flagship example: 4 services, mixed access modes, legal framework,
// hard/soft rules, browser configs, and cross-service audit trail.
const token = await apoa.createToken({
  principal: { id: 'did:apoa:jane', name: 'Jane Doe' },
  agent: { id: 'did:apoa:homebot', name: 'HomeBot Pro' },
  agentProvider: {
    name: 'HomeBot Inc.',
    id: 'did:apoa:provider:homebot',
    contact: 'legal@homebot.ai',
  },
  services: [
    // Browser mode: mortgage lender portal
    {
      service: 'nationwidemortgage.com',
      scopes: ['rate_lock:read', 'documents:read', 'timeline:read'],
      constraints: { signing: false, data_export: false },
      accessMode: 'browser',
      browserConfig: {
        allowedUrls: [
          'https://portal.nationwidemortgage.com/application/*',
          'https://portal.nationwidemortgage.com/documents/*',
        ],
        credentialVaultRef: '1password://vault/mortgage-portal',
        allowFormInteraction: false,
        maxSessionDuration: 1800,
        captureScreenshots: true,
        blockedActions: ['click:*sign*', 'click:*submit*', 'click:*approve*', 'navigate:*/settings/*'],
      },
    },
    // Browser mode: title company
    {
      service: 'titlecompany.com',
      scopes: ['title_search:read', 'closing_status:read'],
      constraints: { signing: false },
      accessMode: 'browser',
      browserConfig: {
        allowedUrls: ['https://portal.titlecompany.com/*'],
        credentialVaultRef: '1password://vault/title-company',
        allowFormInteraction: false,
        maxSessionDuration: 900,
      },
    },
    // Browser mode: DocuSign
    {
      service: 'docusign.com',
      scopes: ['documents:read', 'documents:flag_for_review'],
      constraints: { signing: false },
      accessMode: 'browser',
      browserConfig: {
        allowedUrls: ['https://app.docusign.com/documents/*'],
        credentialVaultRef: '1password://vault/docusign',
        allowFormInteraction: false,
        blockedActions: ['click:*sign*', 'click:*decline*'],
      },
    },
    // API mode: Redfin
    {
      service: 'api.redfin.com',
      scopes: ['listings:read', 'offers:read', 'market_data:read'],
      accessMode: 'api',
      apiConfig: {
        oauthScopes: ['read_only'],
      },
    },
  ],
  rules: [
    { id: 'no-signing', description: 'Never sign, submit, or commit to anything', enforcement: 'hard' },
    {
      id: 'deadline-alert',
      description: 'Alert me if any deadline is within 48 hours',
      enforcement: 'soft',
      onViolation: (v) => console.log(`⚠️  DEADLINE ALERT: ${v.details}`),
    },
  ],
  legal: {
    model: 'provider-as-agent',
    jurisdiction: 'US-CA',
    legalBasis: ['UETA-14', 'E-SIGN'],
    pairedLegalInstrument: false,
  },
  expires: '2026-06-15',
});

console.log(`Home purchase token created: ${token.jti}`);
console.log(`Services: ${token.audience?.join(', ')}`);
console.log(`Legal: ${token.definition.legal?.model} (${token.definition.legal?.jurisdiction})`);

// Scope checks across services
console.log('\n--- Cross-Service Scope Checks ---');
const checks = [
  ['nationwidemortgage.com', 'rate_lock:read'],
  ['nationwidemortgage.com', 'rate_lock:write'],
  ['titlecompany.com', 'title_search:read'],
  ['docusign.com', 'documents:read'],
  ['docusign.com', 'documents:sign'],
  ['api.redfin.com', 'listings:read'],
  ['api.redfin.com', 'offers:submit'],
] as const;

for (const [svc, action] of checks) {
  const r = apoa.checkScope(token, svc, action);
  console.log(`  ${svc} ${action} → ${r.allowed ? '✓' : '✗'} (${r.reason})`);
}

// Simulate browser-mode audit entries
console.log('\n--- Simulating Agent Actions ---');

await apoa.logAction(token.jti, {
  action: 'rate_lock:read',
  service: 'nationwidemortgage.com',
  result: 'allowed',
  url: 'https://portal.nationwidemortgage.com/application/rate-lock',
  accessMode: 'browser',
  screenshotRef: 's3://homebot-audit/jane/mortgage/rate-lock-001.png',
  details: { rate: '6.25%', locked_until: '2026-04-15' },
});

await apoa.logAction(token.jti, {
  action: 'documents:read',
  service: 'docusign.com',
  result: 'allowed',
  url: 'https://app.docusign.com/documents/closing-disclosure',
  accessMode: 'browser',
  details: { documentType: 'Closing Disclosure', pages: 5 },
});

await apoa.logAction(token.jti, {
  action: 'listings:read',
  service: 'api.redfin.com',
  result: 'allowed',
  accessMode: 'api',
  details: { listingsReturned: 42, zipCode: '94110' },
});

// Cross-service audit trail
console.log('\n--- Cross-Service Audit Trail ---');
const trail = await apoa.getAuditTrail(token.jti);
for (const entry of trail) {
  const mode = entry.accessMode ?? 'unknown';
  const url = entry.url ? ` @ ${entry.url}` : '';
  console.log(`  [${mode}] ${entry.service} → ${entry.action}${url}`);
}

// Service-specific trail
const mortgageTrail = await apoa.getAuditTrailByService('nationwidemortgage.com');
console.log(`\nMortgage audit entries: ${mortgageTrail.length}`);
console.log(`  Access mode: ${mortgageTrail[0]?.accessMode}`);
console.log(`  URL: ${mortgageTrail[0]?.url}`);
console.log(`  Screenshot: ${mortgageTrail[0]?.screenshotRef}`);
